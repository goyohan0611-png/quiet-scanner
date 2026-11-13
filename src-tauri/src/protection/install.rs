//! Root-owned, resumable provisioning. Never run apt in the GUI worker request.
use super::linux::{self, run, secure_directory, MARKER, SYSTEMCTL};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

const SETUP_UNIT: &str = "quiet-scanner-protection-setup.service";
const SETUP_UNIT_PATH: &str = "/etc/systemd/system/quiet-scanner-protection-setup.service";
const STAGE: &str = "/etc/quiet-scanner/protection/setup-stage.json";
const REPORT: &str = "/etc/quiet-scanner/protection/sources.json";
const CANCEL: &str = "/etc/quiet-scanner/protection/cancel-start";
const WORKER: &str = "/etc/quiet-scanner/protection/setup-worker";
const SCRIPT: &str = "/etc/quiet-scanner/protection/install.sh";
const HELPER: &str = "/etc/quiet-scanner/protection/configure.py";

pub fn supported() -> bool {
    fs::read_to_string("/etc/os-release").is_ok_and(|s| {
        let values: std::collections::BTreeMap<_, _> = s
            .lines()
            .filter_map(|s| s.split_once('='))
            .map(|(k, v)| (k, v.trim_matches('"')))
            .collect();
        values.get("ID") == Some(&"ubuntu")
            && values
                .get("VERSION_ID")
                .and_then(|v| v.split('.').next())
                .and_then(|v| v.parse::<u32>().ok())
                .is_some_and(|v| v >= 24)
    }) && Path::new("/run/systemd/system").is_dir()
}
fn read_json(path: &str) -> Option<Value> {
    let m = fs::symlink_metadata(path).ok()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.len() > 64 * 1024 {
        return None;
    }
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let opened = f.metadata().ok()?;
    if opened.ino() != m.ino() || opened.dev() != m.dev() {
        return None;
    }
    serde_json::from_reader(f).ok()
}
fn unit_property(name: &str) -> Result<String, String> {
    run(
        SYSTEMCTL,
        &["show", &format!("--property={name}"), "--value", SETUP_UNIT],
    )
    .map(|s| s.trim().to_string())
}
pub fn running() -> bool {
    Path::new(SETUP_UNIT_PATH).exists()
        && unit_property("ActiveState")
            .is_ok_and(|v| matches!(v.as_str(), "activating" | "active" | "deactivating"))
}
pub fn configured() -> bool {
    read_json(REPORT).is_some_and(|v| v["inputs"].as_array().is_some_and(|a| !a.is_empty()))
}
pub fn sources() -> Value {
    read_json(REPORT)
        .and_then(|v| v.get("inputs").cloned())
        .unwrap_or_else(|| json!([]))
}
pub fn managed_engine() -> bool {
    read_json(REPORT).is_some_and(|v| v["managedEngine"] == true)
}
pub fn others_use_engine() -> bool {
    let own = read_json(REPORT).unwrap_or_default();
    let ignore = own["packageBouncers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let Ok(v) = linux::json_command("/usr/bin/cscli", &["bouncers", "list", "-o", "json"]) else {
        return true;
    };
    v.as_array().is_none_or(|rows| {
        rows.iter()
            .any(|r| r["name"] != "quiet-scanner" && !ignore.contains(&r["name"]))
    })
}
pub fn cancelled() -> bool {
    Path::new(CANCEL).exists()
}
pub fn cancel() -> Result<(), String> {
    if !cancelled() {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(CANCEL)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn clear_failure() -> Result<(), String> {
    if Path::new(SETUP_UNIT_PATH).exists() {
        run(SYSTEMCTL, &["reset-failed", SETUP_UNIT])?;
        linux::write_private_json(STAGE, &json!({"stage":"cancelled"}))?;
    }
    Ok(())
}
pub fn state() -> Option<Value> {
    if !Path::new(SETUP_UNIT_PATH).exists() {
        return None;
    }
    let active = unit_property("ActiveState").ok()?;
    let stage = read_json(STAGE).unwrap_or_else(|| json!({"stage":"starting"}));
    let code = stage["stage"].as_str().unwrap_or("starting");
    let (pct, message) = match code {
        "repository" => (12, "공식 패키지 저장소를 준비하는 중"),
        "packages" => (30, "탐지 엔진과 차단 구성요소를 설치하는 중"),
        "configure" => (65, "서버 서비스와 로그 수집을 자동 설정하는 중"),
        "validate" => (82, "탐지 설정과 서비스 실행을 확인하는 중"),
        "activate" => (92, "보호 구성과 자동 시작을 연결하는 중"),
        "done" => (100, "설치와 기본 설정 완료 · 보호 상태 확인 중"),
        "cancelled" => (100, "설치는 완료됐고 보호 시작은 취소됐습니다."),
        _ => (3, "보호 모드 설치를 준비하는 중"),
    };
    if matches!(active.as_str(), "activating" | "active" | "deactivating") {
        return Some(
            json!({"phase":"installing","protecting":false,"installation":{"stage":code,"pct":pct,"cancelled":cancelled()},"message":if cancelled(){"설치는 안전하게 마무리하고 보호 시작은 취소합니다."}else{message}}),
        );
    }
    if active == "failed" || code == "failed" {
        return Some(
            json!({"phase":"install_failed","protecting":false,"installation":{"stage":"failed","pct":0},"message":"설치 또는 자동 설정을 완료하지 못했습니다. 네트워크·패키지 잠금·로그 설정을 확인한 뒤 다시 켜십시오. 관리자 설치 로그: /var/log/quiet-scanner-protection-setup.log"}),
        );
    }
    None
}
fn replace_owned(path: &str, content: &[u8], mode: u32) -> Result<(), String> {
    if Path::new(path).exists() {
        let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("기존 설치 파일의 소유자·권한을 확인하십시오.".into());
        }
        if path != WORKER && !fs::read_to_string(path).is_ok_and(|s| s.starts_with(MARKER)) {
            return Err("기존 설치 파일을 덮어쓰지 않습니다.".into());
        }
    }
    let temporary = format!("{path}.{}.tmp", std::process::id());
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.write_all(content)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        fs::rename(&temporary, path).map_err(|e| e.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
pub fn start() -> Result<(), String> {
    if !supported() {
        return Err("자동 설치는 systemd를 사용하는 Ubuntu 24.04 이상에서 지원합니다.".into());
    }
    if running() {
        return Ok(());
    }
    secure_directory()?;
    // Copy the actual running image, not a user-writable executable pathname.
    let image = fs::read("/proc/self/exe").map_err(|e| e.to_string())?;
    replace_owned(WORKER, &image, 0o700)?;
    replace_owned(SCRIPT, include_bytes!("install.sh"), 0o700)?;
    replace_owned(HELPER, include_bytes!("configure.py"), 0o600)?;
    let unit=format!("{MARKER}\n[Unit]\nDescription=Quiet Scanner first-use protection setup\nWants=network-online.target\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/bin/bash {SCRIPT}\nTimeoutStartSec=1800\nUMask=0077\nPrivateTmp=true\nProtectHome=true\nStandardOutput=append:/var/log/quiet-scanner-protection-setup.log\nStandardError=append:/var/log/quiet-scanner-protection-setup.log\n");
    replace_owned(SETUP_UNIT_PATH, unit.as_bytes(), 0o600)?;
    let stage = json!({"stage":"starting"});
    linux::write_private_json(STAGE, &stage)?;
    if cancelled() {
        fs::remove_file(CANCEL).map_err(|e| e.to_string())?;
    }
    let log = "/var/log/quiet-scanner-protection-setup.log";
    let f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(log)
        .map_err(|e| e.to_string())?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err("관리자 설치 로그 파일의 권한을 확인하십시오.".into());
    }
    run(SYSTEMCTL, &["daemon-reload"])?;
    run(SYSTEMCTL, &["reset-failed", SETUP_UNIT])?;
    run(SYSTEMCTL, &["--no-block", "start", SETUP_UNIT])?;
    Ok(())
}
