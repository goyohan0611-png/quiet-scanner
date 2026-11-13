//! CrowdSec owns detection; its official bouncer owns enforcement. Only a
//! dedicated unit and two dedicated nftables tables belong to Quiet Scanner.
use super::{model, Command as GuardCommand};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(super) const DIRECTORY: &str = "/etc/quiet-scanner/protection";
const CONFIG: &str = "/etc/quiet-scanner/protection/firewall.yaml";
const UNIT_PATH: &str = "/etc/systemd/system/quiet-scanner-protection.service";
const UNIT: &str = "quiet-scanner-protection.service";
const ALLOWLIST: &str = "quiet-scanner-user";
pub(super) const MARKER: &str = "# Managed by Quiet Scanner protection v1";
const MAX_OUTPUT: u64 = 384 * 1024;
const CSCLI: &str = "/usr/bin/cscli";
const NFT: &str = "/usr/sbin/nft";
pub(super) const SYSTEMCTL: &str = "/usr/bin/systemctl";
const BOUNCER: &str = "/usr/bin/crowdsec-firewall-bouncer";

fn root() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("관리자 권한으로 보호 작업을 실행하십시오.".into());
    }
    Ok(())
}

// No shell, inherited PATH, child input, unbounded output or credential-bearing
// stderr is exposed to the UI. cscli uses the root-owned local credentials.
pub(super) fn run(program: &str, arguments: &[&str]) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            format!(
                "{} 실행 파일을 확인하십시오.",
                Path::new(program)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            )
        })?;
    let stdout = child.stdout.take().ok_or("작업 출력 연결 실패")?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_OUTPUT + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err("보호 구성요소 응답 시간이 초과됐습니다. 다시 확인하십시오.".into());
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| "보호 작업 출력 오류")?
        .map_err(|_| "보호 작업 출력 읽기 실패")?;
    if bytes.len() as u64 > MAX_OUTPUT {
        return Err("보호 작업 결과가 너무 큽니다. 엔진 관리 도구에서 확인하십시오.".into());
    }
    if !status.success() {
        return Err(format!(
            "{} 작업에 실패했습니다. 관리자 로그에서 확인하십시오.",
            Path::new(program)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ));
    }
    String::from_utf8(bytes).map_err(|_| "보호 작업 응답을 읽지 못했습니다.".into())
}
pub(super) fn json_command(program: &str, args: &[&str]) -> Result<Value, String> {
    serde_json::from_str(&run(program, args)?)
        .map_err(|_| "보호 구성요소의 JSON 응답 형식이 잘못됐습니다.".into())
}
fn active(unit: &str) -> bool {
    run(SYSTEMCTL, &["is-active", unit]).is_ok_and(|s| s.trim() == "active")
}
fn unit_state() -> Result<(bool, bool), String> {
    let output = run(
        SYSTEMCTL,
        &["show", "--property=ActiveState,UnitFileState", UNIT],
    )?;
    let fields: std::collections::BTreeMap<_, _> =
        output.lines().filter_map(|s| s.split_once('=')).collect();
    let state = fields
        .get("ActiveState")
        .ok_or("차단 서비스 상태를 읽지 못했습니다.")?;
    let boot = fields
        .get("UnitFileState")
        .ok_or("재시작 설정을 읽지 못했습니다.")?;
    if ![
        "active",
        "inactive",
        "failed",
        "activating",
        "deactivating",
        "reloading",
    ]
    .contains(state)
    {
        return Err("알 수 없는 차단 서비스 상태입니다.".into());
    }
    Ok((!["inactive", "failed"].contains(state), *boot == "enabled"))
}
fn table(family: &str, name: &str) -> Result<Value, String> {
    // Omit potentially huge IP set contents; health needs only set/rule metadata.
    json_command(NFT, &["-j", "-t", "list", "table", family, name])
}
fn dependencies() -> bool {
    [CSCLI, NFT, SYSTEMCTL, BOUNCER]
        .iter()
        .all(|p| Path::new(p).is_file())
        && Path::new("/run/systemd/system").is_dir()
}
pub fn info() -> Value {
    json!({"supported":true,"autoInstallSupported":super::install::supported(),"platform":"linux","phase":"unchecked","protecting":false,"dependencies":dependencies(),"prepared":Path::new(CONFIG).is_file() && Path::new(UNIT_PATH).is_file(),"message":"보호를 켜면 관리자 승인 후 필요한 구성요소를 자동 설치·설정합니다."})
}
fn owned_file(path: &str) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "보호 구성이 없습니다. 보호 준비를 실행하십시오.")?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 16 * 1024
    {
        return Err("보호 구성 파일의 소유자·권한을 확인하지 못했습니다.".into());
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "보호 구성 파일을 열지 못했습니다.")?;
    let opened = file.metadata().map_err(|_| "보호 구성 확인 실패")?;
    if opened.ino() != metadata.ino() || opened.dev() != metadata.dev() {
        return Err("보호 구성 파일이 변경됐습니다.".into());
    }
    let mut text = String::new();
    file.take(16 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| "보호 구성 읽기 실패")?;
    if !text.starts_with(MARKER) {
        return Err("Quiet Scanner가 관리하는 구성이 아닙니다. 기존 설정을 유지합니다.".into());
    }
    Ok(text)
}
fn check_owned() -> Result<(), String> {
    owned_file(CONFIG)?;
    owned_file(UNIT_PATH)?;
    Ok(())
}
pub(super) fn secure_directory() -> Result<(), String> {
    for path in ["/etc/quiet-scanner", DIRECTORY] {
        if !Path::new(path).exists() {
            fs::create_dir(path).map_err(|e| e.to_string())?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("보호 설정 폴더의 소유자·권한을 확인하십시오.".into());
        }
    }
    Ok(())
}
pub(super) fn write_private_json(path: &str, value: &Value) -> Result<(), String> {
    let temporary = format!("{path}.{}.tmp", std::process::id());
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        f.write_all(&serde_json::to_vec(value).map_err(|e| e.to_string())?)
            .and_then(|_| f.sync_all())
            .map_err(|e| e.to_string())?;
        fs::rename(&temporary, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
fn enable_service() -> Result<(), String> {
    check_owned()?;
    if !active("crowdsec.service") && !super::install::managed_engine() {
        return Err(
            "탐지 엔진이 실행 중이 아닙니다. 기존 CrowdSec 설정과 로그 수집을 확인하십시오.".into(),
        );
    }
    run(SYSTEMCTL, &["enable", UNIT])?;
    if let Err(e) = run(SYSTEMCTL, &["--no-block", "start", UNIT]) {
        let _ = run(SYSTEMCTL, &["disable", UNIT]);
        return Err(e);
    }
    Ok(())
}
fn write_new(path: &str, text: &str) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "기존 보호 구성을 덮어쓰지 않습니다. 설정 파일을 확인하십시오.")?;
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())
}
fn prepare() -> Result<(), String> {
    if !dependencies() {
        return Err("CrowdSec·공식 nftables 방화벽 구성요소·systemd가 필요합니다. 보호 설정의 설치 안내를 확인하십시오.".into());
    }
    secure_directory()?;
    if Path::new(CONFIG).exists() || Path::new(UNIT_PATH).exists() {
        check_owned()?;
        run(SYSTEMCTL, &["daemon-reload"])?;
        return Ok(());
    }
    if !run(
        SYSTEMCTL,
        &["show", "--property=FragmentPath", "--value", UNIT],
    )?
    .trim()
    .is_empty()
    {
        return Err("같은 이름의 기존 서비스가 있습니다. 기존 서비스를 덮어쓰지 않습니다.".into());
    }
    // Avoid taking ownership of an existing engine key or firewall table.
    let bouncers = json_command(CSCLI, &["bouncers", "list", "-o", "json"])?;
    if bouncers
        .as_array()
        .is_none_or(|a| a.iter().any(|b| b["name"] == "quiet-scanner"))
    {
        return Err(
            "quiet-scanner 엔진 키가 이미 있거나 목록을 확인하지 못했습니다. 기존 키를 유지합니다."
                .into(),
        );
    }
    for (family, name) in [("ip", "quiet_scanner"), ("ip6", "quiet_scanner6")] {
        if table(family, name).is_ok() {
            return Err(
                "기존 Quiet Scanner 방화벽 테이블이 있습니다. 상태를 먼저 확인하십시오.".into(),
            );
        }
    }
    run(CSCLI, &["allowlists", "list", "-o", "json"])?; // Requires current allowlist-capable CrowdSec.
    let key = run(CSCLI, &["bouncers", "add", "quiet-scanner", "-o", "raw"])?;
    let key = key.trim();
    if key.len() < 16
        || key.len() > 256
        || !key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"+/=_-".contains(&c))
    {
        let _ = run(CSCLI, &["bouncers", "delete", "quiet-scanner"]);
        return Err("탐지 엔진 인증 키 형식을 확인하지 못했습니다.".into());
    }
    let config=format!("{MARKER}\nmode: nftables\nupdate_frequency: 10s\nlog_mode: stdout\nlog_level: info\napi_url: http://127.0.0.1:8080/\napi_key: {key}\ninsecure_skip_verify: false\ndisable_ipv6: false\ndeny_action: DROP\ndeny_log: false\nsupported_decisions_types: [ban]\nblacklists_ipv4: quiet_scanner_bans\nblacklists_ipv6: quiet_scanner_bans6\nnftables:\n  ipv4:\n    enabled: true\n    set-only: false\n    table: quiet_scanner\n    chain: quiet_scanner_input\n    priority: -10\n  ipv6:\n    enabled: true\n    set-only: false\n    table: quiet_scanner6\n    chain: quiet_scanner_input\n    priority: -10\nnftables_hooks: [input]\nprometheus:\n  enabled: false\n");
    let unit=format!("{MARKER}\n[Unit]\nDescription=Quiet Scanner host protection (CrowdSec)\nAfter=network-online.target crowdsec.service\nWants=network-online.target\nRequires=crowdsec.service\n[Service]\nType=simple\nExecStart={BOUNCER} -c {CONFIG}\nExecStopPost=-{NFT} delete table ip quiet_scanner\nExecStopPost=-{NFT} delete table ip6 quiet_scanner6\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=10\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nCapabilityBoundingSet=CAP_NET_ADMIN\n[Install]\nWantedBy=multi-user.target\n");
    let (mut wrote_config, mut wrote_unit) = (false, false);
    let result = (|| {
        write_new(CONFIG, &config)?;
        wrote_config = true;
        write_new(UNIT_PATH, &unit)?;
        wrote_unit = true;
        run(SYSTEMCTL, &["daemon-reload"])?;
        Ok(())
    })();
    if result.is_err() {
        if wrote_unit {
            let _ = fs::remove_file(UNIT_PATH);
        }
        if wrote_config {
            let _ = fs::remove_file(CONFIG);
        }
        let _ = run(CSCLI, &["bouncers", "delete", "quiet-scanner"]);
        let _ = run(SYSTEMCTL, &["daemon-reload"]);
    }
    result
}

fn status() -> Result<Value, String> {
    let mut result = info();
    if let Some(installation) = super::install::state() {
        for (key, value) in installation.as_object().unwrap() {
            result[key] = value.clone();
        }
        return Ok(result);
    }
    result["sources"] = super::install::sources();
    if !dependencies() {
        result["phase"] = json!("missing");
        result["message"] = json!("보호 구성요소를 설치한 뒤 다시 확인하십시오.");
        return Ok(result);
    }
    if check_owned().is_err() {
        result["phase"] = json!("unprepared");
        result["message"] = json!("아직 보호 구성이 없습니다. 보호 준비를 실행하십시오.");
        return Ok(result);
    }
    let engine = active("crowdsec.service");
    let unit = unit_state();
    let (service, boot) = unit.as_ref().copied().unwrap_or((false, false));
    let decisions = json_command(
        CSCLI,
        &[
            "decisions",
            "list",
            "--no-simu",
            "--limit",
            "100",
            "-o",
            "json",
        ],
    )
    .and_then(|v| model::decisions(&v));
    let fresh = json_command(CSCLI, &["bouncers", "list", "-o", "json"])
        .is_ok_and(|v| model::fresh_pull(&v, chrono::Utc::now().timestamp()));
    let v4 = table("ip", "quiet_scanner");
    let v6 = table("ip6", "quiet_scanner6");
    let bans4 = decisions.as_ref().is_ok_and(|ds| {
        ds.iter()
            .any(|d| d.ip.parse::<std::net::Ipv4Addr>().is_ok())
    });
    let bans6 = decisions.as_ref().is_ok_and(|ds| {
        ds.iter()
            .any(|d| d.ip.parse::<std::net::Ipv6Addr>().is_ok())
    });
    let firewall4 = v4.as_ref().is_ok_and(|v| {
        model::firewall_verified(v, "ip", "quiet_scanner", "quiet_scanner_bans", bans4)
    });
    let firewall6 = v6.as_ref().is_ok_and(|v| {
        model::firewall_verified(v, "ip6", "quiet_scanner6", "quiet_scanner_bans6", bans6)
    });
    let tables = json_command(NFT, &["-j", "list", "tables"]);
    let absent = tables
        .as_ref()
        .ok()
        .and_then(|v| v["nftables"].as_array())
        .is_some_and(|rows| {
            !rows.iter().any(|r| {
                r.get("table").is_some_and(|t| {
                    (t["family"] == "ip" && t["name"] == "quiet_scanner")
                        || (t["family"] == "ip6" && t["name"] == "quiet_scanner6")
                })
            })
        });
    let protecting = unit.is_ok()
        && engine
        && service
        && boot
        && fresh
        && firewall4
        && firewall6
        && decisions.is_ok();
    let phase = if protecting {
        "on"
    } else if unit.is_err() || service || boot || !absent {
        "degraded"
    } else {
        "off"
    };
    let message = match phase {
        "on" => "탐지 엔진 연결과 IPv4·IPv6 수신 경로를 확인했습니다.",
        "off" => "보호 모드가 꺼져 있습니다.",
        _ => "보호 상태를 확인하지 못했습니다. 일부 차단 규칙은 남아 있을 수 있습니다.",
    };
    result["phase"] = json!(phase);
    result["protecting"] = json!(protecting);
    result["message"] = json!(message);
    result["checks"] = json!({"engine":engine,"service":service,"boot":boot,"connection":fresh,"ipv4":firewall4,"ipv6":firewall6,"decisions":decisions.is_ok()});
    result["decisions"] = json!(decisions.unwrap_or_default());
    result["checkedAt"] = json!(chrono::Utc::now().to_rfc3339());
    if let Ok(allowlist) = json_command(CSCLI, &["allowlists", "inspect", ALLOWLIST, "-o", "json"])
    {
        let ips: Vec<_> = allowlist["items"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v["value"].as_str())
            .filter_map(|v| model::safe_ip(v).ok())
            .take(200)
            .collect();
        result["allowlist"] = json!(ips);
    }
    Ok(result)
}

pub fn execute(command: GuardCommand) -> Result<Value, String> {
    root()?;
    // Observations must not contend with the installer's finalization lock.
    // Files are replaced atomically; partial/unknown health never reports ON.
    if matches!(command, GuardCommand::Status {}) {
        return status();
    }
    // Serialize app/CLI operations across processes so OFF cannot race an ON.
    secure_directory()?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(format!("{DIRECTORY}/operation.lock"))
        .map_err(|_| "보호 작업 잠금 실패")?;
    let lock_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&lock),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } == 0
        {
            break;
        }
        if Instant::now() >= lock_deadline {
            return Err("다른 보호 작업이 진행 중입니다. 잠시 후 다시 확인하십시오.".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    match command {
        GuardCommand::Status {} => {}
        GuardCommand::Prepare {} => prepare()?,
        GuardCommand::Enable {} => enable_service()?,
        GuardCommand::AutoEnable {} => {
            if super::install::running() {
                return status();
            }
            let failed = super::install::state().is_some_and(|v| v["phase"] == "install_failed");
            if dependencies() && check_owned().is_ok() && super::install::configured() && !failed {
                enable_service()?;
            } else {
                super::install::start()?;
            }
        }
        GuardCommand::FinishInstall {} => {
            if !super::install::configured() {
                return Err("로그 수집 자동 설정을 확인하지 못했습니다.".into());
            }
            prepare()?;
            if !super::install::cancelled() {
                enable_service()?;
            } else if super::install::managed_engine() && !super::install::others_use_engine() {
                run(SYSTEMCTL, &["disable", "crowdsec.service"])?;
                run(SYSTEMCTL, &["--no-block", "stop", "crowdsec.service"])?;
            }
        }
        GuardCommand::Disable {} => {
            if super::install::running() {
                super::install::cancel()?;
                // Finalization holds this same lock. A late cancellation must
                // stop an already queued bouncer, without killing apt/dpkg.
                if check_owned().is_ok() {
                    run(SYSTEMCTL, &["disable", UNIT])?;
                    run(SYSTEMCTL, &["--no-block", "stop", UNIT])?;
                    if super::install::activating()
                        && super::install::managed_engine()
                        && !super::install::others_use_engine()
                    {
                        run(SYSTEMCTL, &["disable", "crowdsec.service"])?;
                        run(SYSTEMCTL, &["--no-block", "stop", "crowdsec.service"])?;
                    }
                }
                return status();
            }
            check_owned()?;
            run(SYSTEMCTL, &["disable", UNIT])?;
            run(SYSTEMCTL, &["--no-block", "stop", UNIT])?;
            if unit_state().is_ok_and(|(running, _)| !running) {
                for (family, name) in [("ip", "quiet_scanner"), ("ip6", "quiet_scanner6")] {
                    if table(family, name).is_ok() {
                        run(NFT, &["delete", "table", family, name])?;
                    }
                }
            }
            if super::install::managed_engine() && !super::install::others_use_engine() {
                run(SYSTEMCTL, &["disable", "crowdsec.service"])?;
                run(SYSTEMCTL, &["--no-block", "stop", "crowdsec.service"])?;
            }
            super::install::clear_failure()?;
            // The bouncer removes only its own tables when it stops. The UI
            // stays degraded/stopping until both tables are actually absent.
        }
        GuardCommand::Allow { ip } => {
            check_owned()?;
            let ip = model::safe_ip(&ip)?;
            if json_command(CSCLI, &["allowlists", "inspect", ALLOWLIST, "-o", "json"]).is_err() {
                run(
                    CSCLI,
                    &[
                        "allowlists",
                        "create",
                        ALLOWLIST,
                        "-d",
                        "Quiet Scanner explicit user exceptions",
                    ],
                )?;
            }
            run(
                CSCLI,
                &[
                    "allowlists",
                    "add",
                    ALLOWLIST,
                    &ip,
                    "-d",
                    "Explicitly allowed in Quiet Scanner",
                ],
            )?;
            // An allowlist prevents future decisions; delete active bans too.
            run(CSCLI, &["decisions", "delete", "--ip", &ip])?;
        }
        GuardCommand::RemoveAllow { ip } => {
            check_owned()?;
            let ip = model::safe_ip(&ip)?;
            run(CSCLI, &["allowlists", "remove", ALLOWLIST, &ip])?;
        }
    }
    status()
}
