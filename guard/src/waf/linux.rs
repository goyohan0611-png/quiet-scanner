use super::*;
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
const PUBLIC: &str = "/var/lib/quiet-guard/waf/public.json";
const HEALTH: &str = "/var/lib/quiet-guard/waf/health.json";
const SCRIPT: &str = concat!(
    include_str!("../../scripts/nginx_config.py"),
    "\n",
    include_str!("../../scripts/waf_setup.py")
);

fn read(path: &str, limit: u64) -> Result<Vec<u8>, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "Missing WAF evidence")?;
    let meta = file.metadata().map_err(|_| "Unreadable WAF evidence")?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.len() > limit {
        return Err("Untrusted WAF evidence".into());
    }
    let mut data = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Unreadable WAF evidence")?;
    if data.len() as u64 > limit {
        return Err("Oversized WAF evidence".into());
    }
    Ok(data)
}
fn helper(args: &[String]) -> Result<Vec<u8>, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Use sudo for WAF control. The normal agent stays unprivileged.".into());
    }
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", "-c", SCRIPT])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env(
            "QG_BINARY",
            std::env::current_exe().map_err(|e| e.to_string())?,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| "Cannot start WAF controller")?;
    let mut stdin = child.stdin.take().ok_or("Missing controller input")?;
    let data = serde_json::to_vec(&assets()).map_err(|e| e.to_string())?;
    let writer = thread::spawn(move || stdin.write_all(&data));
    let stdout = child.stdout.take().ok_or("Missing controller output")?;
    let reader = thread::spawn(move || {
        let mut data = Vec::new();
        stdout.take(524289).read_to_end(&mut data).map(|_| data)
    });
    let start = Instant::now();
    let limit = if args.first().map(String::as_str) == Some("check") {
        20
    } else {
        180
    };
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < Duration::from_secs(limit) => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(
                    "WAF controller timed out; inspect configuration before retrying".into(),
                );
            }
        }
    };
    let _ = writer.join();
    let data = reader
        .join()
        .map_err(|_| "Controller output failed")?
        .map_err(|_| "Controller output failed")?;
    if !status.success() || data.len() > 524288 {
        return Err("WAF check/control could not be completed".into());
    }
    Ok(data)
}
pub fn control(args: &[String]) -> Result<(), String> {
    // Internal checks include private probe credentials; they are never CLI output.
    if args.first().map(String::as_str) == Some("check") {
        return Err("Internal WAF checks are not a public command".into());
    }
    let data = helper(args)?;
    std::io::stdout()
        .write_all(&data)
        .map_err(|e| e.to_string())
}
fn boot_id() -> Result<String, String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().into())
        .map_err(|_| "Boot identity unavailable".into())
}
fn save(path: &str, value: &serde_json::Value) -> Result<(), String> {
    let temporary = format!("{path}.{}.tmp", std::process::id());
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|e| e.to_string())?;
    // UMask is restrictive in the monitor, but this metadata-only status is public.
    file.set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(|e| e.to_string())?;
    let result = (|| {
        file.write_all(&serde_json::to_vec(value).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temporary, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
fn event_log(events: &[&Event]) -> Result<(), String> {
    if events.is_empty() {
        return Ok(());
    }
    let path = "/var/lib/quiet-guard/waf/events.jsonl";
    if Path::new(path).exists() {
        let current = read(path, 2 * 1024 * 1024 + 131072)?;
        if current.len() > 2 * 1024 * 1024 {
            fs::rename(path, "/var/lib/quiet-guard/waf/events.previous.jsonl")
                .map_err(|e| e.to_string())?;
        }
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err("Untrusted WAF event file".into());
    }
    for event in events {
        serde_json::to_writer(&mut file, event).map_err(|e| e.to_string())?;
        file.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn monitor() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("WAF monitor requires its dedicated service".into());
    }
    let mut previous = String::new();
    let mut last_epoch = String::new();
    let mut last_seq = 0;
    loop {
        let now = crate::runtime::boot_seconds();
        let public: serde_json::Value = serde_json::from_slice(&read(PUBLIC, 65536)?)
            .map_err(|_| "Invalid WAF enable state")?;
        let result: Result<serde_json::Value, String> = (|| {
            let raw = helper(&["check".into()])?;
            #[derive(Deserialize)]
            struct Check {
                config: Config,
                snapshot: Snapshot,
                engine_epoch: String,
            }
            let check: Check =
                serde_json::from_slice(&raw).map_err(|_| "Invalid private WAF observation")?;
            let phase = evaluate(
                &check.config,
                &check.snapshot,
                &check.engine_epoch,
                crate::runtime::boot_seconds(),
            )?;
            if last_epoch != check.snapshot.nginx_epoch {
                last_seq = 0;
                last_epoch = check.snapshot.nginx_epoch.clone();
            }
            let mut events: Vec<_> = check
                .snapshot
                .events
                .iter()
                .filter(|e| e.epoch == last_epoch && e.seq > last_seq)
                .collect();
            events.sort_by_key(|e| e.seq);
            let lost = events
                .first()
                .map(|e| e.seq.saturating_sub(last_seq + 1))
                .unwrap_or(0);
            event_log(&events)?;
            last_seq = check.snapshot.event_seq;
            Ok(
                serde_json::json!({"schema":1,"generation":check.config.generation,"boot_id":boot_id()?,"boot_seconds":now,"phase":phase,
                "allowed":check.snapshot.allowed,"blocked":check.snapshot.blocked,"incomplete":check.snapshot.incomplete,"failures":check.snapshot.failures,
                "event_gap":lost,"message":"Per-request inspection only; exposure risk is not assessed. External path proofs expire after 180 seconds."}),
            )
        })();
        let health=result.unwrap_or_else(|_|serde_json::json!({"schema":1,"generation":public["generation"],"boot_id":boot_id().unwrap_or_default(),"boot_seconds":now,"phase":"unknown","message":"Web inspection or its configuration cannot be verified. Passthrough may be active; inspect service logs."}));
        let phase = health["phase"].as_str().unwrap_or("unknown");
        if previous != phase {
            println!("WAF state: {phase}");
            previous = phase.into();
        }
        save(HEALTH, &health)?;
        thread::sleep(Duration::from_secs(10));
    }
}
pub fn observation() -> serde_json::Value {
    let result: Result<serde_json::Value, String> = (|| {
        let public: serde_json::Value =
            serde_json::from_slice(&read(PUBLIC, 65536)?).map_err(|_| "Invalid WAF status")?;
        if public["enabled"] != true {
            return Ok(serde_json::json!({"state":"off"}));
        }
        let health: serde_json::Value =
            serde_json::from_slice(&read(HEALTH, 65536)?).map_err(|_| "Missing WAF health")?;
        let now = crate::runtime::boot_seconds();
        let observed = health["boot_seconds"].as_u64().ok_or("Invalid WAF clock")?;
        if health["generation"] != public["generation"]
            || health["boot_id"] != boot_id()?
            || observed > now
            || now - observed > 30
        {
            return Err("WAF observation expired".into());
        }
        let mut health = health;
        health["state"] = health["phase"].clone();
        Ok(health)
    })();
    result.unwrap_or_else(|_|serde_json::json!({"state":if Path::new(PUBLIC).exists(){"unknown"}else{"not_configured"}}))
}
