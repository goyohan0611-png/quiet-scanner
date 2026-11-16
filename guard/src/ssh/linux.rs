use super::*;
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const NFT: &str = "/usr/sbin/nft";
const POLICY: &str = "/run/credentials/quiet-guard-ssh-enforcer.service/policy";
const CURL: &str = "/run/credentials/quiet-guard-ssh-enforcer.service/api.curl";
const HEALTH: &str = "/run/quiet-guard-ssh/health.json";
const PUBLIC: &str = "/var/lib/quiet-guard/ssh/public.json";

fn root_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "missing protected file")?;
    let meta = file
        .metadata()
        .map_err(|_| "cannot inspect protected file")?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.len() > limit {
        return Err("untrusted protected file".into());
    }
    let mut raw = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "cannot read protected file")?;
    if raw.len() as u64 > limit {
        return Err("protected file exceeds limit".into());
    }
    Ok(raw)
}
fn command(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
    limit: u64,
) -> Result<Vec<u8>, String> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", "/nonexistent")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| format!("cannot start {program}"))?;
    let stdout = child.stdout.take().ok_or("missing command output")?;
    let reader = thread::spawn(move || {
        let mut data = Vec::new();
        stdout.take(limit + 1).read_to_end(&mut data).map(|_| data)
    });
    let writer = child.stdin.take().map(|mut stdin| {
        let data = input.unwrap_or_default().to_vec();
        thread::spawn(move || stdin.write_all(&data))
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < Duration::from_secs(8) => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program} timed out or could not be observed"));
            }
        }
    };
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| "command writer failed")?
            .map_err(|_| "command input failed")?;
    }
    let output = reader
        .join()
        .map_err(|_| "command reader failed")?
        .map_err(|_| "command output failed")?;
    if !status.success() || output.len() as u64 > limit {
        return Err(format!("{program} failed or exceeded its output limit"));
    }
    Ok(output)
}
fn nft_read() -> Result<Vec<u8>, String> {
    command(
        NFT,
        &["-j", "list", "table", "inet", TABLE],
        None,
        4 * 1024 * 1024,
    )
}
fn table_exists() -> Result<bool, String> {
    let tables: serde_json::Value =
        serde_json::from_slice(&command(NFT, &["-j", "list", "tables"], None, 1024 * 1024)?)
            .map_err(|_| "bad table list")?;
    Ok(tables["nftables"]
        .as_array()
        .ok_or("missing table list")?
        .iter()
        .any(|r| r["table"]["family"] == "inet" && r["table"]["name"] == TABLE))
}
fn verify_installation() -> Result<(), String> {
    let record: serde_json::Value = serde_json::from_slice(&root_file(
        Path::new("/etc/quiet-guard/ssh/ownership.json"),
        262144,
    )?)
    .map_err(|_| "invalid ownership record")?;
    if record["marker"] != MARKER {
        return Err("invalid SSH ownership marker".into());
    }
    let files = record["files"]
        .as_object()
        .ok_or("missing ownership hashes")?;
    let mut expected: std::collections::BTreeSet<String> = assets()
        .as_object()
        .ok_or("missing embedded assets")?
        .keys()
        .filter(|name| !name.ends_with(".service"))
        .map(|name| format!("/etc/quiet-guard/ssh/rules/{name}"))
        .collect();
    for name in [
        "config.yaml",
        "policy.json",
        "local_api_credentials.yaml",
        "api.curl",
        "acquis.yaml",
        "profiles.yaml",
        "simulation.yaml",
    ] {
        expected.insert(format!("/etc/quiet-guard/ssh/{name}"));
    }
    expected.insert("/etc/systemd/system/quiet-guard-ssh-engine.service".into());
    expected.insert("/etc/systemd/system/quiet-guard-ssh-enforcer.service".into());
    if expected != files.keys().cloned().collect() {
        return Err("incomplete/extra SSH ownership records".into());
    }
    for (name, digest) in files {
        if !(name.starts_with("/etc/quiet-guard/ssh/")
            || name == "/etc/systemd/system/quiet-guard-ssh-engine.service"
            || name == "/etc/systemd/system/quiet-guard-ssh-enforcer.service")
            || Path::new(name)
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Err("unrecognized owned path".into());
        }
        if hex::encode(Sha256::digest(root_file(Path::new(name), 262144)?))
            != digest.as_str().ok_or("invalid ownership digest")?
        {
            return Err("SSH configuration/rules/service changed; revalidation required".into());
        }
    }
    for unit in [
        "quiet-guard-ssh-engine.service",
        "quiet-guard-ssh-enforcer.service",
    ] {
        command(
            "/usr/bin/systemctl",
            &["is-active", "--quiet", unit],
            None,
            65536,
        )?;
    }
    let version = command(
        "/usr/bin/dpkg-query",
        &["-W", "-f=${Version}", "crowdsec"],
        None,
        4096,
    )?;
    let version = std::str::from_utf8(&version)
        .map_err(|_| "invalid engine package version")?
        .trim();
    if version != "1.8.2" && !version.starts_with("1.8.2-") {
        return Err("detection engine version changed; revalidation required".into());
    }
    Ok(())
}
fn current_members(raw: &[u8]) -> Result<BTreeMap<IpAddr, u64>, String> {
    let value: serde_json::Value = serde_json::from_slice(raw).map_err(|_| "bad nft JSON")?;
    let mut result = BTreeMap::new();
    for row in value["nftables"].as_array().ok_or("missing nft objects")? {
        if let Some(elements) = row["set"]["elem"].as_array() {
            for element in elements {
                let ip = element["elem"]["val"]
                    .as_str()
                    .ok_or("bad IP")?
                    .parse()
                    .map_err(|_| "bad IP")?;
                result.insert(ip, LEASE);
            }
        }
    }
    Ok(result)
}
fn ensure_table(config: &Config) -> Result<(), String> {
    // Enumerate first: permission/command errors must never be mistaken for absence.
    let tables: serde_json::Value =
        serde_json::from_slice(&command(NFT, &["-j", "list", "tables"], None, 1024 * 1024)?)
            .map_err(|_| "bad table list")?;
    let exists = tables["nftables"]
        .as_array()
        .ok_or("missing table list")?
        .iter()
        .any(|r| r["table"]["family"] == "inet" && r["table"]["name"] == TABLE);
    if exists {
        let raw = nft_read()?;
        verify_table(&raw, config, &current_members(&raw)?)?;
    } else {
        command(
            NFT,
            &["-f", "-"],
            Some(initial_rules(config)?.as_bytes()),
            65536,
        )?;
        verify_table(&nft_read()?, config, &BTreeMap::new())?;
    }
    Ok(())
}
fn boot_id() -> Result<String, String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().into())
        .map_err(|_| "boot identity unavailable".into())
}
fn write_health(config: &Config, phase: &str, count: usize, message: &str) -> Result<(), String> {
    let health = Health {
        schema: 1,
        boot_id: boot_id()?,
        boot_seconds: crate::runtime::boot_seconds(),
        policy_revision: config.revision(),
        phase: phase.into(),
        blocked_ips: count,
        message: message.into(),
    };
    let path = Path::new(HEALTH);
    let directory = path.parent().unwrap();
    let meta = fs::symlink_metadata(directory).map_err(|_| "health directory unavailable")?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err("untrusted health directory".into());
    }
    let temp = directory.join(format!("health-{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|_| "cannot create health observation")?;
        file.write_all(&serde_json::to_vec(&health).map_err(|_| "health serialization failed")?)
            .map_err(|_| "health write failed")?;
        file.sync_all().map_err(|_| "health sync failed")?;
        fs::rename(&temp, path).map_err(|_| "health publish failed")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
pub fn enforce(cleanup: bool) -> Result<(), String> {
    let config: Config = serde_json::from_slice(&root_file(Path::new(POLICY), 65536)?)
        .map_err(|_| "invalid SSH policy")?;
    config.validate()?;
    if cleanup {
        // Never delete a foreign table, including one replacing ours after a failure.
        if table_exists()? {
            let raw = nft_read()?;
            verify_table(&raw, &config, &current_members(&raw)?)?;
            command(NFT, &["delete", "table", "inet", TABLE], None, 65536)?;
        }
        write_health(&config, "off", 0, "SSH enforcement stopped")?;
        return Ok(());
    }
    root_file(Path::new(CURL), 4096)?;
    write_health(
        &config,
        "starting",
        0,
        "Waiting for local detection engine and firewall verification",
    )?;
    loop {
        let result = (|| {
            verify_installation()?;
            ensure_table(&config)?;
            let raw = command(
                "/usr/bin/curl",
                &[
                    "-q",
                    "--config",
                    CURL,
                    "--noproxy",
                    "*",
                    "--proto",
                    "=http",
                    "--fail",
                    "--silent",
                    "--connect-timeout",
                    "1",
                    "--max-time",
                    "3",
                    "--max-filesize",
                    "4194304",
                    "http://127.0.0.1:17423/v1/decisions?scope=Ip&type=ban",
                ],
                None,
                4 * 1024 * 1024,
            )?;
            let wanted = decisions(&raw, &config)?;
            command(
                NFT,
                &["-f", "-"],
                Some(update_rules(&wanted).as_bytes()),
                65536,
            )?;
            verify_table(&nft_read()?, &config, &wanted)?;
            write_health(
                &config,
                "verified",
                wanted.len(),
                "Local API and SSH-only firewall membership verified",
            )
        })();
        if let Err(error) = result {
            write_health(&config,"unknown",0,&format!("SSH protection cannot be verified: {error}. Existing leases expire within 45 seconds."))?;
        }
        thread::sleep(Duration::from_secs(10));
    }
}
pub fn observation() -> serde_json::Value {
    let result = (|| -> Result<serde_json::Value, String> {
        let public: serde_json::Value =
            serde_json::from_slice(&root_file(Path::new(PUBLIC), 65536)?)
                .map_err(|_| "invalid SSH registration")?;
        if public["enabled"] != true {
            return Ok(serde_json::json!({"state":"off","blocked_ips":0}));
        }
        let h: Health = serde_json::from_slice(&root_file(Path::new(HEALTH), 65536)?)
            .map_err(|_| "invalid SSH observation")?;
        let revision = public["policy_revision"]
            .as_str()
            .ok_or("missing policy revision")?;
        let verified = h.current(crate::runtime::boot_seconds(), &boot_id()?, revision);
        Ok(
            serde_json::json!({"state":if verified{"verified"}else{"unknown"},"blocked_ips":if verified{h.blocked_ips}else{0},"message":h.message,"verified_boot_seconds":h.boot_seconds}),
        )
    })();
    match result {
        Ok(value) => value,
        Err(error) => {
            serde_json::json!({"state":if Path::new(PUBLIC).exists(){"unknown"}else{"not_configured"},"message":error})
        }
    }
}
pub fn control(args: &[String]) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Run SSH setup/control with sudo. The normal agent stays unprivileged.".into());
    }
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", "-c", include_str!("../../scripts/ssh_setup.py")])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env(
            "QG_POLICY_REVISION_BINARY",
            std::env::current_exe().map_err(|e| e.to_string())?,
        )
        .env(
            "SSH_CONNECTION",
            std::env::var("SSH_CONNECTION").unwrap_or_default(),
        )
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or("setup input unavailable")?
        .write_all(&serde_json::to_vec(&assets()).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if !child.wait().map_err(|e| e.to_string())?.success() {
        return Err("SSH setup/control did not complete; see the diagnostic above".into());
    }
    Ok(())
}
