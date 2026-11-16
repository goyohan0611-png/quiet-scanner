use super::*;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};
const ROOT: &str = "/etc/quiet-guard/exposure";
const STATE: &str = "/var/lib/quiet-guard/exposure";
const PROGRAM: &str = "/usr/local/lib/quiet-guard/quiet-guard";
const SERVICE: &str = "quiet-guard-exposure.service";
const TIMER: &str = "quiet-guard-exposure.timer";
const MARKER: &str = "quiet-guard-exposure-v1";
const UNIT: &str = include_str!("../../systemd/quiet-guard-exposure.service");
const TIMER_UNIT: &str = include_str!("../../systemd/quiet-guard-exposure.timer");
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: u32,
    marker: String,
    generation: String,
    enabled: bool,
    files: BTreeMap<String, String>,
}

fn read(path: &Path, limit: u64, root: bool) -> Result<Vec<u8>, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| format!("Cannot read {}", path.display()))?;
    let m = file.metadata().map_err(|_| "Cannot inspect file")?;
    if !m.is_file() || m.len() > limit || (root && (m.uid() != 0 || m.mode() & 0o022 != 0)) {
        return Err("Invalid file ownership/type/size".into());
    }
    let mut data = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Cannot read bounded file")?;
    if data.len() as u64 > limit {
        return Err("File exceeded size limit".into());
    }
    Ok(data)
}
fn directory(path: &Path, mode: u32) -> Result<(), String> {
    if !path.exists() {
        fs::create_dir(path).map_err(|e| e.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    }
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err("Untrusted exposure directory".into());
    }
    Ok(())
}
fn random() -> Result<String, String> {
    let mut data = [0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut data))
        .map_err(|_| "System randomness unavailable")?;
    Ok(hex::encode(data))
}
fn atomic(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let temporary = path.with_file_name(format!(".exposure-{}.tmp", random()?));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| e.to_string())?;
        file.write_all(data).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temporary, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
fn save(path: &Path, value: &impl Serialize, mode: u32) -> Result<(), String> {
    atomic(
        path,
        &serde_json::to_vec(value).map_err(|e| e.to_string())?,
        mode,
    )
}
fn command(args: &[&str]) -> Result<Vec<u8>, String> {
    let mut child = Command::new("/usr/bin/systemctl")
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot start service controller")?;
    let stdout = child.stdout.take().ok_or("Missing controller output")?;
    let reader = std::thread::spawn(move || {
        let mut data = Vec::new();
        stdout.take(65537).read_to_end(&mut data).map(|_| data)
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < Duration::from_secs(25) => {
                std::thread::sleep(Duration::from_millis(25))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Service control timed out".into());
            }
        }
    };
    let data = reader
        .join()
        .map_err(|_| "Controller output failed")?
        .map_err(|_| "Controller output failed")?;
    if !status.success() || data.len() > 65536 {
        return Err(format!(
            "Exposure service control failed: {}",
            args.first().unwrap_or(&"unknown")
        ));
    }
    Ok(data)
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn config() -> Result<Config, String> {
    let cfg: Config =
        serde_json::from_slice(&read(&Path::new(ROOT).join("ownership.json"), 65536, true)?)
            .map_err(|_| "Invalid exposure ownership record")?;
    let expected: BTreeMap<_, _> = [(SERVICE, UNIT), (TIMER, TIMER_UNIT)]
        .into_iter()
        .map(|(name, data)| (format!("/etc/systemd/system/{name}"), hash(data.as_bytes())))
        .collect();
    if cfg.schema != 1
        || cfg.marker != MARKER
        || cfg.generation.len() != 32
        || !cfg.generation.bytes().all(|c| c.is_ascii_hexdigit())
        || cfg.files != expected
    {
        return Err("Unknown or incompatible exposure ownership record".into());
    }
    for (path, digest) in &expected {
        if hash(&read(Path::new(path), 65536, true)?) != *digest {
            return Err("Exposure service files changed; preserving them".into());
        }
    }
    Ok(cfg)
}
fn boot_id() -> Result<String, String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().into())
        .map_err(|_| "Boot identity unavailable".into())
}
fn tables() -> Result<(Vec<Listener>, Vec<String>), String> {
    let mut sockets = Vec::new();
    let mut coverage = Vec::new();
    for (name, transport, v6) in [
        ("tcp", "tcp", false),
        ("tcp6", "tcp", true),
        ("udp", "udp", false),
        ("udp6", "udp", true),
    ] {
        let raw = fs::File::open(format!("/proc/net/{name}"));
        match raw {
            Ok(file) => {
                let mut raw = String::new();
                file.take(4 * 1024 * 1024 + 1)
                    .read_to_string(&mut raw)
                    .map_err(|_| "Unreadable kernel socket table")?;
                sockets.extend(proc_sockets(&raw, transport, v6)?);
            }
            Err(_) if name != "tcp" => coverage.push(format!("{name}_table_unavailable")),
            Err(_) => return Err("TCP listener inventory unavailable".into()),
        }
    }
    if sockets.len() > 4096 {
        return Err("Host exceeds current socket inventory limit".into());
    }
    sockets.sort();
    Ok((sockets, coverage))
}
fn addresses() -> Result<Vec<IpAddr>, String> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err("Local interface inventory unavailable".into());
    }
    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) }
        }
    }
    let _guard = Guard(head);
    let mut pointer = head;
    let mut addresses = BTreeSet::new();
    let mut count = 0;
    while !pointer.is_null() {
        count += 1;
        if count > 4096 {
            return Err("Too many interface records".into());
        }
        let row = unsafe { &*pointer };
        if !row.ifa_addr.is_null() {
            let family = unsafe { (*row.ifa_addr).sa_family } as i32;
            if family == libc::AF_INET {
                let value = unsafe { &*(row.ifa_addr as *const libc::sockaddr_in) };
                addresses.insert(IpAddr::V4(value.sin_addr.s_addr.to_ne_bytes().into()));
            }
            if family == libc::AF_INET6 {
                let value = unsafe { &*(row.ifa_addr as *const libc::sockaddr_in6) };
                addresses.insert(IpAddr::V6(value.sin6_addr.s6_addr.into()));
            }
        }
        pointer = row.ifa_next;
    }
    if addresses.is_empty() || addresses.len() > 512 {
        return Err("Unsupported interface inventory size".into());
    }
    Ok(addresses.into_iter().collect())
}
fn inventory() -> Result<Inventory, String> {
    let (mut sockets, mut coverage) = tables()?;
    let mut owners: BTreeMap<u64, Vec<Owner>> = sockets.iter().map(|s| (s.inode, vec![])).collect();
    let started = Instant::now();
    let mut descriptors = 0usize;
    'processes: for entry in fs::read_dir("/proc")
        .map_err(|_| "Process inventory unavailable")?
        .take(32769)
    {
        let Ok(entry) = entry else { continue };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if started.elapsed() > Duration::from_secs(4) {
            coverage.push("process_inventory_time_limit".into());
            break;
        }
        let executable = fs::read_link(entry.path().join("exe"))
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .filter(|s| {
                s.len() <= 64
                    && s.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            });
        let Some(executable) = executable else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.take(4097) {
            descriptors += 1;
            if descriptors > 262144 || started.elapsed() > Duration::from_secs(4) {
                coverage.push("process_inventory_limit".into());
                break 'processes;
            }
            let Ok(fd) = fd else { continue };
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            if let Some(list) = owners.get_mut(&inode) {
                if list.len() < 8 {
                    let owner = Owner {
                        pid,
                        executable: executable.clone(),
                    };
                    if !list.contains(&owner) {
                        list.push(owner);
                    }
                }
            }
        }
    }
    for socket in &mut sockets {
        socket.owners = owners.remove(&socket.inode).unwrap_or_default();
        socket.owners.sort();
    }
    if sockets.iter().any(|s| s.owners.is_empty()) {
        coverage.push("some_process_owners_unavailable".into());
    }
    let local_addresses = addresses()?;
    let (second, _) = tables()?;
    let keys = |rows: &[Listener]| {
        rows.iter()
            .map(|s| (&s.transport, s.address, s.port, s.inode))
            .map(|(t, a, p, i)| (t.clone(), a, p, i))
            .collect::<Vec<_>>()
    };
    if keys(&sockets) != keys(&second) {
        coverage.push("sockets_changed_during_collection".into());
    }
    let namespace = fs::read_link("/proc/self/ns/net")
        .map_err(|_| "Network namespace identity unavailable")?
        .to_string_lossy()
        .into_owned();
    Ok(Inventory {
        addresses: local_addresses,
        listeners: sockets,
        coverage,
        namespace,
    })
}
fn public(cfg: &Config) -> Result<(), String> {
    save(
        &Path::new(STATE).join("public.json"),
        &serde_json::json!({"schema":1,"generation":cfg.generation,"enabled":cfg.enabled}),
        0o644,
    )
}
fn collect() -> Result<Report, String> {
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/run/lock/quiet-guard-exposure.lock")
        .map_err(|e| e.to_string())?;
    let m = lock.metadata().map_err(|e| e.to_string())?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o077 != 0
        || unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&lock),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
    {
        return Err(
            "Another exposure collection is running or its lock is untrusted; retry shortly".into(),
        );
    }
    let cfg = config()?;
    if !cfg.enabled {
        return Err("Exposure inspection is off".into());
    }
    let external = read(&Path::new(STATE).join("external.json"), 262144, true)
        .ok()
        .and_then(|raw| serde_json::from_slice::<External>(&raw).ok());
    let report = report(
        inventory()?,
        cfg.generation,
        boot_id()?,
        crate::runtime::boot_seconds(),
        external,
    );
    save(&Path::new(STATE).join("report.json"), &report, 0o644)?;
    Ok(report)
}
fn require_foundation() -> Result<(), String> {
    if std::env::current_exe()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?
        != Path::new(PROGRAM)
    {
        return Err("Use the signed, installed Quiet Guard command".into());
    }
    let record: serde_json::Value = serde_json::from_slice(&read(
        Path::new("/etc/quiet-guard/install.json"),
        65536,
        true,
    )?)
    .map_err(|_| "Invalid foundation record")?;
    if record["marker"] != "quiet-guard-foundation-v1"
        || record["hashes"]["quiet-guard"]
            != hash(&read(Path::new(PROGRAM), 128 * 1024 * 1024, true)?)
    {
        return Err("Foundation binary changed; exposure setup refused".into());
    }
    Ok(())
}
fn enable() -> Result<(), String> {
    require_foundation()?;
    let root = Path::new(ROOT);
    let state = Path::new(STATE);
    if !root.exists() {
        if fs::symlink_metadata(root).is_ok() || fs::symlink_metadata(state).is_ok() {
            return Err("Unowned exposure installation paths found; preserving them".into());
        }
        for name in [SERVICE, TIMER] {
            if fs::symlink_metadata(format!("/etc/systemd/system/{name}")).is_ok()
                || !command(&["show", "--property=FragmentPath", "--value", name])?
                    .iter()
                    .all(u8::is_ascii_whitespace)
            {
                return Err("An unowned exposure service already exists".into());
            }
        }
        directory(root, 0o700)?;
        directory(state.parent().ok_or("State parent missing")?, 0o755)?;
        directory(state, 0o755)?;
        let cfg = Config {
            schema: 1,
            marker: MARKER.into(),
            generation: random()?[..32].into(),
            enabled: false,
            files: [(SERVICE, UNIT), (TIMER, TIMER_UNIT)]
                .into_iter()
                .map(|(n, s)| (format!("/etc/systemd/system/{n}"), hash(s.as_bytes())))
                .collect(),
        };
        let result = (|| {
            for (name, data) in [(SERVICE, UNIT), (TIMER, TIMER_UNIT)] {
                atomic(
                    Path::new(&format!("/etc/systemd/system/{name}")),
                    data.as_bytes(),
                    0o644,
                )?;
            }
            save(&root.join("ownership.json"), &cfg, 0o600)?;
            public(&cfg)?;
            command(&["daemon-reload"])?;
            Ok::<_, String>(())
        })();
        if result.is_err() {
            for (name, data) in [(SERVICE, UNIT), (TIMER, TIMER_UNIT)] {
                let path = PathBuf::from(format!("/etc/systemd/system/{name}"));
                if read(&path, 65536, true).is_ok_and(|r| r == data.as_bytes()) {
                    let _ = fs::remove_file(path);
                }
            }
            for path in [root.join("ownership.json"), state.join("public.json")] {
                let _ = fs::remove_file(path);
            }
            let _ = fs::remove_dir(root);
            let _ = fs::remove_dir(state);
            let _ = command(&["daemon-reload"]);
            result?;
        }
    }
    let mut cfg = config()?;
    cfg.enabled = true;
    save(&root.join("ownership.json"), &cfg, 0o600)?;
    public(&cfg)?;
    let result = (|| {
        command(&["start", SERVICE])?;
        command(&["enable", "--now", TIMER])?;
        Ok::<_, String>(())
    })();
    if let Err(error) = result {
        let _ = command(&["disable", "--now", TIMER]);
        let _ = command(&["stop", SERVICE]);
        cfg.enabled = false;
        save(&root.join("ownership.json"), &cfg, 0o600)?;
        public(&cfg)?;
        return Err(error);
    }
    Ok(())
}
fn stop(remove: bool) -> Result<(), String> {
    let mut cfg = config()?;
    command(&["disable", "--now", TIMER])?;
    command(&["stop", SERVICE])?;
    cfg.enabled = false;
    save(&Path::new(ROOT).join("ownership.json"), &cfg, 0o600)?;
    public(&cfg)?;
    if remove {
        let archive = Path::new(STATE)
            .parent()
            .ok_or("State parent missing")?
            .join(format!("exposure-archive-{}", &random()?[..16]));
        directory(&archive, 0o700)?;
        for name in [
            "public.json",
            "report.json",
            "request.json",
            "external.json",
        ] {
            let path = Path::new(STATE).join(name);
            if path.exists() {
                read(&path, 2 * 1024 * 1024, true)?;
                fs::rename(&path, archive.join(name)).map_err(|e| e.to_string())?;
            }
        }
        for path in cfg.files.keys() {
            fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        fs::remove_file(Path::new(ROOT).join("ownership.json")).map_err(|e| e.to_string())?;
        let _ = fs::remove_dir(ROOT);
        let _ = fs::remove_dir(STATE);
        command(&["daemon-reload"])?;
    }
    Ok(())
}
fn ports(value: &str) -> Result<Vec<u16>, String> {
    let ports = value
        .split(',')
        .map(|s| {
            s.parse::<u16>()
                .map_err(|_| "Use comma-separated numeric TCP ports".to_string())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if ports.is_empty() || ports.len() > MAX_PORTS || ports.contains(&0) {
        return Err("Select 1..128 distinct TCP ports (1..65535)".into());
    }
    Ok(ports.into_iter().collect())
}
pub fn control(args: &[String]) -> Result<(), String> {
    let parts = args.iter().map(String::as_str).collect::<Vec<_>>();
    if parts.as_slice() == ["status"] {
        println!(
            "{}",
            serde_json::to_string_pretty(&observation()).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "Use sudo for host exposure inspection/control; probes run separately without root"
                .into(),
        );
    }
    // Collector and setup share this lock, separate from the deployment lock:
    // systemctl start waits for the collector, which must not inherit a lock held
    // by its caller. The deployment lock serializes only setup/lifecycle changes.
    let _lock = if parts.as_slice() == ["collect"] {
        None
    } else {
        let lock = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open("/run/lock/quiet-guard-deploy.lock")
            .map_err(|e| e.to_string())?;
        let m = lock.metadata().map_err(|e| e.to_string())?;
        if !m.is_file()
            || m.uid() != 0
            || m.mode() & 0o077 != 0
            || unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&lock),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            } != 0
        {
            return Err("Another setup is running or the deployment lock is untrusted".into());
        }
        Some(lock)
    };
    match parts.as_slice(){
        ["enable"]=>{enable()?;println!("Read-only exposure inspection enabled. Run exposure status for findings; external connectivity is not inferred from local binds.");}
        ["disable"]=>{stop(false)?;println!("Exposure inspection is off. Server services and firewall rules were not modified.");}
        ["remove"]=>{stop(true)?;println!("Exposure inspector removed; its previous reports were archived.");}
        ["collect"]=>{collect()?;}
        ["check"]=>println!("{}",serde_json::to_string_pretty(&collect()?).map_err(|e|e.to_string())?),
        ["prepare","--target",target,rest @ ..]=>{
            let report=collect()?;
            if report.inventory.coverage.iter().any(|c|c=="sockets_changed_during_collection"){return Err("Sockets changed during inspection; retry before preparing a probe".into());}
            let selected=match rest {[]=>{let mut p: BTreeSet<u16>=COMMON_PORTS.iter().copied().collect();p.extend(report.inventory.listeners.iter().filter(|l|l.transport=="tcp").map(|l|l.port));p.into_iter().collect()},["--ports",value]=>ports(value)?,_=>return Err("Use prepare --target IP [--ports 3000,5432,...]".into())};
            let request=Request{schema:1,nonce:random()?,revision:report.revision,generation:report.generation,boot_id:report.boot_id,issued_boot_seconds:crate::runtime::boot_seconds(),target:target.parse().map_err(|_|"Use one literal target IP, not a hostname or subnet")?,ports:selected,server_addresses:report.inventory.addresses};
            request.validate()?;save(&Path::new(STATE).join("request.json"),&request,0o600)?;
            println!("{}",serde_json::to_string_pretty(&request).map_err(|e|e.to_string())?);
        }
        ["import",path]=>{
            let result:ProbeResult=serde_json::from_slice(&read(Path::new(path),262144,false)?).map_err(|_|"Invalid probe result")?;
            let request:Request=serde_json::from_slice(&read(&Path::new(STATE).join("request.json"),262144,true)?).map_err(|_|"Missing active exposure request")?;
            let cfg=config()?;if !cfg.enabled{return Err("Exposure inspection is off".into());}
            let inventory=inventory()?;
            if inventory.coverage.iter().any(|c|c=="sockets_changed_during_collection"){return Err("Sockets changed during inspection; retry before importing evidence".into());}
            validate_result(&request,&result,&inventory.revision(),&boot_id()?,&cfg.generation,crate::runtime::boot_seconds())?;
            let external=External{request,result};save(&Path::new(STATE).join("external.json"),&external,0o600)?;
            fs::remove_file(Path::new(STATE).join("request.json")).map_err(|e|e.to_string())?;
            collect()?;println!("Operator TCP evidence imported. Failed connects do not prove safety; exposure status lists remaining limits.");
        }
        _=>return Err("Use exposure enable|check|status|disable|remove, prepare --target IP [--ports LIST], import RESULT.json, or probe REQUEST.json".into())
    }
    Ok(())
}
pub fn observation() -> serde_json::Value {
    let result = (|| {
        let public: serde_json::Value =
            serde_json::from_slice(&read(&Path::new(STATE).join("public.json"), 65536, true)?)
                .map_err(|_| "Invalid inspector enable state")?;
        if public["enabled"] != true {
            return Ok(serde_json::json!({"state":"off","risk":"not_assessed"}));
        }
        let report: Report = serde_json::from_slice(&read(
            &Path::new(STATE).join("report.json"),
            2 * 1024 * 1024,
            true,
        )?)
        .map_err(|_| "Invalid exposure report")?;
        let now = crate::runtime::boot_seconds();
        if report.schema != 1
            || public["generation"] != report.generation
            || report.boot_id != boot_id()?
            || report.boot_seconds > now
            || now - report.boot_seconds > REPORT_TTL
        {
            return Err("Exposure observation expired or generation changed".to_string());
        }
        let external_current = report.external.as_ref().is_some_and(|e| {
            validate_result(
                &e.request,
                &e.result,
                &report.revision,
                &report.boot_id,
                &report.generation,
                now,
            )
            .is_ok()
        });
        Ok(
            serde_json::json!({"state":if report.state=="local_and_operator_probe"&&!external_current{"local_only"}else{&report.state},"risk":report.risk,"checked_boot_seconds":report.boot_seconds,"listener_count":report.inventory.listeners.len(),"review_count":report.findings.iter().filter(|f|f.evidence=="non_loopback_bind_only").count(),"external_probe_current":external_current,"external_evidence_trust":"operator_supplied","limitations":report.limitations}),
        )
    })();
    result.unwrap_or_else(|error|serde_json::json!({"state":if Path::new(STATE).join("public.json").exists(){"unknown"}else{"not_configured"},"risk":"not_assessed","message":error}))
}
