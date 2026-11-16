use super::*;
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::Mutex,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
const PROGRAM: &str = "/usr/local/lib/quiet-guard/quiet-guard";
const ROOT: &str = "/etc/quiet-guard/dashboard";
const DATA: &str = "/var/lib/quiet-guard/dashboard";
fn read(path: &Path, max: u64, private: bool) -> Result<Vec<u8>, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "Management file unavailable")?;
    let m = file.metadata().map_err(|_| "Management file unavailable")?;
    if !m.is_file()
        || m.len() > max
        || m.mode() & 0o022 != 0
        || (private && (m.uid() != 0 || m.mode() & 0o077 != 0))
    {
        return Err("Untrusted management file".into());
    }
    let mut raw = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "Management read failed")?;
    if raw.len() as u64 > max {
        return Err("Management file exceeds limit".into());
    }
    Ok(raw)
}
pub fn credential() -> Result<String, String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err("Run the web process with its unprivileged service identity".into());
    }
    let directory =
        std::env::var("CREDENTIALS_DIRECTORY").map_err(|_| "Service credential is unavailable")?;
    let token = String::from_utf8(read(&Path::new(&directory).join("access"), 128, false)?)
        .map_err(|_| "Invalid management credential")?;
    if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid management credential".into());
    }
    Ok(token)
}
fn verify_foundation() -> Result<(), String> {
    use sha2::Digest;
    let install: serde_json::Value = serde_json::from_slice(&read(
        Path::new("/etc/quiet-guard/install.json"),
        65536,
        true,
    )?)
    .map_err(|_| "Invalid foundation record")?;
    if install["marker"] != "quiet-guard-foundation-v1"
        || install["hashes"]["quiet-guard"]
            != hex::encode(sha2::Sha256::digest(read(
                Path::new(PROGRAM),
                128 * 1024 * 1024,
                false,
            )?))
    {
        return Err("Foundation binary changed; preserving configuration".into());
    }
    if install["hashes"]["quiet-guard.service"]
        != hex::encode(sha2::Sha256::digest(read(
            Path::new("/etc/systemd/system/quiet-guard.service"),
            65536,
            false,
        )?))
    {
        return Err("Foundation service changed; preserving configuration".into());
    }
    Ok(())
}
fn atomic_jobs(jobs: &[Job]) -> Result<(), String> {
    let path = Path::new(DATA).join("jobs.json");
    let temporary = Path::new(DATA).join(format!(".jobs-{}.tmp", secret()?));
    let summaries: Vec<_> = jobs
        .iter()
        .map(|j| Job {
            output: String::new(),
            ..j.clone()
        })
        .collect();
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| "Cannot save job record")?;
        file.write_all(&serde_json::to_vec(&summaries).map_err(|_| "Invalid job record")?)
            .map_err(|_| "Cannot save job record")?;
        file.sync_all().map_err(|_| "Cannot sync job record")?;
        fs::rename(&temporary, path).map_err(|_| "Cannot replace job record")
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(String::from)
}
struct Controller {
    token: String,
    jobs: Mutex<Vec<Job>>,
    gate: tokio::sync::Mutex<()>,
}
fn deployment_lock() -> Result<fs::File, String> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/run/lock/quiet-guard-deploy.lock")
        .map_err(|_| "Setup lock unavailable")?;
    let m = file.metadata().map_err(|_| "Setup lock unavailable")?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o077 != 0
        || unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
    {
        return Err("Another setup is running".into());
    }
    Ok(file)
}
fn transient_active(jobs: &[Job]) -> bool {
    jobs.iter().any(|job| {
        if job.id.len() != 24 || !job.id.bytes().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        let state = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "--property=ActiveState",
                "--value",
                &format!("quiet-guard-task-{}.service", job.id),
            ])
            .stdin(Stdio::null())
            .output();
        state.is_ok_and(|s| {
            matches!(
                s.stdout.as_slice(),
                b"active\n" | b"activating\n" | b"deactivating\n"
            )
        })
    })
}
fn snapshot(jobs: &[Job]) -> serde_json::Value {
    let agent = crate::runtime::read(Path::new("/run/quiet-guard"))
        .map(|s| serde_json::to_value(s).unwrap_or_default())
        .unwrap_or_else(
            |_| serde_json::json!({"agent":"unknown","protection":"unknown","risk":"not_assessed"}),
        );
    let report = read(
        Path::new("/var/lib/quiet-guard/exposure/report.json"),
        8 * 1024 * 1024,
        true,
    )
    .ok()
    .and_then(|r| serde_json::from_slice::<crate::exposure::Report>(&r).ok());
    let (listeners, findings, truncated) = report
        .map(|mut r| {
            let truncated = r.inventory.listeners.len() > 256 || r.findings.len() > 128;
            r.inventory.listeners.truncate(256);
            r.findings.truncate(128);
            for listener in &mut r.inventory.listeners {
                listener.owners.truncate(4);
            }
            (
                serde_json::to_value(r.inventory.listeners).unwrap_or_default(),
                serde_json::to_value(r.findings).unwrap_or_default(),
                truncated,
            )
        })
        .unwrap_or((serde_json::json!([]), serde_json::json!([]), false));
    let jobs: Vec<_> = jobs
        .iter()
        .map(|job| {
            let mut job = job.clone();
            job.output = job.output.chars().take(2000).collect();
            job
        })
        .collect();
    let hostname = fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "서버".into())
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect::<String>();
    serde_json::json!({"preview":false,"version":concat!(env!("CARGO_PKG_VERSION")," 개발판"),"server":{"hostname":hostname,"platform":"Ubuntu / Linux"},"updated":now(),
        "agent":agent,"ssh":crate::ssh::observation(),"waf":crate::waf::observation(),"exposure":crate::exposure::observation(),
        "configured":{"ssh":Path::new("/etc/quiet-guard/ssh/ownership.json").exists(),"waf":Path::new("/etc/quiet-guard/waf/ownership.json").exists(),"exposure":Path::new("/etc/quiet-guard/exposure/ownership.json").exists()},
        "prerequisites":{"crowdsec":Path::new("/usr/bin/crowdsec").exists(),"nginx":Path::new("/usr/sbin/nginx").exists(),"lua":Path::new("/usr/lib/nginx/modules/ngx_http_lua_module.so").exists(),"nftables":Path::new("/usr/sbin/nft").exists()},
        "listeners":listeners,"findings":findings,"exposure_truncated":truncated,"jobs":jobs})
}
async fn stream_tail(
    mut input: impl tokio::io::AsyncRead + Unpin,
    controller: Arc<Controller>,
    id: String,
) -> String {
    let mut tail = Vec::new();
    let mut buffer = [0u8; 2048];
    loop {
        match input.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                tail.extend_from_slice(&buffer[..n]);
                if tail.len() > 8192 {
                    tail.drain(..tail.len() - 8192);
                }
                let output =
                    String::from_utf8_lossy(&tail).replace(&controller.token, "[접속 키 숨김]");
                if let Ok(mut jobs) = controller.jobs.lock() {
                    if let Some(job) = jobs.iter_mut().find(|j| j.id == id) {
                        job.output = output;
                    }
                }
            }
        }
    }
    String::from_utf8_lossy(&tail).replace(&controller.token, "[접속 키 숨김]")
}
async fn run_job(controller: Arc<Controller>, action: Action, id: String) {
    let result = async {
        verify_foundation()?;
        let limit = if matches!(action, Action::PrepareDependencies { .. }) {
            900
        } else {
            180
        };
        let mut command = tokio::process::Command::new("/usr/bin/systemd-run");
        command
            .args([
                "--quiet",
                "--wait",
                "--collect",
                "--pipe",
                "--service-type=exec",
            ])
            .arg(format!("--unit=quiet-guard-task-{id}"))
            .arg(format!(
                "--description=Quiet Guard administrative task {}",
                action.kind()
            ))
            .arg(format!("--property=RuntimeMaxSec={limit}"))
            .args([
                "--property=TimeoutStopSec=10",
                "--property=NoNewPrivileges=yes",
                "--property=UMask=0077",
                "--",
            ]);
        if matches!(action, Action::AgentRestart { .. }) {
            command.args(["/usr/bin/systemctl", "restart", "quiet-guard.service"]);
        } else {
            command.arg(PROGRAM).args(action.args()?);
        }
        let mut child = command
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .env("HOME", "/root")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| "작업을 시작하지 못했습니다.".to_string())?;
        let stdout = child.stdout.take().ok_or("작업 출력을 읽을 수 없습니다.")?;
        let stderr = child.stderr.take().ok_or("진단 출력을 읽을 수 없습니다.")?;
        let out = tokio::spawn(stream_tail(stdout, controller.clone(), id.clone()));
        let err = tokio::spawn(stream_tail(stderr, controller.clone(), id.clone()));
        let status =
            match tokio::time::timeout(std::time::Duration::from_secs(limit + 15), child.wait())
                .await
            {
                Ok(Ok(s)) => s,
                _ => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    let _ = out.await;
                    let _ = err.await;
                    return Err(
                        "작업 응답 시간이 지났습니다. 현재 상태를 확인한 뒤 다시 시도해 주세요."
                            .into(),
                    );
                }
            };
        let output = format!(
            "{}\n{}",
            out.await.unwrap_or_default(),
            err.await.unwrap_or_default()
        );
        if status.success() {
            Ok(output)
        } else {
            Err(output)
        }
    }
    .await;
    if let Ok(mut jobs) = controller.jobs.lock() {
        if let Some(job) = jobs.iter_mut().find(|j| j.id == id) {
            job.status = if result.is_ok() {
                "succeeded"
            } else {
                "failed"
            }
            .into();
            job.finished = Some(now());
            job.output = result
                .unwrap_or_else(|s| s)
                .chars()
                .rev()
                .take(12000)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            println!("management action={} result={}", job.action, job.status);
        }
        let _ = atomic_jobs(&jobs);
    }
}
async fn handle(
    mut socket: tokio::net::UnixStream,
    controller: Arc<Controller>,
) -> Result<(), String> {
    let call = async {
        let length = socket
            .read_u32()
            .await
            .map_err(|_| "Missing control frame")? as usize;
        if length > 32768 {
            return Err("Oversized control request".into());
        }
        let mut bytes = vec![0; length];
        socket
            .read_exact(&mut bytes)
            .await
            .map_err(|_| "Incomplete control frame")?;
        let rpc: Rpc = serde_json::from_slice(&bytes).map_err(|_| "Invalid control frame")?;
        if !authorized(&rpc.token, &controller.token) {
            return Err("Unauthorized control request".into());
        }
        let result = match rpc.request {
            Operation::Snapshot { .. } => {
                let jobs = controller
                    .jobs
                    .lock()
                    .map_err(|_| "Job state unavailable")?
                    .clone();
                tokio::task::spawn_blocking(move || snapshot(&jobs))
                    .await
                    .map_err(|_| "Snapshot failed")?
            }
            Operation::Start { action } => {
                action.args()?;
                let _guard = controller.gate.lock().await;
                // Serialize acceptance with CLI disable/rotation/removal. The job
                // record is durable before this lock is released; stop refuses it.
                let _deployment = deployment_lock()?;
                let previous = controller
                    .jobs
                    .lock()
                    .map_err(|_| "Job state unavailable")?
                    .clone();
                let unit_running = tokio::task::spawn_blocking(move || transient_active(&previous))
                    .await
                    .map_err(|_| "Administrative task status unavailable")?;
                let mut jobs = controller
                    .jobs
                    .lock()
                    .map_err(|_| "Job state unavailable")?;
                if unit_running || jobs.iter().any(|j| j.status == "running") {
                    serde_json::json!({"error":"다른 작업을 처리하고 있습니다. 완료 후 다시 시도해 주세요."})
                } else {
                    let id = secret()?[..24].to_string();
                    jobs.insert(
                        0,
                        Job {
                            id: id.clone(),
                            action: action.kind().into(),
                            status: "running".into(),
                            started: now(),
                            finished: None,
                            output: String::new(),
                        },
                    );
                    jobs.truncate(20);
                    atomic_jobs(&jobs)?;
                    tokio::spawn(run_job(controller.clone(), action, id.clone()));
                    serde_json::json!({"id":id,"status":"running"})
                }
            }
        };
        let raw = serde_json::to_vec(&result).map_err(|_| "Invalid control result")?;
        if raw.len() > MAX_FRAME {
            return Err("Control reply exceeded limit".into());
        }
        socket
            .write_u32(raw.len() as u32)
            .await
            .map_err(|_| "Control write failed")?;
        socket
            .write_all(&raw)
            .await
            .map_err(|_| "Control write failed")?;
        Ok(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), call)
        .await
        .map_err(|_| "Control connection timed out".to_string())?
}
pub fn broker() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("The privileged broker requires its dedicated service".into());
    }
    verify_foundation()?;
    let token = String::from_utf8(read(&Path::new(ROOT).join("access-token"), 128, true)?)
        .map_err(|_| "Invalid access key")?;
    if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid access key".into());
    }
    if std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse().ok())
        != Some(std::process::id())
        || std::env::var("LISTEN_FDS").as_deref() != Ok("1")
    {
        return Err("Start the broker through its owned systemd socket".into());
    }
    use std::os::fd::FromRawFd;
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
    if listener
        .local_addr()
        .map_err(|_| "Invalid control socket")?
        .as_pathname()
        != Some(Path::new("/run/quiet-guard-control/control.sock"))
    {
        return Err("Unexpected control socket".into());
    }
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let mut jobs = read(&Path::new(DATA).join("jobs.json"), 262144, true)
        .ok()
        .and_then(|r| serde_json::from_slice::<Vec<Job>>(&r).ok())
        .unwrap_or_default();
    jobs.truncate(20);
    for job in &mut jobs {
        if job.status == "running" {
            job.status = "interrupted".into();
            job.finished = Some(now());
            job.output =
                "작업 중 관리 서비스가 중단됐습니다. 현재 보호 상태를 먼저 확인해 주세요.".into();
        }
    }
    atomic_jobs(&jobs)?;
    let controller = Arc::new(Controller {
        token,
        jobs: Mutex::new(jobs),
        gate: tokio::sync::Mutex::new(()),
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let listener = tokio::net::UnixListener::from_std(listener).map_err(|e| e.to_string())?;
        let slots = Arc::new(tokio::sync::Semaphore::new(8));
        loop {
            let (socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                drop(socket);
                continue;
            };
            let controller = controller.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = handle(socket, controller).await;
            });
        }
    })
}
pub fn control(args: &[String]) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Use sudo for dashboard setup or login-link retrieval".into());
    }
    let assets = serde_json::json!({"quiet-guard-control.socket":include_str!("../../systemd/quiet-guard-control.socket"),"quiet-guard-control.service":include_str!("../../systemd/quiet-guard-control.service"),"quiet-guard-dashboard.service":include_str!("../../systemd/quiet-guard-dashboard.service")});
    let mut child = Command::new("/usr/bin/python3")
        .args(["-I", "-c", include_str!("../../scripts/dashboard_setup.py")])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env(
            "QG_BINARY",
            std::env::current_exe().map_err(|e| e.to_string())?,
        )
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or("Setup input unavailable")?
        .write_all(&serde_json::to_vec(&assets).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if child.wait().map_err(|e| e.to_string())?.success() {
        Ok(())
    } else {
        Err("Dashboard setup/control failed; see the message above".into())
    }
}
pub fn prepare_dependencies() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("Package preparation requires administrator privileges".into());
    }
    verify_foundation()?;
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/run/lock/quiet-guard-deploy.lock")
        .map_err(|e| e.to_string())?;
    let meta = lock.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
        || unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&lock),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
    {
        return Err("Another setup is running or the deployment lock is untrusted".into());
    }
    for script in [
        include_str!("../../scripts/install_ssh_dependencies.sh"),
        include_str!("../../scripts/install_waf_dependencies.sh"),
    ] {
        let status = Command::new("/bin/bash")
            .args(["--noprofile", "--norc", "-c", script])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .env("HOME", "/root")
            .stdin(Stdio::null())
            .status()
            .map_err(|_| "Cannot start package preparation")?;
        if !status.success() {
            return Err(
                "Package preparation did not complete; protection settings were not enabled".into(),
            );
        }
    }
    Ok(())
}
