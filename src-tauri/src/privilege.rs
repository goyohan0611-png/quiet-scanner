//! A per-session network worker. The WebView always keeps the user's identity.
//! OS authentication launches only this executable's non-GUI worker mode. A
//! private socket, random token and kernel peer credentials authenticate it.
use crate::{
    capture::LocalCapture,
    native,
    packet::{self, Mac},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs::{self, DirBuilder, OpenOptions},
    io::{Read, Write},
    net::Ipv4Addr,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

const MAX_MESSAGE: usize = 512 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Ready,
    Open { iface: String, filter: String },
    Send { id: u64, data: Vec<u8> },
    Next { id: u64 },
    Close { id: u64 },
    Pin { ip: Ipv4Addr, index: u32, mac: Mac },
    Release { ip: Ipv4Addr, index: u32, mac: Mac },
    Shutdown,
}
#[derive(Serialize, Deserialize)]
struct Hello {
    token: String,
}
#[derive(Serialize, Deserialize)]
struct Reply {
    value: Value,
    error: Option<String>,
}
fn write_message(writer: &mut impl Write, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_MESSAGE {
        return Err("네트워크 작업 메시지가 너무 큽니다.".into());
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .map_err(|e| e.to_string())
}
fn read_message<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, String> {
    let mut size = [0; 4];
    reader.read_exact(&mut size).map_err(|e| e.to_string())?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_MESSAGE {
        return Err("잘못된 네트워크 작업 메시지 크기입니다.".into());
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
fn peer_uid(stream: &UnixStream) -> Result<u32, String> {
    #[cfg(target_os = "linux")]
    {
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut size,
            )
        };
        if rc != 0 || size as usize != std::mem::size_of_val(&peer) {
            return Err("작업 연결의 권한을 확인하지 못했습니다.".into());
        }
        Ok(peer.uid)
    }
    #[cfg(target_os = "macos")]
    {
        let (mut uid, mut gid) = (0, 0);
        if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err("작업 연결의 권한을 확인하지 못했습니다.".into());
        }
        Ok(uid)
    }
}
#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn launcher(
    exe: &Path,
    socket: &Path,
    token: &Path,
    uid: u32,
    test: bool,
) -> Result<Child, String> {
    let arguments = [
        "--privileged-worker".to_string(),
        socket.to_string_lossy().into_owned(),
        token.to_string_lossy().into_owned(),
        uid.to_string(),
    ];
    if test {
        return Command::new("/usr/bin/sudo")
            .arg("-n")
            .arg(exe)
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string());
    }
    #[cfg(target_os = "linux")]
    let mut command = {
        let executable = ["/usr/bin/pkexec", "/bin/pkexec"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .ok_or(
                "관리자 승인 도구가 없습니다. pkexec와 데스크톱 인증 에이전트를 설치하십시오.",
            )?;
        let mut command = Command::new(executable);
        command.arg(exe).args(&arguments);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let exe = exe.to_str().ok_or("프로그램 경로를 읽지 못했습니다.")?;
        if exe.chars().any(char::is_control) {
            return Err("프로그램 경로에 지원하지 않는 문자가 있습니다.".into());
        }
        let shell = std::iter::once(exe)
            .chain(arguments.iter().map(String::as_str))
            .map(shell_quote)
            .collect::<Vec<_>>()
            .join(" ");
        let script = format!(
            "do shell script \"exec {}\" with administrator privileges",
            shell.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let mut command = Command::new("/usr/bin/osascript");
        command.args(["-e", &script]);
        command
    };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("관리자 작업을 시작하지 못했습니다: {e}"))
}

struct Client {
    stream: UnixStream,
    _launcher: Child,
    healthy: bool,
}
impl Client {
    fn connect(test: bool) -> Result<Self, String> {
        let uid = unsafe { libc::geteuid() };
        // macOS's per-user temporary directory can exceed sockaddr_un's limit.
        let directory =
            PathBuf::from("/tmp").join(format!("qs-{uid}-{:032x}", rand::random::<u128>()));
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|e| e.to_string())?;
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_file(self.0.join("token"));
                let _ = fs::remove_file(self.0.join("worker.sock"));
                let _ = fs::remove_dir(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let socket = directory.join("worker.sock");
        let token_path = directory.join("token");
        let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let token = format!(
            "{:032x}{:032x}",
            rand::random::<u128>(),
            rand::random::<u128>()
        );
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token_path)
            .and_then(|mut f| f.write_all(token.as_bytes()))
            .map_err(|e| e.to_string())?;
        let mut child = launcher(
            &std::env::current_exe().map_err(|e| e.to_string())?,
            &socket,
            &token_path,
            uid,
            test,
        )?;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if peer_uid(&stream)? != 0 {
                        continue;
                    }
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .map_err(|e| e.to_string())?;
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .map_err(|e| e.to_string())?;
                    let hello: Hello = read_message(&mut stream)?;
                    if hello.token != token {
                        return Err("관리자 작업 연결 인증에 실패했습니다.".into());
                    }
                    return Ok(Self {
                        stream,
                        _launcher: child,
                        healthy: true,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.to_string()),
            }
            if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err("관리자 승인이 취소됐거나 네트워크 작업을 시작하지 못했습니다.".into());
            }
            if Instant::now() >= deadline {
                return Err("관리자 승인 시간이 초과됐습니다. 다시 시도하십시오.".into());
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    }
    fn call(&mut self, request: &Request) -> Result<Value, String> {
        self.healthy = false;
        write_message(&mut self.stream, request)?;
        let reply: Reply = read_message(&mut self.stream)?;
        self.healthy = true;
        if let Some(error) = reply.error {
            Err(error)
        } else {
            Ok(reply.value)
        }
    }
}
static CLIENT: OnceLock<Mutex<Option<Client>>> = OnceLock::new();
fn call(request: Request, start: bool) -> Result<Value, String> {
    let mut client = CLIENT
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "네트워크 작업 잠금 오류")?;
    if client.is_none() && start {
        *client = Some(Client::connect(false)?);
    }
    let current = client
        .as_mut()
        .ok_or("관리자 작업 연결이 종료됐습니다. 다시 시작하십시오.")?;
    let result = current.call(&request);
    if !current.healthy {
        *client = None;
    }
    result
}
pub fn authorize() -> Result<(), String> {
    call(Request::Ready, true).map(|_| ())
}
pub fn open_capture(iface: &str, filter: &str) -> Result<u64, String> {
    call(
        Request::Open {
            iface: iface.into(),
            filter: filter.into(),
        },
        true,
    )?
    .as_u64()
    .ok_or_else(|| "잘못된 캡처 번호입니다.".into())
}
pub fn send(id: u64, data: &[u8]) -> Result<(), String> {
    call(
        Request::Send {
            id,
            data: data.into(),
        },
        false,
    )
    .map(|_| ())
}
pub fn next(id: u64) -> Result<Option<Vec<u8>>, String> {
    serde_json::from_value(call(Request::Next { id }, false)?).map_err(|e| e.to_string())
}
pub fn close_capture(id: u64) {
    let _ = call(Request::Close { id }, false);
}
pub fn pin(ip: Ipv4Addr, index: u32, mac: Mac) -> Result<(), String> {
    call(Request::Pin { ip, index, mac }, true).map(|_| ())
}
pub fn release(ip: Ipv4Addr, index: u32, mac: Mac) -> Result<(), String> {
    call(Request::Release { ip, index, mac }, true).map(|_| ())
}
pub fn shutdown() {
    if let Some(client) = CLIENT.get() {
        if let Ok(mut client) = client.lock() {
            if let Some(mut current) = client.take() {
                let _ = current.call(&Request::Shutdown);
            }
        }
    }
}
fn valid_frame(data: &[u8]) -> bool {
    (data.len() == 42 && data[12..14] == [8, 6] && data[20..22] == [0, 1])
        || (data.len() >= 282
            && data.len() <= 1500
            && data[12..14] == [8, 0]
            && data[14] == 0x45
            && data[23] == 17
            && data[34..38] == [0, 68, 0, 67])
}
pub fn worker(arguments: &[String]) -> Result<(), String> {
    if !native::admin() || arguments.len() != 3 {
        return Err("관리자 네트워크 작업의 인자가 잘못됐습니다.".into());
    }
    let socket = Path::new(&arguments[0]);
    let token_path = Path::new(&arguments[1]);
    let uid: u32 = arguments[2]
        .parse()
        .map_err(|_| "잘못된 작업 사용자입니다.")?;
    if uid == 0
        || socket.parent() != token_path.parent()
        || socket.file_name().and_then(|p| p.to_str()) != Some("worker.sock")
        || token_path.file_name().and_then(|p| p.to_str()) != Some("token")
    {
        return Err("잘못된 작업 경로입니다.".into());
    }
    let directory = socket.parent().ok_or("작업 폴더가 없습니다.")?;
    let parent = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
    let metadata = fs::symlink_metadata(token_path).map_err(|e| e.to_string())?;
    if !parent.is_dir()
        || parent.uid() != uid
        || parent.mode() & 0o777 != 0o700
        || !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.len() != 64
    {
        return Err("안전한 관리자 작업 폴더를 확인하지 못했습니다.".into());
    }
    let mut token_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(token_path)
        .map_err(|e| e.to_string())?;
    let opened = token_file.metadata().map_err(|e| e.to_string())?;
    if opened.uid() != uid || !opened.is_file() || opened.mode() & 0o077 != 0 || opened.len() != 64
    {
        return Err("작업 인증 파일이 변경됐습니다.".into());
    }
    let mut token = String::new();
    token_file
        .read_to_string(&mut token)
        .map_err(|e| e.to_string())?;
    if !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("잘못된 작업 인증 정보입니다.".into());
    }
    let mut stream = UnixStream::connect(socket).map_err(|e| e.to_string())?;
    if peer_uid(&stream)? != uid {
        return Err("요청한 사용자와 작업 연결이 다릅니다.".into());
    }
    stream.set_read_timeout(None).map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    write_message(&mut stream, &Hello { token })?;
    let mut captures = HashMap::<u64, LocalCapture>::new();
    let mut pins = HashMap::<(Ipv4Addr, u32), Mac>::new();
    let mut sequence = 0u64;
    while let Ok(request) = read_message::<Request>(&mut stream) {
        let stop = matches!(request, Request::Shutdown);
        let result: Result<Value, String> = (|| match request {
            Request::Ready => Ok(json!(true)),
            Request::Open { iface, filter } => {
                if captures.len() >= 16
                    || !matches!(
                        filter.as_str(),
                        "arp" | "udp and src port 67 and dst port 68"
                    )
                {
                    return Err("지원하지 않는 캡처 요청입니다.".into());
                }
                native::live(&iface)?;
                let capture = LocalCapture::open(&iface, &filter)?;
                sequence = sequence.checked_add(1).ok_or("캡처 번호 초과")?;
                captures.insert(sequence, capture);
                Ok(json!(sequence))
            }
            Request::Send { id, data } => {
                if !valid_frame(&data) {
                    return Err("ARP 검색·DHCP 탐색 패킷만 보낼 수 있습니다.".into());
                }
                captures
                    .get(&id)
                    .ok_or("캡처가 종료됐습니다.")?
                    .send(&data)?;
                Ok(Value::Null)
            }
            Request::Next { id } => Ok(json!(captures
                .get(&id)
                .ok_or("캡처가 종료됐습니다.")?
                .next()?)),
            Request::Close { id } => {
                captures.remove(&id);
                Ok(Value::Null)
            }
            Request::Pin { ip, index, mac } => {
                packet::parse_mac(&packet::mac_text(&mac))?;
                // Only a successful, verified write belongs to this worker.
                // A rejected pre-existing static entry must never be claimed.
                native::pin(ip, index, mac)?;
                pins.insert((ip, index), mac);
                Ok(Value::Null)
            }
            Request::Release { ip, index, mac } => {
                packet::parse_mac(&packet::mac_text(&mac))?;
                native::release(ip, index, mac)?;
                pins.remove(&(ip, index));
                Ok(Value::Null)
            }
            Request::Shutdown => Ok(Value::Null),
        })();
        let reply = match result {
            Ok(value) => Reply { value, error: None },
            Err(error) => Reply {
                value: Value::Null,
                error: Some(error),
            },
        };
        if write_message(&mut stream, &reply).is_err() || stop {
            break;
        }
    }
    // Socket EOF also closes capture handles and releases only MACs
    // this worker pinned. The GUI keeps its independent recovery journal.
    for ((ip, index), mac) in pins {
        let _ = native::release(ip, index, mac);
    }
    Ok(())
}
pub fn transport_test() -> Result<Value, String> {
    let mut client = Client::connect(true)?;
    let ready = client.call(&Request::Ready)?;
    let cards = native::interfaces()?;
    if let Some(card) = cards
        .iter()
        .find(|c| !c.mac.is_empty() && !c.ips.is_empty())
    {
        let id = client
            .call(&Request::Open {
                iface: card.id.clone(),
                filter: "arp".into(),
            })?
            .as_u64()
            .ok_or("캡처 번호 오류")?;
        client.call(&Request::Next { id })?;
        if client
            .call(&Request::Send {
                id,
                data: vec![0; 42],
            })
            .is_ok()
        {
            return Err("허용되지 않은 패킷 요청을 거부하지 못했습니다.".into());
        }
        client.call(&Request::Ready)?;
        client.call(&Request::Close { id })?;
    }
    client.call(&Request::Shutdown)?;
    Ok(json!({"authenticatedWorker":ready,"interfaces":cards.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_is_bounded_and_credentials_are_kernel_reported() {
        assert!(read_message::<Value>(&mut &((MAX_MESSAGE as u32 + 1).to_be_bytes())[..]).is_err());
        let mut bytes = Vec::new();
        write_message(
            &mut bytes,
            &Request::Open {
                iface: "en0".into(),
                filter: "arp".into(),
            },
        )
        .unwrap();
        assert!(matches!(
            read_message::<Request>(&mut &bytes[..]).unwrap(),
            Request::Open { .. }
        ));
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), unsafe { libc::geteuid() });
    }
    #[test]
    fn worker_only_sends_supported_discovery_frames() {
        assert!(!valid_frame(&[]));
        assert!(!valid_frame(&vec![0; 65535]));
        let mac = [2, 0, 0, 0, 0, 1];
        assert!(valid_frame(&packet::arp_request(
            mac,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST
        )));
        assert!(valid_frame(&packet::dhcp_discover(mac, 42)));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn quoted_paths_cannot_add_shell_commands() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(
            shell_quote("/Applications/Quiet Scanner.app"),
            "'/Applications/Quiet Scanner.app'"
        );
    }
}
