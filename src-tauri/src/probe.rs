use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    NetworkManagement::IpHelper::*,
};

#[derive(Debug, Serialize)]
pub struct ResultRow {
    pub ip: String,
    pub port: Option<u16>,
    pub ok: bool,
    pub status: &'static str,
    pub message: String,
    pub ms: Option<u64>,
    pub code: Option<u32>,
}
struct Icmp(HANDLE);
impl Drop for Icmp {
    fn drop(&mut self) {
        unsafe {
            IcmpCloseHandle(self.0);
        }
    }
}
fn icmp_status(code: u32) -> (&'static str, String) {
    match code {
        IP_REQ_TIMED_OUT => ("timeout", "응답 시간 초과".into()),
        IP_DEST_NET_UNREACHABLE | IP_DEST_HOST_UNREACHABLE | IP_BAD_ROUTE => (
            "unreachable",
            "대상 또는 네트워크 경로에 도달할 수 없습니다".into(),
        ),
        IP_TTL_EXPIRED_TRANSIT | IP_TTL_EXPIRED_REASSEM => {
            ("unreachable", "경로에서 TTL이 만료됐습니다".into())
        }
        _ => ("error", format!("Ping 확인 실패 (Windows {code})")),
    }
}
pub fn ping(source: Ipv4Addr, target: Ipv4Addr) -> Result<ResultRow, String> {
    let handle = unsafe { IcmpCreateFile() };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(format!("Ping 핸들 생성 실패 (Windows {})", unsafe {
            GetLastError()
        }));
    }
    let handle = Icmp(handle);
    let payload: [u8; 32] = rand::random();
    // Covers reply/options/data, ICMP error and IO_STATUS_BLOCK; aligned for Windows.
    let mut reply = [0u64; 64];
    let count = unsafe {
        IcmpSendEcho2Ex(
            handle.0,
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            u32::from_ne_bytes(source.octets()),
            u32::from_ne_bytes(target.octets()),
            payload.as_ptr().cast(),
            payload.len() as u16,
            std::ptr::null(),
            reply.as_mut_ptr().cast(),
            std::mem::size_of_val(&reply) as u32,
            800,
        )
    };
    // ICMP_ECHO_REPLY/ICMP_ECHO_REPLY32 share this prefix. Never dereference
    // their architecture-dependent data or options pointers.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Header {
        address: u32,
        status: u32,
        ms: u32,
    }
    let header = unsafe { std::ptr::read(reply.as_ptr().cast::<Header>()) };
    let code = if count == 0 {
        unsafe { GetLastError() }
    } else {
        header.status
    };
    let ok =
        count > 0 && code == IP_SUCCESS && header.address == u32::from_ne_bytes(target.octets());
    let (status, message) = if ok {
        ("reply", "응답 받음".into())
    } else {
        icmp_status(code)
    };
    Ok(ResultRow {
        ip: target.to_string(),
        port: None,
        ok,
        status,
        message,
        ms: ok.then_some(header.ms as u64),
        code: (!ok).then_some(code),
    })
}
fn tcp_status(error: &io::Error) -> (&'static str, String) {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => {
            ("refused", "연결 거부 · TCP 연결을 받지 않습니다".into())
        }
        io::ErrorKind::TimedOut => (
            "timeout",
            "시간 초과 · 차단 또는 무응답 여부를 확인하십시오".into(),
        ),
        io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::AddrNotAvailable => (
            "unreachable",
            "대상 또는 네트워크 경로에 도달할 수 없습니다".into(),
        ),
        io::ErrorKind::PermissionDenied => ("blocked", "이 PC에서 연결 요청이 차단됐습니다".into()),
        _ => ("error", format!("TCP 연결 확인 실패: {error}")),
    }
}

pub fn tcp(source: Ipv4Addr, target: Ipv4Addr, port: u16) -> Result<ResultRow, String> {
    if port == 0 {
        return Err("포트는 1~65535 범위로 입력하십시오.".into());
    }
    let socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(|e| e.to_string())?;
    socket
        .bind(&SocketAddrV4::new(source, 0).into())
        .map_err(|e| {
            format!("선택한 인터페이스로 연결할 수 없습니다. 새로고침 후 다시 확인하십시오: {e}")
        })?;
    let started = Instant::now();
    let result = socket.connect_timeout(
        &SocketAddrV4::new(target, port).into(),
        Duration::from_millis(1500),
    );
    let elapsed = started.elapsed().as_millis() as u64;
    let (ok, status, message, code) = match result {
        Ok(()) => (true, "open", "열림 · TCP 연결 성공".into(), None),
        Err(error) => {
            let (status, message) = tcp_status(&error);
            (
                false,
                status,
                message,
                error.raw_os_error().map(|n| n as u32),
            )
        }
    };
    // Drop closes the test connection; no application data is sent.
    Ok(ResultRow {
        ip: target.to_string(),
        port: Some(port),
        ok,
        status,
        message,
        ms: Some(elapsed),
        code,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tcp_open_and_not_open() {
        let local = Ipv4Addr::LOCALHOST;
        let listener = std::net::TcpListener::bind((local, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let open = tcp(local, local, port).unwrap();
        assert!(open.ok);
        assert_eq!(open.status, "open");
        drop(listener);
        let closed = tcp(local, local, port).unwrap();
        assert!(!closed.ok);
        // Windows may silently drop probes after a listener closes. Preserve
        // the observed timeout instead of relabeling it as a refusal.
        assert!(matches!(closed.status, "refused" | "timeout"), "{closed:?}");
    }
    #[test]
    fn ping_loopback() {
        let reply = ping(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST).unwrap();
        assert!(reply.ok, "{reply:?}");
        assert!(reply.ms.is_some());
    }
    #[test]
    fn failures_are_not_reported_as_closed() {
        assert_eq!(
            tcp_status(&io::Error::from(io::ErrorKind::ConnectionRefused)).0,
            "refused"
        );
        assert_eq!(
            tcp_status(&io::Error::from(io::ErrorKind::TimedOut)).0,
            "timeout"
        );
        assert_eq!(
            tcp_status(&io::Error::from(io::ErrorKind::NetworkUnreachable)).0,
            "unreachable"
        );
        assert_eq!(icmp_status(IP_REQ_TIMED_OUT).0, "timeout");
        assert!(tcp(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 0).is_err());
    }
}
