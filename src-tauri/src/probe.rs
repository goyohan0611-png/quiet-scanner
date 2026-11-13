use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4},
    time::{Duration, Instant},
};
#[cfg(windows)]
#[path = "probe/windows.rs"]
mod platform;
#[cfg(unix)]
#[path = "probe/unix.rs"]
mod platform;
pub use platform::ping;

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
    let destination = SocketAddrV4::new(target, port);
    // A local probe can otherwise bind the destination's now-free ephemeral
    // port and successfully connect to itself on Linux. Keep that collision
    // reserved while a second socket gets a distinct source port.
    let mut collisions = Vec::new();
    let socket =
        loop {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
                .map_err(|e| e.to_string())?;
            socket.bind(&SocketAddrV4::new(source, 0).into()).map_err(|e| {
            format!("선택한 인터페이스로 연결할 수 없습니다. 새로고침 후 다시 확인하십시오: {e}")
        })?;
            if socket
                .local_addr()
                .map_err(|e| e.to_string())?
                .as_socket_ipv4()
                == Some(destination)
            {
                collisions.push(socket);
            } else {
                break socket;
            }
        };
    let started = Instant::now();
    let result = socket.connect_timeout(&destination.into(), Duration::from_millis(1500));
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
        // A bound, non-listening socket reserves this port against unrelated
        // parallel tests/processes without accepting TCP connections.
        let reserved = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        reserved.bind(&SocketAddrV4::new(local, 0).into()).unwrap();
        let closed_port = reserved
            .local_addr()
            .unwrap()
            .as_socket_ipv4()
            .unwrap()
            .port();
        let closed = tcp(local, local, closed_port).unwrap();
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
        #[cfg(windows)]
        assert_eq!(
            platform::icmp_status(
                windows_sys::Win32::NetworkManagement::IpHelper::IP_REQ_TIMED_OUT
            )
            .0,
            "timeout"
        );
        assert!(tcp(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 0).is_err());
    }
}
