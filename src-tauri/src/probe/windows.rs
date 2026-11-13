use super::*;
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    NetworkManagement::IpHelper::*,
};

struct Icmp(HANDLE);
impl Drop for Icmp {
    fn drop(&mut self) {
        unsafe {
            IcmpCloseHandle(self.0);
        }
    }
}
pub(super) fn icmp_status(code: u32) -> (&'static str, String) {
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
