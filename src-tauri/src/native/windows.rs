use super::*;
use std::ffi::CStr;
use windows_sys::Win32::{
    NetworkManagement::IpHelper::*,
    Networking::WinSock::{NlnsPermanent, AF_INET, SOCKADDR_IN},
};

unsafe fn wide(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut n = 0;
    while n < 32768 && *ptr.add(n) != 0 {
        n += 1
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, n))
}
pub fn interfaces() -> Result<Vec<Iface>, String> {
    let mut size = 15000u32;
    // Aligned allocation; never cast a byte-aligned Vec<u8> to a Windows structure.
    for _ in 0..4 {
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let first = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                GAA_FLAG_INCLUDE_PREFIX
                    | GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_SKIP_DNS_SERVER,
                std::ptr::null(),
                first,
                &mut size,
            )
        };
        if rc == 111 {
            continue;
        }
        if rc == 232 {
            return Ok(vec![]);
        }
        if rc != 0 {
            return Err(format!("인터페이스 조회 실패 (Windows {rc})"));
        }
        let mut out = Vec::new();
        let mut ptr = first;
        while !ptr.is_null() {
            let a = unsafe { &*ptr };
            let mut ips = Vec::new();
            let mut unicast = a.FirstUnicastAddress;
            while !unicast.is_null() {
                let u = unsafe { &*unicast };
                if !u.Address.lpSockaddr.is_null()
                    && unsafe { (*u.Address.lpSockaddr).sa_family } == AF_INET
                    && u.OnLinkPrefixLength <= 32
                {
                    let addr = unsafe { &*(u.Address.lpSockaddr as *const SOCKADDR_IN) };
                    let ip = Ipv4Addr::from(unsafe { addr.sin_addr.S_un.S_addr }.to_ne_bytes());
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        ips.push(Ipv4Info {
                            ip: ip.to_string(),
                            prefix: u.OnLinkPrefixLength,
                            cidr: packet::cidr(ip, u.OnLinkPrefixLength),
                        });
                    }
                }
                unicast = u.Next;
            }
            let mac = if a.PhysicalAddressLength == 6 {
                packet::mac_text(a.PhysicalAddress[..6].try_into().unwrap())
            } else {
                String::new()
            };
            if !ips.is_empty() || !mac.is_empty() {
                let guid = if a.AdapterName.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(a.AdapterName as *const i8) }
                        .to_string_lossy()
                        .into_owned()
                };
                let index = unsafe { a.Anonymous1.Anonymous.IfIndex };
                if index > 0 && !guid.is_empty() {
                    out.push(Iface {
                        name: unsafe { wide(a.FriendlyName) },
                        id: format!(r"\Device\NPF_{}", guid),
                        desc: unsafe { wide(a.Description) },
                        ips: ips.iter().map(|a| a.ip.clone()).collect(),
                        ipv4: ips,
                        index,
                        mac,
                    });
                }
            }
            ptr = a.Next;
        }
        out.sort_by(|a, b| {
            a.ips
                .is_empty()
                .cmp(&b.ips.is_empty())
                .then(a.desc.cmp(&b.desc))
        });
        return Ok(out);
    }
    Err("네트워크 구성이 계속 바뀌고 있습니다. 잠시 후 새로고침하십시오.".into())
}
pub fn admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

pub fn authorize() -> Result<(), String> {
    if admin() {
        Ok(())
    } else {
        Err("분리 기능은 관리자 권한이 필요합니다.".into())
    }
}
fn row(ip: Ipv4Addr, index: u32) -> Result<MIB_IPNET_ROW2, String> {
    if index == 0 {
        return Err("인터페이스 번호를 확인할 수 없습니다.".into());
    }
    let mut row = MIB_IPNET_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    // Resolve the current adapter identity instead of depending on an index-only
    // write. A missing adapter is an error, never an absent/released ARP entry.
    let rc = unsafe { ConvertInterfaceIndexToLuid(index, &mut row.InterfaceLuid) };
    if rc != 0 {
        return Err(format!(
            "네트워크 인터페이스를 찾을 수 없습니다 (번호 {index}, Windows {rc}). 새로고침 후 다시 스캔하십시오."
        ));
    }
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
    Ok(row)
}
pub fn read(ip: Ipv4Addr, index: u32) -> Result<Option<Neighbor>, String> {
    let mut r = row(ip, index)?;
    let rc = unsafe { GetIpNetEntry2(&mut r) };
    if rc == 1168 {
        return Ok(None);
    }
    if rc != 0 {
        return Err(format!("분리 상태 조회 실패 (Windows {rc})"));
    }
    let n = r.PhysicalAddressLength as usize;
    if n > r.PhysicalAddress.len() {
        return Err("Windows가 잘못된 MAC 길이를 반환했습니다.".into());
    }
    Ok(Some(Neighbor {
        mac: r.PhysicalAddress[..n].to_vec(),
        permanent: r.State == NlnsPermanent,
    }))
}
pub fn pin(ip: Ipv4Addr, index: u32, mac: Mac) -> Result<(), String> {
    let mut r = row(ip, index)?;
    r.PhysicalAddress[..6].copy_from_slice(&mac);
    r.PhysicalAddressLength = 6;
    r.State = NlnsPermanent;
    pin_with_retry(
        || read(ip, index),
        |operation| unsafe {
            match operation {
                PinWrite::Set => SetIpNetEntry2(&r),
                PinWrite::Create => CreateIpNetEntry2(&r),
                PinWrite::DeleteDynamic => DeleteIpNetEntry2(&r),
            }
        },
        || verify(ip, index, mac),
    )
    .map_err(|error| format!("{error} [IP {ip}, 인터페이스 {index}]"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinWrite {
    Set,
    Create,
    DeleteDynamic,
}
fn pin_error(code: u32, operation: PinWrite) -> String {
    let detail = match code {
        5 => "관리자 권한으로 실행하십시오.",
        1168 | 2 => {
            "네트워크 인터페이스 또는 ARP 항목을 찾지 못했습니다. 새로고침 후 다시 스캔하십시오."
        }
        5010 => "ARP 항목이 작업 중 변경됐습니다. 다시 시도하십시오.",
        87 => "인터페이스나 IP·MAC 설정을 확인하십시오.",
        _ => "네트워크 어댑터 상태를 확인하십시오.",
    };
    format!("분리 설정 실패 ({operation:?}, Windows {code}). {detail}")
}
fn reject_static(entry: &Option<Neighbor>) -> Result<(), String> {
    if entry.as_ref().is_some_and(|n| n.permanent) {
        Err("이미 정적으로 고정된 주소입니다. 기존 설정은 변경하지 않았습니다.".into())
    } else {
        Ok(())
    }
}
/// The cache can expire between Get and Set, or be repopulated between Get and
/// Create. Some adapters also reject converting a dynamic entry with Set. Retry
/// those cases only; preserve static entries and propagate real failures.
fn pin_with_retry<R, W, V>(mut read: R, mut write: W, mut verify: V) -> Result<(), String>
where
    R: FnMut() -> Result<Option<Neighbor>, String>,
    W: FnMut(PinWrite) -> u32,
    V: FnMut() -> Result<(), String>,
{
    for _ in 0..3 {
        let existing = read()?;
        reject_static(&existing)?;
        let operation = if existing.is_some() {
            PinWrite::Set
        } else {
            PinWrite::Create
        };
        let mut code = write(operation);
        let mut last = operation;
        if operation == PinWrite::Set && code == 1168 {
            let current = read()?;
            reject_static(&current)?;
            if current.is_some() {
                // Only the selected dynamic cache row is removed. Do not flush
                // the adapter or touch any IP configuration/persistent entries.
                let deleted = write(PinWrite::DeleteDynamic);
                if deleted != 0 && deleted != 1168 {
                    return Err(pin_error(deleted, PinWrite::DeleteDynamic));
                }
            }
            last = PinWrite::Create;
            code = write(last);
        }
        if code == 0 {
            return verify();
        }
        if last == PinWrite::Create && code == 5010 {
            continue;
        }
        return Err(pin_error(code, last));
    }
    Err("분리 중 ARP 항목이 반복해서 변경됐습니다. 다시 스캔 후 시도하십시오.".into())
}
pub fn release(ip: Ipv4Addr, index: u32, mac: Mac) -> Result<(), String> {
    release_checked(
        mac,
        || read(ip, index),
        || {
            let r = row(ip, index)?;
            let rc = unsafe { DeleteIpNetEntry2(&r) };
            if rc == 0 || rc == 1168 {
                Ok(())
            } else {
                Err(format!("분리 해제 실패 (Windows {rc})"))
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    fn dynamic() -> Option<Neighbor> {
        Some(Neighbor {
            mac: vec![2, 0, 0, 0, 0, 1],
            permanent: false,
        })
    }
    fn permanent() -> Option<Neighbor> {
        Some(Neighbor {
            mac: vec![2, 0, 0, 0, 0, 2],
            permanent: true,
        })
    }
    fn exercise(
        reads: Vec<Option<Neighbor>>,
        writes: Vec<(PinWrite, u32)>,
        verified: bool,
    ) -> Result<(), String> {
        let mut reads: VecDeque<_> = reads.into();
        let mut writes: VecDeque<_> = writes.into();
        let result = pin_with_retry(
            || Ok(reads.pop_front().expect("unexpected read")),
            |operation| {
                let (expected, code) = writes.pop_front().expect("unexpected write");
                assert_eq!(operation, expected);
                code
            },
            || {
                if verified {
                    Ok(())
                } else {
                    Err("verification failed".into())
                }
            },
        );
        assert!(writes.is_empty(), "unconsumed writes");
        result
    }
    #[test]
    fn expired_neighbor_is_created_after_set_not_found() {
        assert!(exercise(
            vec![dynamic(), None],
            vec![(PinWrite::Set, 1168), (PinWrite::Create, 0)],
            true
        )
        .is_ok());
    }
    #[test]
    fn adapter_rejecting_set_recreates_only_dynamic_entry() {
        assert!(exercise(
            vec![dynamic(), dynamic()],
            vec![
                (PinWrite::Set, 1168),
                (PinWrite::DeleteDynamic, 0),
                (PinWrite::Create, 0)
            ],
            true
        )
        .is_ok());
    }
    #[test]
    fn static_entry_appearing_during_retry_is_preserved() {
        assert!(exercise(
            vec![dynamic(), permanent()],
            vec![(PinWrite::Set, 1168)],
            true
        )
        .is_err());
        assert!(exercise(
            vec![None, permanent()],
            vec![(PinWrite::Create, 5010)],
            true
        )
        .is_err());
    }
    #[test]
    fn cache_repopulated_before_create_retries_set() {
        assert!(exercise(
            vec![None, dynamic()],
            vec![(PinWrite::Create, 5010), (PinWrite::Set, 0)],
            true
        )
        .is_ok());
    }
    #[test]
    fn failures_are_not_reported_as_success_or_permission_errors() {
        assert!(exercise(vec![None], vec![(PinWrite::Create, 1168)], true)
            .unwrap_err()
            .contains("새로고침"));
        assert!(exercise(vec![dynamic()], vec![(PinWrite::Set, 5)], true)
            .unwrap_err()
            .contains("관리자"));
        assert!(exercise(
            vec![dynamic(), dynamic()],
            vec![(PinWrite::Set, 1168), (PinWrite::DeleteDynamic, 5)],
            true
        )
        .is_err());
        assert!(exercise(vec![None], vec![(PinWrite::Create, 0)], false).is_err());
        assert!(!pin_error(1168, PinWrite::Set).contains("관리자"));
    }
    #[test]
    fn retry_is_bounded() {
        assert!(exercise(
            vec![None, None, None],
            vec![(PinWrite::Create, 5010); 3],
            true
        )
        .is_err());
    }
}
