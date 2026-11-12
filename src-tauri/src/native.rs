use crate::packet::{self, Mac};
use serde::{Deserialize, Serialize};
use std::{ffi::CStr, net::Ipv4Addr};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::*,
    Networking::WinSock::{NlnsPermanent, AF_INET, SOCKADDR_IN},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ipv4Info {
    pub ip: String,
    pub prefix: u8,
    pub cidr: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Iface {
    pub name: String,
    #[serde(rename = "scapyName")]
    pub id: String,
    pub desc: String,
    pub ips: Vec<String>,
    pub ipv4: Vec<Ipv4Info>,
    pub index: u32,
    pub mac: String,
}
impl Iface {
    pub fn source_for(&self, target: Ipv4Addr) -> Ipv4Addr {
        self.ipv4
            .iter()
            .filter_map(|a| a.ip.parse().ok().map(|ip| (ip, a.prefix)))
            .filter(|(ip, p)| packet::same_subnet(target, *ip, *p))
            .max_by_key(|(_, p)| *p)
            .map(|(ip, _)| ip)
            .or_else(|| self.ips.first().and_then(|s| s.parse().ok()))
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }
}
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
pub fn live(id: &str) -> Result<Iface, String> {
    interfaces()?
        .into_iter()
        .find(|a| a.id.eq_ignore_ascii_case(id))
        .ok_or_else(|| "선택한 인터페이스가 사라졌습니다. 새로고침 후 다시 선택하십시오.".into())
}
pub fn admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Neighbor {
    pub mac: Vec<u8>,
    pub permanent: bool,
}
fn row(ip: Ipv4Addr, index: u32) -> Result<MIB_IPNET_ROW2, String> {
    if index == 0 {
        return Err("인터페이스 번호를 확인할 수 없습니다.".into());
    }
    let mut row = MIB_IPNET_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
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
pub fn is_pinned_to(entry: &Option<Neighbor>, mac: Mac) -> bool {
    entry.as_ref().is_some_and(|n| n.permanent && n.mac == mac)
}
pub fn verify(ip: Ipv4Addr, index: u32, mac: Mac) -> Result<(), String> {
    if is_pinned_to(&read(ip, index)?, mac) {
        Ok(())
    } else {
        Err(
            "선택한 MAC으로 고정된 것을 확인하지 못했습니다. 분리 해제 후 다시 시도하십시오."
                .into(),
        )
    }
}
pub fn pin(ip: Ipv4Addr, index: u32, mac: Mac) -> Result<(), String> {
    let mut r = row(ip, index)?;
    r.PhysicalAddress[..6].copy_from_slice(&mac);
    r.PhysicalAddressLength = 6;
    r.State = NlnsPermanent;
    let existing = read(ip, index)?;
    if existing.as_ref().is_some_and(|n| n.permanent) {
        return Err("이미 정적으로 고정된 주소입니다. 기존 설정을 먼저 확인하십시오.".into());
    }
    let rc = unsafe {
        if existing.is_some() {
            SetIpNetEntry2(&r)
        } else {
            CreateIpNetEntry2(&r)
        }
    };
    if rc != 0 {
        return Err(format!(
            "분리 설정 실패 (Windows {rc}). 관리자 권한을 확인하십시오."
        ));
    }
    verify(ip, index, mac)
}
pub fn release_checked<R, D>(expected: Mac, mut read: R, mut delete: D) -> Result<(), String>
where
    R: FnMut() -> Result<Option<Neighbor>, String>,
    D: FnMut() -> Result<(), String>,
{
    let before = read()?;
    if !before.as_ref().is_some_and(|n| n.permanent) {
        return Ok(());
    }
    if !is_pinned_to(&before, expected) {
        return Err(
            "고정 MAC이 작업 기록과 다릅니다. 다른 정적 설정은 삭제하지 않았습니다.".into(),
        );
    }
    delete()?;
    if read()?.as_ref().is_some_and(|n| n.permanent) {
        Err("분리 해제를 확인하지 못했습니다. 상태를 유지합니다.".into())
    } else {
        Ok(())
    }
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
    use std::cell::Cell;
    const MAC: Mac = [2, 0, 0, 0, 0, 1];
    fn entry(mac: Mac) -> Option<Neighbor> {
        Some(Neighbor {
            mac: mac.to_vec(),
            permanent: true,
        })
    }
    #[test]
    fn verified_mac_only() {
        assert!(is_pinned_to(&entry(MAC), MAC));
        assert!(!is_pinned_to(&entry([2, 0, 0, 0, 0, 2]), MAC));
        assert!(!is_pinned_to(&None, MAC));
    }
    #[test]
    fn unknown_is_not_released() {
        let called = Cell::new(false);
        assert!(release_checked(
            MAC,
            || Err("read failed".into()),
            || {
                called.set(true);
                Ok(())
            }
        )
        .is_err());
        assert!(!called.get());
    }
    #[test]
    fn dont_delete_other_static_entry() {
        let called = Cell::new(false);
        assert!(release_checked(
            MAC,
            || Ok(entry([2, 0, 0, 0, 0, 2])),
            || {
                called.set(true);
                Ok(())
            }
        )
        .is_err());
        assert!(!called.get());
    }
    #[test]
    fn failed_delete_is_not_success() {
        assert!(release_checked(MAC, || Ok(entry(MAC)), || Err("denied".into())).is_err());
    }
    #[test]
    fn reread_after_delete() {
        assert!(release_checked(MAC, || Ok(entry(MAC)), || Ok(())).is_err());
        let n = Cell::new(0);
        assert!(release_checked(
            MAC,
            || {
                n.set(n.get() + 1);
                Ok(if n.get() == 1 { entry(MAC) } else { None })
            },
            || Ok(())
        )
        .is_ok());
    }
    #[test]
    fn no_write_for_dynamic() {
        let called = Cell::new(false);
        assert!(release_checked(
            MAC,
            || Ok(Some(Neighbor {
                mac: MAC.to_vec(),
                permanent: false
            })),
            || {
                called.set(true);
                Ok(())
            }
        )
        .is_ok());
        assert!(!called.get());
    }
}
