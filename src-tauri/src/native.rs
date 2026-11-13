use crate::packet::{self, Mac};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[cfg(windows)]
#[path = "native/windows.rs"]
mod platform;
#[cfg(unix)]
#[path = "native/unix.rs"]
mod platform;
pub use platform::{admin, authorize, interfaces, pin, read, release};

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
pub fn live(id: &str) -> Result<Iface, String> {
    interfaces()?
        .into_iter()
        .find(|a| a.id.eq_ignore_ascii_case(id))
        .ok_or_else(|| "선택한 인터페이스가 사라졌습니다. 새로고침 후 다시 선택하십시오.".into())
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Neighbor {
    pub mac: Vec<u8>,
    pub permanent: bool,
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
