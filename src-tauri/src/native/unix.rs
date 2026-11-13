use super::*;
use std::{collections::BTreeMap, ffi::CStr, process::Command};

pub fn interfaces() -> Result<Vec<Iface>, String> {
    let mut first = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(format!(
            "인터페이스 조회 실패: {}",
            std::io::Error::last_os_error()
        ));
    }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) }
        }
    }
    let _addresses = Addresses(first);
    let mut cards = BTreeMap::new();
    let mut current = first;
    while !current.is_null() {
        let address = unsafe { &*current };
        current = address.ifa_next;
        if address.ifa_name.is_null()
            || address.ifa_addr.is_null()
            || address.ifa_flags & libc::IFF_LOOPBACK as u32 != 0
        {
            continue;
        }
        let name = unsafe { CStr::from_ptr(address.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let index = unsafe { libc::if_nametoindex(address.ifa_name) };
        if index == 0 {
            continue;
        }
        let card = cards.entry(name.clone()).or_insert_with(|| Iface {
            name: name.clone(),
            id: name.clone(),
            desc: name,
            ips: Vec::new(),
            ipv4: Vec::new(),
            index,
            mac: String::new(),
        });
        let family = unsafe { (*address.ifa_addr).sa_family as i32 };
        if family == libc::AF_INET && !address.ifa_netmask.is_null() {
            let addr = unsafe { &*(address.ifa_addr as *const libc::sockaddr_in) };
            let mask = unsafe { &*(address.ifa_netmask as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
            let mask = u32::from_be_bytes(mask.sin_addr.s_addr.to_ne_bytes());
            let prefix = mask.leading_ones() as u8;
            let expected = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            if !ip.is_loopback() && !ip.is_unspecified() && mask == expected {
                let text = ip.to_string();
                if !card.ips.contains(&text) {
                    card.ips.push(text.clone());
                    card.ipv4.push(Ipv4Info {
                        ip: text,
                        prefix,
                        cidr: packet::cidr(ip, prefix),
                    });
                }
            }
        }
        #[cfg(target_os = "linux")]
        if family == libc::AF_PACKET {
            let link = unsafe { &*(address.ifa_addr as *const libc::sockaddr_ll) };
            if link.sll_halen == 6 {
                card.mac = packet::mac_text(link.sll_addr[..6].try_into().unwrap());
            }
        }
        #[cfg(target_os = "macos")]
        if family == libc::AF_LINK {
            let link = unsafe { &*(address.ifa_addr as *const libc::sockaddr_dl) };
            let offset = std::mem::offset_of!(libc::sockaddr_dl, sdl_data) + link.sdl_nlen as usize;
            if link.sdl_alen == 6 && offset + 6 <= link.sdl_len as usize {
                let bytes = unsafe {
                    std::slice::from_raw_parts((address.ifa_addr as *const u8).add(offset), 6)
                };
                let mac: Mac = bytes.try_into().unwrap();
                card.mac = packet::mac_text(&mac);
            }
        }
    }
    let mut out: Vec<_> = cards
        .into_values()
        .filter(|c| !c.ips.is_empty() || !c.mac.is_empty())
        .collect();
    out.sort_by(|a, b| {
        a.ips
            .is_empty()
            .cmp(&b.ips.is_empty())
            .then(a.name.cmp(&b.name))
    });
    Ok(out)
}

pub fn admin() -> bool {
    unsafe { libc::geteuid() == 0 }
}
pub fn authorize() -> Result<(), String> {
    if admin() {
        Ok(())
    } else {
        crate::privilege::authorize()
    }
}

fn interface_name(index: u32) -> Result<String, String> {
    interfaces()?
        .into_iter()
        .find(|c| c.index == index)
        .map(|c| c.name)
        .ok_or_else(|| "인터페이스가 변경됐습니다. 새로고침 후 다시 확인하십시오.".into())
}
fn command(arguments: &[&str]) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    let paths = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"];
    #[cfg(target_os = "macos")]
    let paths = ["/usr/sbin/arp", "/sbin/arp"];
    let executable = paths
        .iter()
        .find(|p| std::path::Path::new(p).is_file())
        .ok_or("네트워크 관리 도구를 찾지 못했습니다. Linux에서는 iproute2를 설치하십시오.")?;
    let output = Command::new(executable)
        .env("LC_ALL", "C")
        .args(arguments)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "네트워크 설정 확인 실패: {}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(600)
                .collect::<String>()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn parse_neighbor(text: &str, ip: Ipv4Addr) -> Result<Option<Neighbor>, String> {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(text).map_err(|e| format!("ARP 조회 결과 해석 실패: {e}"))?;
    let mut result = None;
    for row in rows {
        if row["dst"].as_str().and_then(|s| s.parse::<Ipv4Addr>().ok()) != Some(ip) {
            continue;
        }
        let Some(mac) = row["lladdr"].as_str() else {
            continue;
        };
        let mac = packet::parse_mac(mac)?;
        let permanent = match &row["state"] {
            serde_json::Value::Array(states) => {
                states.iter().any(|s| s.as_str() == Some("PERMANENT"))
            }
            serde_json::Value::String(state) => state == "PERMANENT",
            _ => return Err("ARP 상태를 확인하지 못했습니다.".into()),
        };
        if result.is_some() {
            return Err("동일 인터페이스의 ARP 결과가 중복됩니다.".into());
        }
        result = Some(Neighbor {
            mac: mac.to_vec(),
            permanent,
        });
    }
    Ok(result)
}

#[cfg(target_os = "macos")]
fn parse_neighbor(text: &str, ip: Ipv4Addr) -> Result<Option<Neighbor>, String> {
    let mut result = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 6
            || fields[1].trim_matches(['(', ')']).parse::<Ipv4Addr>().ok() != Some(ip)
        {
            continue;
        }
        if fields[3] == "(incomplete)" {
            continue;
        }
        let bytes: Result<Vec<u8>, _> = fields[3]
            .split(':')
            .map(|p| u8::from_str_radix(p, 16))
            .collect();
        let mac: Mac = bytes
            .map_err(|_| "ARP MAC 해석 실패")?
            .try_into()
            .map_err(|_| "ARP MAC 길이가 잘못됐습니다.")?;
        packet::parse_mac(&packet::mac_text(&mac))?;
        if result.is_some() {
            return Err("동일 인터페이스의 ARP 결과가 중복됩니다.".into());
        }
        result = Some(Neighbor {
            mac: mac.to_vec(),
            permanent: fields.contains(&"permanent"),
        });
    }
    Ok(result)
}

pub fn read(ip: Ipv4Addr, index: u32) -> Result<Option<Neighbor>, String> {
    let name = interface_name(index)?;
    #[cfg(target_os = "linux")]
    let text = command(&[
        "-j",
        "-4",
        "neigh",
        "show",
        "to",
        &ip.to_string(),
        "dev",
        &name,
    ])?;
    #[cfg(target_os = "macos")]
    let text = command(&["-an", "-i", &name])?;
    parse_neighbor(&text, ip)
}
pub fn pin(ip: Ipv4Addr, index: u32, mac: Mac) -> Result<(), String> {
    if !admin() {
        return crate::privilege::pin(ip, index, mac);
    }
    let name = interface_name(index)?;
    if read(ip, index)?.as_ref().is_some_and(|n| n.permanent) {
        return Err("이미 정적으로 고정된 주소입니다. 기존 설정을 먼저 확인하십시오.".into());
    }
    #[cfg(target_os = "linux")]
    command(&[
        "-4",
        "neigh",
        "replace",
        &ip.to_string(),
        "lladdr",
        &packet::mac_text(&mac),
        "nud",
        "permanent",
        "dev",
        &name,
    ])?;
    #[cfg(target_os = "macos")]
    command(&[
        "-s",
        &ip.to_string(),
        &packet::mac_text(&mac),
        "ifscope",
        &name,
    ])?;
    verify(ip, index, mac)
}
pub fn release(ip: Ipv4Addr, index: u32, mac: Mac) -> Result<(), String> {
    if !admin() {
        return crate::privilege::release(ip, index, mac);
    }
    let name = interface_name(index)?;
    release_checked(
        mac,
        || read(ip, index),
        || {
            #[cfg(target_os = "linux")]
            command(&["-4", "neigh", "del", &ip.to_string(), "dev", &name])?;
            #[cfg(target_os = "macos")]
            command(&["-d", &ip.to_string(), "ifscope", &name])?;
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn neighbor_parser_preserves_permanent_and_exact_addresses() {
        #[cfg(target_os = "linux")]
        let input = r#"[{"dst":"192.0.2.1","lladdr":"02:00:00:00:00:01","state":["PERMANENT"]}]"#;
        #[cfg(target_os = "macos")]
        let input = "? (192.0.2.1) at 2:0:0:0:0:1 on en0 ifscope permanent [ethernet]";
        let row = parse_neighbor(input, "192.0.2.1".parse().unwrap())
            .unwrap()
            .unwrap();
        assert!(row.permanent);
        assert_eq!(row.mac, vec![2, 0, 0, 0, 0, 1]);
        assert!(parse_neighbor(input, "192.0.2.10".parse().unwrap())
            .unwrap()
            .is_none());
    }
}
