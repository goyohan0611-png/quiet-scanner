use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    net::Ipv4Addr,
};

pub type Mac = [u8; 6];
pub fn mac_text(mac: &Mac) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
pub fn digits(text: &str) -> Result<String, String> {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_hexdigit() {
            out.push(c.to_ascii_lowercase());
        } else if !matches!(c, ':' | '-' | '.' | ' ' | '\t') {
            return Err("MAC에는 0~9, A~F와 구분자만 입력하십시오.".into());
        }
    }
    Ok(out)
}
pub fn parse_mac(text: &str) -> Result<Mac, String> {
    let hex = digits(text)?;
    if hex.len() != 12 {
        return Err("MAC 주소 6바이트가 필요합니다.".into());
    }
    let mut mac = [0; 6];
    for (i, part) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        mac[i] = u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16)
            .map_err(|e| e.to_string())?;
    }
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return Err("유효한 장비의 유니캐스트 MAC 주소가 필요합니다.".into());
    }
    Ok(mac)
}
pub fn parse_target(text: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut out = BTreeSet::new();
    for part in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (start, end) = if let Some((ip, prefix)) = part.split_once('/') {
            let ip: Ipv4Addr = ip.parse().map_err(|_| "잘못된 IPv4 주소입니다.")?;
            let prefix: u32 = prefix.parse().map_err(|_| "잘못된 서브넷입니다.")?;
            if prefix > 32 {
                return Err("서브넷은 /0~32 범위여야 합니다.".into());
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = u32::from(ip) & mask;
            let broadcast = network | !mask;
            if prefix <= 30 {
                (network as u64 + 1, broadcast as u64 - 1)
            } else {
                (network as u64, broadcast as u64)
            }
        } else if let Some((left, right)) = part.split_once('-') {
            let left: Ipv4Addr = left
                .trim()
                .parse()
                .map_err(|_| "범위의 시작 IP가 잘못됐습니다.")?;
            let right: Ipv4Addr = if right.contains('.') {
                right
                    .trim()
                    .parse()
                    .map_err(|_| "범위의 끝 IP가 잘못됐습니다.")?
            } else {
                let last: u8 = right
                    .trim()
                    .parse()
                    .map_err(|_| "끝자리는 0~255 범위여야 합니다.")?;
                let [a, b, c, _] = left.octets();
                Ipv4Addr::new(a, b, c, last)
            };
            (u32::from(left) as u64, u32::from(right) as u64)
        } else {
            let ip: Ipv4Addr = part
                .parse()
                .map_err(|_| "스캔할 IPv4 주소를 확인하십시오.")?;
            (u32::from(ip) as u64, u32::from(ip) as u64)
        };
        if start > end {
            return Err("시작 IP가 끝 IP보다 큽니다.".into());
        }
        if end - start + 1 > 4096 {
            return Err("한 번에 4,096개 주소까지만 스캔할 수 있습니다.".into());
        }
        for ip in start..=end {
            out.insert(Ipv4Addr::from(ip as u32));
        }
        if out.len() > 4096 {
            return Err("한 번에 4,096개 주소까지만 스캔할 수 있습니다.".into());
        }
    }
    if out.is_empty() {
        return Err("스캔할 대역을 입력하십시오.".into());
    }
    Ok(out.into_iter().collect())
}
pub fn cidr(ip: Ipv4Addr, prefix: u8) -> String {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    format!("{}/{}", Ipv4Addr::from(u32::from(ip) & mask), prefix)
}
pub fn same_subnet(ip: Ipv4Addr, own: Ipv4Addr, prefix: u8) -> bool {
    cidr(ip, prefix) == cidr(own, prefix)
}
pub fn arp_request(mac: Mac, source: Ipv4Addr, target: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0; 42];
    p[..6].fill(255);
    p[6..12].copy_from_slice(&mac);
    p[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    p[22..28].copy_from_slice(&mac);
    p[28..32].copy_from_slice(&source.octets());
    p[38..42].copy_from_slice(&target.octets());
    p
}
fn ethernet(p: &[u8]) -> Option<(u16, usize)> {
    if p.len() < 14 {
        return None;
    }
    let mut ty = u16::from_be_bytes([p[12], p[13]]);
    let mut offset = 14;
    for _ in 0..2 {
        if ty != 0x8100 && ty != 0x88a8 {
            break;
        }
        let tag = p.get(offset..offset + 4)?;
        ty = u16::from_be_bytes([tag[2], tag[3]]);
        offset += 4;
    }
    Some((ty, offset))
}
pub fn arp_reply(p: &[u8]) -> Option<(Ipv4Addr, Mac)> {
    let (ty, start) = ethernet(p)?;
    if ty != 0x0806 {
        return None;
    }
    let a = p.get(start..start + 28)?;
    if a[..8] != [0, 1, 8, 0, 6, 4, 0, 2] {
        return None;
    }
    let mac: Mac = a[8..14].try_into().ok()?;
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return None;
    }
    Some((Ipv4Addr::new(a[14], a[15], a[16], a[17]), mac))
}
fn checksum(p: &[u8]) -> u16 {
    let mut n: u32 = p
        .chunks(2)
        .map(|c| ((c[0] as u32) << 8) | (*c.get(1).unwrap_or(&0) as u32))
        .sum();
    while n >> 16 != 0 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
fn udp_frame(mac: Mac, source: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0; 42 + payload.len()];
    p[..6].fill(255);
    p[6..12].copy_from_slice(&mac);
    p[12..14].copy_from_slice(&[8, 0]);
    p[14] = 0x45;
    let length = (28 + payload.len()) as u16;
    p[16..18].copy_from_slice(&length.to_be_bytes());
    p[22] = 64;
    p[23] = 17;
    p[26..30].copy_from_slice(&source.octets());
    p[30..34].fill(255);
    let sum = checksum(&p[14..34]);
    p[24..26].copy_from_slice(&sum.to_be_bytes());
    p[34..36].copy_from_slice(&sport.to_be_bytes());
    p[36..38].copy_from_slice(&dport.to_be_bytes());
    let udp = (8 + payload.len()) as u16;
    p[38..40].copy_from_slice(&udp.to_be_bytes());
    p[42..].copy_from_slice(payload);
    p
}
pub fn dhcp_discover(mac: Mac, xid: u32) -> Vec<u8> {
    let mut b = vec![0; 240];
    b[..3].copy_from_slice(&[1, 1, 6]);
    b[4..8].copy_from_slice(&xid.to_be_bytes());
    b[10] = 0x80;
    b[28..34].copy_from_slice(&mac);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    b.extend_from_slice(&[53, 1, 1, 55, 6, 1, 3, 6, 15, 51, 54, 61, 7, 1]);
    b.extend_from_slice(&mac);
    b.push(255);
    b.resize(300, 0);
    udp_frame(mac, Ipv4Addr::UNSPECIFIED, 68, 67, &b)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Offer {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub kind: String,
    pub offered: String,
    pub mask: String,
    pub router: Vec<String>,
    pub dns: Vec<String>,
    pub domain: String,
    pub lease: Option<u32>,
    pub relay: String,
}
fn options(p: &[u8], map: &mut HashMap<u8, Vec<u8>>) -> Option<()> {
    let mut i = 0;
    while i < p.len() {
        let code = p[i];
        i += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            return Some(());
        }
        let n = *p.get(i)? as usize;
        i += 1;
        let value = p.get(i..i + n)?;
        i += n;
        map.entry(code).or_insert_with(|| value.to_vec());
    }
    Some(())
}
fn ip4(p: &[u8]) -> Option<Ipv4Addr> {
    let a: [u8; 4] = p.try_into().ok()?;
    Some(Ipv4Addr::from(a))
}
fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && ip != Ipv4Addr::BROADCAST
}
pub fn dhcp_offer(p: &[u8], xid: u32, client: Mac) -> Option<Offer> {
    let (ty, start) = ethernet(p)?;
    if ty != 0x0800 {
        return None;
    }
    let ip = p.get(start..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 17 {
        return None;
    }
    let ihl = (ip[0] & 15) as usize * 4;
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if ihl < 20
        || total > ip.len()
        || total < ihl + 8
        || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
    {
        return None;
    }
    let u = ip.get(ihl..total)?;
    if u[..4] != [0, 67, 0, 68] {
        return None;
    }
    let len = u16::from_be_bytes([u[4], u[5]]) as usize;
    if len < 248 || len > u.len() {
        return None;
    }
    let b = &u[8..len];
    if b[..3] != [2, 1, 6]
        || u32::from_be_bytes(b[4..8].try_into().ok()?) != xid
        || b[28..34] != client
        || b[236..240] != [99, 130, 83, 99]
    {
        return None;
    }
    let mut opt = HashMap::new();
    options(&b[240..], &mut opt)?;
    let overload = opt.get(&52).and_then(|v| v.first()).copied().unwrap_or(0);
    if overload & 1 != 0 {
        options(&b[108..236], &mut opt)?;
    }
    if overload & 2 != 0 {
        options(&b[44..108], &mut opt)?;
    }
    if opt.get(&53).map(Vec::as_slice) != Some(&[2][..]) {
        return None;
    }
    let server = if let Some(id) = opt.get(&54) {
        ip4(id)?
    } else {
        ip4(&ip[12..16])?
    };
    let offered = ip4(&b[16..20])?;
    if !unicast(server) || !unicast(offered) {
        return None;
    }
    let mac: Mac = p[6..12].try_into().ok()?;
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return None;
    }
    let ips = |code: u8| {
        opt.get(&code)
            .map(|v| {
                v.as_chunks::<4>()
                    .0
                    .iter()
                    .filter_map(|bytes| ip4(bytes))
                    .filter(|ip| unicast(*ip))
                    .map(|ip| ip.to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    let relay = ip4(&b[24..28])?;
    Some(Offer {
        ip: server.to_string(),
        mac: mac_text(&mac),
        vendor: String::new(),
        kind: String::new(),
        offered: offered.to_string(),
        mask: opt
            .get(&1)
            .and_then(|v| ip4(v))
            .map(|v| v.to_string())
            .unwrap_or_default(),
        router: ips(3),
        dns: ips(6),
        domain: opt
            .get(&15)
            .map(|v| String::from_utf8_lossy(v).trim_matches('\0').to_string())
            .unwrap_or_default(),
        lease: opt
            .get(&51)
            .and_then(|v| <[u8; 4]>::try_from(v.as_slice()).ok())
            .map(u32::from_be_bytes),
        relay: if relay.is_unspecified() {
            String::new()
        } else {
            relay.to_string()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const CLIENT: Mac = [2, 0, 0, 0, 0, 1];
    const SERVER: Mac = [0x50, 0xc7, 0xbf, 0x11, 0x22, 0x33];
    fn offer(xid: u32, client: Mac) -> Vec<u8> {
        let discover = dhcp_discover(client, xid);
        let mut b = discover[42..282].to_vec();
        b[0] = 2;
        b[16..20].copy_from_slice(&[192, 168, 0, 57]);
        b.extend_from_slice(&[
            53, 1, 2, 54, 4, 192, 168, 0, 1, 1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 0, 1, 6, 8, 8,
            8, 8, 8, 1, 1, 1, 1, 51, 4, 0, 0, 28, 32, 255,
        ]);
        udp_frame(SERVER, Ipv4Addr::new(192, 168, 0, 1), 67, 68, &b)
    }
    #[test]
    fn targets_subnets() {
        assert_eq!(parse_target("192.168.0.0/23").unwrap().len(), 510);
        assert_eq!(parse_target("192.168.0.0/22").unwrap().len(), 1022);
        assert_eq!(parse_target("192.168.0.0/31").unwrap().len(), 2);
        assert_eq!(parse_target("192.168.0.1/32").unwrap().len(), 1);
    }
    #[test]
    fn targets_limits() {
        for s in [
            "",
            "192.168.0.0/0",
            "192.168.0.0/19",
            "192.168.0.0/33",
            "192.168.0.9-1",
            "192.168.0.1-256",
            "not-ip",
        ] {
            assert!(parse_target(s).is_err(), "{s}");
        }
    }
    #[test]
    fn targets_unique() {
        assert_eq!(parse_target("192.168.0.1-3,192.168.0.2").unwrap().len(), 3);
    }
    #[test]
    fn mac_validation() {
        assert_eq!(
            parse_mac("70-B3-D5-21-B7-CE").unwrap(),
            [112, 179, 213, 33, 183, 206]
        );
        for s in [
            "",
            "zz:00:00:00:00:00",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
        ] {
            assert!(parse_mac(s).is_err());
        }
    }
    #[test]
    fn arp_roundtrip() {
        let mut p = arp_request(
            CLIENT,
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(192, 168, 0, 2),
        );
        assert!(arp_reply(&p).is_none());
        p[21] = 2;
        assert_eq!(
            arp_reply(&p).unwrap(),
            (Ipv4Addr::new(192, 168, 0, 1), CLIENT)
        );
        assert!(arp_reply(&p[..30]).is_none());
    }
    #[test]
    fn offer_fields() {
        let o = dhcp_offer(&offer(7, CLIENT), 7, CLIENT).unwrap();
        assert_eq!(o.ip, "192.168.0.1");
        assert_eq!(o.offered, "192.168.0.57");
        assert_eq!(o.dns, vec!["8.8.8.8", "1.1.1.1"]);
        assert_eq!(o.lease, Some(7200));
    }
    #[test]
    fn ignore_other_clients() {
        assert!(dhcp_offer(&offer(7, CLIENT), 8, CLIENT).is_none());
        assert!(dhcp_offer(&offer(7, [2, 0, 0, 0, 0, 2]), 7, CLIENT).is_none());
    }
    #[test]
    fn no_request() {
        let p = dhcp_discover(CLIENT, 7);
        assert_eq!(&p[34..38], &[0, 68, 0, 67]);
        assert_eq!(p[42], 1);
        assert_eq!(&p[282..285], &[53, 1, 1]);
        assert_eq!(checksum(&p[14..34]), 0);
    }
    #[test]
    fn malformed_offer_never_panics() {
        let p = offer(7, CLIENT);
        for n in 0..p.len() {
            let _ = dhcp_offer(&p[..n], 7, CLIENT);
        }
        let mut p = p;
        p[283] = 255;
        assert!(dhcp_offer(&p, 7, CLIENT).is_none());
    }
    #[test]
    fn reject_wrong_port_and_fragment() {
        let mut p = offer(7, CLIENT);
        p[35] = 68;
        assert!(dhcp_offer(&p, 7, CLIENT).is_none());
        let mut p = offer(7, CLIENT);
        p[20] = 0x20;
        assert!(dhcp_offer(&p, 7, CLIENT).is_none());
    }
    #[test]
    fn relay_preserved() {
        let mut p = offer(7, CLIENT);
        p[66..70].copy_from_slice(&[192, 168, 0, 254]);
        assert_eq!(dhcp_offer(&p, 7, CLIENT).unwrap().relay, "192.168.0.254");
    }
}
