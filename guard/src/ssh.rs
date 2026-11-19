//! SSH-only remediation. CrowdSec detects attacks; this adapter owns one nft table.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::IpAddr};

pub const TABLE: &str = "quiet_guard_ssh";
pub const MARKER: &str = "quiet-guard-ssh-v1";
pub const HEALTH_TTL: u64 = 30;
pub const LEASE: u64 = 45;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub direct_ssh_confirmed: bool,
    pub ports: Vec<u16>,
    pub management_ips: Vec<IpAddr>,
    pub allow_ips: Vec<IpAddr>,
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 || !self.direct_ssh_confirmed {
            return Err(
                "Confirm a direct SSH path; jump hosts/shared proxies require a separate policy"
                    .into(),
            );
        }
        if self.ports.is_empty() || self.ports.len() > 16 || self.ports.contains(&0) {
            return Err("Specify 1..16 real SSH ports".into());
        }
        if self.management_ips.is_empty()
            || self.management_ips.len() > 32
            || self.allow_ips.len() > 1024
            || self
                .management_ips
                .iter()
                .chain(&self.allow_ips)
                .any(|ip| !usable(*ip))
        {
            return Err(
                "A usable management IP and bounded exact-IP exceptions are required".into(),
            );
        }
        Ok(())
    }
    pub fn revision(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("serializable policy"),
        ))
    }
    fn exempt(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.management_ips.contains(&ip) || self.allow_ips.contains(&ip)
    }
}
fn usable(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(v) if v.is_broadcast())
        && !matches!(ip, IpAddr::V6(v) if v.to_ipv4_mapped().is_some())
}

#[derive(Debug, Deserialize)]
struct Decision {
    duration: String,
    scope: String,
    #[serde(rename = "type")]
    kind: String,
    value: String,
    scenario: String,
    origin: String,
}
/// Parse the positive subset of Go duration strings returned by the local API.
fn duration_seconds(raw: &str) -> Result<u64, String> {
    if raw.is_empty() || raw.len() > 96 {
        return Err("invalid decision duration".into());
    }
    let bytes = raw.as_bytes();
    let mut index = 0;
    let mut total = 0.0f64;
    while index < bytes.len() {
        let start = index;
        while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
            index += 1;
        }
        let number: f64 = raw[start..index]
            .parse()
            .map_err(|_| "invalid duration number")?;
        let tail = &raw[index..];
        let (unit, scale) = if tail.starts_with("ms") {
            (2, 0.001)
        } else if tail.starts_with("us") {
            (2, 0.000001)
        } else if tail.starts_with("ns") {
            (2, 0.000000001)
        } else if tail.starts_with('h') {
            (1, 3600.0)
        } else if tail.starts_with('m') {
            (1, 60.0)
        } else if tail.starts_with('s') {
            (1, 1.0)
        } else {
            return Err("invalid duration unit".into());
        };
        total += number * scale;
        index += unit;
    }
    if !total.is_finite() || total <= 0.0 {
        return Err("expired/invalid decision".into());
    }
    // Short leases remove stale bans if the engine/enforcer stops renewing.
    Ok(total.floor().min(LEASE as f64) as u64)
}
pub fn decisions(raw: &[u8], config: &Config) -> Result<BTreeMap<IpAddr, u64>, String> {
    config.validate()?;
    if raw.len() > 4 * 1024 * 1024 {
        return Err("decision response exceeds limit".into());
    }
    let entries: Option<Vec<Decision>> =
        serde_json::from_slice(raw).map_err(|_| "invalid local API response")?;
    let entries = entries.unwrap_or_default();
    if entries.len() > 10000 {
        return Err("too many decisions; protection cannot be verified".into());
    }
    let mut result = BTreeMap::new();
    for entry in entries {
        // This engine is dedicated to SSH. Ignore non-SSH automatic decisions even if misconfigured.
        if entry.scope != "Ip"
            || entry.kind != "ban"
            || !(entry.origin == "cscli" || entry.scenario.starts_with("crowdsecurity/ssh-"))
        {
            continue;
        }
        let ip: IpAddr = entry.value.parse().map_err(|_| "invalid IP decision")?;
        if !usable(ip) || config.exempt(ip) {
            continue;
        }
        let ttl = duration_seconds(&entry.duration)?;
        if ttl > 0 {
            result
                .entry(ip)
                .and_modify(|v: &mut u64| *v = (*v).max(ttl))
                .or_insert(ttl);
        }
    }
    Ok(result)
}

pub fn initial_rules(config: &Config) -> Result<String, String> {
    config.validate()?;
    let ports = config
        .ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!(
        "add table inet {TABLE} {{ comment \"{MARKER}\"; }}\n\
add set inet {TABLE} banned4 {{ type ipv4_addr; flags timeout; }}\n\
add set inet {TABLE} banned6 {{ type ipv6_addr; flags timeout; }}\n\
add chain inet {TABLE} input {{ type filter hook input priority -10; policy accept; }}\n\
add rule inet {TABLE} input ip saddr @banned4 tcp dport {{ {ports} }} drop\n\
add rule inet {TABLE} input ip6 saddr @banned6 tcp dport {{ {ports} }} drop\n"
    ))
}
pub fn update_rules(entries: &BTreeMap<IpAddr, u64>) -> String {
    let mut output = format!("flush set inet {TABLE} banned4\nflush set inet {TABLE} banned6\n");
    for (ipv4, set) in [(true, "banned4"), (false, "banned6")] {
        let elements = entries
            .iter()
            .filter(|(ip, _)| ip.is_ipv4() == ipv4)
            .map(|(ip, ttl)| format!("{ip} timeout {ttl}s"))
            .collect::<Vec<_>>();
        if !elements.is_empty() {
            output.push_str(&format!(
                "add element inet {TABLE} {set} {{ {} }}\n",
                elements.join(", ")
            ));
        }
    }
    output
}
/// Verify the kernel readback structurally, including every rule and set member.
pub fn verify_table(
    raw: &[u8],
    config: &Config,
    wanted: &BTreeMap<IpAddr, u64>,
) -> Result<(), String> {
    let document: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| "invalid nft readback")?;
    let rows = document["nftables"]
        .as_array()
        .ok_or("missing nft readback")?;
    let mut table_count = 0;
    let mut chain_count = 0;
    let mut sets = BTreeMap::new();
    let mut rules = Vec::new();
    for row in rows {
        if row.get("metainfo").is_some() {
            continue;
        }
        if let Some(table) = row.get("table") {
            if table["family"] != "inet" || table["name"] != TABLE || table["comment"] != MARKER {
                return Err("foreign firewall table".into());
            }
            table_count += 1;
        } else if let Some(chain) = row.get("chain") {
            if chain["family"] != "inet"
                || chain["table"] != TABLE
                || chain["name"] != "input"
                || chain["type"] != "filter"
                || chain["hook"] != "input"
                || chain["prio"] != -10
                || chain["policy"] != "accept"
            {
                return Err("unexpected firewall chain".into());
            }
            chain_count += 1;
        } else if let Some(set) = row.get("set") {
            let name = set["name"].as_str().ok_or("missing set name")?;
            let kind = match name {
                "banned4" => "ipv4_addr",
                "banned6" => "ipv6_addr",
                _ => return Err("unexpected firewall set".into()),
            };
            if set["family"] != "inet"
                || set["table"] != TABLE
                || set["type"] != kind
                || set["flags"] != serde_json::json!(["timeout"])
                || sets.contains_key(name)
            {
                return Err("unexpected set configuration".into());
            }
            let mut members = Vec::new();
            if let Some(elements) = set.get("elem") {
                for element in elements.as_array().ok_or("invalid set elements")? {
                    let elem = element.get("elem").ok_or("missing timed element")?;
                    let ip: IpAddr = elem["val"]
                        .as_str()
                        .ok_or("invalid member IP")?
                        .parse()
                        .map_err(|_| "invalid member IP")?;
                    if ip.is_ipv4() != (name == "banned4")
                        || !wanted.contains_key(&ip)
                        || members.contains(&ip)
                    {
                        return Err("firewall membership differs".into());
                    }
                    let timeout = elem["timeout"].as_u64().ok_or("missing finite timeout")?;
                    if timeout == 0 || timeout > LEASE * 1000 {
                        return Err("unbounded firewall lease".into());
                    }
                    members.push(ip);
                }
            }
            sets.insert(name.to_string(), members);
        } else if let Some(rule) = row.get("rule") {
            if rule["family"] != "inet" || rule["table"] != TABLE || rule["chain"] != "input" {
                return Err("unexpected firewall rule".into());
            }
            rules.push(rule["expr"].clone());
        } else {
            return Err("unknown firewall object".into());
        }
    }
    if table_count != 1 || chain_count != 1 || sets.len() != 2 || rules.len() != 2 {
        return Err("incomplete/extra firewall objects".into());
    }
    let actual: std::collections::BTreeSet<_> = sets.values().flatten().copied().collect();
    if actual != wanted.keys().copied().collect() {
        return Err("firewall membership differs".into());
    }
    for (index, (proto, name)) in [("ip", "banned4"), ("ip6", "banned6")].iter().enumerate() {
        let expression = rules[index].as_array().ok_or("invalid rule expression")?;
        if expression.len() != 3 {
            return Err("extra firewall expressions".into());
        }
        let source = &expression[0]["match"];
        let port = &expression[1]["match"];
        if source["op"] != "=="
            || source["left"] != serde_json::json!({"payload":{"protocol":proto,"field":"saddr"}})
            || source["right"] != format!("@{name}")
            || port["op"] != "=="
            || port["left"] != serde_json::json!({"payload":{"protocol":"tcp","field":"dport"}})
            || expression[2] != serde_json::json!({"drop":null})
        {
            return Err("SSH rule scope differs".into());
        }
        let values: Vec<u16> = if let Some(value) = port["right"].as_u64() {
            vec![u16::try_from(value).map_err(|_| "invalid port")?]
        } else {
            port["right"]["set"]
                .as_array()
                .ok_or("invalid port set")?
                .iter()
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u16::try_from(n).ok())
                        .ok_or("invalid port")
                })
                .collect::<Result<_, _>>()?
        };
        let mut expected = config.ports.clone();
        expected.sort_unstable();
        expected.dedup();
        let mut values = values;
        values.sort_unstable();
        if values != expected {
            return Err("SSH ports differ".into());
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    pub schema: u32,
    pub boot_id: String,
    pub boot_seconds: u64,
    pub policy_revision: String,
    pub phase: String,
    pub blocked_ips: Option<usize>,
    pub message: String,
}
impl Health {
    pub fn current(&self, now: u64, boot_id: &str, revision: &str) -> bool {
        self.schema == 1
            && self.phase == "verified"
            && self.blocked_ips.is_some()
            && self.boot_id == boot_id
            && now >= self.boot_seconds
            && now - self.boot_seconds <= HEALTH_TTL
            && self.policy_revision == revision
    }
}

pub fn assets() -> serde_json::Value {
    let mut result = serde_json::json!({
        "parsers/s00-raw/syslog-logs.yaml":include_str!("../vendor/crowdsec-ssh/syslog-logs.yaml"),
        "parsers/s01-parse/sshd-logs.yaml":include_str!("../vendor/crowdsec-ssh/sshd-logs.yaml"),
        "parsers/s02-enrich/dateparse-enrich.yaml":include_str!("../vendor/crowdsec-ssh/dateparse-enrich.yaml"),
        "scenarios/ssh-bf.yaml":include_str!("../vendor/crowdsec-ssh/ssh-bf.yaml"),
        "LICENSE.hub":include_str!("../vendor/crowdsec-ssh/LICENSE"),
        "upstream.json":include_str!("../vendor/crowdsec-ssh/upstream.json"),
        "LICENSE.engine":include_str!("../vendor/crowdsec-ssh/LICENSE.engine"),
        "engine-upstream.json":include_str!("../vendor/crowdsec-ssh/engine-upstream.json"),
        // These are fixed local items, not an automatically upgraded Hub install.
        "hub/.index.json":"{}\n",
        "engine.service":include_str!("../systemd/quiet-guard-ssh-engine.service"),
        "enforcer.service":include_str!("../systemd/quiet-guard-ssh-enforcer.service")
    });
    let patterns: BTreeMap<String, String> =
        serde_json::from_str(include_str!("../vendor/crowdsec-ssh/patterns.json"))
            .expect("vendored patterns");
    for (name, text) in patterns {
        result
            .as_object_mut()
            .unwrap()
            .insert(format!("patterns/{name}"), text.into());
    }
    result
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{control, enforce, observation};
#[cfg(not(target_os = "linux"))]
pub fn control(_: &[String]) -> Result<(), String> {
    Err("SSH protection requires Ubuntu Linux".into())
}
#[cfg(not(target_os = "linux"))]
pub fn enforce(_: bool) -> Result<(), String> {
    Err("SSH enforcement requires Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            schema: 1,
            direct_ssh_confirmed: true,
            ports: vec![22],
            management_ips: vec!["192.0.2.1".parse().unwrap()],
            allow_ips: vec![],
        }
    }
    fn decision(ip: &str, duration: &str) -> serde_json::Value {
        serde_json::json!({"scope":"Ip","type":"ban","value":ip,"duration":duration,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf"})
    }
    #[test]
    fn exempts_management_loopback_and_explicit_exceptions() {
        let mut c = config();
        c.allow_ips.push("2001:db8::5".parse().unwrap());
        let raw = serde_json::to_vec(&vec![
            decision("192.0.2.1", "1h"),
            decision("127.0.0.2", "1h"),
            decision("::1", "1h"),
            decision("2001:db8::5", "1h"),
            decision("192.0.2.2", "3h51m57.3s"),
        ])
        .unwrap();
        let result = decisions(&raw, &c).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[&"192.0.2.2".parse::<IpAddr>().unwrap()], 45);
    }
    #[test]
    fn strict_decisions_and_finite_lease() {
        for bad in [b"{}".as_slice(), b"truncated", b"[{}]"] {
            assert!(decisions(bad, &config()).is_err());
        }
        assert!(decisions(
            &serde_json::to_vec(&vec![decision("1.2.3.4; flush ruleset", "1h")]).unwrap(),
            &config()
        )
        .is_err());
        for raw in ["-1s", "nan", "1e5s", "2d", "1.2.3s", "0s", ""] {
            assert!(duration_seconds(raw).is_err());
        }
        assert_eq!(duration_seconds("2s500ms").unwrap(), 2);
        assert!(decisions(b"null", &config()).unwrap().is_empty());
    }
    #[test]
    fn refuses_ambiguous_management_path_and_cannot_touch_other_ports() {
        let mut c = config();
        c.direct_ssh_confirmed = false;
        assert!(initial_rules(&c).is_err());
        c.direct_ssh_confirmed = true;
        let rules = initial_rules(&c).unwrap();
        assert!(rules.contains("tcp dport { 22 } drop"));
        assert!(!rules.contains("flush ruleset"));
        c.management_ips.clear();
        assert!(c.validate().is_err());
    }
    #[test]
    fn health_expires_across_failure_policy_change_and_reboot() {
        let mut h = Health {
            schema: 1,
            boot_id: "boot1".into(),
            boot_seconds: 100,
            policy_revision: "a".into(),
            phase: "verified".into(),
            blocked_ips: Some(0),
            message: String::new(),
        };
        assert!(h.current(130, "boot1", "a"));
        assert!(!h.current(131, "boot1", "a"));
        assert!(!h.current(101, "boot2", "a"));
        assert!(!h.current(101, "boot1", "b"));
        h.phase = "unknown".into();
        assert!(!h.current(101, "boot1", "a"));
    }
    #[test]
    fn firewall_readback_must_prove_hook_scope_membership_and_finite_leases() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/nft-ssh.json")).unwrap();
        let wanted = BTreeMap::from([
            ("192.0.2.2".parse().unwrap(), 45),
            ("2001:db8::2".parse().unwrap(), 45),
        ]);
        let check = |value: &serde_json::Value| {
            verify_table(&serde_json::to_vec(value).unwrap(), &config(), &wanted)
        };
        assert!(check(&fixture).is_ok());
        let changes = [
            ("/nftables/1/table/comment", serde_json::json!("foreign")),
            ("/nftables/4/chain/hook", serde_json::json!("forward")),
            ("/nftables/5/rule/expr/1/match/right", serde_json::json!(80)),
            ("/nftables/5/rule/expr/0/match/op", serde_json::json!("!=")),
            ("/nftables/2/set/elem", serde_json::json!([])),
            ("/nftables/2/set/elem/0/elem/timeout", serde_json::json!(0)),
            (
                "/nftables/2/set/elem/0/elem/timeout",
                serde_json::json!(46000),
            ),
            (
                "/nftables/3/set/elem/0/elem/val",
                serde_json::json!("2001:db8::3"),
            ),
        ];
        for (pointer, value) in changes {
            let mut bad = fixture.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(check(&bad).is_err(), "accepted {pointer}");
        }
        let mut extra = fixture.clone();
        extra["nftables"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"chain":{"name":"unexpected"}}));
        assert!(check(&extra).is_err());
        assert!(verify_table(
            &serde_json::to_vec(&fixture).unwrap(),
            &config(),
            &BTreeMap::new()
        )
        .is_err());
    }
}
