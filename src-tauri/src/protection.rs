//! Optional host protection. The renderer never receives engine credentials.
use serde::{Deserialize, Serialize};
#[cfg(not(target_os = "linux"))]
use serde_json::json;
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Status {},
    Prepare {},
    Enable {},
    Disable {},
    Allow { ip: String },
    RemoveAllow { ip: String },
}

pub fn request(action: &str, payload: Value) -> Result<Value, String> {
    if action == "protection_info" {
        return Ok(info());
    }
    let command = match action {
        "protection_status" => Command::Status {},
        "protection_prepare" => Command::Prepare {},
        "protection_enable" => Command::Enable {},
        "protection_disable" => Command::Disable {},
        "protection_allow" => Command::Allow {
            ip: address(&payload)?,
        },
        "protection_remove_allow" => Command::RemoveAllow {
            ip: address(&payload)?,
        },
        _ => return Err("지원하지 않는 보호 작업입니다.".into()),
    };
    #[cfg(target_os = "linux")]
    {
        crate::privilege::protection(command)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
        Err(
            "보호 모드는 현재 Ubuntu/Linux에서 지원합니다. 스캐너는 계속 사용할 수 있습니다."
                .into(),
        )
    }
}

fn address(payload: &Value) -> Result<String, String> {
    let ip = payload
        .get("ip")
        .and_then(Value::as_str)
        .ok_or("IP 주소를 입력하십시오.")?;
    ip.parse::<std::net::IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| {
            "하나의 IPv4 또는 IPv6 주소를 입력하십시오. 대역·옵션·호스트명은 사용할 수 없습니다."
                .into()
        })
}

pub fn info() -> Value {
    #[cfg(target_os = "linux")]
    {
        linux::info()
    }
    #[cfg(not(target_os = "linux"))]
    {
        json!({"supported":false,"platform":std::env::consts::OS,"phase":"unsupported","message":"보호 모드는 Ubuntu/Linux부터 지원합니다.","protecting":false})
    }
}

#[cfg(target_os = "linux")]
#[path = "protection/linux.rs"]
pub mod linux;

#[cfg(any(target_os = "linux", test))]
mod model {
    use serde::Serialize;
    use serde_json::Value;
    use std::{collections::BTreeMap, net::IpAddr};

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Decision {
        pub ip: String,
        pub reason: String,
        pub origin: String,
        pub remaining: String,
        pub id: u64,
    }

    // cscli emits alerts containing decisions, rather than a flat decision array.
    // Also accept the flat LAPI shape for compatibility with fixture/older versions.
    pub fn decisions(value: &Value) -> Result<Vec<Decision>, String> {
        if value.is_null() {
            return Ok(vec![]);
        }
        let items = value
            .as_array()
            .ok_or("탐지 엔진의 차단 목록 형식을 확인하지 못했습니다.")?;
        let mut result = BTreeMap::new();
        for item in items {
            if item.get("simulated").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let nested = item.get("decisions").and_then(Value::as_array);
            let list: Vec<&Value> = nested
                .map(|v| v.iter().collect())
                .unwrap_or_else(|| vec![item]);
            for d in list {
                let text = |key| d.get(key).and_then(Value::as_str).unwrap_or("");
                if text("type") != "ban" || !text("scope").eq_ignore_ascii_case("ip") {
                    continue;
                }
                let Ok(ip) = text("value").parse::<IpAddr>() else {
                    continue;
                };
                let remaining = text("duration");
                if remaining.starts_with('-') || remaining == "0s" {
                    continue;
                }
                let decision = Decision {
                    ip: ip.to_string(),
                    reason: text("scenario").chars().take(240).collect(),
                    origin: text("origin").chars().take(60).collect(),
                    remaining: remaining.chars().take(80).collect(),
                    id: d.get("id").and_then(Value::as_u64).unwrap_or(0),
                };
                result.insert((decision.ip.clone(), decision.id), decision);
                if result.len() > 1000 {
                    return Err(
                        "차단 목록이 1,000개를 초과했습니다. 엔진 관리 도구에서 확인하십시오."
                            .into(),
                    );
                }
            }
        }
        Ok(result.into_values().collect())
    }

    pub fn fresh_pull(value: &Value, now: i64) -> bool {
        value.as_array().is_some_and(|rows| {
            rows.iter().any(|row| {
                row.get("name").and_then(Value::as_str) == Some("quiet-scanner")
                    && row.get("revoked").and_then(Value::as_bool) != Some(true)
                    && row.get("valid").and_then(Value::as_bool) != Some(false)
                    && row
                        .get("last_pull")
                        .and_then(Value::as_str)
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .is_some_and(|t| (0..=45).contains(&(now - t.timestamp())))
            })
        })
    }

    pub fn safe_ip(ip: &str) -> Result<String, String> {
        ip.parse::<IpAddr>()
            .map(|v| v.to_string())
            .map_err(|_| "잘못된 IP 주소입니다.".into())
    }

    pub fn firewall_verified(
        value: &Value,
        family: &str,
        table: &str,
        set_prefix: &str,
        require_drop: bool,
    ) -> bool {
        let Some(rows) = value.get("nftables").and_then(Value::as_array) else {
            return false;
        };
        let owned = |v: &Value| {
            v.get("family").and_then(Value::as_str) == Some(family)
                && v.get("table").and_then(Value::as_str) == Some(table)
        };
        let chain = rows.iter().any(|row| {
            row.get("chain").is_some_and(|c| {
                owned(c)
                    && c["name"] == "quiet_scanner_input-input"
                    && c["hook"] == "input"
                    && c["type"] == "filter"
            })
        });
        let sets: Vec<_> = rows
            .iter()
            .filter_map(|row| row.get("set"))
            .filter(|s| owned(s))
            .filter_map(|s| s["name"].as_str())
            .filter(|name| *name == set_prefix || name.starts_with(&format!("{set_prefix}-")))
            .collect();
        // The official bouncer creates an empty hooked chain at startup, then
        // creates a source set + DROP rule lazily for each decision origin.
        // A local ban must never be considered enforced by an empty chain.
        if !chain || (require_drop && sets.is_empty()) {
            return false;
        }
        sets.iter().all(|set| {
            rows.iter().any(|row| {
                row.get("rule").is_some_and(|r| {
                    if !owned(r) || r["chain"] != "quiet_scanner_input-input" {
                        return false;
                    }
                    let Some(expr) = r["expr"].as_array() else {
                        return false;
                    };
                    let source = expr.iter().any(|e| {
                        e.get("match").is_some_and(|m| {
                            m["op"] == "=="
                                && m["left"]["payload"]["field"] == "saddr"
                                && m["left"]["payload"]["protocol"] == family
                                && m["right"].as_str() == Some(&format!("@{set}"))
                        })
                    });
                    source && expr.iter().any(|e| e.get("drop").is_some())
                })
            })
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;
        #[test]
        fn reads_nested_decisions_and_excludes_simulations() {
            let d = json!({"id":7,"type":"ban","scope":"Ip","value":"198.51.100.2","duration":"9m2s","scenario":"ssh-bf","origin":"crowdsec"});
            let rows=decisions(&json!([{"simulated":false,"decisions":[d.clone()]},{"simulated":true,"decisions":[d]}])).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].reason, "ssh-bf");
        }
        #[test]
        fn rejects_malformed_output_instead_of_empty_success() {
            assert!(decisions(&json!({"error":"denied"})).is_err());
        }
        #[test]
        fn only_accepts_single_addresses() {
            for ip in ["--all", "127.0.0.1; reboot", "1.2.3.4/24", "example.com"] {
                assert!(safe_ip(ip).is_err());
            }
            assert_eq!(safe_ip("2001:db8::1").unwrap(), "2001:db8::1");
        }
        #[test]
        fn never_claims_healthy_on_old_invalid_or_future_pull() {
            let b = |t, revoked| json!([{"name":"quiet-scanner","last_pull":t,"revoked":revoked}]);
            assert!(fresh_pull(&b("2026-11-13T00:00:00Z", false), 1794528020));
            assert!(!fresh_pull(&b("2026-11-13T00:00:00Z", false), 1794528100));
            assert!(!fresh_pull(&b("2026-11-13T00:00:00Z", true), 1794528020));
            assert!(!fresh_pull(&b("2026-11-13T00:00:00Z", false), 1794527990));
        }
        #[test]
        fn nft_table_alone_is_not_protection() {
            assert!(!firewall_verified(
                &json!({"nftables":[{"table":{"family":"ip","name":"quiet_scanner"}}]}),
                "ip",
                "quiet_scanner",
                "quiet_scanner_bans",
                true
            ));
        }
        #[test]
        fn verifies_source_set_and_drop_in_input_hook() {
            let v = json!({"nftables":[{"chain":{"family":"ip","table":"quiet_scanner","name":"quiet_scanner_input-input","type":"filter","hook":"input"}},{"set":{"family":"ip","table":"quiet_scanner","name":"quiet_scanner_bans-cscli"}},{"rule":{"family":"ip","table":"quiet_scanner","chain":"quiet_scanner_input-input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@quiet_scanner_bans-cscli"}},{"drop":null}]}}]});
            assert!(firewall_verified(
                &v,
                "ip",
                "quiet_scanner",
                "quiet_scanner_bans",
                true
            ));
            assert!(!firewall_verified(
                &v,
                "ip6",
                "quiet_scanner6",
                "quiet_scanner_bans6",
                true
            ));
        }
        #[test]
        fn empty_hooked_chain_is_ready_only_without_active_bans() {
            let v = json!({"nftables":[{"chain":{"family":"ip","table":"quiet_scanner","name":"quiet_scanner_input-input","type":"filter","hook":"input"}}]});
            assert!(firewall_verified(
                &v,
                "ip",
                "quiet_scanner",
                "quiet_scanner_bans",
                false
            ));
            assert!(!firewall_verified(
                &v,
                "ip",
                "quiet_scanner",
                "quiet_scanner_bans",
                true
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rejects_extra_rpc_fields() {
        assert!(serde_json::from_value::<Command>(
            json!({"operation":"enable","shell":"anything"})
        )
        .is_err());
    }
    #[test]
    fn validates_address_before_privilege() {
        assert!(address(&json!({"ip":"--all"})).is_err());
    }
}
