//! Web request inspection policy and externally observed proof validation.
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

pub const PROOF_TTL: u64 = 180;
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub scope: String,
    pub url: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub id: String,
    pub redirect_only: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub generation: String,
    pub probe_peer: IpAddr,
    pub probe_token: String,
    pub targets: Vec<Target>,
    pub scopes: Vec<Scope>,
    pub failure_action: String,
    pub body_action: String,
    pub max_inspect_bytes: u64,
    pub insecure_probe: bool,
}
fn identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 96 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1
            || self.generation.len() != 32
            || !self.generation.bytes().all(|c| c.is_ascii_hexdigit())
            || self.probe_token.len() != 64
            || !self.probe_token.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err("Invalid private WAF configuration".into());
        }
        if self.probe_peer.is_loopback()
            || self.probe_peer.is_unspecified()
            || self.probe_peer.is_multicast()
        {
            return Err("The verifier must use an explicit peer outside this server".into());
        }
        if !["passthrough", "deny"].contains(&self.failure_action.as_str())
            || !["passthrough", "deny"].contains(&self.body_action.as_str())
            || !(65536..=10485760).contains(&self.max_inspect_bytes)
        {
            return Err("Unsupported inspection policy".into());
        }
        if self.targets.is_empty() || self.targets.len() > 128 || self.scopes.len() > 256 {
            return Err("WAF needs 1..128 verified request paths".into());
        }
        let scopes: BTreeSet<_> = self.scopes.iter().map(|s| s.id.as_str()).collect();
        if scopes.len() != self.scopes.len() || scopes.iter().any(|s| !identifier(s)) {
            return Err("Invalid WAF scopes".into());
        }
        let mut ids = BTreeSet::new();
        for target in &self.targets {
            if !identifier(&target.id)
                || !ids.insert(&target.id)
                || !scopes.contains(target.scope.as_str())
                || target.port == 0
                || !target.path.starts_with('/')
                || target.path.len() > 1024
                || !target
                    .path
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"/_-.%".contains(&c))
                || !target
                    .host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".:-".contains(&c))
                || !(target.url.starts_with("https://")
                    || (self.insecure_probe && target.url.starts_with("http://")))
            {
                return Err("Invalid or insecure verification target".into());
            }
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub target: String,
    pub scope: String,
    pub kind: String,
    pub peer: IpAddr,
    pub host: String,
    pub port: u16,
    pub generation: String,
    pub nginx_epoch: String,
    pub engine_epoch: String,
    pub boot_seconds: u64,
    pub outcome: String,
    pub status: u16,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub seq: u64,
    pub epoch: String,
    pub boot_seconds: u64,
    pub scope: String,
    pub peer: IpAddr,
    pub outcome: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: u32,
    pub generation: String,
    pub nginx_epoch: String,
    pub engine_epoch: String,
    pub enabled: bool,
    pub allowed: u64,
    pub blocked: u64,
    pub incomplete: u64,
    pub failures: u64,
    pub last_incomplete: u64,
    pub last_failure: u64,
    pub event_seq: u64,
    pub proofs: Vec<Proof>,
    pub events: Vec<Event>,
}
pub fn evaluate(
    config: &Config,
    snapshot: &Snapshot,
    engine_epoch: &str,
    now: u64,
) -> Result<String, String> {
    config.validate()?;
    if snapshot.schema != 1
        || snapshot.generation != config.generation
        || snapshot.engine_epoch != engine_epoch
        || !snapshot.enabled
        || snapshot.nginx_epoch.is_empty()
    {
        return Err("Nginx/engine generation is not the configured active integration".into());
    }
    if snapshot.proofs.len() > 384 || snapshot.events.len() > 256 {
        return Err("Oversized WAF observation".into());
    }
    let mut found = BTreeMap::new();
    for p in &snapshot.proofs {
        let Some(target) = config.targets.iter().find(|t| t.id == p.target) else {
            return Err("Unknown verification path".into());
        };
        if p.scope != target.scope
            || p.peer != config.probe_peer
            || p.host != target.host
            || p.port != target.port
            || p.generation != config.generation
            || p.nginx_epoch != snapshot.nginx_epoch
            || p.engine_epoch != engine_epoch
            || p.boot_seconds > now
            || now - p.boot_seconds > PROOF_TTL
        {
            continue;
        }
        let valid = match p.kind.as_str() {
            "get" | "post" => p.outcome == "inspected" && p.status == 204,
            "block" => p.outcome == "blocked" && p.status == 403,
            _ => false,
        };
        if valid {
            found.insert((p.target.as_str(), p.kind.as_str()), true);
        }
    }
    if config.targets.iter().any(|t| {
        ["get", "post", "block"]
            .iter()
            .any(|kind| !found.contains_key(&(t.id.as_str(), *kind)))
    }) {
        return Ok("awaiting_external_check".into());
    }
    for last in [snapshot.last_failure, snapshot.last_incomplete] {
        if last > now {
            return Err("Invalid WAF observation clock".into());
        }
        if last != 0 && now - last <= PROOF_TTL {
            return Ok("degraded".into());
        }
    }
    Ok("verified".into())
}
pub fn assets() -> serde_json::Value {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../vendor/waf/assets.json")).expect("frozen WAF assets");
    let map = value.as_object_mut().unwrap();
    for (name, content) in [
        ("nginx/init.lua", include_str!("../nginx/waf_init.lua")),
        ("nginx/access.lua", include_str!("../nginx/waf_access.lua")),
        ("nginx/log.lua", include_str!("../nginx/waf_log.lua")),
        ("nginx/status.lua", include_str!("../nginx/waf_status.lua")),
        (
            "engine.service",
            include_str!("../systemd/quiet-guard-waf-engine.service"),
        ),
        (
            "monitor.service",
            include_str!("../systemd/quiet-guard-waf-monitor.service"),
        ),
        ("upstream.json", include_str!("../vendor/waf/upstream.json")),
    ] {
        map.insert(name.into(), content.into());
    }
    value
}
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{control, monitor, observation};
#[cfg(not(target_os = "linux"))]
pub fn control(_: &[String]) -> Result<(), String> {
    Err("WAF integration requires Ubuntu Linux".into())
}
#[cfg(not(target_os = "linux"))]
pub fn monitor() -> Result<(), String> {
    Err("WAF monitoring requires Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Config, Snapshot) {
        let cfg:Config=serde_json::from_value(serde_json::json!({"schema":1,"generation":"a".repeat(32),"probe_peer":"10.204.0.2","probe_token":"b".repeat(64),"failure_action":"passthrough","body_action":"passthrough","max_inspect_bytes":1048576,"insecure_probe":false,"scopes":[{"id":"qg_main","redirect_only":false}],"targets":[{"id":"qg_main_host","scope":"qg_main","url":"https://guard.test/__quiet_guard_probe__","host":"guard.test","port":443,"path":"/__quiet_guard_probe__"}]})).unwrap();
        let proofs: Vec<Proof> = ["get", "post", "block"]
            .into_iter()
            .map(|kind| Proof {
                target: cfg.targets[0].id.clone(),
                scope: "qg_main".into(),
                kind: kind.into(),
                peer: cfg.probe_peer,
                host: "guard.test".into(),
                port: 443,
                generation: cfg.generation.clone(),
                nginx_epoch: "nginx1".into(),
                engine_epoch: "engine1".into(),
                boot_seconds: 100,
                outcome: if kind == "block" {
                    "blocked"
                } else {
                    "inspected"
                }
                .into(),
                status: if kind == "block" { 403 } else { 204 },
            })
            .collect();
        let snap = Snapshot {
            schema: 1,
            generation: cfg.generation.clone(),
            nginx_epoch: "nginx1".into(),
            engine_epoch: "engine1".into(),
            enabled: true,
            allowed: 0,
            blocked: 0,
            incomplete: 0,
            failures: 0,
            last_incomplete: 0,
            last_failure: 0,
            event_seq: 0,
            proofs,
            events: vec![],
        };
        (cfg, snap)
    }
    #[test]
    fn requires_real_external_paths_body_block_and_fresh_epochs() {
        let (mut cfg, mut snap) = fixture();
        assert_eq!(evaluate(&cfg, &snap, "engine1", 110).unwrap(), "verified");
        snap.proofs[2].status = 204;
        assert_eq!(
            evaluate(&cfg, &snap, "engine1", 110).unwrap(),
            "awaiting_external_check"
        );
        snap.proofs[2].status = 403;
        assert_eq!(
            evaluate(&cfg, &snap, "engine1", 281).unwrap(),
            "awaiting_external_check"
        );
        snap.nginx_epoch = "reloaded".into();
        assert_eq!(
            evaluate(&cfg, &snap, "engine1", 110).unwrap(),
            "awaiting_external_check"
        );
        assert!(evaluate(&cfg, &snap, "restarted", 110).is_err());
        cfg.probe_peer = "127.0.0.1".parse().unwrap();
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn partial_inspection_and_fail_open_cannot_report_verified() {
        let (cfg, mut snap) = fixture();
        snap.last_failure = 105;
        assert_eq!(evaluate(&cfg, &snap, "engine1", 110).unwrap(), "degraded");
        snap.last_failure = 0;
        snap.last_incomplete = 105;
        assert_eq!(evaluate(&cfg, &snap, "engine1", 110).unwrap(), "degraded");
        snap.last_incomplete = 111;
        assert!(evaluate(&cfg, &snap, "engine1", 110).is_err());
    }
    #[test]
    fn frozen_vendor_contents_match_documented_original_or_patch_hashes() {
        use sha2::{Digest, Sha256};
        let assets = assets();
        let meta: serde_json::Value =
            serde_json::from_str(include_str!("../vendor/waf/upstream.json")).unwrap();
        for (name, entry) in meta["files"].as_object().unwrap() {
            let expected = entry
                .get("patched_sha256")
                .unwrap_or(&entry["sha256"])
                .as_str()
                .unwrap();
            assert_eq!(
                hex::encode(Sha256::digest(assets[name].as_str().unwrap().as_bytes())),
                expected,
                "{name}"
            );
        }
    }
}
