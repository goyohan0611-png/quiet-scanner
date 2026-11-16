//! Independent web/SSH policy: proxy uncertainty must never disable unrelated SSH.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Direct,
    Proxied,
    Unknown,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IngressPolicy {
    pub web: PathKind,
    pub web_verified: bool,
    pub suspicious_peer_concentration: bool,
    pub ssh: PathKind,
    pub ssh_verified: bool,
}

impl IngressPolicy {
    pub fn web_ip_ban_allowed(&self) -> bool {
        self.web == PathKind::Direct && self.web_verified && !self.suspicious_peer_concentration
    }
    pub fn ssh_ip_ban_allowed(&self) -> bool {
        self.ssh == PathKind::Direct && self.ssh_verified
    }
}

pub const SERVICE_PERIOD: u64 = 10;
pub const SERVICE_TTL: u64 = 30;
pub const WAF_PERIOD: u64 = 60;
pub const WAF_TTL: u64 = 180;

// Age uses a monotonic boot clock. Explicit failure/config changes override TTL.
pub fn result_is_current(age: u64, ttl: u64, failed: bool, revision_matches: bool) -> bool {
    age <= ttl && !failed && revision_matches
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(web: PathKind) -> IngressPolicy {
        IngressPolicy {
            web,
            web_verified: true,
            suspicious_peer_concentration: false,
            ssh: PathKind::Direct,
            ssh_verified: true,
        }
    }
    #[test]
    fn web_proxy_does_not_suspend_verified_direct_ssh() {
        for web in [PathKind::Proxied, PathKind::Unknown] {
            let p = policy(web);
            assert!(!p.web_ip_ban_allowed());
            assert!(p.ssh_ip_ban_allowed());
        }
    }
    #[test]
    fn claimed_direct_web_is_not_sufficient() {
        let mut p = policy(PathKind::Direct);
        assert!(p.web_ip_ban_allowed());
        p.web_verified = false;
        assert!(!p.web_ip_ban_allowed());
        p.web_verified = true;
        p.suspicious_peer_concentration = true;
        assert!(!p.web_ip_ban_allowed());
    }
    #[test]
    fn ssh_requires_its_own_evidence() {
        let mut p = policy(PathKind::Direct);
        p.ssh = PathKind::Proxied;
        assert!(!p.ssh_ip_ban_allowed());
        assert!(p.web_ip_ban_allowed());
    }
    #[test]
    fn failure_and_rules_change_invalidate_success_immediately() {
        assert!(result_is_current(180, WAF_TTL, false, true));
        assert!(!result_is_current(181, WAF_TTL, false, true));
        assert!(!result_is_current(1, WAF_TTL, true, true));
        assert!(!result_is_current(1, WAF_TTL, false, false));
    }
}
