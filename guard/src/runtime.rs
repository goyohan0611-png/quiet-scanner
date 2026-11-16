//! Low-privilege service heartbeat and bounded observations of protection services.
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path, thread, time::Duration};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: u32,
    pub version: String,
    pub pid: u32,
    pub boot_seconds: u64,
    pub agent: String,
    pub protection: String,
    pub risk: String,
    pub message: String,
    #[serde(default)]
    pub ssh: Option<serde_json::Value>,
    #[serde(default)]
    pub waf: Option<serde_json::Value>,
}

pub fn boot_seconds() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } == 0 {
            return value.tv_sec.max(0) as u64;
        }
    }
    0
}
pub fn state() -> State {
    let state = State {
        schema: 1,
        version: env!("CARGO_PKG_VERSION").into(),
        pid: std::process::id(),
        boot_seconds: boot_seconds(),
        agent: "running".into(),
        protection: "not_configured".into(),
        risk: "not_assessed".into(),
        message: "No protection is configured. WAF and exposure checks are not connected yet."
            .into(),
        ssh: None,
        waf: None,
    };
    #[cfg(target_os = "linux")]
    let state = {
        let mut state = state;
        apply_ssh(&mut state, crate::ssh::observation());
        apply_waf(&mut state, crate::waf::observation());
        state
    };
    state
}
#[cfg(any(target_os = "linux", test))]
fn apply_waf(state: &mut State, observation: serde_json::Value) {
    let ssh_verified = state.ssh.as_ref().and_then(|s| s["state"].as_str()) == Some("verified");
    let waf_phase = observation["state"].as_str().unwrap_or("unknown");
    if waf_phase == "verified" || ssh_verified {
        state.protection = "partially_protected".into();
        state.message="Some protection components are verified. Review SSH/WAF component states separately; exposure risk is not assessed.".into();
    } else if !["off", "not_configured"].contains(&waf_phase) {
        state.protection = "unknown".into();
        state.message =
            "Web inspection is not verified. External checks or service repair are required."
                .into();
    } else if waf_phase == "off" && state.protection == "not_configured" {
        state.protection = "off".into();
    }
    state.waf = Some(observation);
}
#[cfg(any(target_os = "linux", test))]
fn apply_ssh(state: &mut State, observation: serde_json::Value) {
    match observation["state"].as_str() {
        Some("verified") => {
            state.protection = "partially_protected".into();
            state.message = "SSH engine and SSH-only firewall recently verified. WAF/exposure checks are not connected; overall risk is not assessed.".into();
        }
        Some("unknown") => {
            state.protection = "unknown".into();
            state.message = "SSH protection cannot currently be verified. Existing bans may expire; do not assume protection is active.".into();
        }
        Some("off") => {
            state.protection = "off".into();
            state.message =
                "SSH protection is explicitly off. WAF/exposure checks are not connected.".into();
        }
        _ => {}
    }
    state.ssh = Some(observation);
}
pub fn run(directory: &Path, once: bool) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("The agent runs on Linux. Offline verification works on this platform.".into());
    }
    let metadata = fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
    if !metadata.is_dir() {
        return Err("runtime must be a real existing directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err("runtime directory ownership/permissions invalid".into());
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
    }
    loop {
        let temporary = directory.join(format!("state-{}.tmp", std::process::id()));
        let result: Result<(), String> = (|| {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
            }
            let mut file = options.open(&temporary).map_err(|e| e.to_string())?;
            file.write_all(&serde_json::to_vec(&state()).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            fs::rename(&temporary, directory.join("state.json")).map_err(|e| e.to_string())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        if once {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(crate::policy::SERVICE_PERIOD));
    }
}
pub fn read(directory: &Path) -> Result<State, String> {
    let path = directory.join("state.json");
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| "No agent observation is available; protection state is unknown.")?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err("invalid state file".into());
    }
    let mut state: State = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let now = boot_seconds();
    if now < state.boot_seconds || now - state.boot_seconds > crate::policy::SERVICE_TTL {
        state.agent = "unknown".into();
        state.protection = "unknown".into();
        state.message = "Agent observation expired. This does not prove external protection services are stopped.".into();
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    #[test]
    fn foundation_never_reports_protection_or_risk_checks_passed() {
        let state = super::state();
        assert_eq!(state.protection, "not_configured");
        assert_eq!(state.risk, "not_assessed");
    }
    #[test]
    fn ssh_only_can_never_claim_complete_protection_or_risk_assessment() {
        let mut state = super::state();
        super::apply_ssh(&mut state, serde_json::json!({"state":"verified"}));
        assert_eq!(state.protection, "partially_protected");
        assert_eq!(state.risk, "not_assessed");
        super::apply_ssh(&mut state, serde_json::json!({"state":"unknown"}));
        assert_eq!(state.protection, "unknown");
        super::apply_ssh(&mut state, serde_json::json!({"state":"off"}));
        assert_eq!(state.protection, "off");
    }
    #[test]
    fn component_failure_does_not_hide_other_verified_protection_or_clear_risk() {
        let mut state = super::state();
        super::apply_ssh(&mut state, serde_json::json!({"state":"verified"}));
        super::apply_waf(&mut state, serde_json::json!({"state":"degraded"}));
        assert_eq!(state.protection, "partially_protected");
        assert_eq!(state.waf.unwrap()["state"], "degraded");
        assert_eq!(state.risk, "not_assessed");
    }
}
