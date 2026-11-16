use quiet_guard::{
    bundle::{self, Kind},
    dashboard, exposure,
    policy::IngressPolicy,
    runtime, ssh, waf,
};
use std::{env, fs, io::Write, path::Path};

const USAGE: &str = "Quiet Guard 0.1 development\nCommands:\n  agent [runtime-directory] [--once]\n  status [runtime-directory]\n  ssh enable --direct --management-ip IP [--port 22]\n  ssh enable|status|disable|remove\n  ssh allow|remove-allow|unblock IP\n  ssh-policy <policy.json>\n  waf enable --direct --probe-peer IP --site https://example.com\n  waf enable|status|disable|remove\n  exposure enable|check|status|disable|remove\n  exposure prepare --target IP [--ports LIST]\n  exposure probe REQUEST.json\n  exposure import RESULT.json\n  dashboard enable|disable|remove|login|rotate-token|status\n  dashboard preview\n  policy <policy.json>\n  bundle manifest <directory> <release|rules> <sequence> <version>\n  bundle verify <directory> <trusted-public.pem>\n  rules stage <directory> <trusted-public.pem> <store>\nSSH and Nginx WAF are opt-in on Ubuntu 24.04. External WAF proofs are required. Read-only exposure checks are opt-in. The authenticated dashboard binds only to server loopback.";
fn run(args: &[String]) -> Result<(), String> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["--help"] | ["help"] => println!("{USAGE}"),
        ["--version"] => println!("quiet-guard {}", env!("CARGO_PKG_VERSION")),
        ["dashboard", "preview"] => dashboard::serve(true)?,
        ["dashboard", "serve"] => dashboard::serve(false)?,
        ["dashboard", "broker"] => dashboard::broker()?,
        ["dashboard", "prepare-dependencies"] => dashboard::prepare_dependencies()?,
        ["dashboard", rest @ ..] => {
            dashboard::control(&rest.iter().map(|s| s.to_string()).collect::<Vec<_>>())?
        }
        ["exposure", "probe", path] => {
            if !fs::symlink_metadata(path)
                .map_err(|e| e.to_string())?
                .is_file()
            {
                return Err("Probe request must be a regular JSON file".into());
            }
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let file = options.open(path).map_err(|e| e.to_string())?;
            if !file.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err("Probe request must be a regular JSON file".into());
            }
            let mut raw = String::new();
            std::io::Read::read_to_string(&mut std::io::Read::take(file, 262145), &mut raw)
                .map_err(|e| e.to_string())?;
            if raw.len() > 262144 {
                return Err("Probe request exceeds size limit".into());
            }
            let request: exposure::Request =
                serde_json::from_str(&raw).map_err(|_| "Invalid exposure probe request")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&exposure::probe(
                    &request,
                    std::time::Duration::from_millis(500)
                )?)
                .map_err(|e| e.to_string())?
            );
        }
        ["exposure", rest @ ..] => {
            exposure::control(&rest.iter().map(|s| s.to_string()).collect::<Vec<_>>())?
        }
        ["waf", rest @ ..] => {
            waf::control(&rest.iter().map(|s| s.to_string()).collect::<Vec<_>>())?
        }
        ["waf-monitor"] => waf::monitor()?,
        ["waf-policy", input] => {
            let config: waf::Config =
                serde_json::from_slice(&fs::read(input).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            config.validate()?;
            println!("{{\"valid\":true,\"applied\":false}}");
        }
        ["ssh", rest @ ..] => {
            ssh::control(&rest.iter().map(|s| s.to_string()).collect::<Vec<_>>())?
        }
        ["ssh-policy", input] => {
            let config: ssh::Config =
                serde_json::from_slice(&fs::read(input).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            config.validate()?;
            println!(
                "{}",
                serde_json::json!({"revision":config.revision(),"applied":false})
            );
        }
        ["ssh-enforcer"] => ssh::enforce(false)?,
        ["ssh-enforcer-cleanup"] => ssh::enforce(true)?,
        ["agent"] => runtime::run(Path::new("/run/quiet-guard"), false)?,
        ["agent", directory] => runtime::run(Path::new(directory), false)?,
        ["agent", directory, "--once"] => runtime::run(Path::new(directory), true)?,
        ["status"] => println!(
            "{}",
            serde_json::to_string_pretty(&runtime::read(Path::new("/run/quiet-guard"))?)
                .map_err(|e| e.to_string())?
        ),
        ["status", directory] => println!(
            "{}",
            serde_json::to_string_pretty(&runtime::read(Path::new(directory))?)
                .map_err(|e| e.to_string())?
        ),
        ["policy", input] => {
            let policy: IngressPolicy =
                serde_json::from_slice(&fs::read(input).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::json!({"web_ip_ban_allowed":policy.web_ip_ban_allowed(),"ssh_ip_ban_allowed":policy.ssh_ip_ban_allowed(),"applied":false})
            );
        }
        ["bundle", "manifest", directory, kind, sequence, version] => {
            let kind = match *kind {
                "release" => Kind::Release,
                "rules" => Kind::Rules,
                _ => return Err("unknown bundle kind".into()),
            };
            let manifest = bundle::build(
                Path::new(directory),
                kind,
                sequence.parse().map_err(|_| "invalid sequence")?,
                (*version).into(),
            )?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(Path::new(directory).join("manifest.json"))
                .map_err(|e| e.to_string())?;
            file.write_all(&serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            println!("Manifest created. It is NOT trusted until signed and verified.");
        }
        ["bundle", "verify", directory, key] => println!(
            "{}",
            serde_json::to_string_pretty(&bundle::verify(Path::new(directory), Path::new(key))?)
                .map_err(|e| e.to_string())?
        ),
        ["rules", "stage", directory, key, store] => {
            let path = bundle::stage_rules(Path::new(directory), Path::new(key), Path::new(store))?;
            println!("Staged only; not activated: {}", path.display());
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}
fn main() {
    if let Err(error) = run(&env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
