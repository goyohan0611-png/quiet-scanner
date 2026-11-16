use quiet_guard::{
    bundle::{self, Kind},
    policy::IngressPolicy,
    runtime, ssh, waf,
};
use std::{env, fs, io::Write, path::Path};

const USAGE: &str = "Quiet Guard 0.1 development\nCommands:\n  agent [runtime-directory] [--once]\n  status [runtime-directory]\n  ssh enable --direct --management-ip IP [--port 22]\n  ssh enable|status|disable|remove\n  ssh allow|remove-allow|unblock IP\n  ssh-policy <policy.json>\n  policy <policy.json>\n  bundle manifest <directory> <release|rules> <sequence> <version>\n  bundle verify <directory> <trusted-public.pem>\n  rules stage <directory> <trusted-public.pem> <store>\nSSH is opt-in on Ubuntu 24.04. WAF/exposure checks and the dashboard are not connected yet.";
fn run(args: &[String]) -> Result<(), String> {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["--help"] | ["help"] => println!("{USAGE}"),
        ["--version"] => println!("quiet-guard {}", env!("CARGO_PKG_VERSION")),
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
