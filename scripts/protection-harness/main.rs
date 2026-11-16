// Compiles and exercises the actual production protection module without GTK.
#[path = "../../src-tauri/src/protection.rs"]
mod protection;
#[cfg(target_os = "linux")]
mod privilege {
    pub fn protection(_: crate::protection::Command) -> Result<serde_json::Value, String> {
        Err("GUI privilege transport is intentionally unavailable in the test harness".into())
    }
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|a| a == "--protection-finalize") {
        if let Err(e) = protection::linux::execute(protection::Command::FinishInstall {}) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    }
    if args.first().is_some_and(|a| a == "info") {
        println!("{}", protection::info());
        return;
    }
    // Keep the public GUI request entry point type-checked as well.
    if args.first().is_some_and(|a| a == "rpc-check") {
        assert!(
            protection::request("protection_allow", serde_json::json!({"ip":"--all"})).is_err()
        );
        return;
    }
    let command: protection::Command =
        serde_json::from_str(args.first().expect("JSON operation required"))
            .expect("valid operation");
    #[cfg(target_os = "linux")]
    match protection::linux::execute(command) {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
    }
}
