#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod book;
mod capture;
mod engine;
mod native;
mod packet;
#[cfg(unix)]
mod privilege;
mod probe;
mod protection;

use engine::Engine;
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tauri::{Emitter, Manager};

#[tauri::command]
async fn request(
    action: String,
    payload: Option<Value>,
    engine: tauri::State<'_, Arc<Engine>>,
) -> Result<Value, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.request(&action, payload.unwrap_or_else(|| json!({})))
    })
    .await
    .map_err(|e| format!("작업 실행 오류: {e}"))?
}
#[tauri::command]
fn copy_text(text: String) -> Result<(), String> {
    // A complete list of up to 4,096 IPv4 candidates fits within this bound.
    if text.len() > 128 * 1024 {
        return Err("복사할 내용이 너무 깁니다.".into());
    }
    #[cfg(windows)]
    {
        clipboard_win::set_clipboard_string(&text).map_err(|e| format!("클립보드 복사 실패: {e}"))
    }
    #[cfg(unix)]
    {
        static CLIPBOARD: std::sync::OnceLock<std::sync::Mutex<Option<arboard::Clipboard>>> =
            std::sync::OnceLock::new();
        let mut clipboard = CLIPBOARD
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .map_err(|_| "클립보드 잠금 오류")?;
        if clipboard.is_none() {
            *clipboard = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
        }
        clipboard
            .as_mut()
            .unwrap()
            .set_text(text)
            .map_err(|e| format!("클립보드 복사 실패: {e}"))
    }
}
#[cfg(windows)]
fn data_directory() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Quiet Scanner")
}
#[cfg(target_os = "macos")]
fn data_directory() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Library/Application Support/Quiet Scanner")
}
#[cfg(target_os = "linux")]
fn data_directory() -> PathBuf {
    if let Some(path) = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        path.join("quiet-scanner")
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(".local/share/quiet-scanner")
    }
}
fn smoke(args: &[String]) -> Result<Value, String> {
    let started = std::time::Instant::now();
    let cards = native::interfaces()?;
    let e = Engine::new(if args.first().is_some_and(|a| a == "neighbor") {
        data_directory()
    } else {
        std::env::temp_dir().join(format!("quiet-smoke-{}", std::process::id()))
    });
    match args.first().map(String::as_str).unwrap_or("interfaces") {
        #[cfg(unix)]
        "transport" => privilege::transport_test(),
        "interfaces" => Ok(
            json!({"interfaces":cards,"elapsedMs":started.elapsed().as_millis(),"diagnostics":e.diagnostics()}),
        ),
        "neighbor" => {
            let card = cards
                .iter()
                .find(|c| !c.mac.is_empty() && c.ips.iter().any(|ip| !ip.starts_with("169.254.")))
                .ok_or("사용 가능한 인터페이스가 없습니다.")?;
            e.self_test_neighbor(card)
        }
        "scan" | "dhcp" => {
            let action = &args[0];
            let card = if let Some(id) = args.get(2) {
                cards.iter().find(|c| c.id.eq_ignore_ascii_case(id))
            } else {
                cards
                    .iter()
                    .find(|c| c.ips.iter().any(|ip| !ip.starts_with("169.254.")))
            }
            .ok_or("사용 가능한 인터페이스가 없습니다.")?;
            let target = args.get(1).map(String::as_str).unwrap_or("");
            let result = e.request(
                if action == "scan" {
                    "scan"
                } else {
                    "dhcp_servers"
                },
                json!({"iface":card,"target":target}),
            )?;
            Ok(
                json!({"result":result,"elapsedMs":started.elapsed().as_millis(),"diagnostics":e.diagnostics()}),
            )
        }
        _ => Err("지원하지 않는 진단입니다.".into()),
    }
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|a| a == "--protection-finalize") {
        match protection::linux::execute(protection::Command::FinishInstall {}) {
            Ok(_) => {}
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.first().is_some_and(|a| a == "--protection") {
        let command = match args.get(1).map(String::as_str) {
            Some("status") => protection::Command::Status {},
            Some("prepare") => protection::Command::Prepare {},
            Some("on") => protection::Command::AutoEnable {},
            Some("off") => protection::Command::Disable {},
            Some("allow") if args.len() == 3 => protection::Command::Allow {
                ip: args[2].clone(),
            },
            Some("remove-allow") if args.len() == 3 => protection::Command::RemoveAllow {
                ip: args[2].clone(),
            },
            _ => {
                eprintln!("--protection status|prepare|on|off|allow IP|remove-allow IP");
                std::process::exit(2);
            }
        };
        #[cfg(target_os = "linux")]
        let result = protection::linux::execute(command);
        #[cfg(not(target_os = "linux"))]
        let result: Result<Value, String> = {
            let _ = command;
            Err("보호 모드는 Ubuntu/Linux에서 지원합니다.".into())
        };
        match result {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    #[cfg(unix)]
    if args.first().is_some_and(|a| a == "--privileged-worker") {
        if let Err(error) = privilege::worker(&args[1..]) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if args.first().is_some_and(|a| a == "--smoke") {
        let result = smoke(&args[1..]);
        if args.get(1).is_some_and(|a| a == "neighbor") {
            let output = match &result {
                Ok(value) => value.clone(),
                Err(error) => json!({"error":error}),
            };
            let _ = book::atomic_write(
                &data_directory().join("native-check.json"),
                &serde_json::to_vec_pretty(&output).unwrap(),
            );
        }
        match result {
            Ok(result) => println!("{}", serde_json::to_string_pretty(&result).unwrap()),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    let closing = Arc::new(AtomicBool::new(false));
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .setup(|app| {
            let directory = data_directory();
            let migration = engine::migrate_legacy(&directory);
            let engine = Arc::new(Engine::new(directory));
            if let Err(e) = migration {
                engine.migration_error(e);
            }
            let handle = app.handle().clone();
            engine.set_emitter(Arc::new(move |state| {
                let _ = handle.emit("network:state", state);
            }));
            engine.recover();
            app.manage(engine);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![request, copy_text])
        .on_window_event(move |window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                if closing.swap(true, Ordering::AcqRel) {
                    return;
                }
                let _ = window.hide();
                let app = window.app_handle().clone();
                let engine = app.state::<Arc<Engine>>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    let _ = tauri::async_runtime::spawn_blocking(move || engine.shutdown()).await;
                    #[cfg(unix)]
                    privilege::shutdown();
                    app.exit(0);
                });
            }
        })
        .run(tauri::generate_context!())
        .expect("Quiet Scanner 실행 실패");
}
