//! Authenticated loopback UI; privileged operations cross a separate local broker.
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
pub const PORT: u16 = 9417;
pub const MAX_FRAME: usize = 524288;
pub fn secret() -> Result<String, String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| "Secure randomness unavailable")?;
    Ok(hex::encode(bytes))
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .unwrap_or(0)
}
pub fn authorized(actual: &str, expected: &str) -> bool {
    actual.len() == 64
        && expected.len() == 64
        && bool::from(actual.as_bytes().ct_eq(expected.as_bytes()))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    PrepareDependencies {},
    ExposureEnable {},
    ExposureCheck {},
    ExposureDisable {},
    SshEnable {
        #[serde(default)]
        management_ips: Vec<IpAddr>,
        #[serde(default)]
        ports: Vec<u16>,
        #[serde(default)]
        direct: bool,
    },
    SshDisable {
        confirmed: bool,
    },
    WafEnable {
        probe_peer: Option<IpAddr>,
        #[serde(default)]
        sites: Vec<String>,
        #[serde(default)]
        direct: bool,
    },
    WafDisable {
        confirmed: bool,
    },
    AgentRestart {},
}
impl Action {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PrepareDependencies { .. } => "prepare_dependencies",
            Self::ExposureEnable { .. } => "exposure_enable",
            Self::ExposureCheck { .. } => "exposure_check",
            Self::ExposureDisable { .. } => "exposure_disable",
            Self::SshEnable { .. } => "ssh_enable",
            Self::SshDisable { .. } => "ssh_disable",
            Self::WafEnable { .. } => "waf_enable",
            Self::WafDisable { .. } => "waf_disable",
            Self::AgentRestart { .. } => "agent_restart",
        }
    }
    pub fn args(&self) -> Result<Vec<String>, String> {
        let strings = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        Ok(match self {
            Self::PrepareDependencies { .. } => strings(&["dashboard", "prepare-dependencies"]),
            Self::ExposureEnable { .. } => strings(&["exposure", "enable"]),
            Self::ExposureCheck { .. } => strings(&["exposure", "check"]),
            Self::ExposureDisable { .. } => strings(&["exposure", "disable"]),
            Self::SshEnable {
                management_ips,
                ports,
                direct,
            } => {
                if management_ips.len() > 16 || ports.len() > 16 || ports.contains(&0) {
                    return Err("Invalid SSH management addresses or ports".into());
                }
                if (!management_ips.is_empty() || !ports.is_empty()) && !*direct {
                    return Err("Confirm direct SSH access before first setup".into());
                }
                let mut a = strings(&["ssh", "enable"]);
                if *direct {
                    a.push("--direct".into());
                }
                for ip in management_ips {
                    if ip.is_unspecified() || ip.is_multicast() {
                        return Err("Invalid management IP".into());
                    }
                    a.extend(["--management-ip".into(), ip.to_string()]);
                }
                for port in ports {
                    a.extend(["--port".into(), port.to_string()]);
                }
                a
            }
            Self::SshDisable { confirmed } | Self::WafDisable { confirmed } => {
                if !confirmed {
                    return Err("Confirm protection-off before continuing".into());
                }
                strings(&[
                    if matches!(self, Self::SshDisable { .. }) {
                        "ssh"
                    } else {
                        "waf"
                    },
                    "disable",
                ])
            }
            Self::WafEnable {
                probe_peer,
                sites,
                direct,
            } => {
                if sites.len() > 16
                    || sites.iter().any(|s| {
                        !s.starts_with("https://")
                            || s.contains('@')
                            || s.len() > 1024
                            || s.chars().any(|c| c.is_control() || c.is_whitespace())
                    })
                {
                    return Err("Use HTTPS site origins, one per line".into());
                }
                if (probe_peer.is_some() || !sites.is_empty()) && !*direct {
                    return Err("Confirm direct web access before first setup".into());
                }
                if probe_peer
                    .is_some_and(|ip| ip.is_loopback() || ip.is_unspecified() || ip.is_multicast())
                {
                    return Err("Use an external verifier address".into());
                }
                let mut a = strings(&["waf", "enable"]);
                if *direct {
                    a.push("--direct".into());
                }
                if let Some(ip) = probe_peer {
                    a.extend(["--probe-peer".into(), ip.to_string()]);
                }
                for site in sites {
                    a.extend(["--site".into(), site.clone()]);
                }
                a
            }
            Self::AgentRestart { .. } => vec![],
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub action: String,
    pub status: String,
    pub started: u64,
    pub finished: Option<u64>,
    pub output: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Snapshot {},
    Start { action: Action },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rpc {
    pub token: String,
    pub request: Operation,
}

#[derive(Clone)]
struct Web {
    token: String,
    preview: bool,
}
fn headers_allowed(headers: &HeaderMap, mutation: bool) -> bool {
    let expected = format!("127.0.0.1:{PORT}");
    let localhost = format!("localhost:{PORT}");
    if !headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|h| h == expected || h == localhost)
    {
        return false;
    }
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if origin
        .is_some_and(|o| o != format!("http://{expected}") && o != format!("http://{localhost}"))
    {
        return false;
    }
    if headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("cross-site") {
        return false;
    }
    !mutation || origin.is_some()
}
async fn security(State(web): State<Arc<Web>>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let api = path.starts_with("/api/");
    let mutation =
        request.method() != axum::http::Method::GET && request.method() != axum::http::Method::HEAD;
    let auth = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let mut response = if !headers_allowed(request.headers(), mutation) {
        (StatusCode::FORBIDDEN,Json(serde_json::json!({"error":"다른 출처의 요청은 허용하지 않습니다. 관리 화면에서 다시 시도해 주세요."}))).into_response()
    } else if api && !auth.is_some_and(|s| authorized(s, &web.token)) {
        (StatusCode::UNAUTHORIZED,Json(serde_json::json!({"error":"접속 키가 필요합니다. 서버에서 dashboard login으로 새 접속 주소를 확인해 주세요."}))).into_response()
    } else {
        next.run(request).await
    };
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert(header::CONTENT_SECURITY_POLICY,"default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'".parse().unwrap());
    h.insert("x-content-type-options", "nosniff".parse().unwrap());
    h.insert("x-frame-options", "DENY".parse().unwrap());
    h.insert("referrer-policy", "no-referrer".parse().unwrap());
    response
}
fn asset(content_type: &'static str, data: &'static [u8]) -> Response {
    ([(header::CONTENT_TYPE, content_type)], Body::from(data)).into_response()
}
async fn snapshot(State(web): State<Arc<Web>>) -> Response {
    let result = if web.preview {
        Ok(preview_snapshot())
    } else {
        rpc(&web.token, Operation::Snapshot {}).await
    };
    match result{Ok(value)=>Json(value).into_response(),Err(_)=>(StatusCode::SERVICE_UNAVAILABLE,Json(serde_json::json!({"error":"서버 상태를 불러오지 못했습니다. 연결과 관리 서비스를 확인해 주세요."}))).into_response()}
}
async fn action(State(web): State<Arc<Web>>, Json(value): Json<Action>) -> Response {
    if web.preview {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"미리보기에서는 서버 설정을 변경하지 않습니다."})),
        )
            .into_response();
    }
    if let Err(error) = value.args() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":error})),
        )
            .into_response();
    }
    match rpc(&web.token,Operation::Start{action:value}).await{Ok(v)=>{let code=if v.get("error").is_some(){StatusCode::CONFLICT}else{StatusCode::ACCEPTED};(code,Json(v)).into_response()},Err(_)=>(StatusCode::SERVICE_UNAVAILABLE,Json(serde_json::json!({"error":"작업을 시작하지 못했습니다. 관리 서비스 연결을 확인해 주세요."}))).into_response()}
}
async fn rpc(token: &str, request: Operation) -> Result<serde_json::Value, String> {
    #[cfg(target_os = "linux")]
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let call = async {
            let mut socket =
                tokio::net::UnixStream::connect("/run/quiet-guard-control/control.sock")
                    .await
                    .map_err(|_| "Control socket unavailable")?;
            let raw = serde_json::to_vec(&Rpc {
                token: token.into(),
                request,
            })
            .map_err(|_| "Invalid control request")?;
            socket
                .write_u32(raw.len() as u32)
                .await
                .map_err(|_| "Control write failed")?;
            socket
                .write_all(&raw)
                .await
                .map_err(|_| "Control write failed")?;
            let length = socket.read_u32().await.map_err(|_| "Control read failed")? as usize;
            if length > MAX_FRAME {
                return Err("Oversized control reply");
            }
            let mut raw = vec![0; length];
            socket
                .read_exact(&mut raw)
                .await
                .map_err(|_| "Control read failed")?;
            serde_json::from_slice(&raw).map_err(|_| "Invalid control reply")
        };
        tokio::time::timeout(std::time::Duration::from_secs(4), call)
            .await
            .map_err(|_| "Control request timed out".to_string())?
            .map_err(String::from)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (token, request);
        Err("Linux control unavailable".into())
    }
}
pub fn serve(preview: bool) -> Result<(), String> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, PORT))
        .map_err(|_| "Management port is already in use")?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let token = if preview { secret()? } else { credential()? };
    if preview {
        let path = std::env::temp_dir().join(format!(
            "quiet-guard-preview-access-{}.txt",
            std::process::id()
        ));
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| e.to_string())?;
            f.write_all(token.as_bytes()).map_err(|e| e.to_string())?;
        }
        #[cfg(not(unix))]
        std::fs::write(&path, &token).map_err(|e| e.to_string())?;
        println!(
            "Preview: http://127.0.0.1:{PORT}/ (access key saved in {})",
            path.display()
        );
    }
    let web = Arc::new(Web { token, preview });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    asset(
                        "text/html; charset=utf-8",
                        include_bytes!("../dashboard/index.html"),
                    )
                }),
            )
            .route(
                "/app.js",
                get(|| async {
                    asset(
                        "text/javascript; charset=utf-8",
                        include_bytes!("../dashboard/app.js"),
                    )
                }),
            )
            .route(
                "/app.css",
                get(|| async {
                    asset(
                        "text/css; charset=utf-8",
                        include_bytes!("../dashboard/app.css"),
                    )
                }),
            )
            .route(
                "/fonts/suit.woff2",
                get(|| async {
                    asset(
                        "font/woff2",
                        include_bytes!("../dashboard/fonts/suit.woff2"),
                    )
                }),
            )
            .route("/api/state", get(snapshot))
            .route("/api/actions", post(action))
            .fallback(|| async { StatusCode::NOT_FOUND })
            .layer(DefaultBodyLimit::max(32768))
            .layer(middleware::from_fn_with_state(web.clone(), security))
            .with_state(web);
        let listener = tokio::net::TcpListener::from_std(listener).map_err(|e| e.to_string())?;
        axum::serve(listener, app).await.map_err(|e| e.to_string())
    })
}
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{broker, control, credential, prepare_dependencies};
#[cfg(not(target_os = "linux"))]
fn credential() -> Result<String, String> {
    Err(
        "The management service runs on Linux. Use dashboard preview to inspect the interface."
            .into(),
    )
}
#[cfg(not(target_os = "linux"))]
pub fn control(_: &[String]) -> Result<(), String> {
    Err("Dashboard setup requires Linux".into())
}
#[cfg(not(target_os = "linux"))]
pub fn broker() -> Result<(), String> {
    Err("Privileged control requires Linux".into())
}
#[cfg(not(target_os = "linux"))]
pub fn prepare_dependencies() -> Result<(), String> {
    Err("Package preparation requires Linux".into())
}

fn preview_snapshot() -> serde_json::Value {
    serde_json::json!({"preview":true,"version":"0.1.0 개발판","server":{"hostname":"quiet-demo","platform":"Ubuntu 24.04 LTS"},"updated":now(),
        "agent":{"agent":"running","protection":"partially_protected","risk":"attention"},
        "ssh":{"state":"verified","blocked_ips":2},"waf":{"state":"awaiting_external_check","allowed":1240,"blocked":7,"failures":0,"incomplete":0},
        "exposure":{"state":"local_only","risk":"attention","review_count":2,"listener_count":5,"external_probe_current":false},
        "configured":{"ssh":true,"waf":true,"exposure":true},"prerequisites":{"crowdsec":true,"nginx":true,"lua":true,"nftables":true},
        "findings":[{"severity":"review","address":"0.0.0.0","port":3000,"transport":"tcp","category":"application_process","evidence":"non_loopback_bind_only","hint":"Application/admin candidate"},{"severity":"review","address":"0.0.0.0","port":5432,"transport":"tcp","category":"database_process","evidence":"non_loopback_bind_only","hint":"Database candidate"}],
        "listeners":[{"transport":"tcp","address":"0.0.0.0","port":3000,"owners":[{"pid":1248,"executable":"node"}]},{"transport":"tcp","address":"0.0.0.0","port":5432,"owners":[{"pid":1104,"executable":"postgres"}]},{"transport":"tcp","address":"127.0.0.1","port":6379,"owners":[{"pid":1108,"executable":"redis-server"}]},{"transport":"tcp","address":"0.0.0.0","port":443,"owners":[{"pid":970,"executable":"nginx"}]},{"transport":"tcp","address":"0.0.0.0","port":22,"owners":[{"pid":920,"executable":"sshd"}]}],
        "exposure_truncated":false,"jobs":[{"id":"preview1","action":"exposure_check","status":"succeeded","started":now().saturating_sub(80),"finished":now().saturating_sub(78),"output":"예시 데이터입니다."},{"id":"preview2","action":"ssh_enable","status":"succeeded","started":now().saturating_sub(300),"finished":now().saturating_sub(290),"output":"예시 데이터입니다."}]})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unconfirmed_changes_and_argument_injection() {
        assert!(Action::SshDisable { confirmed: false }.args().is_err());
        assert!(Action::WafEnable {
            probe_peer: None,
            sites: vec!["--config=/tmp/evil".into()],
            direct: true
        }
        .args()
        .is_err());
        assert!(Action::SshEnable {
            management_ips: vec!["1.2.3.4".parse().unwrap()],
            ports: vec![22],
            direct: false
        }
        .args()
        .is_err());
        assert!(
            serde_json::from_str::<Action>(r#"{"action":"agent_restart","command":"rm"}"#).is_err()
        );
    }
    #[test]
    fn origin_host_and_bearer_are_required() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "127.0.0.1:9417".parse().unwrap());
        assert!(headers_allowed(&h, false));
        assert!(!headers_allowed(&h, true));
        h.insert(header::ORIGIN, "http://evil.example".parse().unwrap());
        assert!(!headers_allowed(&h, true));
        h.insert(header::ORIGIN, "http://127.0.0.1:9417".parse().unwrap());
        assert!(headers_allowed(&h, true));
        h.insert(header::HOST, "evil.example:9417".parse().unwrap());
        assert!(!headers_allowed(&h, false));
        assert!(!authorized("", &"a".repeat(64)));
        assert!(!authorized(&"b".repeat(64), &"a".repeat(64)));
        assert!(authorized(&"a".repeat(64), &"a".repeat(64)));
    }
}
