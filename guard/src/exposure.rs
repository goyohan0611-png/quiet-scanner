//! Read-only host socket inventory and explicitly scoped, operator-supplied
//! connectivity evidence. A failed TCP connect never proves a server safe.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    time::Duration,
};

pub const REPORT_TTL: u64 = 90;
pub const PROBE_TTL: u64 = 180;
pub const MAX_PORTS: usize = 128;
pub const COMMON_PORTS: &[u16] = &[
    22, 80, 443, 2375, 2376, 3000, 3306, 5432, 5672, 5900, 6379, 8000, 8080, 9000, 9200, 11211,
    27017,
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub pid: u32,
    pub executable: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub transport: String,
    pub address: IpAddr,
    pub port: u16,
    pub inode: u64,
    pub owners: Vec<Owner>,
}
impl Listener {
    pub fn binding(&self) -> &'static str {
        if self.address.is_loopback() {
            "loopback"
        } else if self.address.is_unspecified() {
            "all_interfaces"
        } else {
            "specific_interface"
        }
    }
    pub fn role(&self) -> &'static str {
        for owner in &self.owners {
            match owner.executable.as_str() {
                "postgres" | "mysqld" | "mariadbd" | "mongod" => return "database_process",
                "redis-server" | "memcached" => return "cache_process",
                "sshd" | "sshd-session" | "xrdp" | "Xtigervnc" => return "remote_admin_process",
                "dockerd" | "containerd" => return "container_control_process",
                "node" | "nodejs" | "uvicorn" | "gunicorn" | "java" | "dotnet" => {
                    return "application_process"
                }
                "nginx" | "apache2" | "httpd" => return "web_frontend_process",
                _ => {}
            }
        }
        "unidentified_process"
    }
    pub fn needs_review(&self) -> bool {
        !self.address.is_loopback() && self.role() != "web_frontend_process"
    }
}
pub fn port_hint(port: u16) -> &'static str {
    match port {
        22 => "SSH candidate",
        80 | 443 => "Web candidate",
        2375 | 2376 => "Container API candidate",
        3000 | 5000 | 8000 | 8080 | 9000 => "Application/admin candidate",
        3306 | 5432 | 27017 => "Database candidate",
        6379 | 11211 => "Cache candidate",
        5672 | 15672 => "Message broker/admin candidate",
        5900 | 3389 => "Remote desktop candidate",
        9200 => "Search database candidate",
        _ => "Unidentified service",
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub addresses: Vec<IpAddr>,
    pub listeners: Vec<Listener>,
    pub coverage: Vec<String>,
    pub namespace: String,
}
impl Inventory {
    pub fn revision(&self) -> String {
        // Process attribution can be incomplete or change without socket changes.
        // Bind evidence, socket identity and address changes fence probe tickets.
        let sockets: Vec<_> = self
            .listeners
            .iter()
            .map(|l| (&l.transport, l.address, l.port, l.inode))
            .collect();
        hex::encode(Sha256::digest(
            serde_json::to_vec(&(&self.addresses, sockets, &self.coverage, &self.namespace))
                .expect("inventory serialization"),
        ))
    }
}
pub fn proc_sockets(raw: &str, transport: &str, v6: bool) -> Result<Vec<Listener>, String> {
    if raw.len() > 4 * 1024 * 1024 || !["tcp", "udp"].contains(&transport) {
        return Err("Unsupported or oversized socket table".into());
    }
    let mut result = Vec::new();
    for line in raw.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields.len() < 10 {
            return Err("Incomplete kernel socket row".into());
        }
        let selected = if transport == "tcp" {
            fields[3] == "0A"
        } else {
            fields[3] == "07"
        };
        if !selected {
            continue;
        }
        let (address, port) = fields[1].split_once(':').ok_or("Invalid socket address")?;
        let port = u16::from_str_radix(port, 16).map_err(|_| "Invalid socket port")?;
        let inode = fields[9].parse().map_err(|_| "Invalid socket identity")?;
        let address = if v6 {
            if address.len() != 32 || !address.is_ascii() {
                return Err("Invalid IPv6 socket address".into());
            }
            let mut bytes = [0u8; 16];
            for index in 0..4 {
                bytes[index * 4..index * 4 + 4].copy_from_slice(
                    &u32::from_str_radix(&address[index * 8..index * 8 + 8], 16)
                        .map_err(|_| "Invalid IPv6 word")?
                        .to_ne_bytes(),
                );
            }
            IpAddr::V6(bytes.into())
        } else {
            if address.len() != 8 {
                return Err("Invalid IPv4 socket address".into());
            }
            IpAddr::V4(
                u32::from_str_radix(address, 16)
                    .map_err(|_| "Invalid IPv4 word")?
                    .to_ne_bytes()
                    .into(),
            )
        };
        if port != 0 {
            result.push(Listener {
                transport: transport.into(),
                address,
                port,
                inode,
                owners: vec![],
            });
        }
        if result.len() > 4096 {
            return Err("Too many bound sockets".into());
        }
    }
    result.sort();
    Ok(result)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    pub nonce: String,
    pub revision: String,
    pub generation: String,
    pub boot_id: String,
    pub issued_boot_seconds: u64,
    pub target: IpAddr,
    pub ports: Vec<u16>,
    pub server_addresses: Vec<IpAddr>,
}
impl Request {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1
            || self.nonce.len() != 64
            || self.revision.len() != 64
            || self.generation.len() != 32
            || [&self.nonce, &self.revision, &self.generation]
                .iter()
                .any(|s| !s.bytes().all(|c| c.is_ascii_hexdigit()))
            || self.boot_id.is_empty()
            || self.boot_id.len() > 64
            || self.server_addresses.is_empty()
            || self.server_addresses.len() > 512
            || self.target.is_unspecified()
            || self.target.is_loopback()
            || self.target.is_multicast()
            || self.ports.is_empty()
            || self.ports.len() > MAX_PORTS
            || self.ports.contains(&0)
            || self.ports.iter().copied().collect::<BTreeSet<_>>().len() != self.ports.len()
        {
            return Err("Invalid or overly broad exposure request".into());
        }
        Ok(())
    }
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("request serialization"),
        ))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub port: u16,
    pub outcome: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    pub schema: u32,
    pub request_sha256: String,
    pub nonce: String,
    pub target: IpAddr,
    pub source: IpAddr,
    pub attempts: Vec<Attempt>,
}
pub fn probe(request: &Request, timeout: Duration) -> Result<ProbeResult, String> {
    request.validate()?;
    if !(Duration::from_millis(100)..=Duration::from_secs(2)).contains(&timeout) {
        return Err("Probe timeout must be 100..2000 milliseconds".into());
    }
    // UDP connect selects a route; no datagram is transmitted. Probe traffic
    // below consists only of TCP handshakes, without application data or login.
    let route = UdpSocket::bind(if request.target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|_| "Cannot select probe source")?;
    route
        .connect(SocketAddr::new(request.target, 9))
        .map_err(|_| "No route to the selected target")?;
    let source = route
        .local_addr()
        .map_err(|_| "Probe source unavailable")?
        .ip();
    if source.is_unspecified() || source.is_loopback() || request.server_addresses.contains(&source)
    {
        return Err(
            "Run the probe outside the protected host; local connections are not external evidence"
                .into(),
        );
    }
    let mut attempts = Vec::new();
    for chunk in request.ports.chunks(8) {
        let part = std::thread::scope(|scope| {
            let workers: Vec<_> = chunk
                .iter()
                .map(|&port| {
                    scope.spawn(move || {
                        let outcome = match TcpStream::connect_timeout(
                            &SocketAddr::new(request.target, port),
                            timeout,
                        ) {
                            Ok(stream) => {
                                if stream.local_addr().ok().map(|a| a.ip()) != Some(source) {
                                    return Err("Probe source changed during the check".to_string());
                                }
                                "connected"
                            }
                            Err(e) => match e.kind() {
                                io::ErrorKind::ConnectionRefused => "refused",
                                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "timed_out",
                                _ => "unavailable",
                            },
                        };
                        Ok(Attempt {
                            port,
                            outcome: outcome.into(),
                        })
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|w| w.join().map_err(|_| "Probe worker failed".to_string())?)
                .collect::<Result<Vec<_>, String>>()
        })?;
        attempts.extend(part);
    }
    Ok(ProbeResult {
        schema: 1,
        request_sha256: request.digest(),
        nonce: request.nonce.clone(),
        target: request.target,
        source,
        attempts,
    })
}
pub fn validate_result(
    request: &Request,
    result: &ProbeResult,
    revision: &str,
    boot_id: &str,
    generation: &str,
    now: u64,
) -> Result<(), String> {
    request.validate()?;
    if request.revision != revision
        || request.boot_id != boot_id
        || request.generation != generation
        || request.issued_boot_seconds > now
        || now - request.issued_boot_seconds > PROBE_TTL
    {
        return Err(
            "Exposure request expired or host/socket generation changed; prepare a new request"
                .into(),
        );
    }
    if result.schema != 1
        || result.nonce != request.nonce
        || result.request_sha256 != request.digest()
        || result.target != request.target
        || result.source.is_loopback()
        || result.source.is_unspecified()
        || result.source.is_multicast()
        || request.server_addresses.contains(&result.source)
        || result.attempts.len() != request.ports.len()
    {
        return Err("Mismatched or local exposure result".into());
    }
    let mut seen = BTreeSet::new();
    for attempt in &result.attempts {
        if !request.ports.contains(&attempt.port)
            || !seen.insert(attempt.port)
            || !["connected", "refused", "timed_out", "unavailable"]
                .contains(&attempt.outcome.as_str())
        {
            return Err("Missing, duplicate or unrequested probe outcomes".into());
        }
    }
    Ok(())
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct External {
    pub request: Request,
    pub result: ProbeResult,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema: u32,
    pub generation: String,
    pub boot_id: String,
    pub boot_seconds: u64,
    pub revision: String,
    pub state: String,
    pub risk: String,
    pub inventory: Inventory,
    pub external: Option<External>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub transport: String,
    pub address: Option<IpAddr>,
    pub port: u16,
    pub category: String,
    pub evidence: String,
    pub hint: String,
    pub recommendation: String,
}
pub fn report(
    inventory: Inventory,
    generation: String,
    boot_id: String,
    now: u64,
    external: Option<External>,
) -> Report {
    let revision = inventory.revision();
    let external = external.filter(|e| {
        validate_result(&e.request, &e.result, &revision, &boot_id, &generation, now).is_ok()
    });
    let mut findings = Vec::new();
    for listener in &inventory.listeners {
        if listener.needs_review() {
            findings.push(Finding{transport:listener.transport.clone(),address:Some(listener.address),port:listener.port,
            category:listener.role().into(),evidence:"non_loopback_bind_only".into(),hint:port_hint(listener.port).into(),
            recommendation:"Review whether this binding is intended. Prefer loopback/private bindings and explicit access control for app, database and admin services; a local bind does not prove external reachability.".into()});
        }
    }
    if let Some(external) = &external {
        for attempt in &external.result.attempts {
            if attempt.outcome == "connected" {
                findings.push(Finding{transport:"tcp".into(),address:Some(external.result.target),port:attempt.port,
            category:"operator_reported_tcp_reachability".into(),evidence:"connected_from_one_operator_probe".into(),hint:port_hint(attempt.port).into(),
            recommendation:"Compare this reachable endpoint with intended public services. Connectivity alone does not identify the service, prove WAF coverage, or show who else can connect.".into()});
            }
        }
    }
    let state = if !inventory.coverage.is_empty() {
        "incomplete"
    } else if external.is_some() {
        "local_and_operator_probe"
    } else {
        "local_only"
    }
    .into();
    Report{schema:1,generation,boot_id,boot_seconds:now,revision,state,risk:if findings.is_empty(){"not_assessed"}else{"attention"}.into(),inventory,external,findings,
        limitations:vec!["Local listener inventory covers only the collector's network namespace; Docker/NAT forwarding, other namespaces and cloud firewall policy are not enumerated.".into(),
        "External results are operator-supplied point-in-time TCP evidence from one source, not authenticated server-side receipt evidence or proof of worldwide reachability.".into(),
        "Refusal, timeout, missing IPv6 checks or a successful web-port connection never prove safety. UDP/raw protocols, application authorization and service vulnerabilities are not tested.".into()]}
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{control, observation};
#[cfg(not(target_os = "linux"))]
pub fn control(_: &[String]) -> Result<(), String> {
    Err(
        "Host exposure inspection requires Linux. The external probe command also runs on Windows."
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inventory() -> Inventory {
        Inventory {
            addresses: vec!["10.205.0.1".parse().unwrap()],
            listeners: vec![],
            coverage: vec![],
            namespace: "net:1".into(),
        }
    }
    fn request() -> Request {
        Request {
            schema: 1,
            nonce: "a".repeat(64),
            revision: inventory().revision(),
            generation: "b".repeat(32),
            boot_id: "boot1".into(),
            issued_boot_seconds: 100,
            target: "10.205.0.1".parse().unwrap(),
            ports: vec![5432, 8000],
            server_addresses: inventory().addresses,
        }
    }
    fn result() -> ProbeResult {
        let r = request();
        ProbeResult {
            schema: 1,
            request_sha256: r.digest(),
            nonce: r.nonce,
            target: r.target,
            source: "10.205.0.2".parse().unwrap(),
            attempts: vec![
                Attempt {
                    port: 5432,
                    outcome: "refused".into(),
                },
                Attempt {
                    port: 8000,
                    outcome: "timed_out".into(),
                },
            ],
        }
    }
    #[test]
    fn kernel_tables_distinguish_listeners_loopback_ipv6_and_connected_sockets() {
        let raw="header\n 0: 0100007F:1538 00000000:0000 0A 0:0 0:0 0 0 0 123\n 1: 00000000:1F40 00000000:0000 0A 0:0 0:0 0 0 0 124\n 2: 0100007F:1234 0100007F:4321 01 0:0 0:0 0 0 0 125\n";
        let rows = proc_sockets(raw, "tcp", false).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|r| r.address.is_loopback() && r.port == 5432));
        assert!(rows.iter().any(|r| r.binding() == "all_interfaces"));
        let rows=proc_sockets("header\n0: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 123","tcp",true).unwrap();
        assert!(rows[0].address.is_loopback());
        assert!(proc_sockets("header\ntruncated", "tcp", false).is_err());
    }
    #[test]
    fn port_hints_are_not_service_identity_and_no_connections_never_mean_safe() {
        let r = request();
        let e = result();
        let report = report(
            inventory(),
            r.generation.clone(),
            r.boot_id.clone(),
            110,
            Some(External {
                request: r,
                result: e,
            }),
        );
        assert_eq!(report.risk, "not_assessed");
        assert_eq!(report.state, "local_and_operator_probe");
        let l = Listener {
            transport: "tcp".into(),
            address: "0.0.0.0".parse().unwrap(),
            port: 5432,
            inode: 1,
            owners: vec![],
        };
        assert_eq!(l.role(), "unidentified_process");
        assert!(l.needs_review());
        assert!(port_hint(l.port).contains("candidate"));
    }
    #[test]
    fn rejects_replay_source_forgery_missing_ports_and_changed_inventory() {
        let r = request();
        let mut e = result();
        assert!(validate_result(&r, &e, &r.revision, "boot1", &r.generation, 110).is_ok());
        assert!(validate_result(&r, &e, &r.revision, "boot1", &r.generation, 281).is_err());
        assert!(validate_result(&r, &e, "changed", "boot1", &r.generation, 110).is_err());
        assert!(validate_result(&r, &e, &r.revision, "reboot", &r.generation, 110).is_err());
        e.source = r.target;
        assert!(validate_result(&r, &e, &r.revision, "boot1", &r.generation, 110).is_err());
        e = result();
        e.attempts[1].port = 5432;
        assert!(validate_result(&r, &e, &r.revision, "boot1", &r.generation, 110).is_err());
    }
}
