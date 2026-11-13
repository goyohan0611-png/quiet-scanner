use crate::{
    book::{self, Book},
    capture::{self, Capture},
    native::{self, Iface},
    packet::{self, Mac},
    probe,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

type Emitter = Arc<dyn Fn(Value) + Send + Sync>;
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pin {
    ip: String,
    mac: String,
    ifname: String,
    #[serde(default)]
    ifindex: u32,
}
#[derive(Default, Serialize, Deserialize)]
struct Pins {
    pins: Vec<Pin>,
}
#[derive(Clone, Serialize)]
struct Device {
    key: String,
    ip: String,
    mac: String,
    vendor: String,
    kind: String,
    book: bool,
    book_exact: bool,
    book_note: String,
    status: String,
    ms: Option<u64>,
    ifname: String,
    ifindex: u32,
}
#[derive(Clone, Serialize)]
struct CompletedScan {
    card: Iface,
    target: String,
    completed_at: String,
    #[serde(skip)]
    targets: Vec<Ipv4Addr>,
}
fn same_network(left: &Iface, right: &Iface) -> bool {
    let addresses = |card: &Iface| {
        card.ipv4
            .iter()
            .map(|ip| (ip.ip.clone(), ip.prefix))
            .collect::<BTreeSet<_>>()
    };
    left.id.eq_ignore_ascii_case(&right.id)
        && left.index == right.index
        && left.mac.eq_ignore_ascii_case(&right.mac)
        && left.ips.iter().collect::<BTreeSet<_>>() == right.ips.iter().collect::<BTreeSet<_>>()
        && addresses(left) == addresses(right)
}
fn unused_addresses(scan: &CompletedScan, used: &BTreeSet<Ipv4Addr>) -> Vec<Ipv4Addr> {
    let own: BTreeSet<Ipv4Addr> = scan
        .card
        .ips
        .iter()
        .filter_map(|ip| ip.parse().ok())
        .collect();
    // CIDR parsing already excludes its network/broadcast addresses, preserving
    // valid .0/.255 hosts inside /23 and /22. Explicit ranges use the NIC mask
    // where known; an unresponsive address is still only an assignment candidate.
    let mut candidates = BTreeSet::new();
    for part in scan
        .target
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if let Ok(ips) = packet::parse_target(part) {
            for ip in ips {
                let first = ip.octets()[0];
                if first == 0
                    || first == 127
                    || first >= 224
                    || own.contains(&ip)
                    || used.contains(&ip)
                {
                    continue;
                }
                let reserved = !part.contains('/')
                    && scan.card.ipv4.iter().any(|address| {
                        let Ok(source) = address.ip.parse::<Ipv4Addr>() else {
                            return false;
                        };
                        if address.prefix > 30 || !packet::same_subnet(ip, source, address.prefix) {
                            return false;
                        }
                        let mask = if address.prefix == 0 {
                            0
                        } else {
                            u32::MAX << (32 - address.prefix)
                        };
                        let network = u32::from(source) & mask;
                        u32::from(ip) == network || u32::from(ip) == network | !mask
                    });
                if !reserved {
                    candidates.insert(ip);
                }
            }
        }
    }
    // Never include an address outside the successfully completed request.
    let scanned: BTreeSet<_> = scan.targets.iter().copied().collect();
    candidates
        .into_iter()
        .filter(|ip| scanned.contains(ip))
        .collect()
}
struct State {
    revision: u64,
    devices: BTreeMap<String, Device>,
    book: Book,
    pins: Vec<Pin>,
    logs: Vec<Value>,
    progress: Value,
    iface: String,
    ifindex: u32,
    canceled: bool,
    storage_error: Option<String>,
    completed_scan: Option<CompletedScan>,
}
pub struct Engine {
    state: Mutex<State>,
    emitter: Mutex<Option<Emitter>>,
    busy: AtomicBool,
    cancel: AtomicBool,
    closing: AtomicBool,
    directory: PathBuf,
}
struct Operation<'a>(&'a AtomicBool);
struct ArpRound<'a> {
    addresses: &'a [Ipv4Addr],
    timeout: Duration,
    start: usize,
    end: usize,
    label: &'a str,
}
fn request_progress(start: usize, end: usize, done: usize, total: usize) -> usize {
    // The last point belongs to receiving replies, not just sending requests.
    start + end.saturating_sub(start + 1) * done.min(total) / total.max(1)
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
fn key(ip: &str, mac: &str) -> String {
    format!("{ip}|{mac}")
}
fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap_or("")
}

impl Engine {
    pub fn new(directory: PathBuf) -> Self {
        let loaded_book = Book::load(&directory.join("device-book.local.json"));
        let loaded_pins = if directory.join("isolation.json").exists() {
            book::read_json::<Pins>(&directory.join("isolation.json"))
        } else {
            Ok(Pins::default())
        };
        let storage_error = loaded_book
            .as_ref()
            .err()
            .or(loaded_pins.as_ref().err())
            .cloned();
        let engine = Self {
            state: Mutex::new(State {
                revision: 0,
                devices: BTreeMap::new(),
                book: loaded_book.unwrap_or_else(|_| Book::defaults()),
                pins: loaded_pins.unwrap_or_default().pins,
                logs: vec![],
                progress: json!({}),
                iface: String::new(),
                ifindex: 0,
                canceled: false,
                storage_error,
                completed_scan: None,
            }),
            emitter: Mutex::new(None),
            busy: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            directory,
        };
        let warning = engine.state.lock().unwrap().storage_error.clone();
        if let Some(error) = warning {
            engine.log(&format!("사용자 기록을 읽지 못했습니다. 원본을 보존하며 저장·분리를 중단합니다: {error}"), "error");
        }
        engine
    }
    pub fn set_emitter(&self, emitter: Emitter) {
        *self.emitter.lock().unwrap() = Some(emitter);
    }
    pub fn migration_error(&self, error: String) {
        self.log(
            &format!("기존 기록 이전 실패 · 원본 보존: {error}"),
            "error",
        );
        self.state.lock().unwrap().storage_error = Some(error);
    }
    pub fn snapshot(&self) -> Value {
        let mut s = self.state.lock().unwrap();
        s.revision += 1;
        let mut groups: BTreeMap<Ipv4Addr, Vec<&Device>> = BTreeMap::new();
        for d in s.devices.values() {
            if let Ok(ip) = d.ip.parse() {
                groups.entry(ip).or_default().push(d);
            }
        }
        let conflicts = groups.values().filter(|v| v.len() > 1).count();
        let grouped: Vec<_> = groups.iter().map(|(ip, devices)| json!({"ip": ip.to_string(), "count": devices.len(), "conflict": devices.len()>1, "devices": devices})).collect();
        let isolated = s.pins.first().map(|p| key(&p.ip, &p.mac));
        json!({"revision": s.revision, "groups": grouped, "summary": {"ips": groups.len(), "devices": s.devices.len(), "conflictIps": conflicts},
            "progress": s.progress, "logs": s.logs, "iface": s.iface, "ifindex": s.ifindex,
            "isolated": isolated, "canceled": s.canceled, "completedScan": s.completed_scan})
    }
    fn emit(&self) {
        let emitter = self.emitter.lock().unwrap().clone();
        if let Some(send) = emitter {
            send(self.snapshot());
        }
    }
    fn log(&self, msg: &str, level: &str) {
        let mut s = self.state.lock().unwrap();
        s.logs.push(json!({"t": chrono::Local::now().format("%H:%M:%S").to_string(), "msg": msg, "level": level}));
        if s.logs.len() > 120 {
            s.logs.remove(0);
        }
    }
    fn progress(&self, phase: &str, pct: usize, msg: &str) {
        self.state.lock().unwrap().progress =
            json!({"phase": phase, "pct": pct.min(100), "msg": msg});
        self.emit();
    }
    fn guard(&self) -> Result<Operation<'_>, String> {
        if self.closing.load(Ordering::Acquire) {
            return Err("종료 준비 중입니다.".into());
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "다른 작업이 진행 중입니다. 완료 후 다시 시도하십시오.")?;
        // Close may have started between the first check and acquiring the operation.
        let op = Operation(&self.busy);
        if self.closing.load(Ordering::Acquire) {
            return Err("종료 준비 중입니다.".into());
        }
        self.cancel.store(false, Ordering::Release);
        Ok(op)
    }
    fn storage_ready(&self) -> Result<(), String> {
        self.state
            .lock()
            .unwrap()
            .storage_error
            .clone()
            .map_or(Ok(()), |e| {
                Err(format!("사용자 기록을 먼저 복구해야 합니다: {e}"))
            })
    }
    fn card(&self, payload: &Value) -> Result<Iface, String> {
        let id = payload
            .get("iface")
            .map(|v| field(v, "scapyName"))
            .unwrap_or("");
        if id.is_empty() {
            return Err("네트워크 인터페이스를 선택하십시오.".into());
        }
        native::live(id)
    }
    pub fn request(&self, action: &str, payload: Value) -> Result<Value, String> {
        if action == "cancel" {
            self.cancel.store(true, Ordering::Release);
            return Ok(json!({"state": self.snapshot()}));
        }
        let _op = self.guard()?;
        let result = match action {
            "interfaces" => native::interfaces().map(|cards| {
                self.emit();
                json!(cards)
            }),
            "scan" => self.scan(&payload),
            "dhcp_servers" => self.dhcp(&payload),
            "available_ips" => self.available_ips(&self.card(&payload)?),
            "isolate" => self.isolate(field(&payload, "key")),
            "ping" => self.probe_device(field(&payload, "key"), None),
            "tcp_check" => {
                let port = payload
                    .get("port")
                    .and_then(Value::as_u64)
                    .filter(|p| (1..=65535).contains(p))
                    .ok_or("포트는 1~65535 범위의 정수로 입력하십시오.")?
                    as u16;
                self.probe_device(field(&payload, "key"), Some(port))
            }
            "ping_start" | "ping_stop" => {
                let d = self
                    .state
                    .lock()
                    .unwrap()
                    .devices
                    .get(field(&payload, "key"))
                    .cloned()
                    .ok_or("장비를 다시 선택하십시오.")?;
                self.log(
                    &format!(
                        "{} 연속 Ping {}",
                        d.ip,
                        if action == "ping_start" {
                            "시작"
                        } else {
                            "중지"
                        }
                    ),
                    "info",
                );
                self.emit();
                Ok(json!({"ok":true}))
            }
            "release" => self.release_all().map(|_| self.snapshot()),
            "book_list" => Ok(json!({"rows": self.state.lock().unwrap().book.rows()})),
            "book_lookup" => {
                let p = packet::digits(field(&payload, "prefix"))?;
                let s = self.state.lock().unwrap();
                Ok(s.book
                    .lookup(&p)
                    .map(|e| json!({"prefix":p,"vendor":e.vendor,"kind":e.kind,"note":e.note}))
                    .unwrap_or(Value::Null))
            }
            "book_save" | "book_remove" => self.edit_book(action, &payload),
            _ => Err("지원하지 않는 작업입니다.".into()),
        };
        if let Err(error) = &result {
            self.log(error, "error");
            self.emit();
        }
        result
    }
    fn add_device(&self, ip: Ipv4Addr, mac: Mac, card: &Iface, ms: Option<u64>) -> bool {
        let ip = ip.to_string();
        let mac = packet::mac_text(&mac);
        let k = key(&ip, &mac);
        let mut s = self.state.lock().unwrap();
        if s.devices.contains_key(&k) {
            return false;
        }
        let info = s.book.describe(&mac);
        s.devices.insert(
            k.clone(),
            Device {
                key: k,
                ip,
                mac,
                vendor: info.vendor,
                kind: info.kind,
                book: info.from_book,
                book_exact: info.exact,
                book_note: info.note,
                status: "ok".into(),
                ms,
                ifname: card.id.clone(),
                ifindex: card.index,
            },
        );
        true
    }
    fn probe_device(&self, device_key: &str, port: Option<u16>) -> Result<Value, String> {
        let d = self
            .state
            .lock()
            .unwrap()
            .devices
            .get(device_key)
            .cloned()
            .ok_or("장비를 다시 선택하십시오.")?;
        let card = native::live(&d.ifname)?;
        let target: Ipv4Addr = d.ip.parse().map_err(|_| "장비 IP가 잘못됐습니다.")?;
        let source = card.source_for(target);
        if source.is_unspecified() {
            return Err("선택한 인터페이스에 IPv4 주소가 없습니다. 새로고침하십시오.".into());
        }
        let result = if let Some(port) = port {
            probe::tcp(source, target, port)?
        } else {
            probe::ping(source, target)?
        };
        if let Some(port) = port {
            self.log(
                &format!("TCP {}:{} · {}", d.ip, port, result.message),
                if result.ok { "info" } else { "warn" },
            );
            self.emit();
        }
        Ok(json!(result))
    }
    fn poll_arp(
        &self,
        cap: &Capture,
        targets: &BTreeSet<Ipv4Addr>,
        card: &Iface,
        sent: &HashMap<Ipv4Addr, Instant>,
        updated: &mut bool,
    ) -> Result<(), String> {
        for _ in 0..256 {
            let Some(frame) = cap.next()? else {
                break;
            };
            if let Some((ip, mac)) = packet::arp_reply(&frame) {
                if targets.contains(&ip) {
                    let ms = sent.get(&ip).map(|t| t.elapsed().as_millis() as u64);
                    *updated |= self.add_device(ip, mac, card, ms);
                }
            }
            if self.cancel.load(Ordering::Acquire) {
                break;
            }
        }
        Ok(())
    }
    fn arp_round(
        &self,
        cap: &Capture,
        round: ArpRound<'_>,
        targets: &BTreeSet<Ipv4Addr>,
        card: &Iface,
        mac: Mac,
    ) -> Result<(), String> {
        let mut sent = HashMap::new();
        let mut updated = false;
        let mut last_emit = Instant::now();
        let total = round.addresses.len();
        for (index, ip) in round.addresses.iter().enumerate() {
            if self.cancel.load(Ordering::Acquire) {
                break;
            }
            sent.insert(*ip, Instant::now());
            cap.send(&packet::arp_request(mac, card.source_for(*ip), *ip))?;
            self.poll_arp(cap, targets, card, &sent, &mut updated)?;
            if last_emit.elapsed() >= Duration::from_millis(80) || index + 1 == total {
                self.progress(
                    "scan",
                    request_progress(round.start, round.end, index + 1, total),
                    &format!(
                        "{} · {}/{} 주소 요청 · 응답 수집 중",
                        round.label,
                        index + 1,
                        total
                    ),
                );
                updated = false;
                last_emit = Instant::now();
            }
            // Limit broadcast bursts without waiting for each host's timeout.
            thread::sleep(Duration::from_millis(1));
        }
        let deadline = Instant::now() + round.timeout;
        while Instant::now() < deadline && !self.cancel.load(Ordering::Acquire) {
            self.poll_arp(cap, targets, card, &sent, &mut updated)?;
            if updated && last_emit.elapsed() >= Duration::from_millis(80) {
                self.emit();
                updated = false;
                last_emit = Instant::now();
            }
            thread::sleep(Duration::from_millis(3));
        }
        if updated {
            self.emit();
        }
        if !self.cancel.load(Ordering::Acquire) {
            self.progress(
                "scan",
                round.end,
                &format!("{} · {}개 주소 확인", round.label, total),
            );
        }
        Ok(())
    }
    fn found_ips(&self) -> BTreeSet<Ipv4Addr> {
        self.state
            .lock()
            .unwrap()
            .devices
            .values()
            .filter_map(|d| d.ip.parse().ok())
            .collect()
    }
    fn available_ips(&self, card: &Iface) -> Result<Value, String> {
        let s = self.state.lock().unwrap();
        if s.canceled {
            return Err("중지된 스캔입니다. 대역 스캔을 완료한 뒤 확인하십시오.".into());
        }
        let scan = s
            .completed_scan
            .as_ref()
            .ok_or("대역 스캔을 끝낸 뒤 확인하십시오. 중지·실패한 스캔은 사용할 수 없습니다.")?;
        if !same_network(&scan.card, card) {
            return Err(
                "인터페이스나 IP 설정이 변경됐습니다. 현재 설정으로 다시 스캔하십시오.".into(),
            );
        }
        let found = s
            .devices
            .values()
            .filter_map(|device| device.ip.parse().ok())
            .collect();
        let ips = unused_addresses(scan, &found);
        Ok(
            json!({"ips":ips,"target":scan.target,"completedAt":scan.completed_at,"scanned":scan.targets.len(),"iface":card.desc}),
        )
    }
    fn scan(&self, payload: &Value) -> Result<Value, String> {
        let targets = packet::parse_target(field(payload, "target"))?;
        let card = self.card(payload)?;
        let mac = packet::parse_mac(&card.mac)?;
        self.progress("scan", 0, "인터페이스 확인 · 스캔 준비");
        let cap = Capture::open(&card.id, "arp")?;
        self.release_all()?;
        {
            let mut s = self.state.lock().unwrap();
            s.devices.clear();
            s.iface = card.id.clone();
            s.ifindex = card.index;
            s.canceled = false;
            s.completed_scan = None;
        }
        let target_set: BTreeSet<_> = targets.iter().copied().collect();
        for own in &card.ips {
            if let Ok(ip) = own.parse() {
                if target_set.contains(&ip) {
                    self.add_device(ip, mac, &card, Some(0));
                }
            }
        }
        self.log(
            &format!("{}에서 {}개 주소 스캔 시작", card.desc, targets.len()),
            "info",
        );
        let started = Instant::now();
        let result = (|| {
            for round in 0..2 {
                if self.cancel.load(Ordering::Acquire) {
                    break;
                }
                let label = format!("장비 검색 {}/2", round + 1);
                self.progress("scan", round * 25, &label);
                self.arp_round(
                    &cap,
                    ArpRound {
                        addresses: &targets,
                        timeout: Duration::from_millis(1000),
                        start: round * 25,
                        end: (round + 1) * 25,
                        label: &label,
                    },
                    &target_set,
                    &card,
                    mac,
                )?;
            }
            for round in 0..3 {
                if self.cancel.load(Ordering::Acquire) {
                    break;
                }
                let found = self.found_ips();
                let missing: Vec<_> = targets
                    .iter()
                    .filter(|ip| !found.contains(ip))
                    .copied()
                    .collect();
                if missing.is_empty() {
                    break;
                }
                let label = format!("누락 주소 재확인 {}/3", round + 1);
                if round == 0 {
                    let devices = self.state.lock().unwrap().devices.len();
                    self.log(
                        &format!(
                            "장비 {}대 표시 · 무응답 주소 {}개 재확인",
                            devices,
                            missing.len()
                        ),
                        "info",
                    );
                }
                self.progress("scan", 50 + round * 10, &label);
                self.arp_round(
                    &cap,
                    ArpRound {
                        addresses: &missing,
                        timeout: Duration::from_millis(600),
                        start: 50 + round * 10,
                        end: 60 + round * 10,
                        label: &label,
                    },
                    &target_set,
                    &card,
                    mac,
                )?;
            }
            if !self.cancel.load(Ordering::Acquire) {
                let found: Vec<_> = self.found_ips().into_iter().collect();
                self.log(
                    &format!("응답 IP {}개에서 추가 MAC 재확인", found.len()),
                    "info",
                );
                self.progress("scan", 80, "중복 MAC 재확인");
                self.arp_round(
                    &cap,
                    ArpRound {
                        addresses: &found,
                        timeout: Duration::from_millis(700),
                        start: 80,
                        end: 99,
                        label: "중복 MAC 재확인",
                    },
                    &target_set,
                    &card,
                    mac,
                )?;
            }
            Ok::<(), String>(())
        })();
        let canceled = self.cancel.load(Ordering::Acquire);
        {
            let mut s = self.state.lock().unwrap();
            s.canceled = canceled;
            if result.is_ok() && !canceled {
                s.completed_scan = Some(CompletedScan {
                    card: card.clone(),
                    target: field(payload, "target").trim().to_string(),
                    completed_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    targets,
                });
            }
        }
        let end = if result.is_err() {
            "스캔 오류 · 발견 결과 보존"
        } else if canceled {
            "스캔 중지 · 발견 결과 보존"
        } else {
            "스캔 완료"
        };
        self.log(
            &format!("{end} ({:.1}초)", started.elapsed().as_secs_f64()),
            if result.is_err() { "error" } else { "info" },
        );
        let current = self.state.lock().unwrap().progress["pct"]
            .as_u64()
            .unwrap_or(0) as usize;
        self.progress(
            if canceled || result.is_err() {
                "stopped"
            } else {
                "done"
            },
            if canceled || result.is_err() {
                current
            } else {
                100
            },
            end,
        );
        result?;
        Ok(self.snapshot())
    }
    fn dhcp(&self, payload: &Value) -> Result<Value, String> {
        let card = self.card(payload)?;
        let mac = packet::parse_mac(&card.mac)?;
        let cap = Capture::open(&card.id, "udp and src port 67 and dst port 68")?;
        let xid: u32 = rand::random();
        let frame = packet::dhcp_discover(mac, xid);
        let mut servers = BTreeMap::new();
        self.log(&format!("{}에서 DHCP 서버 확인 시작", card.desc), "info");
        self.emit();
        for _ in 0..2 {
            cap.send(&frame)?;
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline && !self.cancel.load(Ordering::Acquire) {
                for _ in 0..256 {
                    let Some(bytes) = cap.next()? else {
                        break;
                    };
                    if let Some(mut offer) = packet::dhcp_offer(&bytes, xid, mac) {
                        let info = self.state.lock().unwrap().book.describe(&offer.mac);
                        offer.vendor = info.vendor;
                        offer.kind = info.kind;
                        servers.insert(
                            (offer.ip.clone(), offer.mac.clone(), offer.relay.clone()),
                            offer,
                        );
                    }
                }
                thread::sleep(Duration::from_millis(3));
            }
            if !servers.is_empty() || self.cancel.load(Ordering::Acquire) {
                break;
            }
        }
        self.log(
            &format!(
                "DHCP 응답 {}개 확인 · 주소 설정은 변경하지 않았습니다",
                servers.len()
            ),
            "info",
        );
        self.emit();
        Ok(
            json!({"servers": servers.into_values().collect::<Vec<_>>(), "iface": card.desc, "state": self.snapshot()}),
        )
    }
    fn save_pins(&self, pins: &[Pin]) -> Result<(), String> {
        book::atomic_write(
            &self.directory.join("isolation.json"),
            &serde_json::to_vec_pretty(&json!({"pins":pins})).map_err(|e| e.to_string())?,
        )
    }
    fn show_pin(&self, p: &Pin) {
        let mut s = self.state.lock().unwrap();
        let k = key(&p.ip, &p.mac);
        let info = s.book.describe(&p.mac);
        s.devices.entry(k.clone()).or_insert(Device {
            key: k.clone(),
            ip: p.ip.clone(),
            mac: p.mac.clone(),
            vendor: info.vendor,
            kind: info.kind,
            book: info.from_book,
            book_exact: info.exact,
            book_note: info.note,
            status: "isolation_unknown".into(),
            ms: None,
            ifname: p.ifname.clone(),
            ifindex: p.ifindex,
        });
        if let Some(d) = s.devices.get_mut(&k) {
            d.status = "isolation_unknown".into();
        }
    }
    fn release_all(&self) -> Result<(), String> {
        self.storage_ready()?;
        let pins = self.state.lock().unwrap().pins.clone();
        for pin in pins {
            self.show_pin(&pin);
            let card = native::live(&pin.ifname)?;
            native::release(
                pin.ip
                    .parse()
                    .map_err(|_| "분리 기록의 IP가 잘못됐습니다.")?,
                card.index,
                packet::parse_mac(&pin.mac)?,
            )?;
            let remaining: Vec<_> = self
                .state
                .lock()
                .unwrap()
                .pins
                .iter()
                .filter(|p| p.ip != pin.ip || p.ifname != pin.ifname)
                .cloned()
                .collect();
            self.save_pins(&remaining)?;
            {
                let mut s = self.state.lock().unwrap();
                s.pins = remaining;
                if let Some(d) = s.devices.get_mut(&key(&pin.ip, &pin.mac)) {
                    d.status = "ok".into();
                }
            }
            self.log(&format!("{} 분리 해제 확인", pin.ip), "info");
        }
        self.emit();
        Ok(())
    }
    fn isolate(&self, device_key: &str) -> Result<Value, String> {
        self.storage_ready()?;
        if !native::admin() {
            return Err("분리 기능은 관리자 권한이 필요합니다.".into());
        }
        let d = self
            .state
            .lock()
            .unwrap()
            .devices
            .get(device_key)
            .cloned()
            .ok_or("장비를 다시 선택하십시오.")?;
        let card = native::live(&d.ifname)?;
        let mac = packet::parse_mac(&d.mac)?;
        if card.ips.contains(&d.ip) || packet::parse_mac(&card.mac)? == mac {
            return Err("이 컴퓨터의 IP 또는 MAC은 분리할 수 없습니다.".into());
        }
        self.progress("isolate", 10, "이전 분리 상태 확인");
        self.release_all()?;
        let ip = d.ip.parse().map_err(|_| "장비 IP가 잘못됐습니다.")?;
        if native::read(ip, card.index)?.is_some_and(|n| n.permanent) {
            return Err(
                "기존 정적 ARP 설정이 있습니다. 이 프로그램에서는 덮어쓰지 않습니다.".into(),
            );
        }
        let pin = Pin {
            ip: d.ip.clone(),
            mac: d.mac.clone(),
            ifname: card.id,
            ifindex: card.index,
        };
        self.save_pins(std::slice::from_ref(&pin))?;
        self.state.lock().unwrap().pins = vec![pin.clone()];
        self.show_pin(&pin);
        self.progress("isolate", 50, "선택한 MAC으로 연결 고정");
        let result = native::pin(ip, card.index, mac);
        if result.is_ok() {
            self.state
                .lock()
                .unwrap()
                .devices
                .get_mut(device_key)
                .unwrap()
                .status = "ok".into();
            self.log(&format!("{} → {} 분리 확인", d.ip, d.mac), "info");
        }
        self.progress(
            "done",
            100,
            if result.is_ok() {
                "분리 완료"
            } else {
                "분리 상태 확인 필요 · 기록 보존"
            },
        );
        result?;
        Ok(self.snapshot())
    }
    fn edit_book(&self, action: &str, payload: &Value) -> Result<Value, String> {
        self.storage_ready()?;
        let mut next = self.state.lock().unwrap().book.clone();
        let prefix = packet::digits(field(payload, "prefix"))?;
        let created = if action == "book_save" {
            next.upsert(
                &prefix,
                field(payload, "vendor"),
                field(payload, "kind"),
                field(payload, "note"),
            )?
        } else {
            if next.lookup(&prefix).is_none() {
                return Err("등록된 MAC 앞자리가 아닙니다.".into());
            }
            next.remove(&prefix);
            false
        };
        next.save(&self.directory.join("device-book.local.json"))?;
        let rows = next.rows();
        {
            let mut s = self.state.lock().unwrap();
            s.book = next;
            let descriptions: Vec<_> = s
                .devices
                .iter()
                .map(|(k, d)| (k.clone(), s.book.describe(&d.mac)))
                .collect();
            for (k, info) in descriptions {
                if let Some(d) = s.devices.get_mut(&k) {
                    d.vendor = info.vendor;
                    d.kind = info.kind;
                    d.book = info.from_book;
                    d.book_exact = info.exact;
                    d.book_note = info.note;
                }
            }
        }
        self.emit();
        Ok(json!({"created":created,"rows":rows,"state":self.snapshot()}))
    }
    pub fn recover(&self) {
        if let Ok(_op) = self.guard() {
            if let Err(e) = self.release_all() {
                self.log(&format!("이전 분리 기록 복구 필요: {e}"), "error");
                self.emit();
            }
        }
    }
    pub fn shutdown(&self) -> Result<(), String> {
        self.closing.store(true, Ordering::Release);
        self.cancel.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.busy.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                return Err("작업 종료 지연 · 분리 기록은 다음 실행 때 복구합니다.".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.release_all()
    }
    pub fn diagnostics(&self) -> Value {
        json!({"npcap":capture::available().err(),"admin":native::admin(),"data":self.directory})
    }
    /// Check native writes on an unused documentation address, without sending
    /// packets or changing the adapter's IP configuration.
    pub fn self_test_neighbor(&self, card: &Iface) -> Result<Value, String> {
        let _op = self.guard()?;
        self.storage_ready()?;
        if !native::admin() {
            return Err("네이티브 동작 확인에는 관리자 권한이 필요합니다.".into());
        }
        if !self.state.lock().unwrap().pins.is_empty() {
            return Err("현재 분리 기록이 있으므로 테스트를 시작하지 않았습니다.".into());
        }
        let ip: Ipv4Addr = "192.0.2.254".parse().unwrap();
        for iface in native::interfaces()? {
            for row in iface.ipv4 {
                if let Ok(own) = row.ip.parse() {
                    if packet::same_subnet(ip, own, row.prefix) {
                        return Err(
                            "테스트 주소가 현재 네트워크에 속하므로 확인을 중단했습니다.".into(),
                        );
                    }
                }
            }
        }
        if native::read(ip, card.index)?.is_some() {
            return Err("테스트 주소의 기존 ARP 항목이 있어 변경하지 않았습니다.".into());
        }
        let mac = [2, 0, 0, 0, 0, 254];
        self.add_device(ip, mac, card, None);
        let isolated = self.isolate(&key(&ip.to_string(), &packet::mac_text(&mac)));
        let released = self.release_all();
        isolated?;
        released?;
        if native::read(ip, card.index)?.is_some_and(|entry| entry.permanent) {
            return Err("테스트 주소의 해제가 확인되지 않았습니다.".into());
        }
        Ok(
            json!({"pinVerified":true,"releaseVerified":true,"ip":ip.to_string(),"state":self.snapshot()}),
        )
    }
}

/// Import only known legacy locations, never search site folders or overwrite existing records.
pub fn migrate_legacy(directory: &Path) -> Result<(), String> {
    let mut roots = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            roots.push(parent.join("resources/IPFixBackend"));
            roots.push(parent.to_path_buf());
        }
    }
    for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(programs) = std::env::var_os(variable) {
            roots.push(PathBuf::from(programs).join("Quiet Scanner/resources/IPFixBackend"));
        }
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        roots.push(PathBuf::from(local).join("Programs/Quiet Scanner/resources/IPFixBackend"));
    }
    #[cfg(debug_assertions)]
    {
        let project = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        roots.push(project.join("src"));
        roots.push(project.join("dist/IPFixBackend"));
    }
    for file in ["device-book.local.json", "isolation.json"] {
        let dest = directory.join(file);
        if dest.exists() {
            continue;
        }
        if let Some(source) = roots
            .iter()
            .map(|root| root.join(file))
            .find(|path| path.is_file())
        {
            let bytes = std::fs::read(source).map_err(|e| e.to_string())?;
            // Validate before copying. A corrupt source must remain available for manual recovery.
            let _: Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("기존 {file} 확인 실패: {e}"))?;
            book::atomic_write(&dest, &bytes)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_progress_waits_for_replies_and_never_goes_back() {
        let values: Vec<_> = (0..=254)
            .map(|done| request_progress(50, 60, done, 254))
            .collect();
        assert_eq!(values[0], 50);
        assert_eq!(values[254], 59);
        assert!(values.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(request_progress(80, 99, 2, 2), 98);
        assert_eq!(request_progress(0, 25, 0, 0), 0);
    }
    fn engine() -> Engine {
        Engine::new(
            std::env::temp_dir().join(format!("quiet-engine-test-{}", rand::random::<u64>())),
        )
    }
    fn card() -> Iface {
        Iface {
            name: "test".into(),
            id: "test-guid".into(),
            desc: "test".into(),
            ips: vec!["192.168.0.1".into()],
            ipv4: vec![],
            index: 1,
            mac: "02:00:00:00:00:01".into(),
        }
    }
    #[test]
    fn streaming_merge_keeps_all_macs() {
        let e = engine();
        let c = card();
        let ip = "192.168.0.1".parse().unwrap();
        assert!(e.add_device(ip, [2, 0, 0, 0, 0, 1], &c, Some(0)));
        assert!(e.add_device(ip, [2, 0, 0, 0, 0, 2], &c, Some(1)));
        assert!(!e.add_device(ip, [2, 0, 0, 0, 0, 2], &c, Some(5)));
        let s = e.snapshot();
        assert_eq!(s["summary"]["devices"], 2);
        assert_eq!(s["summary"]["conflictIps"], 1);
    }
    fn completed(card: Iface, target: &str) -> CompletedScan {
        CompletedScan {
            card,
            target: target.into(),
            completed_at: "2026-11-13 12:00:00".into(),
            targets: packet::parse_target(target).unwrap(),
        }
    }
    #[test]
    fn available_ips_exclude_own_ips_and_all_responders() {
        let e = engine();
        let mut c = card();
        c.ips.push("192.168.0.2".into());
        e.add_device("192.168.0.3".parse().unwrap(), [2, 0, 0, 0, 0, 3], &c, None);
        e.add_device("192.168.0.3".parse().unwrap(), [2, 0, 0, 0, 0, 4], &c, None);
        e.state.lock().unwrap().completed_scan = Some(completed(c.clone(), "192.168.0.0/29"));
        let result = e.available_ips(&c).unwrap();
        assert_eq!(
            result["ips"],
            json!(["192.168.0.4", "192.168.0.5", "192.168.0.6"])
        );
        assert_eq!(result["scanned"], 6);
        // Streamed snapshots carry only small scan metadata, never 4,096 targets.
        assert!(e.snapshot()["completedScan"].get("targets").is_none());
    }
    #[test]
    fn candidate_subnets_preserve_real_zero_and_255_hosts() {
        for (target, count, last) in [
            ("192.168.0.0/23", 509, "192.168.1.255"),
            ("192.168.0.0/22", 1021, "192.168.3.255"),
        ] {
            let scan = completed(card(), target);
            let ips = unused_addresses(&scan, &BTreeSet::new());
            assert_eq!(ips.len(), count);
            assert!(ips.contains(&"192.168.0.255".parse().unwrap()));
            assert!(ips.contains(&"192.168.1.0".parse().unwrap()));
            assert!(!ips.contains(&"192.168.0.0".parse().unwrap()));
            assert!(!ips.contains(&last.parse().unwrap()));
        }
        let mut c = card();
        c.ipv4.push(native::Ipv4Info {
            ip: "192.168.0.1".into(),
            prefix: 24,
            cidr: "192.168.0.0/24".into(),
        });
        let ips = unused_addresses(&completed(c.clone(), "192.168.0.0-255"), &BTreeSet::new());
        assert_eq!(ips.len(), 253);
        assert!(!ips.contains(&"192.168.0.255".parse().unwrap()));
        assert_eq!(
            unused_addresses(&completed(c, "192.168.0.0/31"), &BTreeSet::new()),
            vec!["192.168.0.0".parse::<Ipv4Addr>().unwrap()]
        );
    }
    #[test]
    fn available_ips_reject_partial_scans_and_network_changes() {
        let e = engine();
        let mut c = card();
        c.ipv4.push(native::Ipv4Info {
            ip: "192.168.0.1".into(),
            prefix: 24,
            cidr: "192.168.0.0/24".into(),
        });
        assert!(e.available_ips(&c).is_err());
        e.state.lock().unwrap().completed_scan = Some(completed(c.clone(), "192.168.0.0/29"));
        assert!(e.available_ips(&c).is_ok());
        let mut changed = c.clone();
        changed.index += 1;
        assert!(e.available_ips(&changed).is_err());
        changed = c.clone();
        changed.ips[0] = "192.168.0.9".into();
        assert!(e.available_ips(&changed).is_err());
        changed = c.clone();
        changed.ipv4[0].prefix = 23;
        assert!(e.available_ips(&changed).is_err());
        changed = c.clone();
        changed.mac = "02:00:00:00:00:02".into();
        assert!(e.available_ips(&changed).is_err());
        e.state.lock().unwrap().canceled = true;
        assert!(e.available_ips(&c).is_err());
    }
    #[test]
    fn busy_and_shutdown_block_mutations() {
        let e = engine();
        {
            let _op = e.guard().unwrap();
            assert!(e.request("book_remove", json!({})).is_err());
        }
        assert!(e.guard().is_ok());
        e.closing.store(true, Ordering::Release);
        assert!(e.guard().is_err());
    }
    #[test]
    fn failed_storage_does_not_change_book() {
        let e = engine();
        std::fs::write(&e.directory, b"not a directory").unwrap();
        let before = e.state.lock().unwrap().book.rows();
        assert!(e
            .request(
                "book_save",
                json!({"prefix":"020000000001","vendor":"changed"})
            )
            .is_err());
        assert_eq!(e.state.lock().unwrap().book.rows(), before);
        std::fs::remove_file(&e.directory).unwrap();
    }
    #[test]
    fn cancel_does_not_drop_devices() {
        let e = engine();
        e.add_device(
            "192.168.0.1".parse().unwrap(),
            [2, 0, 0, 0, 0, 1],
            &card(),
            None,
        );
        e.request("cancel", json!({})).unwrap();
        assert!(e.cancel.load(Ordering::Acquire));
        assert_eq!(e.snapshot()["summary"]["devices"], 1);
    }
}
