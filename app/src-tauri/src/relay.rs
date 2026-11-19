//! Local per-account relay: 127.0.0.1 SOCKS5 + HTTP proxy that forwards to the account's node.
//!
//! - Claude and its child processes only ever see `127.0.0.1:<port>`; the node's credentials
//!   stay inside Hydra.
//! - Hostnames are passed to the node unresolved, so DNS happens at the node.
//! - UDP (SOCKS5 UDP ASSOCIATE) and BIND are refused. There is no direct fallback: if the node
//!   is unreachable, or Hydra is not running, the account has no network.
//! - Relays live in the long-running Hydra tray process. Other Hydra processes (CLI, watchdog)
//!   start the tray process when they need a relay.
//! - Kill switch: `block` pauses a relay (new connections are dropped, open ones are closed),
//!   persisted in `settings.json` so it survives restarts. While accounts use their relay, the
//!   host re-checks each exit against the environment's rules (see `guard`) and blocks on a
//!   confirmed violation.
use crate::guard::Verdict;
use crate::node::NodeConfig;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How often an active account's exit is re-checked (± jitter), and how recently it must have
/// used its relay to be checked at all.
const MONITOR_EVERY: Duration = Duration::from_secs(300);
const MONITOR_JITTER: Duration = Duration::from_secs(60);
const ACTIVE_WITHIN_MS: u64 = 15 * 60 * 1000;
/// How often the monitor looks for due checks.
const MONITOR_TICK: Duration = Duration::from_secs(10);
/// Retries after a check that could not finish: 30 s, doubling, up to `RETRY_MAX` while the
/// account runs and up to `RECOVER_RETRY_MAX` while it is softly cut.
const RETRY_FIRST: Duration = Duration::from_secs(30);
const RETRY_MAX: Duration = Duration::from_secs(120);
const RECOVER_RETRY_MAX: Duration = Duration::from_secs(300);
/// How long checks of a running account may keep failing before it is softly cut.
const SOFT_CUT_AFTER: Duration = Duration::from_secs(600);
/// Per-request timeout of a route check.
const CHECK_TIMEOUT_SECS: u64 = 15;

/// Open client connections of one relay, so a block can close them.
#[derive(Default)]
/// The open connections of one relay, so a cut can close them. Each entry is the handler's own
/// socket, shared rather than duplicated: on Windows a duplicated socket handle is inheritable
/// until it is fixed up, and a process Hydra started in that moment (Claude, Mihomo, PowerShell)
/// kept the connection open after the relay closed it, then reset it when it exited.
struct Conns { next: AtomicU64, open: Mutex<HashMap<u64, Arc<TcpStream>>> }

impl Conns {
    fn add(&self, s: &Arc<TcpStream>) -> Option<u64> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.open.lock().ok()?.insert(id, Arc::clone(s));
        Some(id)
    }
    fn remove(&self, id: u64) { if let Ok(mut m) = self.open.lock() { m.remove(&id); } }
    fn close_all(&self) {
        if let Ok(mut m) = self.open.lock() { for (_, s) in m.drain() { let _ = s.shutdown(Shutdown::Both); } }
    }
}

/// Shared state of a running relay's accept loop.
#[derive(Clone)]
struct Gate {
    node: Arc<RwLock<NodeConfig>>,
    stop: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    conns: Arc<Conns>,
    /// Last time (ms) a client connected.
    active: Arc<AtomicU64>,
    /// What this relay answers on its identity endpoint (see `tag`).
    tag: Arc<String>,
}

impl Gate {
    fn new(node: NodeConfig, paused: bool) -> Gate {
        Gate { node: Arc::new(RwLock::new(node)), stop: Default::default(), paused: Arc::new(AtomicBool::new(paused)), conns: Default::default(), active: Default::default(), tag: Default::default() }
    }
}

const IDENTITY_PATH: &str = "/hydra-relay";

/// Identity of an account's relay. Other Hydra processes ask the port for it before trusting
/// a saved port number: after a restart that port may belong to another program or to another
/// account's relay. This tells relays apart; it is not a secret (any local process of the same
/// user can use a loopback proxy, since Chromium cannot send SOCKS credentials).
pub fn tag(id: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(format!("hydra-relay:{id}").as_bytes())[..12].iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `port` is the running relay of account `id`.
pub fn identified(port: u16, id: &str) -> bool {
    let ask = || -> io::Result<String> {
        let mut s = TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_millis(400))?;
        s.set_read_timeout(Some(Duration::from_secs(2)))?;
        s.set_write_timeout(Some(Duration::from_secs(2)))?;
        s.write_all(format!("GET {IDENTITY_PATH} HTTP/1.0\r\n\r\n").as_bytes())?;
        let mut out = String::new();
        s.take(512).read_to_string(&mut out)?;
        Ok(out)
    };
    ask().is_ok_and(|reply| reply.starts_with("HTTP/1.1 200") && reply.trim_end().ends_with(&tag(id)))
}

struct Relay {
    original: NodeConfig,
    core: Option<crate::clash::Core>,
    port: u16,
    gate: Gate,
    /// Changes whenever the route is built or replaced, so a check that ran without the
    /// route lock can tell whether it still describes the current route.
    generation: u64,
}

fn next_generation() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

static HOST: AtomicBool = AtomicBool::new(false);
fn relays() -> &'static Mutex<HashMap<String, Relay>> {
    static R: OnceLock<Mutex<HashMap<String, Relay>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Marks this process as the relay host (the GUI / tray process).
pub fn set_host() { HOST.store(true, Ordering::SeqCst); }

// Serialize route replacement and authorization so a verdict cannot release a different route.
pub(crate) fn route_change() -> std::sync::MutexGuard<'static, ()> {
    static CHANGE: Mutex<()> = Mutex::new(());
    CHANGE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Starts or updates the relay for an account in this process and returns its port.
///
/// Starting a Mihomo core can take seconds, so the relay table is not locked meanwhile: the
/// kill switch, the monitor and other accounts keep working. While a relay's node is being
/// replaced its route is empty, so nothing is forwarded over the old or a half-built route.
fn ensure(id: &str, node: &NodeConfig, preferred: Option<u16>) -> Result<u16, String> {
    let existing = {
        let mut map = relays().lock().map_err(|_| "中继状态错误。")?;
        match map.get_mut(id) {
            Some(r) => {
                let changed = r.original != *node;
                if !changed && !r.core.as_mut().is_some_and(|c| !c.alive()) { return Ok(r.port); }
                pause(&r.gate);
                *r.gate.node.write().map_err(|_| "中继状态错误。")? = NodeConfig::default();
                r.original = NodeConfig::default();
                r.core = None;
                r.generation = next_generation();
                Some(r.port)
            }
            None => None,
        }
    };
    if let Some(port) = existing {
        let (upstream, core) = crate::clash::resolve(node)?;
        let mut map = relays().lock().map_err(|_| "中继状态错误。")?;
        let r = map.get_mut(id).ok_or("中继已停止。")?;
        *r.gate.node.write().map_err(|_| "中继状态错误。")? = upstream;
        r.original = node.clone();
        r.core = core;
        r.generation = next_generation();
        return Ok(port);
    }
    let listener = preferred
        .and_then(|p| TcpListener::bind((Ipv4Addr::LOCALHOST, p)).ok())
        .map(Ok)
        .unwrap_or_else(|| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|e| format!("无法启动本地代理中继：{e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let (upstream, core) = crate::clash::resolve(node)?;
    let mut gate = Gate::new(upstream, true);
    gate.tag = Arc::new(tag(id));
    let relay = Relay { original: node.clone(), core, port, gate: gate.clone(), generation: next_generation() };
    std::thread::Builder::new().name(format!("relay-{port}")).spawn(move || serve(listener, gate)).map_err(|e| e.to_string())?;
    relays().lock().map_err(|_| "中继状态错误。")?.insert(id.to_string(), relay);
    Ok(port)
}

pub fn shutdown() { if let Ok(mut map) = relays().lock() { map.clear(); } }

fn stop(id: &str) {
    if let Some(r) = relays().lock().ok().and_then(|mut m| m.remove(id)) {
        r.gate.stop.store(true, Ordering::SeqCst);
        r.gate.conns.close_all();
        let _ = TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, r.port)), Duration::from_millis(200));
    }
}

fn gate_of(id: &str) -> Option<Gate> {
    relays().lock().ok().and_then(|m| m.get(id).map(|r| r.gate.clone()))
}

fn pause(gate: &Gate) {
    gate.paused.store(true, Ordering::SeqCst);
    gate.conns.close_all();
}

fn environment_of(id: &str) -> Option<String> { crate::settings::load().effective(id).environment }

/// Full check of an account's route, judged against its rules. Caller holds `route_change`.
fn validate_exit(id: &str) -> Verdict {
    match inspect_route(id, None) {
        Ok((_, found)) => {
            let verdict = crate::guard::judge(environment_of(id).as_deref(), &found);
            if matches!(verdict, Verdict::Unverified(_)) { log_check(id, "check inconclusive", &found); }
            verdict
        }
        Err(reason) => Verdict::Unverified(format!("无法核验代理出口：{reason}")),
    }
}

/// Starts (or keeps) the account's relay and opens it once its exit verifies. A confirmed
/// violation cuts the account; a check that cannot finish leaves it softly cut, so the
/// monitor keeps re-checking and opens it by itself once a check passes.
fn checked_port(id: &str, node: &NodeConfig, preferred: Option<u16>) -> Result<u16, String> {
    let port = ensure(id, node, preferred)?;
    let gate = gate_of(id).ok_or("中继已停止。")?;
    let acc = crate::settings::load().account(id);
    if let Some(reason) = &acc.blocked {
        pause(&gate);
        if !acc.blocked_soft { return Err(reason.clone()); }
    }
    if gate.paused.load(Ordering::SeqCst) {
        match validate_exit(id) {
            Verdict::Pass(_) if acc.blocked.is_some() => unblock(id, "启动前重新核验通过"),
            Verdict::Pass(_) => gate.paused.store(false, Ordering::SeqCst),
            Verdict::Violation(reason) => { block(id, &reason); return Err(reason); }
            Verdict::Unverified(reason) => { soft_block(id, &reason); return Err(reason); }
        }
    }
    Ok(port)
}

/// Host process: makes the running relays match `settings.json` and persists their ports.
/// Blocks on network checks; call it from a worker thread (see `sync_soon`).
pub fn sync_all() {
    if !HOST.load(Ordering::SeqCst) { return; }
    let _change = route_change();
    let s = crate::settings::load();
    let mut wanted = Vec::new();
    let mut ports = Vec::new();
    for (id, acc) in &s.accounts {
        let Some(node) = s.effective(id).node else { continue };
        wanted.push(id.clone());
        match checked_port(id, &node, acc.relay_port) {
            Ok(port) if acc.relay_port != Some(port) => ports.push((id.clone(), port)),
            Ok(_) => {}
            Err(e) => crate::paths::append_log("hydra-error.log", &format!("relay {id}: {e}")),
        }
    }
    let running: Vec<String> = relays().lock().map(|m| m.keys().cloned().collect()).unwrap_or_default();
    for id in running.iter().filter(|id| !wanted.contains(id)) { stop(id); }
    if !ports.is_empty() {
        let _ = crate::settings::update(|s| for (id, port) in &ports { if let Some(a) = s.accounts.get_mut(id) { a.relay_port = Some(*port); } });
    }
}

/// `sync_all` on a worker thread, for callers on the UI thread.
pub fn sync_soon() {
    if !HOST.load(Ordering::SeqCst) { return; }
    let _ = std::thread::Builder::new().name("relay-sync".into()).spawn(sync_all);
}

/// Kill switch for a confirmed violation: cuts the account off the network until the user
/// resumes or rebinds. Host process only.
pub fn block(id: &str, reason: &str) { cut(id, reason, false) }

/// Cut after checks kept failing: the monitor keeps re-checking and lifts it by itself once a
/// check passes (see `start_monitor`). An existing hard cut is never softened.
pub fn soft_block(id: &str, reason: &str) {
    let acc = crate::settings::load().account(id);
    if acc.blocked.is_some() && !acc.blocked_soft {
        if let Some(gate) = gate_of(id) { pause(&gate); }
        return;
    }
    if acc.blocked.is_some() {
        // Already softly cut: keep it paused, refresh the reason, no second notice.
        if let Some(gate) = gate_of(id) { pause(&gate); }
        let _ = crate::settings::update(|s| if let Some(a) = s.accounts.get_mut(id) { a.blocked = Some(reason.to_string()); });
        return;
    }
    cut(id, reason, true)
}

fn cut(id: &str, reason: &str, soft: bool) {
    if let Some(gate) = gate_of(id) { pause(&gate); }
    let _ = crate::settings::update(|s| if let Some(a) = s.accounts.get_mut(id) { a.blocked = Some(reason.to_string()); a.blocked_soft = soft; });
    let kind = if soft { "network paused (unverified, retrying)" } else { "network cut" };
    crate::paths::append_log("hydra-error.log", &format!("guard {id}: {kind}: {reason}"));
    crate::guard::notify(id, reason, soft);
}

/// Lifts a cut. `source` names who lifted it, for the log.
pub fn unblock(id: &str, source: &str) {
    let mut was = None;
    let _ = crate::settings::update(|s| if let Some(a) = s.accounts.get_mut(id) { was = a.blocked.take(); a.blocked_soft = false; });
    if let Some(gate) = gate_of(id) { gate.paused.store(false, Ordering::SeqCst); }
    if let Some(reason) = was { crate::paths::append_log("hydra-error.log", &format!("guard {id}: network restored by {source} (was: {reason})")); }
}

/// Checks an account's current route over its node, bypassing the (possibly paused) relay.
/// Returns the route generation it checked with what the check found; `known` is a previously
/// verified exit of that route whose location is reused if the IP did not change.
pub fn inspect_route(id: &str, known: Option<&crate::node::ExitInfo>) -> Result<(u64, crate::node::Inspection), String> {
    let (original, upstream, generation) = relays().lock().ok()
        .and_then(|m| m.get(id).map(|r| (r.original.clone(), r.gate.node.read().map(|n| n.clone()).unwrap_or_default(), r.generation)))
        .ok_or("这个账号的代理中继没有运行。")?;
    if upstream.host.is_empty() { return Err("这个账号的代理节点正在切换，请稍后再试。".into()); }
    Ok((generation, crate::node::inspect_known(&upstream.client(Duration::from_secs(CHECK_TIMEOUT_SECS))?, &original, known)))
}

/// Checks an account's current exit over its node, bypassing the (possibly paused) relay.
pub fn probe(id: &str) -> Result<crate::node::ExitInfo, String> {
    inspect_route(id, None)?.1.into_result()
}

pub fn running(id: &str) -> bool { gate_of(id).is_some() }

fn generation_of(id: &str) -> Option<u64> {
    relays().lock().ok().and_then(|m| m.get(id).map(|r| r.generation))
}

fn log_check(id: &str, what: &str, found: &crate::node::Inspection) {
    crate::paths::append_log("hydra-error.log", &format!("guard {id}: {what}: {}", found.trail()));
}

/// A delay in `[base - spread, base + spread]`, so accounts do not all ask the check services
/// in the same second.
fn jittered(base: Duration, spread: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default());
    let span = spread.as_millis() as u64 * 2 + 1;
    (base - spread) + Duration::from_millis(h.finish() % span)
}

/// Monitor state of one account.
struct Watch {
    next: Instant,
    /// Route generation `known` belongs to.
    generation: u64,
    /// Last verified exit of this route, so an unchanged IP needs no location lookup.
    known: Option<crate::node::ExitInfo>,
    /// When checks of a running account started failing, and how many in a row did.
    failing_since: Option<Instant>,
    failures: u32,
}

/// Delay before the next try after `failures` checks in a row could not finish.
fn retry_after(failures: u32, cap: Duration) -> Duration {
    (RETRY_FIRST * 2u32.saturating_pow(failures.saturating_sub(1).min(8))).min(cap)
}

/// Host process: re-checks the exit of every account that recently used its relay, and keeps
/// re-checking softly cut accounts until their exit verifies again.
///
/// - Every `MONITOR_EVERY` (± jitter). Only the IP is asked while it stays the same; the
///   location is looked up again only when the IP changes.
/// - A confirmed violation cuts at once. A check that cannot finish is retried with backoff
///   and open connections are left alone; only after `SOFT_CUT_AFTER` of failures is the
///   account softly cut.
/// - Checks run without the route lock (they can take a while); the verdict is applied under
///   the lock, and only if the route is still the one that was checked.
pub fn start_monitor() {
    let _ = std::thread::Builder::new().name("exit-guard".into()).spawn(|| {
        let mut watches: HashMap<String, Watch> = HashMap::new();
        loop {
            std::thread::sleep(MONITOR_TICK);
            let now_ms = crate::paths::now_millis();
            let settings = crate::settings::load();
            // (id, generation, paused, recently active)
            let relays_now: Vec<(String, u64, bool, bool)> = relays().lock().map(|m| m.iter()
                .map(|(id, r)| (id.clone(), r.generation, r.gate.paused.load(Ordering::SeqCst), now_ms.saturating_sub(r.gate.active.load(Ordering::SeqCst)) < ACTIVE_WITHIN_MS))
                .collect()).unwrap_or_default();
            watches.retain(|id, _| relays_now.iter().any(|(r, ..)| r == id));
            for (id, generation, paused, active) in relays_now {
                let acc = settings.account(&id);
                let recovering = paused && acc.blocked.is_some() && acc.blocked_soft;
                if !recovering && (paused || !active) { continue; }
                let watch = watches.entry(id.clone()).or_insert_with(|| Watch {
                    next: Instant::now() + if recovering { RETRY_FIRST } else { jittered(MONITOR_EVERY, MONITOR_JITTER) },
                    generation, known: acc.last_exit.clone(), failing_since: None, failures: 0,
                });
                if watch.generation != generation {
                    // Rebuilt route: what was known about the old one does not apply.
                    *watch = Watch { next: watch.next, generation, known: None, failing_since: None, failures: 0 };
                }
                if Instant::now() < watch.next { continue; }
                let found = inspect_route(&id, watch.known.as_ref());
                let _change = route_change();
                let acc = crate::settings::load().account(&id);
                let still = generation_of(&id) == Some(generation) && gate_of(&id).is_some_and(|g| g.paused.load(Ordering::SeqCst) == paused);
                let still = still && (acc.blocked.is_some() && acc.blocked_soft) == recovering;
                let found = match found {
                    Ok((checked, found)) if still && checked == generation => found,
                    // Route or state changed meanwhile, or the relay is switching: look again soon.
                    _ => { watch.next = Instant::now() + RETRY_FIRST; continue; }
                };
                let mut forget = false;
                match crate::guard::judge(acc.environment.as_deref(), &found) {
                    Verdict::Pass(exit) => {
                        if let Some(exit) = exit { watch.known = Some(exit); }
                        if watch.failures > 0 { log_check(&id, &format!("check passed after {} failed", watch.failures), &found); }
                        watch.failures = 0;
                        watch.failing_since = None;
                        watch.next = Instant::now() + jittered(MONITOR_EVERY, MONITOR_JITTER);
                        if recovering {
                            unblock(&id, "出口保护自动重新核验");
                            crate::guard::notify_restored(&id);
                        }
                    }
                    Verdict::Violation(reason) => {
                        log_check(&id, "violation", &found);
                        block(&id, &reason);
                        forget = true;
                    }
                    Verdict::Unverified(reason) => {
                        watch.failures += 1;
                        let since = *watch.failing_since.get_or_insert_with(Instant::now);
                        log_check(&id, &format!("check inconclusive #{}", watch.failures), &found);
                        if recovering {
                            soft_block(&id, &reason);
                            watch.next = Instant::now() + retry_after(watch.failures, RECOVER_RETRY_MAX);
                        } else if since.elapsed() >= SOFT_CUT_AFTER {
                            soft_block(&id, &reason);
                            watch.failures = 0;
                            watch.failing_since = None;
                            watch.next = Instant::now() + RETRY_FIRST;
                        } else {
                            watch.next = Instant::now() + retry_after(watch.failures, RETRY_MAX);
                        }
                    }
                }
                if forget { watches.remove(&id); }
            }
        }
    });
}

/// Returns the relay port for launching an account, starting the Hydra tray process if needed.
pub fn port_for_launch(id: &str, node: &NodeConfig) -> Result<u16, String> {
    if HOST.load(Ordering::SeqCst) {
        let _change = route_change();
        let preferred = crate::settings::load().account(id).relay_port;
        let port = checked_port(id, node, preferred)?;
        if preferred != Some(port) { crate::settings::update(|s| s.account_mut(id).relay_port = Some(port))?; }
        return Ok(port);
    }
    // Another process hosts the relays. A saved port is only trusted once it answers as this
    // account's relay: the number alone may belong to any program by now.
    let current = || crate::settings::load().account(id).relay_port.filter(|p| identified(*p, id));
    if let Some(port) = current() { return Ok(port); }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    std::process::Command::new(exe).arg("--tray")
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .spawn().map_err(|e| format!("无法启动 Claude-Hydra 后台：{e}"))?;
    let until = Instant::now() + Duration::from_secs(20);
    while Instant::now() < until {
        std::thread::sleep(Duration::from_millis(300));
        if let Some(port) = current() { return Ok(port); }
    }
    Err("Claude-Hydra 后台的本地代理中继未就绪，账号未启动。请先打开 Claude-Hydra。".into())
}

// ---- server ---------------------------------------------------------------------------

fn serve(listener: TcpListener, gate: Gate) {
    for conn in listener.incoming() {
        if gate.stop.load(Ordering::SeqCst) { break; }
        let Ok(client) = conn else { continue };
        // Only loopback clients; the listener is bound to 127.0.0.1 but be explicit.
        if !client.peer_addr().map(|a| a.ip().is_loopback()).unwrap_or(false) { continue; }
        let client = Arc::new(client);
        // Register before looking at the switch: `block` sets it and then closes every
        // registered connection, so a connection accepted around that moment is either seen
        // here as paused or closed there. An unregistered connection could not be cut later.
        let Some(slot) = gate.conns.add(&client) else { let _ = client.shutdown(Shutdown::Both); continue };
        let paused = gate.paused.load(Ordering::SeqCst);
        if !paused { gate.active.store(crate::paths::now_millis(), Ordering::SeqCst); }
        let node = gate.node.read().map(|n| n.clone()).unwrap_or_default();
        let (conns, tag) = (gate.conns.clone(), gate.tag.clone());
        let spawned = std::thread::Builder::new().name("relay-conn".into()).spawn({
            let conns = conns.clone();
            move || {
                // Blocked: only the identity question is answered, nothing is forwarded.
                let _ = handle(&client, &node, &tag, paused);
                conns.remove(slot);
            }
        });
        if spawned.is_err() { conns.remove(slot); }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Host { Name(String), Ip(IpAddr) }

#[derive(Clone, Debug, PartialEq)]
struct Target { host: Host, port: u16 }

impl Target {
    fn authority(&self) -> String {
        match &self.host {
            Host::Name(n) => format!("{n}:{}", self.port),
            Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", self.port),
            Host::Ip(ip) => format!("{ip}:{}", self.port),
        }
    }
    fn parse(authority: &str, default_port: u16) -> Option<Target> {
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (h, tail) = rest.split_once(']')?;
            (h, tail.strip_prefix(':').map(|p| p.parse().ok()).unwrap_or(Some(default_port))?)
        } else if let Some((h, p)) = authority.rsplit_once(':') {
            (h, p.parse().ok()?)
        } else {
            (authority, default_port)
        };
        if host.is_empty() || port == 0 { return None; }
        let host = match host.parse::<IpAddr>() { Ok(ip) => Host::Ip(ip), Err(_) => Host::Name(host.to_ascii_lowercase()) };
        Some(Target { host, port })
    }
}

fn handle(client: &TcpStream, node: &NodeConfig, tag: &str, paused: bool) -> io::Result<()> {
    client.set_read_timeout(Some(if paused { Duration::from_secs(3) } else { HANDSHAKE_TIMEOUT }))?;
    client.set_nodelay(true)?;
    let mut first = [0u8; 1];
    if client.peek(&mut first)? == 0 { return Ok(()); }
    if first[0] == 5 { if paused { Ok(()) } else { socks_server(client, node) } } else { http_server(client, node, tag, paused) }
}

fn socks_server(client: &TcpStream, node: &NodeConfig) -> io::Result<()> {
    let mut client = client;
    let mut head = [0u8; 2];
    client.read_exact(&mut head)?;
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) { return client.write_all(&[5, 0xFF]); }
    client.write_all(&[5, 0])?;
    let mut req = [0u8; 4];
    client.read_exact(&mut req)?;
    let host = read_socks_addr(&mut client, req[3])?;
    let mut port = [0u8; 2];
    client.read_exact(&mut port)?;
    let reply = |client: &mut &TcpStream, code: u8| client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
    if req[1] != 1 {
        // UDP ASSOCIATE / BIND: refused so UDP never leaves outside the node.
        return reply(&mut client, 7);
    }
    let target = Target { host, port: u16::from_be_bytes(port) };
    match open_tunnel(node, &target) {
        Ok((upstream, early)) => { reply(&mut client, 0)?; client.write_all(&early)?; pipe(client, upstream) }
        Err(_) => reply(&mut client, 5),
    }
}

fn read_socks_addr(s: &mut impl Read, atyp: u8) -> io::Result<Host> {
    Ok(match atyp {
        1 => { let mut b = [0u8; 4]; s.read_exact(&mut b)?; Host::Ip(IpAddr::from(b)) }
        4 => { let mut b = [0u8; 16]; s.read_exact(&mut b)?; Host::Ip(IpAddr::from(b)) }
        3 => {
            let mut len = [0u8; 1]; s.read_exact(&mut len)?;
            let mut b = vec![0u8; len[0] as usize]; s.read_exact(&mut b)?;
            Host::Name(String::from_utf8(b).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad host"))?)
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad address type")),
    })
}

/// Reads an HTTP head (up to the blank line). Returns the head and any bytes read past it.
fn read_head(s: &mut impl Read) -> io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = s.read(&mut chunk)?;
        if n == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            return Ok((String::from_utf8_lossy(&buf).into_owned(), rest));
        }
        if buf.len() > 64 * 1024 { return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large")); }
    }
}

fn http_server(client: &TcpStream, node: &NodeConfig, tag: &str, paused: bool) -> io::Result<()> {
    let mut client = client;
    let (head, rest) = read_head(&mut client)?;
    let mut lines = head.split("\r\n");
    let request = lines.next().unwrap_or_default();
    let mut parts = request.split(' ');
    let (method, uri, version) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default(), parts.next().unwrap_or("HTTP/1.1"));
    let bad = |client: &mut &TcpStream, code: &str| client.write_all(format!("HTTP/1.1 {code}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes());
    // Origin-form is never a proxy request, so this path cannot shadow a real destination.
    if method == "GET" && uri == IDENTITY_PATH && !tag.is_empty() {
        return client.write_all(format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{tag}", tag.len()).as_bytes());
    }
    if paused { return bad(&mut client, "503 Service Unavailable"); }
    if method.eq_ignore_ascii_case("CONNECT") {
        let Some(target) = Target::parse(uri, 443) else { return bad(&mut client, "400 Bad Request") };
        return match open_tunnel(node, &target) {
            Ok((mut upstream, early)) => {
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                client.write_all(&early)?;
                if !rest.is_empty() { upstream.write_all(&rest)?; }
                pipe(client, upstream)
            }
            Err(_) => bad(&mut client, "502 Bad Gateway"),
        };
    }
    // Absolute-form plain HTTP request: tunnel to the origin and rewrite to origin-form.
    let Some(after) = uri.strip_prefix("http://") else { return bad(&mut client, "400 Bad Request") };
    let (authority, path) = after.split_at(after.find('/').unwrap_or(after.len()));
    let Some(target) = Target::parse(authority, 80) else { return bad(&mut client, "400 Bad Request") };
    let mut out = format!("{method} {} {version}\r\n", if path.is_empty() { "/" } else { path });
    for line in lines.filter(|l| !l.is_empty()) {
        let name = line.split(':').next().unwrap_or_default().trim().to_ascii_lowercase();
        if !matches!(name.as_str(), "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive") {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out.push_str("Connection: close\r\n\r\n");
    match open_tunnel(node, &target) {
        Ok((mut upstream, early)) => {
            upstream.write_all(out.as_bytes())?;
            if !rest.is_empty() { upstream.write_all(&rest)?; }
            client.write_all(&early)?;
            pipe(client, upstream)
        }
        Err(_) => bad(&mut client, "502 Bad Gateway"),
    }
}

// ---- upstream -------------------------------------------------------------------------

enum Upstream {
    Tcp(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Upstream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> { match self { Upstream::Tcp(s) => s.read(b), Upstream::Tls(s) => s.read(b) } }
}
impl Write for Upstream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> { match self { Upstream::Tcp(s) => s.write(b), Upstream::Tls(s) => s.write(b) } }
    fn flush(&mut self) -> io::Result<()> { match self { Upstream::Tcp(s) => s.flush(), Upstream::Tls(s) => s.flush() } }
}
impl Upstream {
    fn socket(&self) -> &TcpStream { match self { Upstream::Tcp(s) => s, Upstream::Tls(s) => s.get_ref() } }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static C: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    C.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().expect("tls versions")
            .with_root_certificates(roots).with_no_client_auth())
    }).clone()
}

fn connect_node(node: &NodeConfig) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = (node.host.as_str(), node.port).to_socket_addrs()?.collect();
    let mut last = io::Error::new(io::ErrorKind::NotFound, "node address not found");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => { s.set_nodelay(true)?; return Ok(s); }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Opens a tunnel to `target` through the node. Also returns bytes of the target's stream
/// that arrived together with the node's reply; they belong to the client.
fn open_tunnel(node: &NodeConfig, target: &Target) -> io::Result<(Upstream, Vec<u8>)> {
    if node.host.is_empty() { return Err(io::Error::new(io::ErrorKind::NotConnected, "no route")); }
    let tcp = connect_node(node)?;
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut up = match node.kind.as_str() {
        "https" => {
            let name = rustls::pki_types::ServerName::try_from(node.host.clone()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad TLS name"))?;
            let conn = rustls::ClientConnection::new(tls_config(), name).map_err(io::Error::other)?;
            Upstream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
        }
        _ => Upstream::Tcp(tcp),
    };
    let early = if node.kind == "socks5" { socks_client(&mut up, node, target)?; Vec::new() } else { connect_client(&mut up, node, target)? };
    up.socket().set_read_timeout(None)?;
    up.socket().set_write_timeout(None)?;
    Ok((up, early))
}

fn socks_client(s: &mut Upstream, node: &NodeConfig, target: &Target) -> io::Result<()> {
    let auth = !node.username.is_empty();
    s.write_all(if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] })?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel)?;
    let fail = |m: &str| io::Error::new(io::ErrorKind::PermissionDenied, m.to_string());
    match sel[1] {
        0 => {}
        2 if auth => {
            let mut msg = vec![1, node.username.len() as u8];
            msg.extend_from_slice(node.username.as_bytes());
            msg.push(node.password.len() as u8);
            msg.extend_from_slice(node.password.as_bytes());
            s.write_all(&msg)?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r)?;
            if r[1] != 0 { return Err(fail("socks auth rejected")); }
        }
        _ => return Err(fail("socks method rejected")),
    }
    let mut req = vec![5, 1, 0];
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => { req.push(1); req.extend_from_slice(&ip.octets()); }
        Host::Ip(IpAddr::V6(ip)) => { req.push(4); req.extend_from_slice(&ip.octets()); }
        Host::Name(n) => {
            if n.len() > 255 { return Err(fail("host too long")); }
            req.push(3); req.push(n.len() as u8); req.extend_from_slice(n.as_bytes());
        }
    }
    req.extend_from_slice(&target.port.to_be_bytes());
    s.write_all(&req)?;
    let mut rep = [0u8; 4];
    s.read_exact(&mut rep)?;
    if rep[1] != 0 { return Err(fail("socks connect rejected")); }
    read_socks_addr(s, rep[3])?;
    let mut port = [0u8; 2];
    s.read_exact(&mut port)
}

fn connect_client(s: &mut Upstream, node: &NodeConfig, target: &Target) -> io::Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let authority = target.authority();
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if !node.username.is_empty() {
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", STANDARD.encode(format!("{}:{}", node.username, node.password))));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())?;
    s.flush()?;
    let (head, early) = read_head(s)?;
    let ok = head.split(' ').nth(1).map(|c| c == "200").unwrap_or(false);
    if !ok { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "proxy refused CONNECT")); }
    Ok(early)
}

// ---- piping ---------------------------------------------------------------------------

fn copy_half(mut from: impl Read, mut to: impl Write) -> io::Result<u64> {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0;
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 { return Ok(total); }
        to.write_all(&buf[..n])?;
        to.flush()?;
        total += n as u64;
    }
}

fn pipe(client: &TcpStream, upstream: Upstream) -> io::Result<()> {
    client.set_read_timeout(None)?;
    match upstream {
        Upstream::Tcp(up) => {
            // Both directions share the two sockets by reference; a cloned handle would be
            // inheritable on Windows (see `Conns`).
            std::thread::scope(|scope| {
                scope.spawn(|| { let _ = copy_half(client, &up); let _ = up.shutdown(Shutdown::Write); });
                let _ = copy_half(&up, client);
                let _ = client.shutdown(Shutdown::Write);
            });
            Ok(())
        }
        Upstream::Tls(mut tls) => {
            // A TLS stream cannot be split; poll both sides with short timeouts.
            let tick = Some(Duration::from_millis(25));
            client.set_read_timeout(tick)?;
            tls.get_ref().set_read_timeout(tick)?;
            let mut client = client;
            let mut buf = [0u8; 16 * 1024];
            let would_block = |e: &io::Error| matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut);
            loop {
                match client.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => { tls.write_all(&buf[..n])?; tls.flush()?; }
                    Err(e) if would_block(&e) => {}
                    Err(e) => return Err(e),
                }
                match tls.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => client.write_all(&buf[..n])?,
                    Err(e) if would_block(&e) => {}
                    Err(e) => return Err(e),
                }
            }
            let _ = client.shutdown(Shutdown::Both);
            tls.conn.send_close_notify();
            let _ = tls.flush();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, TcpListener};

    /// Fake upstream SOCKS5 server requiring user/pass; echoes the requested target back.
    fn fake_socks(user: &'static str, pass: &'static str) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().take(4) {
                let mut s = s.unwrap();
                std::thread::spawn(move || {
                    let mut h = [0u8; 2]; s.read_exact(&mut h).unwrap();
                    let mut m = vec![0u8; h[1] as usize]; s.read_exact(&mut m).unwrap();
                    assert!(m.contains(&2));
                    s.write_all(&[5, 2]).unwrap();
                    let mut v = [0u8; 2]; s.read_exact(&mut v).unwrap();
                    let mut u = vec![0u8; v[1] as usize]; s.read_exact(&mut u).unwrap();
                    let mut pl = [0u8; 1]; s.read_exact(&mut pl).unwrap();
                    let mut p = vec![0u8; pl[0] as usize]; s.read_exact(&mut p).unwrap();
                    let ok = u == user.as_bytes() && p == pass.as_bytes();
                    s.write_all(&[1, if ok { 0 } else { 1 }]).unwrap();
                    if !ok { return; }
                    let mut r = [0u8; 4]; s.read_exact(&mut r).unwrap();
                    let host = read_socks_addr(&mut s, r[3]).unwrap();
                    let mut port = [0u8; 2]; s.read_exact(&mut port).unwrap();
                    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                    let line = format!("{host:?}:{}\n", u16::from_be_bytes(port));
                    s.write_all(line.as_bytes()).unwrap();
                    let mut b = [0u8; 64];
                    let n = s.read(&mut b).unwrap_or(0);
                    let _ = s.write_all(&b[..n]);
                });
            }
        });
        port
    }

    /// Fake upstream HTTP proxy requiring Basic auth.
    fn fake_http() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().take(2) {
                let mut s = s.unwrap();
                std::thread::spawn(move || {
                    let (head, _) = read_head(&mut s).unwrap();
                    // "u:p w" base64
                    if !head.contains("Proxy-Authorization: Basic dTpwIHc=") { s.write_all(b"HTTP/1.1 407 Auth\r\n\r\n").unwrap(); return; }
                    let target = head.split(' ').nth(1).unwrap().to_string();
                    s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
                    let mut b = [0u8; 512];
                    let n = s.read(&mut b).unwrap();
                    s.write_all(format!("{target}|{}", String::from_utf8_lossy(&b[..n])).as_bytes()).unwrap();
                });
            }
        });
        port
    }

    fn node(kind: &str, port: u16, user: &str, pass: &str) -> NodeConfig {
        NodeConfig { kind: kind.into(), host: "127.0.0.1".into(), port, username: user.into(), password: pass.into(), ..Default::default() }
    }

    fn start(node: NodeConfig) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || serve(l, Gate::new(node, false)));
        port
    }

    #[test]
    fn new_and_replaced_routes_refuse_traffic_before_validation() {
        let _change = route_change();
        let id = "test-route-validation";
        let port = ensure(id, &node("http", 1, "", ""), None).unwrap();
        let refused = || {
            let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
            c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").unwrap();
            assert!(read_all(&mut c).starts_with("HTTP/1.1 503"));
        };
        refused();
        gate_of(id).unwrap().paused.store(false, Ordering::SeqCst);
        assert_eq!(ensure(id, &node("http", 2, "", ""), None).unwrap(), port);
        // Nothing answers on the node: undecided, never a pass.
        assert!(matches!(validate_exit(id), Verdict::Unverified(_)));
        refused();
        stop(id);
    }

    /// A connection is kept for cutting as the handler's own socket, never as a second handle:
    /// a duplicated handle can leak into a child process started at that moment, which then
    /// holds the connection open and resets it when it exits.
    #[test]
    fn kept_connections_share_the_handlers_socket() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let accepted = Arc::new(l.accept().unwrap().0);
        let conns = Conns { next: AtomicU64::new(0), open: Mutex::new(HashMap::new()) };
        let slot = conns.add(&accepted).unwrap();
        assert!(Arc::ptr_eq(&conns.open.lock().unwrap()[&slot], &accepted));
        // Closing the kept connections still cuts the client off.
        conns.close_all();
        let mut buf = [0u8; 1];
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert!(matches!(client.read(&mut buf), Ok(0) | Err(_)));
    }

    #[test]
    fn relay_answers_its_identity_even_while_paused() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let mut gate = Gate::new(node("socks5", 1, "", ""), false);
        gate.tag = Arc::new(tag("Account 2"));
        let g = gate.clone();
        std::thread::spawn(move || serve(l, g));
        assert!(identified(port, "Account 2"));
        // Another account's relay, or any other program on that port, is not accepted.
        assert!(!identified(port, "Account 3"));
        gate.paused.store(true, Ordering::SeqCst);
        assert!(identified(port, "Account 2"));
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let other_port = other.local_addr().unwrap().port();
        std::thread::spawn(move || for s in other.incoming().take(1) { let _ = s.unwrap().write_all(b"HTTP/1.1 200 OK\r\n\r\nhello"); });
        assert!(!identified(other_port, "Account 2"));
        gate.stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn bytes_sent_with_the_proxy_reply_reach_the_client() {
        // The upstream proxy answers CONNECT and the first payload bytes in one packet.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let up = l.local_addr().unwrap().port();
        std::thread::spawn(move || for s in l.incoming().take(1) {
            let mut s = s.unwrap();
            let _ = read_head(&mut s).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\nEARLY").unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let port = start(node("http", up, "", ""));
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        while !got.ends_with(b"EARLY") {
            let n = c.read(&mut buf).unwrap();
            assert!(n > 0, "relay dropped the early bytes: {:?}", String::from_utf8_lossy(&got));
            got.extend_from_slice(&buf[..n]);
        }
    }

    #[test]
    fn paused_relay_refuses_and_closes_connections() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let gate = Gate::new(node("socks5", fake_socks("u", "p"), "u", "p"), false);
        let g = gate.clone();
        std::thread::spawn(move || serve(l, g));
        // An open tunnel is closed when the relay is paused.
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.write_all(&[5, 1, 0]).unwrap();
        let mut sel = [0u8; 2]; c.read_exact(&mut sel).unwrap();
        c.write_all(&[5, 1, 0, 1, 1, 1, 1, 1, 0, 80]).unwrap();
        let mut rep = [0u8; 10]; c.read_exact(&mut rep).unwrap();
        assert_eq!(rep[1], 0);
        let mut banner = [0u8; 15]; c.read_exact(&mut banner).unwrap();
        gate.paused.store(true, Ordering::SeqCst);
        gate.conns.close_all();
        assert_eq!(read_all(&mut c), "", "tunnel must end when the relay is blocked");
        // New connections are refused.
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let _ = c.write_all(&[5, 1, 0]);
        assert_eq!(read_all(&mut c), "", "a blocked relay must not answer");
    }

    fn read_all(s: &mut TcpStream) -> String {
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn socks_client_hostnames_reach_node_unresolved_with_auth() {
        let relay = start(node("socks5", fake_socks("user", "p@ss"), "user", "p@ss"));
        let mut c = TcpStream::connect(("127.0.0.1", relay)).unwrap();
        c.write_all(&[5, 1, 0]).unwrap();
        let mut sel = [0u8; 2]; c.read_exact(&mut sel).unwrap();
        assert_eq!(sel, [5, 0]);
        let host = b"claude.ai";
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host); req.extend_from_slice(&443u16.to_be_bytes());
        c.write_all(&req).unwrap();
        let mut rep = [0u8; 10]; c.read_exact(&mut rep).unwrap();
        assert_eq!(rep[1], 0);
        c.write_all(b"ping").unwrap();
        let out = read_all(&mut c);
        assert!(out.starts_with("Name(\"claude.ai\"):443\n"), "{out}");
        assert!(out.ends_with("ping"));
    }

    #[test]
    fn socks_udp_associate_is_refused() {
        let relay = start(node("socks5", 1, "", ""));
        let mut c = TcpStream::connect(("127.0.0.1", relay)).unwrap();
        c.write_all(&[5, 1, 0]).unwrap();
        let mut sel = [0u8; 2]; c.read_exact(&mut sel).unwrap();
        c.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        let mut rep = [0u8; 10]; c.read_exact(&mut rep).unwrap();
        assert_eq!(rep[1], 7, "UDP ASSOCIATE must be refused");
    }

    #[test]
    fn wrong_credentials_fail_closed() {
        let relay = start(node("socks5", fake_socks("user", "right"), "user", "wrong"));
        let mut c = TcpStream::connect(("127.0.0.1", relay)).unwrap();
        c.write_all(&[5, 1, 0]).unwrap();
        let mut sel = [0u8; 2]; c.read_exact(&mut sel).unwrap();
        c.write_all(&[5, 1, 0, 1, 1, 1, 1, 1, 0, 80]).unwrap();
        let mut rep = [0u8; 10]; c.read_exact(&mut rep).unwrap();
        assert_ne!(rep[1], 0);
    }

    #[test]
    fn http_connect_and_plain_requests_use_basic_auth() {
        let relay = start(node("http", fake_http(), "u", "p w"));
        let mut c = TcpStream::connect(("127.0.0.1", relay)).unwrap();
        c.write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n").unwrap();
        let (head, _) = read_head(&mut c).unwrap();
        assert!(head.starts_with("HTTP/1.1 200"));
        c.write_all(b"hello").unwrap();
        assert_eq!(read_all(&mut c), "api.anthropic.com:443|hello");

        let mut c = TcpStream::connect(("127.0.0.1", relay)).unwrap();
        c.write_all(b"GET http://example.com/a?b HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n").unwrap();
        let out = read_all(&mut c);
        assert!(out.starts_with("example.com:80|GET /a?b HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"), "{out}");
    }

    /// Real forwarding SOCKS5 node with user/pass auth (for the network test below).
    fn forwarding_socks() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || for s in l.incoming() {
            let mut s = s.unwrap();
            std::thread::spawn(move || {
                let mut h = [0u8; 2]; s.read_exact(&mut h).unwrap();
                let mut m = vec![0u8; h[1] as usize]; s.read_exact(&mut m).unwrap();
                s.write_all(&[5, 2]).unwrap();
                let mut v = [0u8; 2]; s.read_exact(&mut v).unwrap();
                let mut u = vec![0u8; v[1] as usize]; s.read_exact(&mut u).unwrap();
                let mut pl = [0u8; 1]; s.read_exact(&mut pl).unwrap();
                let mut p = vec![0u8; pl[0] as usize]; s.read_exact(&mut p).unwrap();
                s.write_all(&[1, 0]).unwrap();
                let mut r = [0u8; 4]; s.read_exact(&mut r).unwrap();
                let host = match read_socks_addr(&mut s, r[3]).unwrap() { Host::Name(n) => n, Host::Ip(ip) => ip.to_string() };
                let mut port = [0u8; 2]; s.read_exact(&mut port).unwrap();
                let up = TcpStream::connect((host.as_str(), u16::from_be_bytes(port))).unwrap();
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                let _ = pipe(&s, Upstream::Tcp(up));
            });
        });
        port
    }

    #[test]
    #[ignore = "needs internet"]
    fn real_https_through_relay_and_authenticated_node() {
        let n = node("socks5", forwarding_socks(), "user", "pass");
        let relay = start(n.clone());
        let client = crate::node::relay_client(relay, Duration::from_secs(20)).unwrap();
        let info = crate::node::inspect(&client, &NodeConfig { ip_version: "ipv4".into(), geo_channel: "ipinfo".into(), ..n }).unwrap();
        println!("exit via relay: {info:?}");
        assert!(info.ip.parse::<std::net::Ipv4Addr>().is_ok());
        // Plain-HTTP child-process style request through the relay's HTTP side.
        let http = reqwest::blocking::Client::builder().no_proxy().proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{relay}")).unwrap()).build().unwrap();
        assert!(http.get("http://ip-api.com/json/?fields=status").send().unwrap().text().unwrap().contains("success"));
        assert!(http.get("https://api4.ipify.org").send().unwrap().status().is_success());
    }

    fn chrome(args: &[String], url: &str) -> String {
        let exe = std::env::var("HYDRA_TEST_CHROME").expect("set HYDRA_TEST_CHROME to a Chromium binary");
        let profile = std::env::temp_dir().join(format!("hydra-chrome-{}-{}", std::process::id(), crate::paths::now_millis()));
        let out = std::process::Command::new(exe)
            .args(["--headless=new", "--disable-gpu", "--no-first-run", "--timeout=9000"])
            .arg(format!("--user-data-dir={}", profile.display()))
            .args(args).arg("--dump-dom").arg(url).output().unwrap();
        let _ = std::fs::remove_dir_all(profile);
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Runs the real Chromium switches Hydra passes to Claude.
    #[test]
    #[ignore = "needs internet and HYDRA_TEST_CHROME"]
    fn chromium_switches_route_everything_through_relay() {
        let relay = start(node("socks5", forwarding_socks(), "user", "pass"));
        let args = crate::node::chromium_args(relay);
        let direct = chrome(&[], "https://api4.ipify.org");
        let proxied = chrome(&args, "https://api4.ipify.org");
        assert!(proxied.contains("<body>"), "proxied page should load: {proxied}");
        println!("direct and proxied loaded: {} / {}", direct.contains("<body>"), proxied.contains("<body>"));

        // Relay down: nothing loads (no direct fallback).
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let closed = chrome(&crate::node::chromium_args(dead), "https://api4.ipify.org");
        let ip_like = |s: &str| s.split(|c: char| !(c.is_ascii_digit() || c == '.')).any(|t| t.parse::<std::net::Ipv4Addr>().is_ok());
        assert!(!ip_like(&closed), "must not load without the relay: {closed}");

        // WebRTC: no host/srflx candidates may be gathered over UDP. The page is served from
        // loopback (never proxied) and holds its load event open while ICE gathering runs.
        let page = TcpListener::bind("127.0.0.1:0").unwrap();
        let page_port = page.local_addr().unwrap().port();
        std::thread::spawn(move || for s in page.incoming() {
            let mut s = s.unwrap();
            std::thread::spawn(move || {
                let (head, _) = read_head(&mut s).unwrap_or_default();
                if head.starts_with("GET /slow") { std::thread::sleep(Duration::from_secs(5)); let _ = s.write_all(b"HTTP/1.1 404 x\r\nContent-Length: 0\r\n\r\n"); return; }
                let body = "<html><body><pre id=o>CANDS:[]</pre><script>const o=document.getElementById('o');const seen=[];\
                    const pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});\
                    pc.onicecandidate=e=>{if(e.candidate){seen.push(e.candidate.candidate);o.textContent='CANDS:'+JSON.stringify(seen)}};\
                    pc.createDataChannel('x');pc.createOffer().then(x=>pc.setLocalDescription(x));</script><img src=/slow></body></html>";
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
            });
        });
        let url = format!("http://127.0.0.1:{page_port}/rtc");
        let count = |out: &str| out.matches("candidate:").count();
        let baseline = chrome(&[], &url);
        let rtc = chrome(&args, &url);
        println!("webrtc candidates: without switches {}, with switches {}", count(&baseline), count(&rtc));
        assert!(rtc.contains("CANDS:["), "candidate list was not written: {rtc}");
        assert!(!rtc.contains(" udp ") && !rtc.contains(" UDP ") && !rtc.contains("typ srflx"), "WebRTC leaked: {rtc}");

        // DNS: names are resolved at the node; a name the local resolver can't see still loads through it.
        let dns = chrome(&args, "https://ipinfo.io/json");
        assert!(dns.contains("\"ip\""), "{dns}");
    }

    #[test]
    fn parses_authorities() {
        assert_eq!(Target::parse("[::1]:8443", 443), Some(Target { host: Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)), port: 8443 }));
        assert_eq!(Target::parse("Example.COM", 80).unwrap().authority(), "example.com:80");
        assert!(Target::parse(":80", 80).is_none());
    }
}
