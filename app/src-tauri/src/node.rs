//! Per-account proxy node: configuration, credential sealing, exit/region detection.
//!
//! Claude never sees the node itself. It talks to a local relay (see `relay.rs`) that
//! forwards every connection to the node with its credentials, so the password never
//! appears on a command line or in an environment variable.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{io::Read, net::IpAddr, time::Duration};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NodeConfig {
    /// "http" | "https" | "socks5"
    pub kind: String,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// Plain text in memory and over IPC; sealed in `settings.json` (see `seal`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    /// Exit IP version to require when checking: "ipv4" | "ipv6".
    #[serde(default)]
    pub ip_version: String,
    /// IP lookup service: "ipinfo" | "ipapi" | "ip-api".
    #[serde(default)]
    pub geo_channel: String,
    /// Provider URL that rotates the node's exit IP (called directly, not through the node).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub refresh_url: String,
    /// Front (transit) proxy this node is dialed through: local relay -> `via` -> this node ->
    /// target. The exit stays this node. Chains run inside the managed Mihomo core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<Box<NodeConfig>>,
}

/// Longest chain: the exit node plus this many front proxies.
pub const MAX_FRONT: usize = 3;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExitInfo {
    pub ip: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub checked_at: u64,
}

impl NodeConfig {
    /// Normalises and validates user input. Errors are user-facing.
    pub fn validated(&self) -> Result<NodeConfig, String> {
        let mut n = self.clone();
        if let Some(front) = &n.via {
            if front.depth() > MAX_FRONT { return Err(format!("代理链最多支持 {MAX_FRONT} 个前置节点。")); }
            n.via = Some(Box::new(front.validated().map_err(|e| format!("前置代理：{e}"))?));
        }
        n.kind = n.kind.trim().to_ascii_lowercase();
        n.host = n.host.trim().trim_start_matches('[').trim_end_matches(']').to_string();
        n.username = n.username.trim().to_string();
        n.refresh_url = n.refresh_url.trim().to_string();
        if n.kind == "clash" {
            let proxy: Value = serde_json::from_str(&n.password).map_err(|_| "Clash 节点无效。")?;
            if proxy.get("server").and_then(Value::as_str) != Some(&n.host) || n.port == 0 || proxy["type"].as_str().is_none() {
                return Err("Clash 节点缺少类型、服务器或端口。".into());
            }
            return Ok(n);
        }
        if !matches!(n.kind.as_str(), "http" | "https" | "socks5") { return Err("代理类型只支持 HTTP、HTTPS 或 SOCKS5。".into()); }
        if n.host.is_empty() || n.host.len() > 253 || !n.host.chars().all(|c| c.is_ascii_alphanumeric() || ".-_:".contains(c)) {
            return Err("代理主机无效。".into());
        }
        if n.port == 0 { return Err("代理端口无效。".into()); }
        if n.username.len() > 200 || n.password.len() > 200 { return Err("代理账号或密码过长（最多 200 个字符）。".into()); }
        if n.username.is_empty() && !n.password.is_empty() { return Err("填写了代理密码时也需要填写代理账号。".into()); }
        if n.username.chars().chain(n.password.chars()).any(char::is_control) { return Err("代理账号或密码包含无效字符。".into()); }
        if n.kind == "socks5" && (n.username.len() > 255 || n.password.len() > 255) { return Err("SOCKS5 账号或密码过长。".into()); }
        if !matches!(n.ip_version.as_str(), "ipv4" | "ipv6") { n.ip_version = "ipv4".into(); }
        if !matches!(n.geo_channel.as_str(), "ipinfo" | "ipapi" | "ip-api") { n.geo_channel = "ipinfo".into(); }
        if !n.refresh_url.is_empty() {
            let u = url::Url::parse(&n.refresh_url).map_err(|_| "刷新 URL 无效。")?;
            if !matches!(u.scheme(), "http" | "https") { return Err("刷新 URL 只支持 http 或 https。".into()); }
        }
        Ok(n)
    }

    /// Number of hops in this chain, itself included.
    pub fn depth(&self) -> usize {
        1 + self.via.as_ref().map_or(0, |v| v.depth())
    }

    /// Copy with every password in the chain sealed for `settings.json`.
    pub fn sealed(&self) -> NodeConfig {
        let mut n = self.clone();
        n.password = seal(&n.password);
        n.via = n.via.map(|v| Box::new(v.sealed()));
        n
    }

    /// Copy with every password in the chain readable again; `None` when one cannot be
    /// decrypted (settings copied from another Windows user or machine).
    pub fn unsealed(&self) -> Option<NodeConfig> {
        let mut n = self.clone();
        n.password = try_unseal(&n.password)?;
        n.via = match n.via { Some(v) => Some(Box::new(v.unsealed()?)), None => None };
        Some(n)
    }

    /// Parses a legacy `scheme://host:port` endpoint saved by earlier versions.
    pub fn from_legacy(endpoint: &str) -> Option<NodeConfig> {
        let u = url::Url::parse(endpoint.trim()).ok()?;
        let kind = match u.scheme() { "socks5" | "socks5h" => "socks5", s @ ("http" | "https") => s, _ => return None };
        Some(NodeConfig { kind: kind.into(), host: u.host_str()?.trim_matches(['[', ']']).into(), port: u.port_or_known_default()?, ..Default::default() }
            .validated().ok()?)
    }

    /// Upstream URL for reqwest, with percent-encoded credentials and remote DNS for SOCKS.
    fn reqwest_proxy(&self) -> Result<reqwest::Proxy, String> {
        let scheme = if self.kind == "socks5" { "socks5h" } else { &self.kind };
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        let mut u = url::Url::parse(&format!("{scheme}://{host}:{}", self.port)).map_err(|_| "代理地址无效。")?;
        if !self.username.is_empty() {
            u.set_username(&self.username).map_err(|_| "代理账号无效。")?;
            u.set_password(Some(&self.password)).map_err(|_| "代理密码无效。")?;
        }
        reqwest::Proxy::all(u.as_str()).map_err(|_| "代理地址无效。".into())
    }

    /// A client that reaches the internet only through this node (never directly).
    pub fn client(&self, timeout: Duration) -> Result<reqwest::blocking::Client, String> {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .proxy(self.reqwest_proxy()?)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| "无法初始化代理连接。".into())
    }
}

/// A client whose only route is the given local relay port.
pub fn relay_client(port: u16, timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")).map_err(|_| "本地中继地址无效。")?;
    reqwest::blocking::Client::builder().no_proxy().proxy(proxy).redirect(reqwest::redirect::Policy::none())
        .timeout(timeout).build().map_err(|_| "无法初始化本地中继连接。".into())
}

/// Why one request to a check service failed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Failure {
    Timeout,
    /// The node, a front proxy or the service could not be reached (includes a refused
    /// proxy login: reqwest reports a failed tunnel as a connect error).
    Connect,
    Status(u16, Option<Duration>),
    Read,
    Other,
}

impl Failure {
    fn describe(&self) -> String {
        match self {
            Failure::Timeout => "超时".into(),
            Failure::Connect => "连接失败".into(),
            Failure::Status(429, _) => "HTTP 429 限流".into(),
            Failure::Status(code, _) => format!("HTTP {code}"),
            Failure::Read => "读取响应失败".into(),
            Failure::Other => "请求失败".into(),
        }
    }
}

fn fetch(client: &reqwest::blocking::Client, url: &str, limit: u64) -> Result<String, Failure> {
    let resp = client.get(url).header("accept", "application/json, text/plain").send().map_err(|e| {
        if e.is_timeout() { Failure::Timeout } else if e.is_connect() { Failure::Connect } else { Failure::Other }
    })?;
    let status = resp.status();
    if !status.is_success() {
        let wait = resp.headers().get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok()).map(Duration::from_secs);
        return Err(Failure::Status(status.as_u16(), wait));
    }
    let mut text = String::new();
    resp.take(limit).read_to_string(&mut text).map_err(|e| if e.kind() == std::io::ErrorKind::TimedOut { Failure::Timeout } else { Failure::Read })?;
    Ok(text)
}

fn get_text(client: &reqwest::blocking::Client, url: &str, limit: u64) -> Result<String, String> {
    fetch(client, url, limit).map_err(|f| format!("访问 {} {}。", host_of(url), f.describe()))
}

fn host_of(url: &str) -> String {
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_else(|| url.to_string())
}

/// One request made while checking a route, kept for the diagnostics log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// "ip" or "geo".
    pub stage: &'static str,
    pub host: String,
    /// "ok", or what went wrong.
    pub outcome: String,
    pub ms: u128,
}

/// Rate limited services, per route: a 429 is about the exit IP that asked, so another
/// account's exit may still use the service.
fn cooldowns() -> &'static std::sync::Mutex<std::collections::HashMap<(String, String), std::time::Instant>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<(String, String), std::time::Instant>>> = std::sync::OnceLock::new();
    C.get_or_init(Default::default)
}

const DEFAULT_COOLDOWN: Duration = Duration::from_secs(600);
const MAX_COOLDOWN: Duration = Duration::from_secs(3600);

fn cooling(route: &str, host: &str) -> bool {
    let Ok(mut map) = cooldowns().lock() else { return false };
    let key = (route.to_string(), host.to_string());
    match map.get(&key) {
        Some(until) if *until > std::time::Instant::now() => true,
        Some(_) => { map.remove(&key); false }
        None => false,
    }
}

fn cool_down(route: &str, host: &str, wait: Option<Duration>) {
    let wait = wait.unwrap_or(DEFAULT_COOLDOWN).clamp(Duration::from_secs(30), MAX_COOLDOWN);
    if let Ok(mut map) = cooldowns().lock() { map.insert((route.to_string(), host.to_string()), std::time::Instant::now() + wait); }
}

/// One check request: skipped while the service is rate limited for this route, recorded in
/// `attempts` either way.
fn attempt(client: &reqwest::blocking::Client, route: &str, stage: &'static str, url: &str, limit: u64, attempts: &mut Vec<Attempt>) -> Option<String> {
    let host = host_of(url);
    if cooling(route, &host) {
        attempts.push(Attempt { stage, host, outcome: "限流冷却中，已跳过".into(), ms: 0 });
        return None;
    }
    let started = std::time::Instant::now();
    let result = fetch(client, url, limit);
    let ms = started.elapsed().as_millis();
    match result {
        Ok(text) => { attempts.push(Attempt { stage, host, outcome: "ok".into(), ms }); Some(text) }
        Err(f) => {
            if let Failure::Status(429, wait) = f { cool_down(route, &host, wait); }
            attempts.push(Attempt { stage, host, outcome: f.describe(), ms });
            None
        }
    }
}

/// Marks the last attempt as unusable although the request itself succeeded.
fn reject(attempts: &mut [Attempt], why: &str) {
    if let Some(last) = attempts.last_mut() { last.outcome = why.to_string(); }
}

pub fn valid_timezone(tz: &str) -> bool {
    let ok = !tz.is_empty() && tz.len() <= 64 && tz.contains('/') || tz == "UTC";
    ok && tz.chars().all(|c| c.is_ascii_alphanumeric() || "/_+-".contains(c)) && !tz.contains("..")
        && (cfg!(windows) || !std::path::Path::new("/usr/share/zoneinfo").is_dir() || std::path::Path::new("/usr/share/zoneinfo").join(tz).is_file())
}

fn parse_geo(channel: &str, body: &str) -> Result<ExitInfo, String> {
    let v: Value = serde_json::from_str(body).map_err(|_| "IP 查询服务返回了无法识别的数据。")?;
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let info = match channel {
        "ip-api" => {
            if s("status") != "success" { return Err(format!("IP 查询失败：{}", s("message"))); }
            ExitInfo { ip: s("query"), country: s("countryCode"), region: s("regionName"), city: s("city"), timezone: s("timezone"), checked_at: 0 }
        }
        "ipapi" => {
            if v.get("error").and_then(Value::as_bool) == Some(true) { return Err(format!("IP 查询失败：{}", s("reason"))); }
            ExitInfo { ip: s("ip"), country: s("country_code"), region: s("region"), city: s("city"), timezone: s("timezone"), checked_at: 0 }
        }
        _ => ExitInfo { ip: s("ip"), country: s("country"), region: s("region"), city: s("city"), timezone: s("timezone"), checked_at: 0 },
    };
    if info.ip.parse::<IpAddr>().is_err() { return Err("IP 查询服务未返回有效的出口 IP。".into()); }
    Ok(info)
}

fn geo_url(channel: &str, ip: IpAddr) -> String {
    match channel {
        "ipapi" => format!("https://ipapi.co/{ip}/json/"),
        "ip-api" => format!("http://ip-api.com/json/{ip}?fields=status,message,query,countryCode,regionName,city,timezone"),
        _ => format!("https://ipinfo.io/{ip}/json"),
    }
}

/// Cloudflare's trace page in front of claude.ai: the exit IP and country exactly as the edge
/// Claude talks to sees them.
const EDGE_TRACE: &str = "https://claude.ai/cdn-cgi/trace";
/// The same page in front of the API Claude Code talks to. A proxy that routes by domain can send
/// it through another exit than claude.ai.
const API_TRACE: &str = "https://api.anthropic.com/cdn-cgi/trace";

/// `(ip, country)` from a Cloudflare trace body.
fn parse_trace(body: &str) -> Option<(IpAddr, String)> {
    let field = |k: &str| body.lines().find_map(|l| l.strip_prefix(k).map(str::trim));
    let ip = field("ip=")?.parse().ok()?;
    let loc = field("loc=").unwrap_or_default();
    // "XX" / "T1" are Cloudflare's unknown / Tor markers, not countries.
    let country = if loc.len() == 2 && loc.chars().all(|c| c.is_ascii_alphabetic()) && loc != "XX" { loc.to_ascii_uppercase() } else { String::new() };
    Some((ip, country))
}

/// Everything one route check found, also when it could not finish.
#[derive(Clone, Debug, Default)]
pub struct Inspection {
    /// Exit IP of the required version, when any IP source answered.
    pub ip: Option<IpAddr>,
    /// Country Cloudflare's edge in front of claude.ai placed the exit in ("" = unknown).
    pub edge_country: String,
    /// Exit IP as the API's edge sees it; `None` when that check did not answer.
    pub api_ip: Option<IpAddr>,
    /// Country the API's edge placed that exit in ("" = unknown).
    pub api_country: String,
    /// The full result (IP, country, region, city, timezone), when the check finished.
    pub exit: Option<ExitInfo>,
    /// The location came from the previous verified exit because the IP did not change.
    pub reused: bool,
    pub attempts: Vec<Attempt>,
    pub(crate) v6: bool,
}

impl Inspection {
    /// One line per check for the diagnostics log: every request with its result and time.
    pub fn trail(&self) -> String {
        self.attempts.iter().map(|a| format!("{}:{} {} {}ms", a.stage, a.host, a.outcome, a.ms)).collect::<Vec<_>>().join("; ")
    }

    /// User-facing reason the check did not finish.
    pub fn failure(&self) -> String {
        let failed = |stage: &str| self.attempts.iter().filter(|a| a.stage == stage)
            .map(|a| format!("{} {}", a.host, a.outcome)).collect::<Vec<_>>().join("，");
        if self.ip.is_none() {
            let all_connect = !self.attempts.is_empty() && self.attempts.iter().all(|a| a.outcome == "连接失败");
            let hint = if all_connect { "所有检测请求都连不上，请检查节点是否在线、地址、账号和密码。" }
                else if self.v6 { "节点可能不支持 IPv6 出口。" } else { "" };
            return format!("查询出口 IP 失败（{}）。{hint}", failed("ip"));
        }
        format!("出口 IP {} 已确认，但位置服务都没有返回结果（{}）。", self.ip.map(|i| i.to_string()).unwrap_or_default(), failed("geo"))
    }

    /// Why claude.ai and the API are proven to leave through different countries. Both countries
    /// come from the same edge, and a rotating exit in one country is not a split.
    pub fn api_split(&self) -> Option<String> {
        let (main, api) = (self.ip?, self.api_ip?);
        let (edge, other) = (self.edge_country.as_str(), self.api_country.as_str());
        (main != api && !edge.is_empty() && !other.is_empty() && edge != other).then(|| format!(
            "claude.ai 和 Claude API 走了不同国家的出口（{edge} 与 {other}），代理可能在按域名分流。请让 Claude 的全部流量走同一个节点。"
        ))
    }

    pub fn into_result(self) -> Result<ExitInfo, String> {
        if let Some(reason) = self.api_split() { return Err(reason); }
        match self.exit { Some(exit) => Ok(exit), None => Err(self.failure()) }
    }
}

/// Checks a route end to end: exit IP of the required version, then its region and timezone.
/// Each step falls back to another public service, so one service being down or rate
/// limited does not cut every account's network.
pub fn inspect(client: &reqwest::blocking::Client, node: &NodeConfig) -> Result<ExitInfo, String> {
    inspect_known(client, node, None).into_result()
}

/// Like `inspect`, but when the exit IP equals `known`'s (a previously verified exit of the
/// same route) its location is reused instead of asking a location service again.
pub fn inspect_known(client: &reqwest::blocking::Client, node: &NodeConfig, known: Option<&ExitInfo>) -> Inspection {
    let v6 = node.ip_version == "ipv6";
    let route = format!("{}:{}", node.host, node.port);
    let mut out = Inspection { v6, ..Default::default() };
    let wanted = |ip: &IpAddr| ip.is_ipv6() == v6;
    if let Some(body) = attempt(client, &route, "ip", EDGE_TRACE, 4096, &mut out.attempts) {
        match parse_trace(&body) {
            Some((ip, country)) if wanted(&ip) => { out.ip = Some(ip); out.edge_country = country; }
            Some(_) => reject(&mut out.attempts, if v6 { "返回的是 IPv4 地址" } else { "返回的是 IPv6 地址" }),
            None => reject(&mut out.attempts, "返回了无法识别的数据"),
        }
    }
    let sources: [&str; 2] = if v6 { ["https://api6.ipify.org", "https://ipv6.icanhazip.com"] } else { ["https://api4.ipify.org", "https://ipv4.icanhazip.com"] };
    for url in sources {
        if out.ip.is_some() { break; }
        if let Some(text) = attempt(client, &route, "ip", url, 64, &mut out.attempts) {
            match text.trim().parse::<IpAddr>() {
                Ok(found) if wanted(&found) => out.ip = Some(found),
                Ok(_) => reject(&mut out.attempts, "返回了另一种 IP 版本"),
                Err(_) => reject(&mut out.attempts, "未返回有效 IP"),
            }
        }
    }
    let Some(ip) = out.ip else { return out };
    // Optional: an API edge that does not answer says nothing about the route.
    if let Some(body) = attempt(client, &route, "api", API_TRACE, 4096, &mut out.attempts) {
        match parse_trace(&body) {
            Some((api, country)) if wanted(&api) => { out.api_ip = Some(api); out.api_country = country; }
            Some(_) => reject(&mut out.attempts, if v6 { "返回的是 IPv4 地址" } else { "返回的是 IPv6 地址" }),
            None => reject(&mut out.attempts, "返回了无法识别的数据"),
        }
    }
    if let Some(known) = known.filter(|k| k.ip.parse::<IpAddr>().ok() == Some(ip) && !k.country.trim().is_empty()) {
        out.exit = Some(ExitInfo { checked_at: crate::paths::now_millis(), ..known.clone() });
        out.reused = true;
        return out;
    }
    let chosen = match node.geo_channel.as_str() { c @ ("ipapi" | "ip-api") => c, _ => "ipinfo" };
    for channel in std::iter::once(chosen).chain(["ipinfo", "ipapi", "ip-api"].into_iter().filter(|c| *c != chosen)) {
        let Some(body) = attempt(client, &route, "geo", &geo_url(channel, ip), 16 * 1024, &mut out.attempts) else { continue };
        let found = parse_geo(channel, &body).and_then(|info| {
            if info.ip.parse::<IpAddr>().ok() != Some(ip) { return Err("返回了其他 IP 的结果".to_string()); }
            // A result without a country cannot be judged by the exit rules.
            if info.country.trim().is_empty() { return Err("未返回国家".to_string()); }
            Ok(info)
        });
        match found {
            Ok(mut info) => {
                if !valid_timezone(&info.timezone) { info.timezone.clear(); }
                info.checked_at = crate::paths::now_millis();
                out.exit = Some(info);
                return out;
            }
            Err(e) => reject(&mut out.attempts, e.trim_end_matches('。')),
        }
    }
    out
}

/// Classification is optional and never participates in the launch check.
pub fn network_quality(client: &reqwest::blocking::Client, ip: &str) -> Option<String> {
    let lookup = |url: &str| -> Option<Value> {
        serde_json::from_str(&get_text(client, url, 128 * 1024).ok()?).ok()
    };
    let routing = lookup(&format!("https://stat.ripe.net/data/network-info/data.json?resource={ip}"))?;
    let origins = routing.pointer("/data/asns")?.as_array()?;
    // Multiple origin ASNs cannot be attributed to a single network operator.
    if origins.len() != 1 { return None; }
    let asn = origins[0].as_str().and_then(|v| v.parse::<u32>().ok())
        .or_else(|| origins[0].as_u64().and_then(|n| u32::try_from(n).ok()))?;
    // MIT-licensed hosting list from github.com/brianhama/bad-asn-list.
    let number = asn.to_string();
    let known_host = include_str!("data/hosting-asns.txt").lines().any(|line| line.trim() == number);
    let (home, hosting, basis) = if known_host {
        ("低", "高", "开源托管 ASN 名单")
    } else {
        let network = lookup(&format!("https://www.peeringdb.com/api/net?asn={asn}"))?;
        match network.pointer("/data/0/info_type")?.as_str()? {
            "Cable/DSL/ISP" => ("较高", "较低", "PeeringDB 宽带运营商"),
            "Content" | "NSP" | "Enterprise" => ("未知", "未知", "网络类型不足以区分家宽与机房"),
            _ => return None,
        }
    };
    Some(format!("家宽可能性：{home} · 机房可能性：{hosting}（AS{asn}，{basis}）"))
}

/// IPsum level 3 contains IPv4 addresses reported by at least three source lists.
pub fn reputation(client: &reqwest::blocking::Client, ip: &str) -> &'static str {
    if ip.parse::<std::net::Ipv4Addr>().is_err() { return "IPsum 风险记录：不覆盖 IPv6"; }
    const LIMIT: u64 = 2 * 1024 * 1024;
    let url = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt";
    let Ok(list) = get_text(client, url, LIMIT) else { return "IPsum 风险记录：查询失败"; };
    if list.len() as u64 >= LIMIT || list.lines().next().and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()).is_none() {
        return "IPsum 风险记录：数据不完整";
    }
    if list.lines().any(|entry| entry.trim() == ip) {
        "IPsum 风险记录：命中至少三份风险名单"
    } else {
        "IPsum 风险记录：未命中三源风险名单"
    }
}

/// Calls the provider's IP rotation URL directly and returns a short status line.
pub fn refresh(url: &str) -> Result<String, String> {
    let u = url::Url::parse(url.trim()).map_err(|_| "刷新 URL 无效。")?;
    if !matches!(u.scheme(), "http" | "https") { return Err("刷新 URL 只支持 http 或 https。".into()); }
    let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(15)).build().map_err(|_| "无法初始化网络连接。")?;
    let resp = client.get(u).send().map_err(|_| "无法访问刷新 URL。")?;
    let status = resp.status();
    let mut body = String::new();
    let _ = resp.take(300).read_to_string(&mut body);
    let body: String = body.chars().filter(|c| !c.is_control()).take(120).collect();
    if status.is_success() { Ok(format!("已请求刷新（HTTP {}）{}", status.as_u16(), if body.is_empty() { String::new() } else { format!("：{body}") })) }
    else { Err(format!("刷新失败（HTTP {}）{}", status.as_u16(), if body.is_empty() { String::new() } else { format!("：{body}") })) }
}

// ---- credential sealing -------------------------------------------------------------

/// Seals a secret for `settings.json`; `secret` owns the per-platform scheme (DPAPI, the macOS
/// login Keychain, or owner-only file permissions as the last resort).
pub fn seal(secret: &str) -> String { crate::secret::seal(secret) }

pub fn try_unseal(stored: &str) -> Option<String> { crate::secret::try_unseal(stored) }

pub fn unseal(stored: &str) -> String { crate::secret::unseal(stored) }

// ---- launch arguments ---------------------------------------------------------------

/// Chromium switches that would override or bypass the managed proxy.
const PROXY_SWITCHES: [&str; 6] = ["--proxy-server", "--no-proxy-server", "--proxy-pac-url", "--proxy-auto-detect", "--proxy-bypass-list", "--host-resolver-rules"];

/// Whether extra launch arguments already contain a proxy switch (exact flag match only).
pub fn args_conflict(args: &str) -> bool {
    args.split_whitespace()
        .map(|a| a.trim_matches('"').split('=').next().unwrap_or_default().to_ascii_lowercase())
        .any(|flag| PROXY_SWITCHES.contains(&flag.as_str()))
}

/// Switches Claude refuses to start with ("a debugging or network-override switch is present
/// on the command line"), matched by prefix after stripping `--`/`-`/`/`. Mirrors the list in
/// Claude's main process; passing any of them makes Claude exit immediately.
const CLAUDE_FORBIDDEN: [&str; 16] = [
    "remote-debugging-port", "remote-debugging-pipe", "ignore-certificate-errors", "host-resolver-rules",
    "host-rules", "disable-web-security", "log-net-log", "net-log-capture-mode", "ssl-key-log-file",
    "renderer-cmd-prefix", "utility-cmd-prefix", "gpu-launcher", "zygote-cmd-prefix",
    "ppapi-plugin-launcher", "nacl-loader-cmd-prefix", "browser-subprocess-path",
];

/// The first switch in `args` that Claude would refuse to start with.
pub fn forbidden_switch(args: &str) -> Option<String> {
    args.split_whitespace().map(|a| a.trim_matches('"')).find(|a| {
        let name = a.trim_start_matches("--").trim_start_matches(['-', '/']).split('=').next().unwrap_or_default().to_ascii_lowercase();
        CLAUDE_FORBIDDEN.iter().any(|f| name.starts_with(f))
    }).map(|a| a.split('=').next().unwrap_or(a).to_string())
}

/// Chromium switches that route everything through the local relay and close the usual leaks:
/// a SOCKS5 proxy (Chromium sends hostnames to it, so names resolve at the node), no QUIC/UDP,
/// WebRTC limited to proxied paths. `--host-resolver-rules` is not used: Claude refuses to
/// start with it, and Claude already disables DNS prefetching itself.
pub fn chromium_args(relay_port: u16) -> Vec<String> {
    vec![
        format!("--proxy-server=socks5://127.0.0.1:{relay_port}"),
        "--disable-quic".into(),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
        "--webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
        "--enforce-webrtc-ip-permission-check".into(),
    ]
}

/// Proxy environment for Claude's child processes (Claude Code, MCP servers, Node tools).
pub fn child_env(relay_port: u16) -> Vec<(String, String)> {
    let http = format!("http://127.0.0.1:{relay_port}");
    let socks = format!("socks5h://127.0.0.1:{relay_port}");
    let mut env = Vec::new();
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] { env.push((k.to_string(), http.clone())); }
    for k in ["ALL_PROXY", "all_proxy"] { env.push((k.to_string(), socks.clone())); }
    for k in ["NO_PROXY", "no_proxy"] { env.push((k.to_string(), "localhost,127.0.0.1,::1".to_string())); }
    // Node 24+ only honours proxy variables for fetch/http when asked to.
    env.push(("NODE_USE_ENV_PROXY".into(), "1".into()));
    // Claude Code resolves API hosts locally before using its proxy unless told the proxy
    // resolves them. Local lookups leak DNS outside a box and fail inside one (DNS guard).
    env.push(("CLAUDE_CODE_PROXY_RESOLVES_HOSTS".into(), "1".into()));
    env
}

pub fn is_proxy_env(key: &str) -> bool {
    ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY", "CLAUDE_CODE_PROXY_RESOLVES_HOSTS"]
        .iter().any(|k| k.eq_ignore_ascii_case(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(kind: &str) -> NodeConfig { NodeConfig { kind: kind.into(), host: "proxy.example".into(), port: 1080, ..Default::default() } }

    #[test]
    fn validates_and_normalises() {
        let n = NodeConfig { kind: " SOCKS5 ".into(), host: "[::1]".into(), ..node("x") }.validated().unwrap();
        assert_eq!((n.kind.as_str(), n.host.as_str(), n.ip_version.as_str(), n.geo_channel.as_str()), ("socks5", "::1", "ipv4", "ipinfo"));
        assert!(NodeConfig { port: 0, ..node("http") }.validated().is_err());
        assert!(NodeConfig { host: "a b".into(), ..node("http") }.validated().is_err());
        assert!(NodeConfig { password: "p".into(), ..node("http") }.validated().is_err());
        assert!(node("ftp").validated().is_err());
        assert!(NodeConfig { refresh_url: "file:///x".into(), ..node("http") }.validated().is_err());
    }

    #[test]
    fn parses_edge_trace() {
        let body = "fl=1\nh=claude.ai\nip=203.0.113.7\nts=1\nloc=jp\ntls=TLSv1.3\n";
        assert_eq!(parse_trace(body), Some(("203.0.113.7".parse().unwrap(), "JP".into())));
        assert_eq!(parse_trace("ip=2001:db8::1\nloc=XX\n"), Some(("2001:db8::1".parse().unwrap(), String::new())));
        assert_eq!(parse_trace("ip=nope\nloc=US\n"), None);
        assert_eq!(parse_trace("<html>"), None);
    }

    #[test]
    fn only_different_countries_split_the_api_route() {
        let found = |main: &str, edge: &str, api: &str, country: &str| Inspection {
            ip: Some(main.parse().unwrap()),
            edge_country: edge.into(),
            api_ip: Some(api.parse().unwrap()),
            api_country: country.into(),
            exit: Some(ExitInfo { ip: main.into(), country: edge.into(), ..Default::default() }),
            ..Default::default()
        };
        let split = found("192.0.2.1", "JP", "192.0.2.2", "US");
        assert!(split.api_split().unwrap().contains("JP 与 US"));
        assert!(split.into_result().is_err());
        assert!(found("192.0.2.1", "JP", "192.0.2.2", "JP").into_result().is_ok(), "a rotating exit is not a split");
        assert!(found("192.0.2.1", "JP", "192.0.2.1", "US").api_split().is_none(), "one IP is one exit");
        assert!(found("192.0.2.1", "", "192.0.2.2", "US").api_split().is_none(), "nothing to compare");
    }

    #[test]
    fn unreachable_node_reports_every_service_and_rate_limits_are_skipped() {
        // Nothing listens on the node's port: every request fails to connect.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let n = NodeConfig { host: "127.0.0.1".into(), port: closed, ip_version: "ipv4".into(), ..node("http") };
        let client = n.client(Duration::from_secs(5)).unwrap();
        let found = inspect_known(&client, &n, None);
        assert!(found.ip.is_none() && found.exit.is_none());
        let hosts: Vec<&str> = found.attempts.iter().map(|a| a.host.as_str()).collect();
        assert_eq!(hosts, ["claude.ai", "api4.ipify.org", "ipv4.icanhazip.com"]);
        assert!(found.attempts.iter().all(|a| a.stage == "ip" && a.outcome == "连接失败"), "{}", found.trail());
        let why = found.failure();
        assert!(why.contains("claude.ai 连接失败") && why.contains("请检查节点"), "{why}");
        // A rate limited service is skipped for this route only.
        let route = format!("127.0.0.1:{closed}");
        cool_down(&route, "api4.ipify.org", Some(Duration::from_secs(60)));
        let again = inspect_known(&client, &n, None);
        assert_eq!(again.attempts[1].outcome, "限流冷却中，已跳过");
        assert!(!cooling("127.0.0.1:1", "api4.ipify.org"));
    }

    #[test]
    fn legacy_endpoint_becomes_node() {
        let n = NodeConfig::from_legacy("socks5://127.0.0.1:7890").unwrap();
        assert_eq!((n.kind.as_str(), n.host.as_str(), n.port), ("socks5", "127.0.0.1", 7890));
        assert!(NodeConfig::from_legacy("nonsense").is_none());
    }

    #[test]
    fn credentials_are_percent_encoded() {
        let n = NodeConfig { username: "u@x".into(), password: "p:w/#".into(), ..node("socks5") };
        assert!(n.reqwest_proxy().is_ok());
    }

    #[test]
    fn seal_round_trip() {
        assert_eq!(unseal(&seal("s3cr:et")), "s3cr:et");
        assert_eq!(seal(""), "");
        assert_eq!(unseal("legacy"), "legacy");
    }

    #[test]
    fn only_real_proxy_switches_conflict() {
        for f in chromium_args(1080) { assert!(forbidden_switch(&f).is_none(), "{f}"); }
        assert_eq!(forbidden_switch("--lang=en --host-resolver-rules=MAP").as_deref(), Some("--host-resolver-rules"));
        assert_eq!(forbidden_switch("\"--Remote-Debugging-Port=9222\"").as_deref(), Some("--Remote-Debugging-Port"));
        assert!(forbidden_switch("--disable-gpu --lang=zh-CN").is_none());
        for args in ["--proxy-server=http://a:1", "--lang=en \"--proxy-pac-url=x\"", "--NO-PROXY-SERVER", "--proxy-bypass-list=*", "--host-resolver-rules=x"] {
            assert!(args_conflict(args), "{args}");
        }
        for args in ["", "--lang=zh-CN", "--no-proxy-xxx", "--proxy-serverless", "--disable-gpu --my-proxy=1"] {
            assert!(!args_conflict(args), "{args}");
        }
    }

    #[test]
    #[ignore = "requires HYDRA_TEST_PROXY and internet"]
    fn checks_configured_proxy_exit() {
        let endpoint = std::env::var("HYDRA_TEST_PROXY").unwrap();
        let node = NodeConfig::from_legacy(&endpoint).unwrap().validated().unwrap();
        let client = node.client(Duration::from_secs(15)).unwrap();
        let found = inspect_known(&client, &node, None);
        println!("check trail: {}", found.trail());
        let exit = found.into_result().unwrap();
        assert!(exit.ip.parse::<IpAddr>().is_ok());
        assert!(!exit.country.is_empty());
        // Same IP again: the location is reused, no location service is asked.
        let again = inspect_known(&client, &node, Some(&exit));
        println!("recheck trail: {}", again.trail());
        assert!(again.reused && again.attempts.iter().all(|a| a.stage != "geo"));
        assert_eq!(again.exit.map(|x| x.country), Some(exit.country.clone()));
        println!("Network classification: {:?}", network_quality(&client, &exit.ip));
        println!("{}", reputation(&client, &exit.ip));
    }

    #[test]
    fn parses_each_geo_channel() {
        let a = parse_geo("ipinfo", r#"{"ip":"192.0.2.1","country":"JP","region":"Tokyo","city":"Tokyo","timezone":"Asia/Tokyo"}"#).unwrap();
        assert_eq!((a.country.as_str(), a.timezone.as_str()), ("JP", "Asia/Tokyo"));
        let b = parse_geo("ipapi", r#"{"ip":"2001:db8::1","country_code":"US","timezone":"America/New_York"}"#).unwrap();
        assert_eq!(b.country, "US");
        let c = parse_geo("ip-api", r#"{"status":"success","query":"192.0.2.9","countryCode":"DE","timezone":"Europe/Berlin"}"#).unwrap();
        assert_eq!(c.timezone, "Europe/Berlin");
        assert!(parse_geo("ip-api", r#"{"status":"fail","message":"private range"}"#).is_err());
        assert!(parse_geo("ipinfo", r#"{"ip":"nope"}"#).is_err());
    }

    #[test]
    fn timezone_names_are_checked() {
        assert!(valid_timezone("Asia/Tokyo"));
        assert!(valid_timezone("UTC"));
        assert!(!valid_timezone("../etc/passwd"));
        assert!(!valid_timezone("Asia/Tokyo; rm"));
        assert!(!valid_timezone(""));
    }
}
