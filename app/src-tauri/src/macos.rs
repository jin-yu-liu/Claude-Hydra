//! macOS isolation: a Seatbelt profile for the network, and the DevTools channel that puts the
//! account's page fingerprint into Claude's renderer.
//!
//! This module is compiled on every platform so its Rust is checked where it is written; only the
//! macOS build calls it. The two mechanisms are deliberately separate:
//!
//! - **Network**: `sandbox-exec` applies a per-account profile (inherited by every child process)
//!   that denies outbound connections except to the account's relay port on loopback. The
//!   profile is *verified* before the account is started: if a direct connection, or a connection
//!   to any other loopback port, still succeeds, the launch is refused. `sandbox-exec` is
//!   deprecated by Apple but still shipped; when it is missing the caller reports that isolation
//!   is unavailable instead of silently running unconfined.
//! - **Page fingerprint**: Claude Desktop is Electron. Started with a remote-debugging port it
//!   accepts a DevTools connection on loopback, which installs the same per-account Canvas /
//!   WebGL / font / screen shim the Windows account browser uses. The script lives as long as the
//!   DevTools session that installed it, so each page's session is held open. This needs no code
//!   signing and no SIP change, but it is script-level: if Claude does not expose the port, the
//!   fingerprint is simply not applied (logged), and anything the process reads outside its
//!   renderer still sees the host.
//!
//! Hardware identifiers (`IOPlatformUUID`, serial numbers, the real MAC addresses) are *not*
//! touched: on macOS those are kernel values a process cannot rewrite without injection, and no
//! equivalent of Sandboxie's virtualization exists. The status document says so.

#![allow(dead_code)]

use crate::macos_isolation::{
    cdp_commands, devtools_port, handshake_request, masked_frame, page_targets, read_frame, reload_command, reply_to,
    seatbelt_profile, Target, INSTALL_ID,
};
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const NC: &str = "/usr/bin/nc";

/// The macOS isolation tool, or a user-facing reason it cannot be used.
pub fn available() -> Result<PathBuf, String> {
    let exe = PathBuf::from(SANDBOX_EXEC);
    if exe.is_file() {
        Ok(exe)
    } else {
        Err("这个 macOS 没有可用的 sandbox-exec（Seatbelt）。macOS 的沙盒隔离靠它在内核层阻断直连；没有它时只能设置代理环境变量，无法保证账号不绕过代理。".into())
    }
}

fn profile_dir() -> PathBuf { crate::paths::storage_root().join("macos-sandbox") }

/// The per-account profile file. Public so an account can be forgotten cleanly.
pub fn profile_path(id: &str) -> PathBuf {
    profile_dir().join(format!("{}.sb", crate::sandbox::account_key(id)))
}

/// Writes the account's profile. `relay_port = None` (no proxy node) leaves the network
/// unrestricted, matching the Windows box which only narrows the network when a relay exists.
pub fn configure(id: &str, relay_port: Option<u16>) -> Result<PathBuf, String> {
    available()?;
    std::fs::create_dir_all(profile_dir()).map_err(|e| format!("无法创建 macOS 沙盒配置目录：{e}"))?;
    let path = profile_path(id);
    std::fs::write(&path, seatbelt_profile(relay_port)).map_err(|e| format!("无法写入 macOS 沙盒配置：{e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

fn probe(profile: &Path, program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(profile)
        .arg(program)
        .args(args)
        .output()
        .map_err(|e| format!("无法运行 macOS 沙盒自检：{e}"))
}

/// Proves the profile works before the account starts: it loads, the relay is reachable, any
/// other loopback port is refused (a host proxy such as Clash would otherwise be a way out) and a
/// direct connection is refused. Anything else refuses the launch. Without a relay the profile has
/// no network rules (there is no exit to send the account through), so only the load check
/// applies - the same behaviour as the Windows box.
pub fn verify(profile: &Path, relay_port: Option<u16>) -> Result<(), String> {
    let loaded = probe(profile, "/usr/bin/true", &[])?;
    if !loaded.status.success() {
        return Err(format!(
            "macOS 沙盒配置无法加载，已停止启动：{}",
            String::from_utf8_lossy(&loaded.stderr).trim()
        ));
    }
    let Some(port) = relay_port else { return Ok(()) };
    let relay = probe(profile, NC, &["-z", "-w", "2", "127.0.0.1", &port.to_string()])?;
    if !relay.status.success() {
        return Err("macOS 沙盒自检失败：本机中继在沙盒内不可达，已停止启动，避免 Claude 在无可达出口的情况下运行。".into());
    }
    // A listener of our own, outside the sandbox: the kernel completes the connection from its
    // backlog, so `nc -z` succeeds exactly when the profile lets the sandbox reach that port.
    let other = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("无法运行 macOS 沙盒自检：{e}"))?;
    let other_port = other.local_addr().map_err(|e| format!("无法运行 macOS 沙盒自检：{e}"))?.port();
    let loopback = probe(profile, NC, &["-z", "-w", "2", "127.0.0.1", &other_port.to_string()])?;
    drop(other);
    if loopback.status.success() {
        return Err("macOS 沙盒自检失败：沙盒内仍能连到本机中继以外的端口（例如本机代理），已停止启动，避免 Claude 绕开账号中继。".into());
    }
    let direct = probe(profile, NC, &["-z", "-w", "2", "1.1.1.1", "443"])?;
    if direct.status.success() {
        return Err("macOS 沙盒自检失败：沙盒内仍能直连外部地址，已停止启动，避免 Claude 绕开代理走主机网络。".into());
    }
    Ok(())
}

/// The command that runs `exe` under the account's profile, with the account's environment.
pub fn command(profile: &Path, exe: &Path, args: &[String], env: &[(String, String)]) -> Command {
    let mut cmd = Command::new(SANDBOX_EXEC);
    cmd.arg("-f").arg(profile).arg(exe).args(args);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd
}

/// A free loopback port for the DevTools endpoint.
pub fn free_port() -> Option<u16> {
    std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?.local_addr().ok().map(|addr| addr.port())
}

// ---- page fingerprint ----------------------------------------------------------------

/// Removes the port file a previous run left behind, so the watcher cannot read a stale port
/// (by now possibly another process's). Called before Claude is started.
pub fn clear_devtools_port(data_dir: &Path) {
    let _ = std::fs::remove_file(data_dir.join("DevToolsActivePort"));
}

/// Watches Claude's DevTools endpoint for as long as it lives and installs the account's
/// fingerprint script in every page that appears. The script belongs to the DevTools session that
/// installed it, so each page keeps its own connection open until the page goes away. A Claude
/// that never opens the port, or a page that refuses the install, is logged and left untouched.
pub fn inject_fingerprint(data_dir: PathBuf, script: String) {
    std::thread::spawn(move || watch(&data_dir, &script));
}

fn watch(data_dir: &Path, script: &str) {
    // The port file appears once Claude's browser process is up.
    let mut port = None;
    for _ in 0..40 {
        port = std::fs::read_to_string(data_dir.join("DevToolsActivePort")).ok().and_then(|text| devtools_port(&text));
        if port.is_some() { break; }
        std::thread::sleep(Duration::from_millis(500));
    }
    let Some(port) = port else {
        crate::paths::append_log(
            "hydra-error.log",
            "account browser fingerprint: Claude exposed no DevTools port; page fingerprint not applied",
        );
        return;
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut failures = 0u32;
    // Until the endpoint stops answering: Claude has quit, and every page session with it.
    while failures < 30 {
        match http_get(port, "/json/list") {
            Some(list) => {
                failures = 0;
                for target in page_targets(&list) {
                    if !seen.insert(target.socket.clone()) { continue; }
                    match attach(port, &target, script) {
                        Ok(()) => crate::paths::append_log(
                            "hydra.log",
                            &format!("account browser fingerprint: installed in page {}", short_url(&target.url)),
                        ),
                        Err(reason) => crate::paths::append_log(
                            "hydra-error.log",
                            &format!("account browser fingerprint: not installed in page {}: {reason}", short_url(&target.url)),
                        ),
                    }
                }
            }
            None => failures += 1,
        }
        std::thread::sleep(Duration::from_millis(700));
    }
}

/// Scheme and host only: the log should not carry conversation paths or query strings.
fn short_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => format!("{scheme}://{}", rest.split(['/', '?', '#']).next().unwrap_or_default()),
        None => url.chars().take(40).collect(),
    }
}

fn http_get(port: u16, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    write!(stream, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").ok()?;
    let mut text = String::new();
    stream.read_to_string(&mut text).ok()?;
    let (_, body) = text.split_once("\r\n\r\n")?;
    Some(body.to_string())
}

fn send(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mask = random::<4>().unwrap_or([1, 2, 3, 4]);
    stream.write_all(&masked_frame(opcode, payload, mask))
}

/// Opens a DevTools session on the page, installs the script, waits for Chromium to confirm it,
/// reloads a web page so the document already showing gets it too, and hands the session to a
/// thread that keeps it open (answering pings) until the page closes.
fn attach(port: u16, target: &Target, script: &str) -> Result<(), String> {
    let rest = target.socket.strip_prefix("ws://").unwrap_or(&target.socket);
    let path = rest.find('/').map(|slash| &rest[slash..]).ok_or("bad debugger url")?;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, random::<16>().unwrap_or([0u8; 16]));
    stream
        .write_all(handshake_request("127.0.0.1", port, path, &key).as_bytes())
        .map_err(|e| format!("handshake: {e}"))?;
    // Byte-wise so the header read does not consume the first frame.
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).map_err(|e| format!("handshake: {e}"))?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") { break; }
        if header.len() > 8192 { return Err("handshake: header too long".into()); }
    }
    let header = String::from_utf8_lossy(&header);
    if !header.starts_with("HTTP/1.1 101") {
        return Err(format!("handshake refused: {}", header.lines().next().unwrap_or_default()));
    }
    for message in cdp_commands(script) {
        send(&mut stream, 1, message.as_bytes()).map_err(|e| format!("send: {e}"))?;
    }
    // Events (from Page.enable) may arrive first; only the install's own reply counts.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() > deadline { return Err("no reply to the install".into()); }
        let frame = read_frame(&mut stream)
            .map_err(|e| format!("read: {e}"))?
            .ok_or("closed before the install was confirmed")?;
        match frame.opcode {
            8 => return Err("closed before the install was confirmed".into()),
            9 => send(&mut stream, 10, &frame.payload).map_err(|e| format!("pong: {e}"))?,
            _ => match reply_to(&frame.payload, INSTALL_ID) {
                Some(true) => break,
                Some(false) => return Err(format!("install refused: {}", String::from_utf8_lossy(&frame.payload))),
                None => {}
            },
        }
    }
    if target.reload_after_install() {
        send(&mut stream, 1, reload_command().as_bytes()).map_err(|e| format!("reload: {e}"))?;
    }
    let _ = stream.set_read_timeout(None);
    std::thread::spawn(move || keep_open(stream));
    Ok(())
}

/// Holds the page's DevTools session (and with it the installed script) until the page or Claude
/// closes it. Events are read and dropped; pings are answered so the session stays up.
fn keep_open(mut stream: TcpStream) {
    loop {
        match read_frame(&mut stream) {
            Ok(Some(frame)) if frame.opcode == 8 => break,
            Ok(Some(frame)) if frame.opcode == 9 => {
                if send(&mut stream, 10, &frame.payload).is_err() { break; }
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
}

fn random<const N: usize>() -> Option<[u8; N]> {
    let mut out = [0u8; N];
    let mut file = std::fs::File::open("/dev/urandom").ok()?;
    file.read_exact(&mut out).ok()?;
    Some(out)
}
