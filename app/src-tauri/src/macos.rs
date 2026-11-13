//! macOS isolation: a Seatbelt profile for the network, and the DevTools channel that puts the
//! account's page fingerprint into Claude's renderer.
//!
//! This module is compiled on every platform so its Rust is checked where it is written; only the
//! macOS build calls it. The two mechanisms are deliberately separate:
//!
//! - **Network**: `sandbox-exec` applies a per-account profile (inherited by every child process)
//!   that denies outbound connections except to loopback, where the account's relay listens. The
//!   profile is *verified* before the account is started: if a direct connection still succeeds,
//!   the launch is refused. `sandbox-exec` is deprecated by Apple but still shipped; when it is
//!   missing the caller reports that isolation is unavailable instead of silently running
//!   unconfined.
//! - **Page fingerprint**: Claude Desktop is Electron. Started with a remote-debugging port it
//!   accepts a DevTools connection on loopback, which installs the same per-account Canvas /
//!   WebGL / font / screen shim the Windows account browser uses. This needs no code signing and
//!   no SIP change, but it is script-level: if Claude does not expose the port, the fingerprint is
//!   simply not applied (logged), and anything the process reads outside its renderer still sees
//!   the host.
//!
//! Hardware identifiers (`IOPlatformUUID`, serial numbers, the real MAC addresses) are *not*
//! touched: on macOS those are kernel values a process cannot rewrite without injection, and no
//! equivalent of Sandboxie's virtualization exists. The status document says so.

#![allow(dead_code)]

use crate::macos_isolation::{
    cdp_commands, devtools_port, handshake_request, masked_frame, page_targets, read_frame, seatbelt_profile,
};
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

/// Proves the profile works before the account starts: it loads, a direct connection is refused,
/// and (when a relay exists) the relay is reachable. Anything else refuses the launch. Without a
/// relay the profile has no network rules (there is no exit to send the account through), so only
/// the load check applies - the same behaviour as the Windows box.
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

/// Watches for Claude's DevTools endpoint and installs the account's fingerprint script in every
/// page that appears. Runs in the background; a Claude that never opens the port, or a WebSocket
/// that is refused, leaves the pages untouched (and is logged once).
pub fn inject_fingerprint(data_dir: PathBuf, script: String) {
    std::thread::spawn(move || watch(&data_dir, &script));
}

fn watch(data_dir: &Path, script: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut injected: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut port: Option<u16> = None;
    let mut waits = 0u32;
    let mut failures = 0u32;
    while Instant::now() < deadline {
        if port.is_none() {
            port = std::fs::read_to_string(data_dir.join("DevToolsActivePort"))
                .ok()
                .and_then(|text| devtools_port(&text));
            if port.is_none() {
                waits += 1;
                if waits == 40 {
                    crate::paths::append_log(
                        "hydra-error.log",
                        "account browser fingerprint: Claude exposed no DevTools port; page fingerprint not applied",
                    );
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        }
        let current = port.unwrap_or_default();
        match http_get(current, "/json/list") {
            Some(list) => {
                failures = 0;
                for url in page_targets(&list) {
                    if injected.contains(&url) { continue; }
                    if inject_into(current, &url, script) {
                        injected.insert(url);
                    }
                }
            }
            None => {
                failures += 1;
                // A dead endpoint means Claude went away; stop instead of polling a stale file.
                if failures >= 30 { break; }
                port = None;
            }
        }
        std::thread::sleep(Duration::from_millis(700));
    }
    if !injected.is_empty() {
        crate::paths::append_log("hydra.log", &format!("account browser fingerprint: installed in {} page(s)", injected.len()));
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

fn inject_into(port: u16, debugger_url: &str, script: &str) -> bool {
    let rest = debugger_url.strip_prefix("ws://").unwrap_or(debugger_url);
    let Some(slash) = rest.find('/') else { return false };
    let path = &rest[slash..];
    let mut stream = match TcpStream::connect(("127.0.0.1", port)) {
        Ok(stream) => stream,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, random::<16>().unwrap_or([0u8; 16]));
    if stream.write_all(handshake_request("127.0.0.1", port, path, &key).as_bytes()).is_err() {
        return false;
    }
    // Byte-wise so the header read does not consume the first frame.
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read_exact(&mut byte).is_err() { return false; }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") { break; }
        if header.len() > 8192 { return false; }
    }
    if !String::from_utf8_lossy(&header).starts_with("HTTP/1.1 101") { return false; }
    for message in cdp_commands(script) {
        let mask = random::<4>().unwrap_or([1, 2, 3, 4]);
        if stream.write_all(&masked_frame(1, message.as_bytes(), mask)).is_err() { return false; }
    }
    // Drain the two replies so the socket does not stay half-read; their contents are not needed.
    for _ in 0..2 {
        match read_frame(&mut stream) {
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    true
}

fn random<const N: usize>() -> Option<[u8; N]> {
    let mut out = [0u8; N];
    let mut file = std::fs::File::open("/dev/urandom").ok()?;
    file.read_exact(&mut out).ok()?;
    Some(out)
}
