//! macOS isolation: a per-account Seatbelt profile applied with `sandbox-exec`.
//!
//! Every process Claude starts inherits the profile, so a program that ignores the proxy settings
//! still cannot leave except through the account's relay. The profile also keeps the account out
//! of other accounts' data and Hydra's own settings.
//!
//! macOS refuses to initialize a sandbox inside one already applied, and Chromium sandboxes each
//! of its child processes, so Claude only runs here with `--no-sandbox`. That removes the renderer
//! sandbox around the claude.ai page; the file rules limit what a compromised page could reach.
//!
//! A process started through LaunchServices or Apple Events runs outside the profile, so only
//! Claude's main process, which opens sign-in links, may use LaunchServices. Login items and shell
//! start-up files would likewise run later outside the profile, so they cannot be written.
//! `sandbox-exec` is deprecated by Apple but still shipped; without it isolation is reported as
//! unavailable instead of the account running unconfined.
//!
//! Hardware identifiers (`IOPlatformUUID`, serial numbers, MAC addresses) stay the host's.

use std::path::{Path, PathBuf};
use std::process::Command;

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
const NC: &str = "/usr/bin/nc";

/// Chromium cannot create its own sandboxes inside Seatbelt (see the module note).
pub const CHROMIUM_SWITCH: &str = "--no-sandbox";

/// What the account may not touch, and the folders of its own inside those.
#[derive(Debug, Default)]
pub struct Files {
    pub denied: Vec<PathBuf>,
    pub allowed: Vec<PathBuf>,
    /// Start-up locations whose contents would later run outside the profile.
    pub startup: Vec<PathBuf>,
    /// The one executable allowed to open links and apps through LaunchServices.
    pub link_opener: Option<PathBuf>,
}

/// Where a program could leave something that runs at the next login or shell start.
pub fn startup_paths(home: &Path) -> Vec<PathBuf> {
    ["Library/LaunchAgents", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile"]
        .map(|p| home.join(p))
        .into()
}

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

/// Seatbelt compares resolved paths, so `/tmp/x` must be written as `/private/tmp/x`.
fn quoted(path: &Path) -> String {
    let real = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    format!("\"{}\"", real.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\""))
}

/// The profile text. With a relay, the only network exit is that one loopback port: a host proxy
/// or another account's relay also listens on loopback, and the system DNS service would resolve
/// names outside the node. Without a relay the network stays open, like the Windows box.
///
/// Reading metadata stays allowed so paths through the denied folders still resolve. The allow
/// rules name `file-read-data` because a broader `file-read*` does not override that denial.
pub fn seatbelt_profile(relay_port: Option<u16>, files: &Files) -> String {
    let mut profile = String::from("(version 1)\n(allow default)\n");
    if let Some(port) = relay_port {
        profile.push_str("(deny network-outbound)\n");
        profile.push_str("(allow network-outbound (remote unix-socket (path-regex #\"^/\")))\n");
        profile.push_str("(deny network-outbound (remote unix-socket (path-literal \"/private/var/run/mDNSResponder\")))\n");
        profile.push_str("(deny mach-lookup (global-name \"com.apple.dnssd.service\"))\n");
        // Seatbelt accepts only `*` or `localhost` as the host here, never a numeric address.
        profile.push_str(&format!("(allow network-outbound (remote ip \"localhost:{port}\"))\n"));
    }
    for path in &files.denied {
        profile.push_str(&format!("(deny file-read-data file-write* (subpath {}))\n", quoted(path)));
    }
    for path in &files.allowed {
        profile.push_str(&format!("(allow file-read-data file-write* (subpath {}))\n", quoted(path)));
    }
    for path in &files.startup {
        profile.push_str(&format!("(deny file-write* (subpath {}))\n", quoted(path)));
    }
    profile.push_str("(deny appleevent-send)\n");
    match &files.link_opener {
        // Matched by path: a signing identifier can be copied by an ad-hoc signed program.
        Some(exe) => profile.push_str(&format!("(deny lsopen (require-not (process-path {})))\n", quoted(exe))),
        None => profile.push_str("(deny lsopen)\n"),
    }
    profile
}

/// Writes the account's profile.
pub fn configure(id: &str, relay_port: Option<u16>, files: &Files) -> Result<PathBuf, String> {
    available()?;
    std::fs::create_dir_all(profile_dir()).map_err(|e| format!("无法创建 macOS 沙盒配置目录：{e}"))?;
    let path = profile_path(id);
    std::fs::write(&path, seatbelt_profile(relay_port, files)).map_err(|e| format!("无法写入 macOS 沙盒配置：{e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

fn probe(profile: &Path, program: &str, args: &[&std::ffi::OsStr]) -> Result<std::process::Output, String> {
    Command::new(SANDBOX_EXEC)
        .arg("-f")
        .arg(profile)
        .arg(program)
        .args(args)
        .output()
        .map_err(|e| format!("无法运行 macOS 沙盒自检：{e}"))
}

fn connects(profile: &Path, host: &str, port: u16) -> Result<bool, String> {
    let port = port.to_string();
    let args = ["-z", "-w", "2", host, port.as_str()].map(std::ffi::OsStr::new);
    Ok(probe(profile, NC, &args)?.status.success())
}

/// Proves the profile before the account starts: it loads, the account can read its own folder
/// but not `protected`, the relay is reachable, and neither another loopback port nor a direct
/// connection is. Anything else refuses the launch.
pub fn verify(profile: &Path, relay_port: Option<u16>, own: &Path, protected: Option<&Path>) -> Result<(), String> {
    let loaded = probe(profile, "/usr/bin/true", &[])?;
    if !loaded.status.success() {
        return Err(format!(
            "macOS 沙盒配置无法加载，已停止启动：{}",
            String::from_utf8_lossy(&loaded.stderr).trim()
        ));
    }
    if !probe(profile, "/bin/ls", &[own.as_os_str()])?.status.success() {
        return Err("macOS 沙盒自检失败：账号读不到自己的数据目录，已停止启动。".into());
    }
    if let Some(path) = protected {
        if probe(profile, "/bin/cat", &[path.as_os_str()])?.status.success() {
            return Err("macOS 沙盒自检失败：沙盒内仍能读取 Hydra 的配置，已停止启动。".into());
        }
    }
    let Some(port) = relay_port else { return Ok(()) };
    if !connects(profile, "127.0.0.1", port)? {
        return Err("macOS 沙盒自检失败：本机中继在沙盒内不可达，已停止启动，避免 Claude 在无可达出口的情况下运行。".into());
    }
    // A listener of our own, outside the sandbox: the kernel completes the connection from its
    // backlog, so `nc -z` succeeds exactly when the profile lets the sandbox reach that port.
    let other = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("无法运行 macOS 沙盒自检：{e}"))?;
    let other_port = other.local_addr().map_err(|e| format!("无法运行 macOS 沙盒自检：{e}"))?.port();
    let loopback = connects(profile, "127.0.0.1", other_port)?;
    drop(other);
    if loopback {
        return Err("macOS 沙盒自检失败：沙盒内仍能连到本机中继以外的端口（例如本机代理），已停止启动，避免 Claude 绕开账号中继。".into());
    }
    if connects(profile, "1.1.1.1", 443)? {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Files {
        Files {
            denied: vec!["/no/hydra".into(), "/no/Cl\"aude".into()],
            allowed: vec!["/no/hydra/profiles/a".into()],
            startup: startup_paths(Path::new("/no/home")),
            link_opener: Some("/no/Claude".into()),
        }
    }

    #[test]
    fn a_relay_is_the_only_network_exit() {
        let text = seatbelt_profile(Some(4242), &Files::default());
        assert!(text.contains("(deny network-outbound)"));
        assert!(text.contains("(allow network-outbound (remote ip \"localhost:4242\"))"));
        assert!(text.contains("/private/var/run/mDNSResponder"));
        assert!(text.contains("com.apple.dnssd.service"));
        assert!(!text.contains("localhost:*"));
    }

    #[test]
    fn without_a_relay_only_files_are_limited() {
        let text = seatbelt_profile(None, &files());
        assert!(!text.contains("network-outbound"));
        assert!(text.contains("(deny file-read-data file-write* (subpath \"/no/hydra\"))"));
    }

    #[test]
    fn the_accounts_own_folder_is_opened_after_the_denials() {
        let text = seatbelt_profile(None, &files());
        let denied = text.find("(deny file-read-data file-write* (subpath \"/no/hydra\"))").unwrap();
        let allowed = text.find("(allow file-read-data file-write* (subpath \"/no/hydra/profiles/a\"))").unwrap();
        assert!(denied < allowed);
        assert!(text.contains("\"/no/Cl\\\"aude\""));
    }

    #[test]
    fn only_claude_can_start_programs_outside_the_profile() {
        let text = seatbelt_profile(None, &files());
        assert!(text.contains("(deny appleevent-send)"));
        assert!(text.contains("(deny lsopen (require-not (process-path \"/no/Claude\")))"));
        for item in ["Library/LaunchAgents", ".zshrc"] {
            let path = Path::new("/no/home").join(item);
            assert!(text.contains(&format!("(deny file-write* (subpath {}))", quoted(&path))));
        }
        assert!(seatbelt_profile(None, &Files::default()).contains("(deny lsopen)"));
    }

    /// Runs the real `sandbox-exec`, which cannot start inside another sandbox.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "needs a shell outside any macOS sandbox"]
    fn the_kernel_enforces_the_profile() {
        let root = std::env::temp_dir().join(format!("hydra-seatbelt-{}", crate::paths::now_millis()));
        let (own, other) = (root.join("profiles/a"), root.join("profiles/b"));
        std::fs::create_dir_all(&own).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let settings = root.join("settings.json");
        std::fs::write(&settings, "{}").unwrap();
        std::fs::write(other.join("Cookies"), "x").unwrap();
        let relay = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = relay.local_addr().unwrap().port();
        let startup = own.join("Library/LaunchAgents");
        std::fs::create_dir_all(&startup).unwrap();
        let files = Files { denied: vec![root.clone()], allowed: vec![own.clone()], startup: vec![startup.clone()], link_opener: None };
        let profile = root.join("a.sb");
        std::fs::write(&profile, seatbelt_profile(Some(port), &files)).unwrap();

        verify(&profile, Some(port), &own, Some(&settings)).unwrap();
        assert!(!probe(&profile, "/bin/cat", &[other.join("Cookies").as_os_str()]).unwrap().status.success());

        let item = startup.join("item.plist");
        assert!(!probe(&profile, "/usr/bin/touch", &[item.as_os_str()]).unwrap().status.success());
        let opened = probe(&profile, "/usr/bin/open", &["-g".as_ref(), own.as_os_str()]).unwrap();
        assert!(!opened.status.success());
        assert!(String::from_utf8_lossy(&opened.stderr).contains("-54"));

        // A profile that leaves the settings readable must stop the launch.
        std::fs::write(&profile, seatbelt_profile(Some(port), &Files::default())).unwrap();
        assert!(verify(&profile, Some(port), &own, Some(&settings)).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
