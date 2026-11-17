//! Account process lifecycle, native desktop shortcuts, and diagnostic reports.

use crate::install::Install;
use crate::profiles::{self, path_key, Profile};
use crate::{paths, settings, sys};
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// The account's own Claude Code folder (`CLAUDE_CONFIG_DIR`), or `None` when it shares
/// `~/.claude`. Session migration uses this to find where each account keeps transcripts.
pub(crate) fn private_code_dir(effective: &settings::Effective, p: &Profile) -> Option<PathBuf> {
    let sandboxed = effective.isolation == "sandboxie";
    (effective.separate_code && (!p.is_default || sandboxed)).then(|| crate::sandbox::code_dir(&p.id))
}

pub fn launch(install: &Install, p: &Profile) -> Result<&'static str, String> {
    let running = profiles::running_map(install).get(&path_key(&p.path)).copied();
    if let Some(pid) = running {
        #[cfg(windows)]
        crate::taskbar::apply(p, pid);
        if sys::focus(pid) {
            return Ok("focused");
        }
    }

    let s = settings::load();
    let outcome = if running.is_some() { "focused" } else { "started" };
    let effective = s.effective(&p.id);
    let node = effective.node.clone();
    let extra = profiles::extra_args(&s, &p.id);
    if let Some(f) = crate::node::forbidden_switch(&extra) {
        return Err(format!("Claude 不允许使用启动参数 {f}，带上它会直接退出。请在环境配置的额外启动参数中移除。"));
    }
    let mut env = profiles::env_vars(&s, &p.id);
    // Hydra-managed switches; passed as separate arguments (some contain spaces).
    let mut managed: Vec<String> = Vec::new();
    let mut timezone = match effective.timezone.as_str() { "" | "proxy" | "system" => None, tz => Some(tz.to_string()) };
    let sandboxed = effective.isolation == "sandboxie";
    if (node.is_some() || timezone.is_some() || sandboxed) && p.is_default && install.is_msix() {
        return Err("商店版默认账号无法应用环境配置中的代理节点、时区或沙箱隔离。".into());
    }
    // A soft cut (checks kept failing) is not refused here: the relay host re-checks the exit
    // before it opens the route, and the launch check below verifies it once more.
    if let Some(reason) = s.account(&p.id).blocked.filter(|_| !s.account(&p.id).blocked_soft) {
        return Err(format!("账号未启动：出口保护已切断这个账号的网络——{reason}\n请在账号菜单中选择“恢复网络”重新检测，或在环境配置中重新绑定出口。"));
    }
    if effective.unusable_node {
        return Err("账号未启动：这个账号的代理节点无法读取（密码不能在本机解密，或节点配置已损坏）。为避免改用本机网络直连，已拒绝启动。请打开它的环境配置，重新填写节点并保存。".into());
    }
    if node.is_none() && !p.is_default && s.requires_environment() {
        return Err(NO_ENVIRONMENT.into());
    }
    let mut relay_port = None;
    if let Some(node) = &node {
        if crate::node::args_conflict(&extra) { return Err("额外启动参数中的代理开关与代理节点冲突，请先移除。".into()); }
        // Claude pins itself to a managed egress proxy over `--proxy-server`, so the account
        // would leave through that proxy (e.g. a local Clash port) instead of its node.
        // Only a Sandboxie box hides that policy from Claude; a macOS Seatbelt profile does not.
        let box_hides_policy = cfg!(windows) && sandboxed && crate::sandbox::available().is_ok();
        if let Some(policy) = sys::claude_egress_policy().filter(|_| !box_hides_policy) {
            return Err(format!(
                "账号未启动：系统策略为 Claude 固定了出口代理 {policy}。Claude 会忽略 Hydra 的代理节点、改走这个代理。如需改走 Hydra 配置，请切换到 Sandboxie-Plus 隔离环境；不使用代理节点的账号不受影响。"
            ));
        }
        let port = crate::relay::port_for_launch(&p.id, node).map_err(|e| format!("账号未启动：{e}"))?;
        // Verify the exact route Claude will use: local relay -> node -> internet.
        let client = crate::node::relay_client(port, std::time::Duration::from_secs(15))?;
        let exit = crate::node::inspect(&client, node).map_err(|e| format!("账号未启动：{e}"))?;
        crate::guard::verify(effective.environment.as_deref(), &exit).map_err(|e| format!("账号未启动：{e}"))?;
        relay_port = Some(port);
        if matches!(effective.timezone.as_str(), "" | "proxy") {
            if exit.timezone.is_empty() {
                return Err("账号未启动：IP 查询服务没有返回出口时区。请换一个 IP 查询渠道，或在账号设置中手动指定时区。".into());
            }
            timezone = Some(exit.timezone.clone());
        }
        let _ = settings::update(|s| s.account_mut(&p.id).last_exit = Some(exit));
        managed = crate::node::chromium_args(port);
        env.retain(|(k, _)| !crate::node::is_proxy_env(k));
        env.extend(crate::node::child_env(port));
    }
    if let Some(tz) = timezone {
        env.retain(|(k, _)| !k.eq_ignore_ascii_case("TZ"));
        env.push(("TZ".into(), tz));
    }
    if sandboxed {
        // The box's identity guard answers `GetComputerNameEx` and `GetUserNameEx` with these
        // values; the environment variables are inherited instead of queried, so they have to be
        // set to the same values or a program reading `COMPUTERNAME`/`USERNAME` would see two
        // different machines and accounts.
        let ids = crate::identity::Identifiers::for_account(&p.id);
        for (key, value) in
            crate::identity::identity_env(&ids.computer_name, &ids.user_name, |k| std::env::var(k).ok())
        {
            env.retain(|(k, _)| !k.eq_ignore_ascii_case(&key));
            env.push((key, value));
        }
    }
    // Claude Code started by this account keeps its sign-in, settings and sessions in the
    // account's own folder instead of the `~/.claude` every account shares.
    let code_dir = private_code_dir(&effective, p);
    if let Some(dir) = &code_dir {
        std::fs::create_dir_all(dir).map_err(|e| format!("账号未启动：无法创建 Claude Code 目录：{e}"))?;
        env.retain(|(k, _)| !k.eq_ignore_ascii_case("CLAUDE_CONFIG_DIR"));
        env.push(("CLAUDE_CONFIG_DIR".into(), dir.to_string_lossy().into_owned()));
    }
    // With Claude's third-party (API/gateway) mode set up, Claude decides 1P vs 3P from
    // machine-wide state and can ignore `--user-data-dir` (see `third_party`).
    if !p.is_default {
        match crate::third_party::mode() {
            crate::third_party::Mode::NotConfigured => {}
            crate::third_party::Mode::FirstParty => managed.push(crate::third_party::KEEP_FIRST_PARTY_SWITCH.into()),
            crate::third_party::Mode::ThirdParty => {
                return Err("账号未启动：本机 Claude 处于第三方推理（API / 网关）模式。此模式下 Claude 会忽略账号目录，所有账号都改用共享的 Claude-3p 数据目录，额外账号会直接退出。请打开默认 Claude，在登录页选择用 Claude 账号登录（切回第一方模式）后重试；或在 Claude 中移除第三方推理配置。".into());
            }
        }
    }
    if p.is_default && install.is_msix() {
        let aumid = install.aumid.as_deref().ok_or("缺少商店版应用标识。")?;
        Command::new("explorer.exe")
            .arg(format!("shell:AppsFolder\\{aumid}"))
            .spawn()
            .map_err(|e| format!("无法启动 Claude：{e}"))?;
        return Ok(outcome);
    }

    let path = PathBuf::from(&p.path);
    if !p.is_default {
        std::fs::create_dir_all(&path).map_err(|e| format!("无法创建账号目录：{e}"))?;
    }

    #[cfg(target_os = "macos")]
    {
        let app = install.aumid.clone().ok_or("找不到 Claude.app。")?;
        let mut pass: Vec<String> = Vec::new();
        if !p.is_default {
            pass.push(format!("--user-data-dir={}", p.path));
        }
        pass.extend(managed);
        pass.extend(extra.split_whitespace().map(str::to_string));
        if sandboxed {
            // macOS isolation: a Seatbelt profile denies everything except loopback, so the only
            // way out is the account's relay. The profile is proven before Claude starts; a check
            // that does not hold refuses the launch instead of running unconfined.
            let profile = crate::macos::configure(&p.id, relay_port).map_err(|e| format!("账号未启动：{e}"))?;
            crate::macos::verify(&profile, relay_port).map_err(|e| format!("账号未启动：{e}"))?;
            let exe = install.launch_exe().ok_or("找不到 Claude 的启动程序。Claude 可能正在更新，请稍后再试。")?;
            // Page fingerprint: Claude is Electron, so a DevTools port lets the account's
            // Canvas/WebGL/font/screen script in before the first page runs. Only accounts with
            // their own data directory have a place for the port file.
            let debug_port = if p.is_default { None } else { crate::macos::free_port() };
            if let Some(port) = debug_port {
                pass.push(format!("--remote-debugging-port={port}"));
            }
            if debug_port.is_some() {
                crate::macos::clear_devtools_port(&path);
            }
            let mut cmd = crate::macos::command(&profile, &exe, &pass, &env);
            cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            let mut child = cmd.spawn().map_err(|e| format!("无法启动 Claude：{e}"))?;
            // `sandbox-exec` execs Claude in place, so this is Claude itself: reap it when it quits.
            std::thread::spawn(move || { let _ = child.wait(); });
            if !p.is_default {
                crate::macos::inject_fingerprint(PathBuf::from(p.path.clone()), crate::browser::fingerprint_script(&p.id));
            }
            return confirm_running(install, p).map(|_| outcome);
        }
        let mut cmd = Command::new("/usr/bin/open");
        cmd.args(["-n", "-a", &app]);
        for (k, v) in &env {
            cmd.args(["--env", &format!("{k}={v}")]);
        }
        if !pass.is_empty() {
            cmd.arg("--args").args(&pass);
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        let status = cmd.status().map_err(|e| format!("无法启动 Claude：{e}"))?;
        if !status.success() { return Err("无法启动 Claude（open 返回错误）。".into()); }
        // `open` returns once the app is launched; Claude may still quit right away (e.g. it
        // rejects a switch). Report that instead of a false "started".
        return confirm_running(install, p).map(|_| outcome);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let exe = if sandboxed {
            crate::sandbox::launch_exe(install).map_err(|e| format!("账号未启动：{e}"))?
        } else {
            install.launch_exe().ok_or("找不到 Claude 的启动程序。Claude 可能正在更新，请稍后再试。")?
        };
        let mut line = Vec::new();
        if !p.is_default {
            line.push(format!("--user-data-dir=\"{}\"", p.path));
        }
        line.extend(managed.into_iter().map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a }));
        if !extra.is_empty() {
            line.push(extra);
        }
        let mut cmd = if sandboxed {
            crate::sandbox::configure(&p.id, &p.path, &crate::sessions::roots(install, p), relay_port).map_err(|e| format!("账号未启动：{e}"))?;
            crate::sandbox::command(&p.id, &exe, &line.join(" "), &env)?
        } else {
            let mut cmd = Command::new(&exe);
            #[cfg(windows)]
            cmd.raw_arg(line.join(" "));
            #[cfg(not(windows))]
            cmd.args(line);
            cmd
        };
        // Claude explains an immediate exit on stderr (e.g. "refusing to start — ..."), so keep it.
        let stderr_path = paths::logs_dir().join(format!("launch-{}.log", safe_file_name(&p.id)));
        let stderr = std::fs::create_dir_all(paths::logs_dir())
            .and_then(|_| std::fs::File::create(&stderr_path))
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());
        cmd.envs(env).stdin(Stdio::null()).stdout(Stdio::null()).stderr(stderr);
        let mut child = cmd.spawn().map_err(|e| format!("无法启动 Claude（{}）：{e}", exe.display()))?;
        #[cfg(windows)]
        if !p.is_default {
            for _ in 0..20 {
                if crate::taskbar::apply(p, child.id()) || !sys::is_alive(child.id()) { break; }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
        }
        let mut result = confirm_started(install, p, &mut child, &stderr_path);
        if sandboxed && result.is_ok() { result = confirm_boxed(install, p); }
        if let Err(e) = &result {
            paths::append_log("hydra-error.log", &format!("launch {}: {e}", p.id));
        }
        result.map(|_| outcome)
    }
}

/// Sandboxed launch: the account's Claude must really run in its box, or it is closed again.
#[cfg(not(target_os = "macos"))]
fn confirm_boxed(install: &Install, p: &Profile) -> Result<(), String> {
    let expected = crate::sandbox::box_name(&p.id);
    let pid = profiles::running_map(install).get(&path_key(&p.path)).copied();
    let actual = pid.and_then(crate::sandbox::box_of);
    if actual.as_deref().is_some_and(|b| b.eq_ignore_ascii_case(&expected)) {
        // Being in the box is not enough: the box's rules open loopback and rely on the
        // guard inside each process to narrow it and to close the DNS path, and the identity
        // guard is what keeps this account from reporting the host's identifiers. If Sandboxie
        // did not load them (blocked by security software, DLL removed), stop here.
        if pid.and_then(crate::sandbox::guard_loaded) == Some(false) {
            let _ = close(install, p);
            return Err("账号未启动：Sandboxie 没有把 Hydra 的防护组件加载进 Claude，沙箱内的 DNS、本机端口限制和设备标识隔离不生效，已将其关闭。请检查安全软件是否拦截了 Hydra 数据目录下 sandbox 文件夹中的 hydra_dnsguard / hydra_idguard DLL，或在 Sandboxie-Plus 中确认该沙箱的 InjectDll64 设置。".into());
        }
        return Ok(());
    }
    let _ = close(install, p);
    if let Some(pid) = pid { if sys::is_alive(pid) { sys::terminate(pid); } }
    Err(format!(
        "账号未启动：Claude 没有运行在沙箱 {expected} 中（{}），为避免在沙箱外联网已将其关闭。请确认 Sandboxie-Plus 服务正在运行，或关闭此环境的沙箱隔离。",
        actual.map(|b| format!("实际所在：{b}")).unwrap_or_else(|| "不在任何沙箱中".into())
    ))
}

#[cfg(not(target_os = "macos"))]
fn safe_file_name(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

/// Waits for the account's Claude main process to appear and survive a moment. Store builds
/// are started through an app execution alias whose own process exits right away, so the
/// spawned child's exit alone proves nothing; only its non-zero exit code is used as a hint.
#[cfg(not(target_os = "macos"))]
fn confirm_started(
    install: &Install,
    p: &Profile,
    child: &mut std::process::Child,
    stderr_path: &std::path::Path,
) -> Result<(), String> {
    use std::time::{Duration, Instant};
    let key = path_key(&p.path);
    let pid = || profiles::running_map(install).get(&key).copied();
    let started = Instant::now();
    let mut code: Option<i32> = None;
    while started.elapsed() < Duration::from_secs(15) {
        if code.is_none() {
            if let Ok(Some(st)) = child.try_wait() {
                code = Some(st.code().unwrap_or(-1));
            }
        }
        if pid().is_some() {
            std::thread::sleep(Duration::from_millis(1500));
            if pid().is_some() {
                return Ok(());
            }
            break;
        }
        // A failing direct child (classic builds, or an alias that could not start the app)
        // needs no further waiting once a little grace time for the real process has passed.
        if matches!(code, Some(c) if c != 0) && started.elapsed() > Duration::from_secs(2) {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    if code.is_none() {
        if let Ok(Some(st)) = child.try_wait() {
            code = Some(st.code().unwrap_or(-1));
        }
    }
    let said = std::fs::read(stderr_path)
        .map(|b| String::from_utf8_lossy(&b).trim().chars().take(600).collect::<String>())
        .unwrap_or_default();
    let mut msg = String::from("Claude 启动后立即退出了");
    if let Some(c) = code.filter(|c| *c != 0) {
        msg.push_str(&format!("（退出码 {c}）"));
    }
    msg.push('。');
    if !said.is_empty() {
        msg.push_str(&format!("Claude 输出：{}", redact_user(&said)));
    } else {
        msg.push_str("请检查环境配置中的额外启动参数，或先完全退出 Claude（含托盘）后重试；详情见该账号数据目录下 logs\\main.log。");
    }
    Err(msg)
}

fn family(main: u32) -> Vec<u32> {
    let all = sys::processes();
    let mut out = vec![main];
    let mut i = 0;
    while i < out.len() {
        let parent = out[i];
        for p in &all {
            if p.ppid == parent && p.pid != parent && !out.contains(&p.pid) {
                out.push(p.pid);
            }
        }
        i += 1;
    }
    out
}

pub fn close(install: &Install, p: &Profile) -> Result<&'static str, String> {
    let Some(main) = profiles::running_map(install).get(&path_key(&p.path)).copied() else {
        return Ok("not running");
    };
    let fam = family(main);
    sys::close_windows(main);
    sys::wait_exit(main, 3000);
    for pid in fam.iter().rev() {
        sys::terminate(*pid);
    }
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < until && sys::is_alive(main) {
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    if sys::is_alive(main) {
        return Err(format!(
            "系统拒绝结束“{}”（进程 {main}）。它可能以更高权限运行，请从其窗口或托盘图标手动退出。",
            p.name
        ));
    }
    // Helpers that detached from Claude's process tree (terminals, MCP servers) still sit in
    // the account's box and would keep using its relay.
    if settings::load().effective(&p.id).isolation == "sandboxie" { crate::sandbox::terminate_box(&p.id); }
    Ok("closed")
}

pub fn restart(install: &Install, p: &Profile) -> Result<&'static str, String> {
    close(install, p)?;
    std::thread::sleep(std::time::Duration::from_millis(400));
    launch(install, p)
}

/// Waits for the account's Claude to appear and stay up for a moment.
#[cfg(target_os = "macos")]
fn confirm_running(install: &Install, p: &Profile) -> Result<(), String> {
    let key = path_key(&p.path);
    let pid = || profiles::running_map(install).get(&key).copied();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while std::time::Instant::now() < until {
        if pid().is_some() {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            if pid().is_some() { return Ok(()); }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Err("Claude 启动后立即退出了。请检查环境配置中的额外启动参数，或先关闭该账号后重试。".into())
}

const NO_ENVIRONMENT: &str = "账号未启动：这个账号没有绑定带代理节点的环境，启动后会用本机网络直连。请在“账号 → 编辑”中为它选择环境；确实需要直连时，可在“设置”中关闭“额外账号必须绑定代理环境”。";

/// Quick add (tray, CLI): creates an account and opens it to sign in. Refused while extra
/// accounts must have a proxy environment, since a new one has none yet.
pub fn add_account(install: &Install) -> Result<Profile, String> {
    if settings::load().requires_environment() {
        return Err("已开启“额外账号必须绑定代理环境”，快速添加的账号没有环境，会用本机网络直连。请在 Claude-Hydra 主界面点“新建账号”并选择环境。".into());
    }
    let created = profiles::create(install, &profiles::next_account_name(install))?;
    launch(install, &created)?;
    Ok(created)
}

/// Creates a native desktop shortcut pointing directly to the Claude-Hydra executable.
pub fn create_shortcut(p: &Profile) -> Result<PathBuf, String> {
    let desktop = paths::desktop_dir().ok_or("无法定位桌面目录。")?;
    std::fs::create_dir_all(&desktop).map_err(|e| format!("无法访问桌面目录：{e}"))?;
    let exe = std::env::current_exe().map_err(|e| format!("无法获取当前程序路径：{e}"))?;
    let ext = if cfg!(windows) { "lnk" } else { "command" };
    let safe_name: String = p
        .name
        .chars()
        .map(|c| if "\\/:*?\"<>|".contains(c) { '_' } else { c })
        .collect();
    let lnk_path = desktop.join(format!("Claude - {safe_name}.{ext}"));
    let args = format!("--launch \"{}\"", p.id);
    let desc = format!("启动 Claude-Hydra 账号：{}", p.name);
    sys::write_shortcut(&lnk_path, &exe, &args, &desc)?;
    #[cfg(windows)]
    crate::taskbar::shortcut(p, &lnk_path)?;
    Ok(lnk_path)
}

fn redact_user(s: &str) -> String {
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    if user.len() >= 2 {
        s.replace(&user, "<user>")
    } else {
        s.to_string()
    }
}

/// Generates a redacted diagnostic report in pure Rust.
pub fn diagnostics(install_res: Result<Install, String>) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Claude-Hydra v{} ({})", env!("CARGO_PKG_VERSION"), std::env::consts::OS));
    lines.push(format!("Storage Root: {}", redact_user(&paths::storage_root().to_string_lossy())));
    lines.push(format!("Settings File: {}", redact_user(&paths::settings_path().to_string_lossy())));
    lines.push(format!(
        "Claude Egress Policy: {}",
        sys::claude_egress_policy().unwrap_or_else(|| "none".into())
    ));
    match install_res {
        Ok(inst) => {
            lines.push(format!("Claude Install Kind: {}", inst.kind));
            if let Some(exe) = &inst.exe {
                lines.push(format!("Claude Exe: {}", redact_user(&exe.to_string_lossy())));
            }
            if let Some(fam) = &inst.family {
                lines.push(format!("Claude Package Family: {fam}"));
            }
            lines.push(format!(
                "Default Profile: {}",
                redact_user(&inst.default_profile.to_string_lossy())
            ));
            lines.push(String::new());
            lines.push("Accounts:".into());
            for p in profiles::list(&inst, true) {
                let status = p.pid.map(|pid| format!("running (pid {pid})")).unwrap_or_else(|| "stopped".into());
                lines.push(format!(
                    "  - {} [{}]: {} | keep_running={} | path={}",
                    p.name,
                    p.id,
                    status,
                    p.keep_running,
                    redact_user(&p.path)
                ));
            }
        }
        Err(e) => {
            lines.push(format!("Claude Install Error: {}", redact_user(&e)));
        }
    }
    let err_log = paths::read_log_tail("hydra-error.log", 4096);
    if !err_log.trim().is_empty() {
        lines.push(String::new());
        lines.push("Recent Errors:".into());
        lines.push(redact_user(err_log.trim()));
    }
    lines.join("\n")
}
