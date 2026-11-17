//! Claude-Hydra application entry, system tray management, and Tauri IPC commands.

pub mod browser;
pub mod cli;
pub mod environment;
pub mod guard;
pub mod identity;
pub mod install;
pub mod launcher;
pub mod login;
#[cfg(target_os = "macos")]
mod mac_url;
pub mod macos;
pub mod macos_isolation;
pub mod paths;
pub mod profiles;
pub mod node;
pub mod quota;
mod releases;
pub mod sandbox;
pub mod clash;
mod relay;
pub mod secret;
pub mod sessions;
pub mod settings;
pub mod sys;
pub mod third_party;
#[cfg(windows)]
mod taskbar;
pub mod watchdog;

use install::Install;
use profiles::{Profile, ProfileOptions};
use serde::Serialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WebviewWindowBuilder};

const TRAY_ID: &str = "hydra";

#[derive(Default)]
struct AppState {
    install: Mutex<Option<Install>>,
}

fn current_install(app: &AppHandle) -> Result<Install, String> {
    let state = app.state::<AppState>();
    let mut guard = state.install.lock().map_err(|_| "内部状态错误")?;
    if let Some(i) = guard.as_ref() {
        if i.launch_exe().is_some() || i.is_msix() {
            return Ok(i.clone());
        }
    }
    let found = install::resolve()?;
    *guard = Some(found.clone());
    Ok(found)
}

fn find(app: &AppHandle, id: &str) -> Result<(Install, Profile), String> {
    let i = current_install(app)?;
    let p = profiles::resolve(&i, id, false).ok_or("找不到这个账号。")?;
    Ok((i, p))
}

fn after_change(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || refresh_tray(&app));
}

#[tauri::command]
fn list_profiles(app: AppHandle) -> Result<Vec<Profile>, String> {
    let i = current_install(&app)?;
    Ok(profiles::list(&i, true))
}

#[tauri::command]
async fn launch_profile(app: AppHandle, id: String) -> Result<String, String> {
    let a = app.clone();
    let r = tauri::async_runtime::spawn_blocking(move || {
        let (i, p) = find(&a, &id)?;
        launcher::launch(&i, &p).map(str::to_string)
    })
    .await
    .map_err(|e| e.to_string())?;
    after_change(&app);
    r
}

#[tauri::command]
async fn close_profile(app: AppHandle, id: String) -> Result<String, String> {
    let a = app.clone();
    let r = tauri::async_runtime::spawn_blocking(move || {
        let (i, p) = find(&a, &id)?;
        launcher::close(&i, &p).map(str::to_string)
    })
    .await
    .map_err(|e| e.to_string())?;
    after_change(&app);
    r
}

#[tauri::command]
async fn restart_profile(app: AppHandle, id: String) -> Result<String, String> {
    let a = app.clone();
    let r = tauri::async_runtime::spawn_blocking(move || {
        let (i, p) = find(&a, &id)?;
        launcher::restart(&i, &p).map(str::to_string)
    })
    .await
    .map_err(|e| e.to_string())?;
    after_change(&app);
    r
}

#[tauri::command]
async fn add_account(app: AppHandle) -> Result<Profile, String> {
    let a = app.clone();
    let r = tauri::async_runtime::spawn_blocking(move || {
        let i = current_install(&a)?;
        if settings::load().requires_environment() {
            return Err("已开启“额外账号必须绑定代理环境”，请用“新建账号”并选择环境。".into());
        }
        let p = profiles::create(&i, &profiles::next_account_name(&i))?;
        #[cfg(target_os = "macos")]
        let _ = login::mac::expect_sign_in(&p.id);
        launcher::launch(&i, &p)?;
        Ok(p)
    })
        .await
        .map_err(|e| e.to_string())?;
    after_change(&app);
    r
}

#[tauri::command]
fn next_account_name(app: AppHandle) -> Result<String, String> {
    Ok(profiles::next_account_name(&current_install(&app)?))
}

#[tauri::command]
async fn create_configured_account(app: AppHandle, name: String, environment: String) -> Result<Profile, String> {
    let a = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let install = current_install(&a)?;
        let name = name.trim();
        profiles::validate_name(&install, name, None)?;
        let environment = profiles::check_environment(&install, &settings::load(), "", &environment)?;
        let p = profiles::create(&install, name)?;
        if let Err(e) = settings::update(|s| s.account_mut(&p.id).environment = environment) {
            let _ = std::fs::remove_dir(&p.path);
            return Err(e);
        }
        relay::sync_all();
        #[cfg(target_os = "macos")]
        let _ = login::mac::expect_sign_in(&p.id);
        if let Err(e) = launcher::launch(&install, &p) { return Err(format!("账号已创建，但启动失败：{e}")); }
        Ok(p)
    }).await.map_err(|e| e.to_string())?;
    after_change(&app);
    result
}

#[tauri::command]
fn list_environments() -> Vec<environment::EnvironmentView> {
    environment::list()
}

#[tauri::command]
fn save_environment(app: AppHandle, id: Option<String>, input: environment::EnvironmentInput) -> Result<String, String> {
    let id = environment::save(&current_install(&app)?, id.as_deref(), &input)?;
    // Starting or re-checking a node can take seconds; never on the UI thread.
    relay::sync_soon();
    after_change(&app);
    Ok(id)
}

#[tauri::command]
fn delete_environment(app: AppHandle, id: String) -> Result<(), String> {
    environment::delete(&id)?;
    // Starting or re-checking a node can take seconds; never on the UI thread.
    relay::sync_soon();
    after_change(&app);
    Ok(())
}

#[tauri::command]
async fn check_node(node: node::NodeConfig) -> Result<(node::ExitInfo, Option<String>, String), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let node = node.validated()?;
        let (node, _core) = clash::resolve(&node)?;
        let client = node.client(Duration::from_secs(15))?;
        let exit = node::inspect(&client, &node)?;
        let quality = node::network_quality(&client, &exit.ip);
        let risk = node::reputation(&client, &exit.ip).to_owned();
        Ok((exit, quality, risk))
    }).await.map_err(|_| "检测任务失败。".to_string())?
}

#[tauri::command]
async fn refresh_node_ip(url: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || node::refresh(&url)).await.map_err(|_| "刷新任务失败。".to_string())?
}

#[tauri::command]
fn profile_options(app: AppHandle, id: String) -> Result<ProfileOptions, String> {
    profiles::options(&current_install(&app)?, &id)
}

#[tauri::command]
fn save_profile_options(app: AppHandle, id: String, options: ProfileOptions) -> Result<(), String> {
    profiles::save_options(&current_install(&app)?, &id, &options)?;
    // Starting or re-checking a node can take seconds; never on the UI thread.
    relay::sync_soon();
    after_change(&app);
    Ok(())
}

#[tauri::command]
fn delete_profile(app: AppHandle, id: String) -> Result<(), String> {
    profiles::remove(&current_install(&app)?, &id)?;
    // Starting or re-checking a node can take seconds; never on the UI thread.
    relay::sync_soon();
    after_change(&app);
    Ok(())
}

#[tauri::command]
fn open_profile_folder(app: AppHandle, id: String) -> Result<(), String> {
    let (_, p) = find(&app, &id)?;
    std::fs::create_dir_all(&p.path).ok();
    let opener = if cfg!(windows) { "explorer.exe" } else { "open" };
    std::process::Command::new(opener)
        .arg(&p.path)
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn create_shortcut(app: AppHandle, id: String) -> Result<String, String> {
    let (_, p) = find(&app, &id)?;
    let path = launcher::create_shortcut(&p)?;
    Ok(format!("已在桌面创建快捷方式：{}", path.file_name().unwrap_or_default().to_string_lossy()))
}

#[tauri::command]
fn setup_login_router() -> Result<(), String> { login::register() }

#[tauri::command]
async fn prepare_login(app: AppHandle, id: String) -> Result<(), String> {
    let a = app.clone();
    // Launching may wait for the proxy check; keep it off the main thread.
    if !cfg!(any(windows, target_os = "macos")) {
        return Err("浏览器登录回调目前仅支持 Windows 和 macOS。".into());
    }
    let r = tauri::async_runtime::spawn_blocking(move || {
        let (i, p) = find(&a, &id)?;
        let signed_in = profiles::resolve(&i, &p.id, true).and_then(|x| x.signed_in).unwrap_or(false);
        login::arm(&p.id, signed_in)?;
        #[cfg(target_os = "macos")]
        login::mac::hold_during_login()?;
        launcher::launch(&i, &p).map(|_| ())
    })
    .await
    .map_err(|e| e.to_string())?;
    after_change(&app);
    r
}

/// Opens the account's own browser on its exit IP and time zone (`url` defaults to sign-in).
#[tauri::command]
async fn open_account_browser(app: AppHandle, id: String, url: Option<String>) -> Result<(), String> {
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || browser::open(&a, browser::plan(&id, url.as_deref())?))
        .await.map_err(|e| e.to_string())?
}

/// Re-checks a blocked account's exit and restores its network when it complies again.
#[tauri::command]
async fn resume_account(app: AppHandle, id: String) -> Result<String, String> {
    let r = tauri::async_runtime::spawn_blocking(move || guard::resume(&id))
        .await.map_err(|e| e.to_string())?;
    after_change(&app);
    r
}

/// Binds an environment's exit rule to the node's current exit and unblocks its accounts.
#[tauri::command]
async fn rebind_exit(app: AppHandle, id: String) -> Result<String, String> {
    let r = tauri::async_runtime::spawn_blocking(move || guard::rebind(&id).map(|x| guard::describe(&x)))
        .await.map_err(|e| e.to_string())?;
    after_change(&app);
    r
}

/// Sandboxie-Plus install folder, or why sandbox isolation is unavailable.
#[tauri::command]
fn sandbox_status() -> Result<String, String> {
    sandbox::available().map(|p| p.display().to_string())
}

#[tauri::command]
fn configure_quiet_sandbox() -> Result<(), String> {
    sandbox::configure_quiet_start()
}

#[tauri::command]
fn diagnostics(app: AppHandle) -> String {
    launcher::diagnostics(current_install(&app))
}

#[tauri::command]
async fn session_preview(app: AppHandle, source: String, target: String, trash: Option<bool>) -> Result<sessions::Preview, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let (i, s) = find(&app, &source)?;
        if target.is_empty() { return sessions::source_preview(&i, &s, trash.unwrap_or(false)); }
        let (_, t) = find(&app, &target)?;
        sessions::preview(&i, &s, &t)
    }).await.map_err(|_| "读取会话任务失败。".to_string())?
}

#[tauri::command]
async fn copy_sessions(app: AppHandle, source: String, target: String, ids: Vec<String>, restart: Option<bool>) -> Result<sessions::TransferResult, String> {
    let a = app.clone();
    let r = tauri::async_runtime::spawn_blocking(move || {
        let (i, s) = find(&a, &source)?;
        let (_, t) = find(&a, &target)?;
        // Desktop reads its session list only at startup: close the target, copy, relaunch.
        let restart = restart.unwrap_or(false) && sessions::needs_closed_target(&i, &t, &ids);
        if restart { launcher::close(&i, &t)?; }
        let copied = sessions::copy(&i, &s, &t, &ids);
        if restart {
            std::thread::sleep(std::time::Duration::from_millis(400));
            if let Err(e) = launcher::launch(&i, &t) {
                return Err(match copied {
                    Ok(_) => format!("会话已迁移，但重新启动「{}」失败：{e}", t.name),
                    Err(c) => format!("{c}（重新启动「{}」也失败：{e}）", t.name),
                });
            }
        }
        copied
    }).await.map_err(|_| "迁移任务失败。".to_string())?;
    after_change(&app);
    r
}

#[tauri::command]
async fn read_import(app: AppHandle, account: String, id: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let (i, p) = find(&app, &account)?;
        sessions::read_import(&i, &p, &id)
    }).await.map_err(|_| "会话操作失败。".to_string())?
}

#[tauri::command]
async fn import_chats(app: AppHandle, account: String, raw: String) -> Result<sessions::TransferResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let (i, p) = find(&app, &account)?;
        sessions::import_chats(&i, &p, &raw)
    }).await.map_err(|_| "会话操作失败。".to_string())?
}

#[tauri::command]
async fn recycle_session(app: AppHandle, account: String, action: String, id: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        let (i, p) = find(&app, &account)?;
        sessions::recycle(&i, &p, &action, &id)
    }).await.map_err(|_| "会话操作失败。".to_string())?
}

#[tauri::command]
async fn profile_quota(app: AppHandle, id: String) -> Result<quota::Quota, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let (install, profile) = find(&app, &id)?;
        quota::fetch(&install, &profile)
    }).await.map_err(|_| "额度查询任务失败。".to_string())?
}

#[tauri::command]
async fn save_transcript(app: AppHandle, text: String) -> Result<String, String> {
    use std::{fs::OpenOptions, io::Write};
    let dir = app.path().download_dir().map_err(|_| "无法定位下载目录。")?;
    tauri::async_runtime::spawn_blocking(move || {
        std::fs::create_dir_all(&dir).map_err(|_| "无法访问下载目录。")?;
        let stamp = paths::now_millis();
        for i in 0..100 {
            let file = dir.join(format!("Claude-chat-{stamp}-{i}.txt"));
            match OpenOptions::new().write(true).create_new(true).open(&file) {
                Ok(mut out) => {
                    if out.write_all(text.as_bytes()).is_err() {
                        drop(out);
                        let _ = std::fs::remove_file(&file);
                        return Err("续聊附件写入失败。".to_string());
                    }
                    return Ok(file.to_string_lossy().into_owned());
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err("无法在下载目录创建附件。".to_string()),
            }
        }
        Err("文件名冲突，请重新保存。".to_string())
    }).await.map_err(|_| "保存任务失败。".to_string())?
}

/// Shows a chat transcript Hydra saved in the file manager, so it can be dragged into Claude.
#[tauri::command]
fn reveal_transcript(app: AppHandle, path: String) -> Result<(), String> {
    let dir = app.path().download_dir().map_err(|_| "无法定位下载目录。")?;
    let file = std::path::PathBuf::from(&path);
    let name = file.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    // Only files written by `save_transcript`.
    if file.parent() != Some(dir.as_path()) || !name.starts_with("Claude-chat-") || !name.ends_with(".txt") || !file.is_file() {
        return Err("只能显示 Hydra 保存的续聊附件。".into());
    }
    #[cfg(windows)]
    let r = std::process::Command::new("explorer.exe").arg(format!("/select,{}", file.display())).spawn();
    #[cfg(not(windows))]
    let r = std::process::Command::new("open").arg("-R").arg(&file).spawn();
    r.map(|_| ()).map_err(|e| format!("无法打开文件位置：{e}"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    version: String,
    platform: String,
    install: Option<Install>,
    install_error: Option<String>,
    claude_path: Option<String>,
    storage_root: String,
    settings_path: String,
    autostart: bool,
    /// Extra accounts refuse to start without a proxy environment.
    require_environment: bool,
}

#[tauri::command]
fn app_info(app: AppHandle) -> AppInfo {
    let (install, install_error) = match current_install(&app) {
        Ok(i) => (Some(i), None),
        Err(e) => (None, Some(e)),
    };
    let s = settings::load();
    AppInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        platform: std::env::consts::OS.into(),
        install,
        install_error,
        claude_path: s.claude_path.clone(),
        storage_root: paths::storage_root().to_string_lossy().into(),
        settings_path: paths::settings_path().to_string_lossy().into(),
        autostart: sys::autostart_enabled(),
        require_environment: s.requires_environment(),
    }
}

#[tauri::command]
fn set_autostart(enabled: bool) -> Result<(), String> {
    if enabled {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        sys::set_autostart(Some(&format!("\"{}\" --tray", exe.display())))
    } else {
        sys::set_autostart(None)
    }
}

#[tauri::command]
fn set_require_environment(enabled: bool) -> Result<(), String> {
    settings::update(|s| s.require_environment = Some(enabled))
}

#[tauri::command]
fn set_claude_path(app: AppHandle, path: Option<String>) -> Result<(), String> {
    let path = path
        .map(|p| p.trim().trim_matches('"').to_string())
        .filter(|p| !p.is_empty());
    if let Some(p) = &path {
        if !std::path::Path::new(p).exists() {
            return Err(format!("路径不存在：{p}"));
        }
        if !install::valid_program_path(std::path::Path::new(p)) {
            return Err("请选择 Claude 的 .exe 程序文件，或留空以自动查找。".into());
        }
    }
    settings::update(|s| {
        s.claude_path = path.clone();
        s.install_cache = None;
    })?;
    if let Ok(mut g) = app.state::<AppState>().install.lock() {
        *g = None;
    }
    current_install(&app).map(|_| ())
}

#[tauri::command]
fn quit_app(app: AppHandle) {
    app.exit(0);
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let Some(cfg) = app.config().app.windows.iter().find(|w| w.label == "main").cloned() else { return };
    let Ok(builder) = WebviewWindowBuilder::from_config(app, &cfg) else { return };
    #[cfg(target_os = "macos")]
    let builder = builder
        .decorations(true)
        .title_bar_style(tauri::TitleBarStyle::Overlay)
        .hidden_title(true)
        // Vertically centre the traffic lights on the 48px sidebar header row.
        .traffic_light_position(tauri::LogicalPosition::new(18.0, 22.0));
    if let Ok(w) = builder.build() {
        fit_to_screen(&w);
        let app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            if let Some(w) = app.get_webview_window("main") {
                if !w.is_visible().unwrap_or(true) {
                    let _ = w.show();
                    let _ = w.unminimize();
                    let _ = w.set_focus();
                }
            }
        });
    }
}

fn fit_to_screen(w: &tauri::WebviewWindow) {
    let (Ok(Some(mon)), Ok(size)) = (w.current_monitor(), w.outer_size()) else { return };
    let area = mon.work_area().size;
    let max_w = (area.width as f64 * 0.9) as u32;
    let max_h = (area.height as f64 * 0.9) as u32;
    if size.width > max_w || size.height > max_h {
        let _ = w.set_size(tauri::PhysicalSize::new(size.width.min(max_w), size.height.min(max_h)));
        let _ = w.center();
    }
}

fn build_menu(app: &AppHandle, list: &[Profile]) -> tauri::Result<Menu<tauri::Wry>> {
    let menu = Menu::new(app)?;
    for p in list {
        let mark = if p.pid.is_some() { "●" } else { "○" };
        menu.append(&MenuItem::with_id(app, format!("p:{}", p.id), format!("{mark}  {}", p.name), true, None::<&str>)?)?;
    }
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&MenuItem::with_id(app, "add", "添加账号…", true, None::<&str>)?)?;
    menu.append(&MenuItem::with_id(app, "show", "打开 Claude-Hydra", true, None::<&str>)?)?;
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?)?;
    Ok(menu)
}

fn signature(list: &[Profile]) -> String {
    list.iter().map(|p| format!("{}|{}|{:?};", p.id, p.name, p.pid)).collect()
}

fn refresh_tray(app: &AppHandle) -> Option<String> {
    let i = current_install(app).ok()?;
    let list = profiles::list(&i, true);
    if let (Some(tray), Ok(menu)) = (app.tray_by_id(TRAY_ID), build_menu(app, &list)) {
        let _ = tray.set_menu(Some(menu));
    }
    let _ = app.emit_to("main", "profiles-changed", &list);
    Some(signature(&list))
}

fn on_menu(app: &AppHandle, id: &str) {
    match id {
        "show" => show_main(app),
        "quit" => app.exit(0),
        "add" => {
            let app = app.clone();
            std::thread::spawn(move || {
                if let Err(e) = current_install(&app).and_then(|i| launcher::add_account(&i)) {
                    sys::error_box(&e);
                }
                refresh_tray(&app);
            });
        }
        other => {
            if let Some(pid) = other.strip_prefix("p:") {
                let (app, pid) = (app.clone(), pid.to_string());
                std::thread::spawn(move || {
                    if let Err(e) = find(&app, &pid).and_then(|(i, p)| launcher::launch(&i, &p)) {
                        sys::error_box(&e);
                    }
                    std::thread::sleep(Duration::from_secs(2));
                    refresh_tray(&app);
                });
            }
        }
    }
}

fn start_background(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last = String::new();
        let mut last_watch = Instant::now();
        // Re-tag a process only when it is new or its set of top-level windows changed,
        // instead of rewriting window properties on every tick.
        #[cfg(windows)]
        let mut tagged: std::collections::HashMap<u32, (usize, usize, String)> = std::collections::HashMap::new();
        loop {
            let open = app.get_webview_window("main").is_some();
            std::thread::sleep(Duration::from_secs(if open { 3 } else { 10 }));
            if let Ok(i) = current_install(&app) {
                let list = profiles::list(&i, true);
                #[cfg(target_os = "macos")]
                login::mac::maintain(&i, &list);
                #[cfg(windows)]
                {
                    tagged.retain(|pid, _| list.iter().any(|p| p.pid == Some(*pid)));
                    for profile in list.iter().filter(|p| !p.is_default) {
                        let Some(pid) = profile.pid else { continue };
                        let windows = (sys::top_windows(pid).len(), profile.color, profile.badge.clone());
                        if tagged.get(&pid) != Some(&windows) && taskbar::apply(profile, pid) {
                            tagged.insert(pid, windows);
                        }
                    }
                }
                let sig = signature(&list);
                if sig != last {
                    if let (Some(tray), Ok(menu)) = (app.tray_by_id(TRAY_ID), build_menu(&app, &list)) {
                        let _ = tray.set_menu(Some(menu));
                    }
                    let _ = app.emit_to("main", "profiles-changed", &list);
                    last = sig;
                }
                if last_watch.elapsed() >= Duration::from_secs(60) {
                    last_watch = Instant::now();
                    if watchdog::any_kept() {
                        watchdog::run_once(&i);
                    }
                }
            }
        }
    });
}

pub fn run(start_in_tray: bool) {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        // `--tray` instances are started only to make sure a host runs (e.g. by link routing).
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| if !args.iter().any(|a| a == "--tray") { show_main(app) }))
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            launch_profile,
            close_profile,
            restart_profile,
            add_account,
            next_account_name,
            create_configured_account,
            profile_options,
            check_node,
            clash::clash_subscription,
            list_environments,
            save_environment,
            delete_environment,
            refresh_node_ip,
            save_profile_options,
            delete_profile,
            open_profile_folder,
            create_shortcut,
            setup_login_router,
            prepare_login,
            open_account_browser,
            resume_account,
            rebind_exit,
            sandbox_status,
            configure_quiet_sandbox,
            diagnostics,
            session_preview,
            read_import,
            import_chats,
            recycle_session,
            copy_sessions,
            profile_quota,
            releases::release_notes,
            releases::open_release_page,
            releases::restart_app,
            save_transcript,
            reveal_transcript,
            app_info,
            set_autostart,
            set_require_environment,
            set_claude_path,
            quit_app,
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            // This process hosts the per-account proxy relays for as long as it runs.
            relay::set_host();
            let notify = handle.clone();
            guard::on_block(move |id, reason, soft| {
                let _ = notify.emit_to("main", "guard-blocked", (id, reason));
                after_change(&notify);
                let name = settings::load().account(id).label.filter(|l| !l.trim().is_empty()).unwrap_or_else(|| id.to_string());
                let text = if soft {
                    format!("出口保护暂时无法核验账号“{name}”的出口，已暂停它的网络。\n\n{reason}\n\nHydra 会自动重试，核验通过后自动恢复网络；也可以在账号菜单中选择“恢复网络”立即重新检测。")
                } else {
                    format!("出口保护已切断账号“{name}”的网络。\n\n{reason}\n\n在账号菜单中选择“恢复网络”可重新检测。")
                };
                std::thread::spawn(move || sys::error_box(&text));
            });
            let restored = handle.clone();
            guard::on_restore(move |_id| after_change(&restored));
            relay::start_monitor();
            browser::start_watcher(handle.clone());
            browser::remember_fallback();
            environment::migrate();
            // A settings file written before the Keychain was used still holds `plain:` secrets;
            // re-seal them in the background (it may wait for the login Keychain to unlock).
            #[cfg(target_os = "macos")]
            std::thread::spawn(|| crate::secret::migrate_settings_file(&crate::paths::settings_path()));
            // Starting Clash-node relays waits for each Mihomo core; keep the window responsive.
            std::thread::spawn(|| { clash::sweep_stale_runs(); relay::sync_all(); });
            let list = current_install(&handle).map(|i| profiles::list(&i, true)).unwrap_or_default();
            let mut tray = TrayIconBuilder::with_id(TRAY_ID)
                .tooltip("Claude-Hydra")
                .menu(&build_menu(&handle, &list)?)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, e| on_menu(app, e.id().as_ref()))
                .on_tray_icon_event(|tray, e| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = e
                    {
                        show_main(tray.app_handle());
                    }
                });
            if let Some(icon) = app.default_window_icon().cloned() {
                tray = tray.icon(icon);
            }
            tray.build(app)?;
            start_background(handle.clone());
            if !start_in_tray {
                show_main(&handle);
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Claude-Hydra")
        .run(|_app, event| {
            if matches!(event, RunEvent::Exit) {
                relay::shutdown();
                #[cfg(target_os = "macos")]
                if let Ok(i) = install::resolve() { login::mac::restore(&i); }
            }
            // Sign-in callbacks arrive as Apple events while Hydra holds `claude://`.
            #[cfg(target_os = "macos")]
            if let RunEvent::Opened { urls } = &event {
                for url in urls.iter().filter(|u| u.scheme() == "claude").map(|u| u.to_string()) {
                    std::thread::spawn(move || if let Err(e) = login::mac::handle(&url) { sys::error_box(&e) });
                }
            }
            if let RunEvent::ExitRequested { code: None, api, .. } = event {
                api.prevent_exit();
            }
        });
}
