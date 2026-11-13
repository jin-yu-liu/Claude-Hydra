//! Account browser: a WebView2 window per account that leaves through the account's relay,
//! with the account's timezone and language, so web sign-in (Google) happens on the same exit
//! IP and with the same time zone as the account's Claude.
//!
//! - Network: the same Chromium switches as Claude (SOCKS5 to the relay, names resolved at the
//!   node, no QUIC, WebRTC limited to proxied paths). Exit rules are checked before it opens,
//!   and the relay's kill switch applies to it as well.
//! - Time zone: WebView2 ignores `TZ`, so it is set over the DevTools protocol
//!   (`Emulation.setTimezoneOverride`) before the first page loads, and checked again after every
//!   navigation; a page that reports another zone is replaced by a warning.
//! - Storage: its own WebView2 data folder per account (cookies never mix between accounts).
//! - Page fingerprint: Canvas pixels, WebGL GPU strings, font measurement, screen size and CPU /
//!   memory are answered per account by a script WebView2 runs before the page's own scripts
//!   (see `FINGERPRINT_JS`); the values are derived from the account, so one account looks like
//!   the same browser every time and two accounts never look like each other.
//! - `claude://` links (the sign-in callback) go straight to the account's Claude.
//!
//! Link routing (`--open-url`, Hydra registered as a browser): links that Claude opens for
//! claude.ai / anthropic.com go to the opening account's browser; everything else goes to the
//! browser the user had before.
use crate::{paths, settings, sys};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::time::Duration;

const START_URL: &str = "https://claude.ai/login";
#[cfg(windows)]
const URL_PROGID: &str = "ClaudeHydra.URL";

fn hex_id(id: &str) -> String { crate::sandbox::box_name(id).trim_start_matches("Hydra_").to_string() }

/// Removes a deleted account's browser data (cookies, sign-in).
pub fn forget(id: &str) {
    let _ = std::fs::remove_dir_all(paths::storage_root().join("account-browser").join(hex_id(id)));
}

fn label(id: &str) -> String { format!("acct-browser-{}", hex_id(id)) }

/// A stable number for the account. Everything the page fingerprint below reports is derived from
/// it, so one account always looks like the same browser and two accounts never look alike.
fn fingerprint_seed(id: &str) -> u32 { u32::from_str_radix(&crate::sandbox::account_key(id)[..8], 16).unwrap_or(1) }

/// The script WebView2 runs in every document before the page's own scripts. Canvas pixels, the
/// WebGL vendor/renderer pair, measured text and element widths, screen size and CPU/memory are
/// answered from the account's seed: the differences are invisible (at most a fraction of a pixel
/// or one colour step) but a fingerprint hash computed in one account does not match another.
/// Everything is wrapped in try/catch and falls back to the untouched value, so a page that does
/// not fit the pattern sees the real browser rather than a broken one.
const FINGERPRINT_JS: &str = r#"(function () {
  'use strict';
  var SEED = __SEED__ >>> 0;
  if (!SEED) { SEED = 1; }
  function step(h, v) { return Math.imul(h ^ v, 16777619) >>> 0; }
  function hashText(text, seed) {
    var h = (2166136261 ^ seed) >>> 0;
    for (var i = 0; i < text.length; i++) { h = step(h, text.charCodeAt(i)); }
    return h >>> 0;
  }
  function hashBytes(bytes, seed) {
    var h = seed >>> 0;
    var stride = Math.max(4, ((bytes.length / 512) | 0) * 4);
    for (var i = 0; i < bytes.length; i += stride) { h = step(h, bytes[i]); }
    return h >>> 0;
  }
  function rng(seed) {
    var s = seed >>> 0 || 1;
    return function () {
      s ^= s << 13; s >>>= 0;
      s ^= s >>> 17;
      s ^= s << 5; s >>>= 0;
      return s;
    };
  }
  function noise(data, seed) {
    var r = rng(seed);
    var pixels = (data.length / 4) | 0;
    if (!pixels) { return data; }
    var count = Math.min(16, Math.max(3, (pixels / 64) | 0));
    var changed = new Set();
    for (var i = 0; i < count; i++) {
      var at = (r() % pixels) * 4;
      if (changed.has(at)) { continue; }
      changed.add(at);
      data[at] += (r() & 1) ? 1 : -1;
    }
    return data;
  }
  function mask(fn, name) {
    try {
      Object.defineProperty(fn, 'name', { value: name });
      Object.defineProperty(fn, 'toString', { value: function () { return 'function ' + name + '() { [native code] }'; } });
    } catch (e) {}
    return fn;
  }
  var canvas = window.HTMLCanvasElement && HTMLCanvasElement.prototype;
  function noised(canvasElement) {
    var width = canvasElement.width, height = canvasElement.height;
    if (!width || !height || width * height > 16777216) { return null; }
    var copy = document.createElement('canvas');
    copy.width = width;
    copy.height = height;
    var context = copy.getContext('2d');
    if (!context) { return null; }
    context.drawImage(canvasElement, 0, 0);
    var image = getImageData.call(context, 0, 0, width, height);
    noise(image.data, hashBytes(image.data, SEED ^ 0x85ebca6b));
    context.putImageData(image, 0, 0);
    return copy;
  }
  if (canvas && canvas.toDataURL) {
    var dataURL = canvas.toDataURL;
    canvas.toDataURL = mask(function () {
      try { var copy = noised(this); if (copy) { return dataURL.apply(copy, arguments); } } catch (e) {}
      return dataURL.apply(this, arguments);
    }, 'toDataURL');
  }
  if (canvas && canvas.toBlob) {
    var toBlob = canvas.toBlob;
    canvas.toBlob = mask(function () {
      try { var copy = noised(this); if (copy) { return toBlob.apply(copy, arguments); } } catch (e) {}
      return toBlob.apply(this, arguments);
    }, 'toBlob');
  }
  var context2d = window.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype;
  if (context2d && context2d.getImageData) {
    var getImageData = context2d.getImageData;
    context2d.getImageData = mask(function () {
      var image = getImageData.apply(this, arguments);
      try { noise(image.data, hashBytes(image.data, SEED ^ 0x85ebca6b)); } catch (e) {}
      return image;
    }, 'getImageData');
  }
  if (context2d && context2d.measureText) {
    var measureText = context2d.measureText;
    context2d.measureText = mask(function (text) {
      var metrics = measureText.apply(this, arguments);
      try {
        var delta = ((hashText(String(text) + '\u0000' + (this.font || ''), SEED) % 5) - 2) * 0.008;
        return new Proxy(metrics, {
          get: function (target, key) {
            if (key === 'width') { return target.width + delta; }
            var value = target[key];
            return typeof value === 'function' ? value.bind(target) : value;
          }
        });
      } catch (e) { return metrics; }
    }, 'measureText');
  }
  function measured(value) { if (value === 0) { return 0; } return value + (((hashText('m' + value, SEED) % 3) - 1) * 0.01); }
  if (window.Element && Element.prototype.getBoundingClientRect) {
    var getBoundingClientRect = Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect = mask(function () {
      var box = getBoundingClientRect.apply(this, arguments);
      try { return new DOMRect(box.x, box.y, measured(box.width), measured(box.height)); } catch (e) { return box; }
    }, 'getBoundingClientRect');
  }
  var screens = [[1920, 1080], [2560, 1440], [1680, 1050], [1920, 1200], [2560, 1600]];
  var chosen = screens[(SEED >>> 8) % screens.length];
  if (window.Screen) {
    var values = { width: chosen[0], availWidth: chosen[0], height: chosen[1], availHeight: chosen[1] - 48, colorDepth: 24, pixelDepth: 24 };
    Object.keys(values).forEach(function (name) {
      try {
        Object.defineProperty(Screen.prototype, name, {
          configurable: true,
          enumerable: true,
          get: mask(function () { return values[name]; }, 'get ' + name)
        });
      } catch (e) {}
    });
  }
  if (window.Navigator) {
    var cores = [4, 8, 12, 16][(SEED >>> 4) & 3];
    var memory = [4, 8, 8, 16][(SEED >>> 6) & 3];
    try {
      Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {
        configurable: true, enumerable: true, get: mask(function () { return cores; }, 'get hardwareConcurrency')
      });
    } catch (e) {}
    try {
      if ('deviceMemory' in Navigator.prototype) {
        Object.defineProperty(Navigator.prototype, 'deviceMemory', {
          configurable: true, enumerable: true, get: mask(function () { return memory; }, 'get deviceMemory')
        });
      }
    } catch (e) {}
  }
  var gpus = [
    ['Google Inc. (NVIDIA)', 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)'],
    ['Google Inc. (NVIDIA)', 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)'],
    ['Google Inc. (Intel)', 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)'],
    ['Google Inc. (AMD)', 'ANGLE (AMD, AMD Radeon RX 580 Series Direct3D11 vs_5_0 ps_5_0, D3D11)'],
    ['Google Inc. (Intel)', 'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)']
  ];
  var gpu = gpus[(SEED >>> 12) % gpus.length];
  ['WebGLRenderingContext', 'WebGL2RenderingContext'].forEach(function (name) {
    var proto = window[name] && window[name].prototype;
    if (!proto || !proto.getParameter) { return; }
    var getParameter = proto.getParameter;
    proto.getParameter = mask(function (parameter) {
      if (parameter === 0x9245) { return gpu[0]; }
      if (parameter === 0x9246) { return gpu[1]; }
      return getParameter.apply(this, arguments);
    }, 'getParameter');
  });
})();
"#;

fn fingerprint_script(id: &str) -> String { FINGERPRINT_JS.replace("__SEED__", &fingerprint_seed(id).to_string()) }

/// Hosts whose links belong to the account (sign-in, account pages).
fn is_claude_host(host: &str) -> bool {
    ["claude.ai", "claude.com", "anthropic.com"].iter().any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

fn valid_web_url(url: &str) -> Option<url::Url> {
    if url.len() > 16384 || url.chars().any(|c| c.is_control() || c.is_whitespace() || c == '"') { return None; }
    url::Url::parse(url).ok().filter(|u| matches!(u.scheme(), "http" | "https"))
}

/// What the account browser needs, decided off the UI thread (it may wait for the node).
pub struct Plan {
    id: String,
    title: String,
    relay_port: Option<u16>,
    /// Applied by the WebView2 browser; other platforms have no account browser.
    #[cfg_attr(not(windows), allow(dead_code))]
    timezone: Option<String>,
    locale: String,
    url: String,
}

/// Checks the account's route like a launch does and returns how to open its browser.
pub fn plan(id: &str, url: Option<&str>) -> Result<Plan, String> {
    let url = url.unwrap_or(START_URL);
    valid_web_url(url).ok_or("只能打开 http 或 https 链接。")?;
    let install = crate::install::resolve()?;
    let p = crate::profiles::resolve(&install, id, false).ok_or("找不到这个账号。")?;
    let s = settings::load();
    let eff = s.effective(id);
    // A soft cut is re-checked by `port_for_launch` below instead of being refused here.
    if let Some(reason) = s.account(id).blocked.filter(|_| !s.account(id).blocked_soft) {
        return Err(format!("出口保护已切断这个账号的网络——{reason}\n请先“恢复网络”或重新绑定出口。"));
    }
    if eff.unusable_node { return Err("这个账号的代理节点无法读取（密码不能解密或配置损坏），为避免直连已拒绝打开。请重新保存它的环境配置。".into()); }
    if eff.node.is_none() && !p.is_default && s.requires_environment() {
        return Err("这个账号没有绑定带代理节点的环境，账号浏览器会用本机网络直连，已拒绝打开。请先在“账号 → 编辑”中选择环境。".into());
    }
    let mut timezone = match eff.timezone.as_str() { "" | "proxy" | "system" => None, tz => Some(tz.to_string()) };
    let mut relay_port = None;
    if let Some(node) = &eff.node {
        let port = crate::relay::port_for_launch(id, node)?;
        let exit = crate::node::inspect(&crate::node::relay_client(port, Duration::from_secs(15))?, node)?;
        crate::guard::verify(eff.environment.as_deref(), &exit)?;
        if matches!(eff.timezone.as_str(), "" | "proxy") {
            if exit.timezone.is_empty() { return Err("IP 查询服务没有返回出口时区，无法让浏览器时区与出口一致。请换一个 IP 查询渠道或手动指定时区。".into()); }
            timezone = Some(exit.timezone.clone());
        }
        relay_port = Some(port);
    }
    let locale = eff.environment.as_deref().and_then(|e| s.environments.get(e)).map(|e| e.locale.clone()).unwrap_or_default();
    Ok(Plan { id: id.to_string(), title: format!("{} · 账号浏览器", p.name), relay_port, timezone, locale, url: url.to_string() })
}

fn browser_args(plan: &Plan) -> String {
    let mut args = vec!["--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection".to_string(), "--no-first-run".into()];
    if let Some(port) = plan.relay_port { args.extend(crate::node::chromium_args(port)); }
    if !plan.locale.is_empty() {
        let lang = plan.locale.split('-').next().unwrap_or_default();
        args.push(format!("--lang={}", plan.locale));
        args.push(format!("--accept-lang={},{lang}", plan.locale));
    }
    args.join(" ")
}

/// Opens (or reuses) the account's browser window. Call from any thread but the UI thread.
pub fn open(app: &tauri::AppHandle, plan: Plan) -> Result<(), String> {
    use tauri::{webview::NewWindowResponse, Manager, WebviewUrl, WebviewWindowBuilder};
    // Decide before any window exists: the time zone override below is WebView2-only, and a
    // window without it would show the account's pages in the system zone.
    if !cfg!(windows) { return Err("账号浏览器目前只支持 Windows。".into()); }
    let label = label(&plan.id);
    if let Some(w) = app.get_webview_window(&label) {
        let target = plan.url.parse().map_err(|_| "链接无效。")?;
        w.navigate(target).map_err(|e| e.to_string())?;
        let _ = w.unminimize();
        let _ = w.set_focus();
        return Ok(());
    }
    let data_dir = paths::storage_root().join("account-browser").join(hex_id(&plan.id));
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("无法创建浏览器数据目录：{e}"))?;
    let (nav_app, nav_id, nav_label) = (app.clone(), plan.id.clone(), label.clone());
    let (win_app, win_label) = (app.clone(), label.clone());
    let w = WebviewWindowBuilder::new(app, &label, WebviewUrl::External("about:blank".parse().expect("static url")))
        .initialization_script(fingerprint_script(&plan.id))
        .title(&plan.title)
        .inner_size(1100.0, 820.0)
        .data_directory(data_dir)
        .additional_browser_args(&browser_args(&plan))
        .on_navigation(move |u| allow_navigation(&nav_app, &nav_id, &nav_label, u))
        .on_new_window(move |u, _| {
            // Popups open in the same window, which keeps the same network and time zone.
            let (app, label) = (win_app.clone(), win_label.clone());
            if matches!(u.scheme(), "http" | "https") {
                std::thread::spawn(move || if let Some(w) = app.get_webview_window(&label) { let _ = w.navigate(u); });
            }
            NewWindowResponse::Deny
        })
        .build()
        .map_err(|e| format!("无法打开账号浏览器：{e}"))?;
    #[cfg(windows)]
    {
        let (tz, url) = (plan.timezone.clone(), plan.url.clone());
        w.with_webview(move |pw| {
            if let Err(e) = unsafe { webview2::start(pw.controller(), tz, url) } {
                paths::append_log("hydra-error.log", &format!("account browser: {e}"));
            }
        }).map_err(|e| e.to_string())?;
    }
    #[cfg(not(windows))]
    let _ = w;
    Ok(())
}

fn allow_navigation(app: &tauri::AppHandle, id: &str, label: &str, u: &url::Url) -> bool {
    match u.scheme() {
        "http" | "https" | "about" | "data" | "blob" => true,
        "claude" => {
            let (app, id, label, url) = (app.clone(), id.to_string(), label.to_string(), u.to_string());
            std::thread::spawn(move || {
                #[cfg(not(target_os = "macos"))]
                let r = crate::login::deliver(&id, &url);
                #[cfg(target_os = "macos")]
                let r: Result<(), String> = { let _ = (&id, &url); Err("macOS 不使用账号浏览器。".into()) };
                match r {
                    Ok(()) => { use tauri::Manager; if let Some(w) = app.get_webview_window(&label) { let _ = w.close(); } }
                    Err(e) => sys::error_box(&e),
                }
            });
            false
        }
        _ => false,
    }
}

#[cfg(windows)]
mod webview2 {
    use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2, ICoreWebView2Controller};
    use webview2_com::{
        CallDevToolsProtocolMethodCompletedHandler, ExecuteScriptCompletedHandler,
        NavigationCompletedEventHandler,
    };
    use windows::core::HSTRING;

    fn warning(text: &str) -> HSTRING {
        HSTRING::from(format!("<!doctype html><meta charset=utf-8><body style=\"font:15px system-ui;padding:40px;color:#b42318\"><h3>账号浏览器已停止加载</h3><p>{text}</p></body>"))
    }

    /// Sets the time zone override, then loads `url`; every finished navigation re-checks the
    /// zone the page actually sees.
    pub unsafe fn start(
        controller: ICoreWebView2Controller,
        tz: Option<String>,
        url: String,
    ) -> windows::core::Result<()> {
        let core = controller.CoreWebView2()?;
        let Some(tz) = tz else { return core.Navigate(&HSTRING::from(url)) };
        let checker = core.clone();
        let expected = tz.clone();
        let mut token = Default::default();
        core.add_NavigationCompleted(&NavigationCompletedEventHandler::create(Box::new(move |_, _| {
            // Only real pages: not the initial about:blank nor the warning itself.
            let mut source = windows::core::PWSTR::null();
            if checker.Source(&mut source).is_err() { return Ok(()); }
            if !webview2_com::take_pwstr(source).starts_with("http") { return Ok(()); }
            let (page, expected) = (checker.clone(), expected.clone());
            let handler = ExecuteScriptCompletedHandler::create(Box::new(move |hr, json| {
                let seen = serde_json::from_str::<String>(&json).unwrap_or_default();
                if hr.is_ok() && !seen.is_empty() && seen != expected {
                    let _ = page.NavigateToString(&warning(&format!("页面看到的时区是 {seen}，与账号时区 {expected} 不一致。请关闭此窗口后重新打开。")));
                }
                Ok(())
            }));
            let _ = checker.ExecuteScript(&HSTRING::from("Intl.DateTimeFormat().resolvedOptions().timeZone"), &handler);
            Ok(())
        })), &mut token)?;
        let nav: ICoreWebView2 = core.clone();
        let done = CallDevToolsProtocolMethodCompletedHandler::create(Box::new(move |hr, _| {
            match hr {
                Ok(()) => nav.Navigate(&HSTRING::from(url)),
                Err(e) => nav.NavigateToString(&warning(&format!("无法设置浏览器时区（{e}），为避免时区与出口不一致，已停止加载。"))),
            }
        }));
        let params = serde_json::json!({ "timezoneId": tz }).to_string();
        core.CallDevToolsProtocolMethod(&HSTRING::from("Emulation.setTimezoneOverride"), &HSTRING::from(params), &done)
    }
}

// ---- link routing ----------------------------------------------------------------------

/// The account whose Claude started this process (Claude opens links with ShellExecute, so it
/// is the parent, possibly behind a launcher).
#[cfg(windows)]
fn caller_account() -> Option<String> {
    let procs = sys::processes();
    let install = crate::install::resolve().ok()?;
    let mut pid = std::process::id();
    for _ in 0..4 {
        let parent = procs.iter().find(|p| p.pid == pid)?.ppid;
        let proc = procs.iter().find(|p| p.pid == parent)?;
        if proc.name.eq_ignore_ascii_case("claude.exe") {
            let cmd = sys::command_line(parent)?;
            let key = crate::profiles::user_data_dir_arg(&cmd)
                .map(|d| crate::profiles::path_key(&d))
                .unwrap_or_else(|| crate::profiles::path_key(&install.default_profile.to_string_lossy()));
            return crate::profiles::list(&install, false).into_iter().find(|p| crate::profiles::path_key(&p.path) == key).map(|p| p.id);
        }
        pid = parent;
    }
    None
}

#[cfg(not(windows))]
fn caller_account() -> Option<String> { None }

/// Whether account `id` should sign in through its own browser.
fn needs_account_browser(id: &str) -> bool {
    let eff = settings::load().effective(id);
    eff.node.is_some() || eff.isolation == "sandboxie"
}

/// `--open-url`: decides where a link goes. Returns once it is handed off.
pub fn route_external(url: &str) -> Result<(), String> {
    let u = valid_web_url(url).ok_or("只能打开 http 或 https 链接。")?;
    let claude = u.host_str().is_some_and(is_claude_host);
    let account = caller_account().or_else(|| claude.then(crate::login::pending).flatten());
    let to_account = claude && account.as_deref().is_some_and(needs_account_browser);
    if to_account || crate::sandbox::inside() {
        // Inside a box this process has no network and its own copy of everything; the host
        // Hydra picks the request up from the drop folder (opened to the box).
        drop_request(account.as_deref(), url)?;
        if !crate::sandbox::inside() { start_host(); }
        return Ok(());
    }
    open_fallback(url)
}

fn drop_request(id: Option<&str>, url: &str) -> Result<(), String> {
    let dir = crate::sandbox::drop_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let data = serde_json::json!({ "id": id, "url": url, "at": paths::now_millis() });
    let tmp = dir.join(format!("{}-{}.tmp", paths::now_millis(), std::process::id()));
    std::fs::write(&tmp, data.to_string()).map_err(|e| format!("无法转交链接：{e}"))?;
    std::fs::rename(&tmp, tmp.with_extension("json")).map_err(|e| format!("无法转交链接：{e}"))
}

/// Starts the tray host if it is not running (a running one swallows the new instance).
fn start_host() {
    if let Ok(exe) = std::env::current_exe() {
        let mut cmd = std::process::Command::new(exe);
        #[cfg(windows)]
        cmd.creation_flags(0x0800_0000);
        let _ = cmd.arg("--tray").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
    }
}

/// Host process: picks up links dropped by `--open-url` (also from inside boxes).
pub fn start_watcher(app: tauri::AppHandle) {
    let _ = std::thread::Builder::new().name("link-router".into()).spawn(move || loop {
        let dir = crate::sandbox::drop_dir();
        let files = std::fs::read_dir(&dir).map(|d| d.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect::<Vec<_>>()).unwrap_or_default();
        for file in files {
            let data = std::fs::read(&file).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
            let _ = std::fs::remove_file(&file);
            let Some(v) = data else { continue };
            let fresh = v["at"].as_u64().is_some_and(|at| paths::now_millis().saturating_sub(at) < 60_000);
            if !fresh { paths::append_log("hydra-error.log", "link router: dropped a link that waited over 60 s for the host"); }
            let Some(url) = v["url"].as_str().filter(|_| fresh).map(str::to_owned) else { continue };
            let id = v["id"].as_str().map(str::to_owned);
            let app = app.clone();
            std::thread::spawn(move || if let Err(e) = handle_request(&app, id.as_deref(), &url) { sys::error_box(&e) });
        }
        std::thread::sleep(Duration::from_millis(700));
    });
}

fn handle_request(app: &tauri::AppHandle, id: Option<&str>, url: &str) -> Result<(), String> {
    let u = valid_web_url(url).ok_or("链接无效。")?;
    match id {
        Some(id) if u.host_str().is_some_and(is_claude_host) && needs_account_browser(id) => open(app, plan(id, Some(url))?),
        _ => open_fallback(url),
    }
}

/// Remembers the user's current https browser (unless it is Hydra itself).
#[cfg(windows)]
pub fn remember_fallback() {
    let current = sys::reg_string(false, r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice", "ProgId");
    if let Some(prog) = current.filter(|p| !p.eq_ignore_ascii_case(URL_PROGID)) {
        let _ = settings::update(|s| s.fallback_browser = Some(prog));
    }
}

#[cfg(not(windows))]
pub fn remember_fallback() {}

/// Opens a link in the user's previous browser (Edge when unknown), never in Hydra.
#[cfg(windows)]
pub fn open_fallback(url: &str) -> Result<(), String> {
    valid_web_url(url).ok_or("链接无效。")?;
    let own = std::env::current_exe().ok().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let command = settings::load().fallback_browser.and_then(|prog| {
        [false, true].into_iter().find_map(|machine| sys::reg_string(machine, &format!(r"Software\Classes\{prog}\shell\open\command"), ""))
    }).filter(|c| !own.is_empty() && !c.to_lowercase().contains(&own) && !c.contains(URL_PROGID));
    if let Some(command) = command {
        let (exe, rest) = match command.strip_prefix('"').and_then(|c| c.split_once('"')) {
            Some((exe, rest)) => (exe.to_string(), rest.to_string()),
            None => match command.split_once(' ') { Some((e, r)) => (e.to_string(), format!(" {r}")), None => (command.clone(), String::new()) },
        };
        let args = if rest.contains("%1") || rest.contains("%L") { rest.replace("%1", url).replace("%L", url) } else { format!("{rest} \"{url}\"") };
        if std::process::Command::new(&exe).raw_arg(args.trim()).spawn().is_ok() { return Ok(()); }
    }
    std::process::Command::new("explorer.exe").arg(format!("microsoft-edge:{url}")).spawn().map(|_| ()).map_err(|e| format!("无法打开链接：{e}"))
}

#[cfg(not(windows))]
pub fn open_fallback(_url: &str) -> Result<(), String> { Err("链接路由目前只支持 Windows。".into()) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_hosts_and_urls() {
        assert!(is_claude_host("claude.ai") && is_claude_host("www.anthropic.com") && is_claude_host("platform.claude.com"));
        assert!(!is_claude_host("notclaude.ai") && !is_claude_host("accounts.google.com"));
        assert!(valid_web_url("https://claude.ai/login/app-google-auth?hop_nonce=x").is_some());
        assert!(valid_web_url("file:///c:/x").is_none());
        assert!(valid_web_url("https://a.com/\" --evil").is_none());
    }

    #[test]
    fn browser_args_route_through_relay() {
        let plan = Plan { id: "a".into(), title: String::new(), relay_port: Some(4321), timezone: None, locale: "ja-JP".into(), url: START_URL.into() };
        let args = browser_args(&plan);
        assert!(args.contains("--proxy-server=socks5://127.0.0.1:4321") && args.contains("--disable-quic"));
        assert!(args.contains("--accept-lang=ja-JP,ja"));
        assert!(!args.contains("--remote-debugging"));
    }

    #[test]
    fn fingerprint_script_follows_the_account() {
        let one = fingerprint_script("account-1");
        assert_eq!(one, fingerprint_script("account-1"), "one account must look like the same browser");
        assert_ne!(one, fingerprint_script("account-2"), "two accounts must not look like one browser");
        assert!(!one.contains("__SEED__"), "the seed must be substituted");
        assert_eq!(fingerprint_seed("account-1"), fingerprint_seed("account-1"));
        assert_ne!(fingerprint_seed("account-1"), fingerprint_seed("account-2"));
        for api in ["toDataURL", "getImageData", "measureText", "getBoundingClientRect", "hardwareConcurrency", "9246"] {
            assert!(one.contains(api), "the script does not cover {api}");
        }
    }

    #[test]
    fn fingerprint_script_parses_as_javascript() {
        let path = std::env::temp_dir().join("hydra-fingerprint-check.js");
        std::fs::write(&path, fingerprint_script("account-1")).unwrap();
        let out = std::process::Command::new("node").args(["--check"]).arg(&path).output()
            .expect("Node.js is required for the browser script tests");
        let _ = std::fs::remove_file(&path);
        assert!(out.status.success(), "node --check: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// Runs the script in Node over a stub canvas/screen/navigator and checks what a fingerprint
    /// script would actually see: two reads of one canvas agree, two accounts do not.
    #[test]
    fn fingerprint_script_changes_what_the_page_measures() {
        let dir = std::env::temp_dir().join("hydra-fingerprint-run");
        let _ = std::fs::create_dir_all(&dir);
        let harness = dir.join("harness.js");
        std::fs::write(&harness, FINGERPRINT_HARNESS).unwrap();
        let run = |account: &str| -> serde_json::Value {
            let script = dir.join(format!("{}.js", fingerprint_seed(account)));
            std::fs::write(&script, fingerprint_script(account)).unwrap();
            let out = std::process::Command::new("node").arg(&harness).arg(&script).output()
                .expect("Node.js is required for the browser script tests");
            assert!(out.status.success(), "node run: {}", String::from_utf8_lossy(&out.stderr));
            serde_json::from_slice(&out.stdout).expect("browser test harness must emit valid JSON")
        };
        let one = run("account-1");
        let two = run("account-2");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(one["stable"], true, "one canvas read twice must agree: {one}");
        assert_eq!(two["stable"], true, "one canvas read twice must agree: {two}");
        assert_ne!(one["canvas"], two["canvas"], "two accounts produced the same canvas: {one} vs {two}");
        let width = one["width"].as_f64().unwrap();
        assert!((99.97..=100.03).contains(&width), "element width moved too far: {one}");
        let font = one["font"].as_f64().unwrap();
        assert!((41.97..=42.03).contains(&font), "measured text moved too far: {one}");
        for value in [&one, &two] {
            let screen = value["screen"].as_str().unwrap_or_default();
            assert!(
                ["1920x1080", "2560x1440", "1680x1050", "1920x1200", "2560x1600"].contains(&screen),
                "unexpected screen: {value}"
            );
            let cores = value["cores"].as_u64().unwrap_or_default();
            assert!([4, 8, 12, 16].contains(&cores), "unexpected core count: {value}");
        }
    }
}

/// The Node-side of `fingerprint_script_changes_what_the_page_measures`: the smallest browser
/// the script can run against, so its overrides are exercised for real rather than only parsed.
#[cfg(test)]
const FINGERPRINT_HARNESS: &str = r#"const fs = require('fs');
global.window = global;
function Context(canvas) { this.canvas = canvas; }
Context.prototype.drawImage = function (source) { this.canvas.pixels = Uint8ClampedArray.from(source.pixels); };
Context.prototype.getImageData = function () { return { data: Uint8ClampedArray.from(this.canvas.pixels) }; };
Context.prototype.putImageData = function (image) { this.canvas.pixels = Uint8ClampedArray.from(image.data); };
Context.prototype.measureText = function () { return { width: 42 }; };
function Canvas() {
  this.width = 8;
  this.height = 8;
  this.pixels = new Uint8ClampedArray(this.width * this.height * 4).fill(180);
}
Canvas.prototype.getContext = function () { return new Context(this); };
Canvas.prototype.toDataURL = function () { return 'pixels:' + Buffer.from(this.pixels).toString('hex'); };
Canvas.prototype.toBlob = function (callback) { callback(null); };
function Element() {}
Element.prototype.getBoundingClientRect = function () { return { x: 1, y: 2, width: 100, height: 20 }; };
function DOMRect(x, y, width, height) { this.x = x; this.y = y; this.width = width; this.height = height; }
function Screen() {}
function Navigator() {}
global.HTMLCanvasElement = Canvas;
global.CanvasRenderingContext2D = Context;
global.document = { createElement: function () { return new Canvas(); } };
global.Element = Element;
global.DOMRect = DOMRect;
global.Screen = Screen;
global.screen = new Screen();
global.Navigator = Navigator;
// Node 21+ has its own read-only global navigator; plain assignment would be ignored.
Object.defineProperty(global, 'navigator', { value: new Navigator(), configurable: true, writable: true });
eval(fs.readFileSync(process.argv[2], 'utf8'));
const canvas = new Canvas();
const first = canvas.toDataURL();
const second = canvas.toDataURL();
const width = new Element().getBoundingClientRect().width;
const font = new Context(canvas).measureText('hello').width;
console.log(JSON.stringify({
  canvas: first,
  stable: first === second,
  width: width,
  font: font,
  screen: screen.width + 'x' + screen.height,
  cores: navigator.hardwareConcurrency
}));
"#;
