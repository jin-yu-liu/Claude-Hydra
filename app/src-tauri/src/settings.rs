//! Persistent application settings stored in `settings.json`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CachedInstall {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aumid: Option<String>,
    pub default_profile_path: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_color: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_color: Option<usize>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub args: String,
    /// Legacy (v3.0) unauthenticated proxy entrance; migrated into `node` on read.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_endpoint: String,
    /// Proxy node; its password is stored sealed (see `node::seal`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<crate::node::NodeConfig>,
    /// "" / "proxy" follow the node's exit region, "system" keeps the OS zone, else an IANA name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub timezone: String,
    /// Stable local relay port so a running Claude keeps working across Hydra restarts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_exit: Option<crate::node::ExitInfo>,
    /// Id of the assigned environment config; `None` = direct connection, system timezone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default)]
    pub keep_running: bool,
    /// Set when the exit guard cut this account's network; cleared by resume / rebind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    /// The cut came from checks that kept failing, not from a confirmed violation: the host
    /// keeps re-checking and lifts it by itself once the exit verifies again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub blocked_soft: bool,
}

/// The launch configuration that actually applies to an account.
#[derive(Clone, Debug, Default)]
pub struct Effective {
    pub node: Option<crate::node::NodeConfig>,
    pub timezone: String,
    pub args: String,
    pub env: BTreeMap<String, String>,
    /// Assigned environment id (exit rule, isolation); `None` for legacy per-account settings.
    pub environment: Option<String>,
    /// "" or "sandboxie".
    pub isolation: String,
    /// A node is configured but cannot be used (undecryptable password, damaged entry).
    /// Such an account must not start: it would silently connect directly.
    pub unusable_node: bool,
    /// The account keeps its own Claude Code folder (see `Environment::separate_code`).
    pub separate_code: bool,
}

impl AccountConfig {
    /// Lifts the exit guard's cut because the settings it judged changed; `source` names the
    /// change for the log, so a cut never disappears without a trace.
    pub fn clear_cut(&mut self, id: &str, source: &str) {
        if let Some(reason) = self.blocked.take() {
            crate::paths::append_log("hydra-error.log", &format!("guard {id}: network cut cleared by {source} (was: {reason})"));
        }
        self.blocked_soft = false;
    }

    /// The account's node with its password unsealed, including a migrated legacy entrance.
    pub fn node(&self) -> Option<crate::node::NodeConfig> {
        if let Some(n) = &self.node {
            return n.unsealed().and_then(|n| n.validated().ok());
        }
        (!self.proxy_endpoint.is_empty()).then(|| crate::node::NodeConfig::from_legacy(&self.proxy_endpoint)).flatten()
    }

    /// Stores a node, sealing its password; `None` removes it.
    pub fn set_node(&mut self, node: Option<crate::node::NodeConfig>) {
        self.proxy_endpoint.clear();
        self.node = node.map(|n| n.sealed());
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_cache: Option<CachedInstall>,
    #[serde(default)]
    pub accounts: BTreeMap<String, AccountConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environments: BTreeMap<String, crate::environment::Environment>,
    /// ProgId of the browser that handled https before Hydra (gets every non-Claude link).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_browser: Option<String>,
    /// Whether extra accounts may start without a proxy environment. Unset = refuse as soon
    /// as any environment with a node exists (see `direct_launch_refused`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_environment: Option<bool>,
}

impl Settings {
    pub fn account(&self, id: &str) -> AccountConfig {
        self.accounts.get(id).cloned().unwrap_or_default()
    }

    pub fn account_mut(&mut self, id: &str) -> &mut AccountConfig {
        self.accounts.entry(id.to_string()).or_default()
    }

    /// Assigned environment if any (a dangling id means none); otherwise legacy per-account fields.
    pub fn effective(&self, id: &str) -> Effective {
        let acc = self.account(id);
        if let Some(env_id) = &acc.environment {
            return match self.environments.get(env_id) {
                Some(e) => Effective { node: e.node(), timezone: e.timezone.clone(), args: e.launch_args(), env: e.env.clone(), environment: Some(env_id.clone()), isolation: e.isolation.clone(), separate_code: e.keeps_code_separate(), unusable_node: e.node.is_some() && e.node().is_none() },
                None => Effective::default(),
            };
        }
        Effective { unusable_node: (acc.node.is_some() || !acc.proxy_endpoint.is_empty()) && acc.node().is_none(), node: acc.node(), timezone: acc.timezone.clone(), args: acc.args.replace(['\r', '\n'], " ").trim().to_string(), env: acc.env.clone(), ..Default::default() }
    }

    pub fn environment_name(&self, id: &str) -> Option<String> {
        self.account(id).environment.and_then(|e| self.environments.get(&e).map(|e| e.name.clone()))
    }

    /// Extra accounts without a proxy node would use the machine's own address.
    pub fn requires_environment(&self) -> bool {
        self.require_environment.unwrap_or_else(|| self.environments.values().any(|e| e.node.is_some()))
    }

    pub fn remove_account(&mut self, id: &str) {
        self.accounts.remove(id);
    }
}

pub fn load() -> Settings {
    load_from(&crate::paths::settings_path())
}

fn backup_of(path: &Path) -> std::path::PathBuf { path.with_extension("json.bak") }

fn parse(path: &Path) -> Option<Result<Settings, ()>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(serde_json::from_slice::<Settings>(&bytes).map_err(|_| ())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => Some(Err(())),
    }
}

/// Reads the settings, falling back to the last good copy when the file is damaged.
/// `Err` means settings exist but neither the file nor its backup can be read, so nothing
/// may be written over them.
pub fn load_checked(path: &Path) -> Result<Settings, String> {
    let main = parse(path);
    if let Some(Ok(s)) = main { return Ok(s); }
    match parse(&backup_of(path)) {
        Some(Ok(s)) => {
            if main.is_some() { crate::paths::append_log("settings", "settings.json 无法解析，已使用备份 settings.json.bak。"); }
            Ok(s)
        }
        _ if main.is_none() => Ok(Settings::default()),
        _ => Err(format!("设置文件已损坏且没有可用备份，为避免覆盖数据已停止写入：{}。请修复或移走该文件后重试。", path.display())),
    }
}

pub fn load_from(path: &Path) -> Settings {
    load_checked(path).unwrap_or_default()
}

/// Serializes read-modify-write cycles within this process and across Hydra processes
/// (tray host, launcher shortcuts, CLI). Not reentrant: never call `update`/`save` inside.
fn locked<T>(path: &Path, run: impl FnOnce() -> T) -> T {
    static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _gate = GATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(dir) = path.parent() { let _ = std::fs::create_dir_all(dir); }
    let file = std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(path.with_extension("lock")).ok();
    if let Some(f) = &file { let _ = f.lock(); }
    let out = run();
    if let Some(f) = &file { let _ = f.unlock(); }
    out
}

/// Runs `run` under the same lock as `update`/`save`, for a writer that edits the file as raw
/// JSON (the secret migration). Not reentrant either.
pub fn with_lock<T>(path: &Path, run: impl FnOnce() -> T) -> T {
    locked(path, run)
}

pub fn save(settings: &Settings) -> Result<(), String> {
    let path = crate::paths::settings_path();
    locked(&path, || save_to(&path, settings))
}

pub fn save_to(path: &Path, settings: &Settings) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("无法创建配置目录：{e}"))?;
    }
    let json = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    // Unique name: two writers must never share (and truncate) one temporary file.
    let tmp = path.with_extension(format!("json.{}.{}.tmp", std::process::id(), uuid::Uuid::new_v4().simple()));
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&json)?;
        f.sync_all()
    };
    if let Err(e) = write() { let _ = std::fs::remove_file(&tmp); return Err(format!("无法写入设置文件：{e}")); }
    // Owner-only: the file may hold proxy credentials.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    // Keep the last file that still parses, so a damaged write can be recovered from.
    if matches!(parse(path), Some(Ok(_))) { let _ = std::fs::copy(path, backup_of(path)); }
    let mut last = None;
    for attempt in 0..6 {
        // Windows refuses the replace while a reader or scanner holds the file open.
        if attempt > 0 { std::thread::sleep(std::time::Duration::from_millis(40 * attempt)); }
        match std::fs::rename(&tmp, path) { Ok(()) => return Ok(()), Err(e) => last = Some(e) }
    }
    let _ = std::fs::remove_file(&tmp);
    Err(format!("无法保存设置文件：{}", last.map(|e| e.to_string()).unwrap_or_default()))
}

/// Locked read-modify-write; saved only when `f` succeeds.
pub fn update_with<T>(f: impl FnOnce(&mut Settings) -> Result<T, String>) -> Result<T, String> {
    let path = crate::paths::settings_path();
    locked(&path, || {
        let mut s = load_checked(&path)?;
        let out = f(&mut s)?;
        save_to(&path, &s)?;
        Ok(out)
    })
}

pub fn update(f: impl FnOnce(&mut Settings)) -> Result<(), String> {
    update_with(|s| { f(s); Ok(()) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_typed_settings() {
        let dir = std::env::temp_dir().join(format!("hydra-settings-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("settings.json");

        let mut s = Settings::default();
        let acc = s.account_mut("Account 2");
        acc.label = Some("工作".into());
        acc.custom_color = Some(3);
        acc.keep_running = true;
        save_to(&file, &s).unwrap();

        let loaded = load_from(&file);
        let loaded_acc = loaded.account("Account 2");
        assert_eq!(loaded_acc.label.as_deref(), Some("工作"));
        assert_eq!(loaded_acc.custom_color, Some(3));
        assert!(loaded_acc.keep_running);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn node_password_is_sealed_and_legacy_migrates() {
        let mut acc = AccountConfig { proxy_endpoint: "http://127.0.0.1:8080".into(), ..Default::default() };
        assert_eq!(acc.node().unwrap().port, 8080);
        let node = crate::node::NodeConfig { kind: "socks5".into(), host: "h".into(), port: 1, username: "u".into(), password: "secret".into(), ..Default::default() };
        acc.set_node(Some(node));
        assert!(acc.proxy_endpoint.is_empty());
        assert_ne!(acc.node.as_ref().unwrap().password, "secret");
        assert_eq!(acc.node().unwrap().password, "secret");
    }

    #[test]
    fn damaged_settings_fall_back_to_backup_and_are_never_overwritten_blindly() {
        let dir = std::env::temp_dir().join(format!("hydra-settings-bak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("settings.json");
        let mut s = Settings::default();
        s.account_mut("A").label = Some("one".into());
        save_to(&file, &s).unwrap();
        s.account_mut("A").label = Some("two".into());
        save_to(&file, &s).unwrap();
        // A torn write leaves garbage: the previous good copy is used instead of defaults.
        std::fs::write(&file, b"{ \"accounts\": ").unwrap();
        assert_eq!(load_from(&file).account("A").label.as_deref(), Some("one"));
        // Without a backup the damaged file must be reported, not replaced by defaults.
        std::fs::remove_file(backup_of(&file)).unwrap();
        assert!(load_checked(&file).is_err());
        assert!(std::fs::read_dir(&dir).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().ends_with(".tmp")));
        let _ = std::fs::remove_dir_all(dir);
    }
}
