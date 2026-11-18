//! Reusable environment configs: proxy node, timezone, window language, launch args and env vars.
//!
//! An environment is saved once and assigned to any number of accounts; an account without one
//! connects directly with the system timezone. Older versions kept these settings per account;
//! `migrate` moves them into one environment per account.
use crate::node::{self, NodeConfig};
use crate::profiles;
use crate::settings::{self, Settings};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const LOCALES: [&str; 7] = ["", "en-US", "en-GB", "zh-CN", "zh-TW", "ja-JP", "ko-KR"];

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Environment {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub clash_subscription: String,
    /// Password sealed at rest (see `node::seal`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeConfig>,
    /// "" / "proxy" follow the node's exit region, "system" keeps the OS zone, else an IANA name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub timezone: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub locale: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub args: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Result of the last manual connectivity check, shown again when the environment is edited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check: Option<NodeCheck>,
    /// Exit rule enforced at launch and while running (see `guard`): "" = only the region
    /// block, "static" | "city" | "region" | "country" = must stay like `exit_baseline`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub exit_rule: String,
    /// Mainland-China exits are refused unless this is set.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_cn: bool,
    /// The exit the rule compares against: the first verified exit, until the user rebinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_baseline: Option<node::ExitInfo>,
    /// "" = run Claude directly, "sandboxie" = inside a Sandboxie-Plus box (see `sandbox`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub isolation: String,
    /// Give each account of this environment its own Claude Code folder (`CLAUDE_CONFIG_DIR`)
    /// instead of the shared `~/.claude`: separate sign-in, settings and sessions.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub separate_code: bool,
}

/// A successful connectivity check: exit info plus the residential/datacenter and risk notes.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NodeCheck {
    pub exit: node::ExitInfo,
    #[serde(default)]
    pub quality: Option<String>,
    #[serde(default)]
    pub risk: String,
}

impl Environment {
    pub fn node(&self) -> Option<NodeConfig> {
        self.node.as_ref()?.unsealed()?.validated().ok()
    }

    /// Whether accounts of this environment keep their own Claude Code folder. Always on in a
    /// box: Claude Code's `userID` and telemetry ids live in `~/.claude.json`, so boxes sharing
    /// that file would each report a different machine GUID but one Claude Code device — a
    /// pairing no real fleet of machines produces, and more telling than no isolation at all.
    pub fn keeps_code_separate(&self) -> bool { self.separate_code || self.isolation == "sandboxie" }

    /// Window language plus the user's extra switches.
    pub fn launch_args(&self) -> String {
        let lang = (!self.locale.is_empty()).then(|| format!("--lang={}", self.locale));
        lang.into_iter().chain([self.args.replace(['\r', '\n'], " ").trim().to_string()]).filter(|a| !a.is_empty()).collect::<Vec<_>>().join(" ")
    }

    /// Whether this environment changes how Claude is launched at all.
    pub fn customizes_launch(&self) -> bool {
        self.node.is_some() || self.keeps_code_separate() || !matches!(self.timezone.as_str(), "" | "proxy" | "system") || !self.launch_args().is_empty() || !self.env.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClashSubscription {
    pub url: String,
    pub nodes: Vec<NodeConfig>,
}

/// What the UI edits: plain-text password and env lines.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentInput {
    #[serde(default)]
    pub clash_subscription: Option<ClashSubscription>,
    pub name: String,
    #[serde(default)]
    pub node: Option<NodeConfig>,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub locale: String,
    #[serde(default)]
    pub args: String,
    #[serde(default)]
    pub env: String,
    #[serde(default)]
    pub last_check: Option<NodeCheck>,
    #[serde(default)]
    pub exit_rule: String,
    #[serde(default)]
    pub allow_cn: bool,
    #[serde(default)]
    pub isolation: String,
    #[serde(default)]
    pub separate_code: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentView {
    pub id: String,
    #[serde(flatten)]
    pub input: EnvironmentInput,
    /// Names of the accounts that use this environment.
    pub used_by: Vec<String>,
    /// Exit timezone last confirmed for this environment's node, from its own connectivity
    /// check or an account's launch check, whichever is newer. `None` without a node.
    pub detected_timezone: Option<String>,
    /// Exit the rule is bound to (read-only; set by the first verified check).
    pub exit_baseline: Option<node::ExitInfo>,
}

fn account_name(s: &Settings, id: &str) -> String {
    s.account(id).label.filter(|l| !l.trim().is_empty()).unwrap_or_else(|| id.to_string())
}

fn view(s: &Settings, id: &str, e: &Environment) -> EnvironmentView {
    EnvironmentView {
        id: id.to_string(),
        input: EnvironmentInput {
            clash_subscription: serde_json::from_str(&node::unseal(&e.clash_subscription)).ok(),
            name: e.name.clone(),
            node: e.node(),
            timezone: if e.timezone.is_empty() { "proxy".into() } else { e.timezone.clone() },
            locale: e.locale.clone(),
            args: e.args.clone(),
            env: e.env.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("\n"),
            last_check: e.last_check.clone(),
            exit_rule: e.exit_rule.clone(),
            allow_cn: e.allow_cn,
            isolation: e.isolation.clone(),
            separate_code: e.separate_code,
        },
        used_by: s.accounts.iter().filter(|(_, a)| a.environment.as_deref() == Some(id)).map(|(aid, _)| account_name(s, aid)).collect(),
        detected_timezone: detected_timezone(s, id, e),
        exit_baseline: e.exit_baseline.clone(),
    }
}

fn detected_timezone(s: &Settings, id: &str, e: &Environment) -> Option<String> {
    e.node.as_ref()?;
    let launches = s.accounts.values().filter(|a| a.environment.as_deref() == Some(id)).filter_map(|a| a.last_exit.as_ref());
    e.last_check.iter().map(|c| &c.exit).chain(launches)
        .filter(|x| !x.timezone.is_empty())
        .max_by_key(|x| x.checked_at)
        .map(|x| x.timezone.clone())
}

pub fn list() -> Vec<EnvironmentView> {
    let s = settings::load();
    let mut out: Vec<_> = s.environments.iter().map(|(id, e)| view(&s, id, e)).collect();
    out.sort_by(|a, b| a.input.name.cmp(&b.input.name));
    out
}

fn new_id(s: &Settings) -> String {
    let mut n = crate::paths::now_millis();
    loop {
        let id = format!("env-{n:x}");
        if !s.environments.contains_key(&id) { return id; }
        n += 1;
    }
}

/// Validates input into a stored environment (password sealed).
fn build(input: &EnvironmentInput) -> Result<Environment, String> {
    let name = input.name.trim();
    if name.is_empty() { return Err("请填写环境名称。".into()); }
    if name.chars().count() > 40 { return Err("环境名称最多 40 个字符。".into()); }
    let node = input.node.as_ref().map(|n| n.validated()).transpose()?;
    let timezone = profiles::normalize_timezone(&input.timezone)?;
    if !LOCALES.contains(&input.locale.as_str()) { return Err("不支持此窗口语言。".into()); }
    let args = input.args.replace(['\r', '\n'], " ").trim().to_string();
    if node.is_some() && node::args_conflict(&args) { return Err("请移除额外启动参数中的代理开关，代理由节点设置。".into()); }
    if let Some(f) = node::forbidden_switch(&args) { return Err(format!("Claude 不允许使用启动参数 {f}，带上它会直接退出，请移除。")); }
    let env = profiles::parse_env_lines(&input.env)?;
    // A check result only describes a node; drop it when the environment has none.
    let last_check = node.as_ref().and(input.last_check.clone());
    if !crate::guard::RULES.contains(&input.exit_rule.as_str()) { return Err("不支持此出口规则。".into()); }
    if !matches!(input.isolation.as_str(), "" | "sandboxie") { return Err("不支持此隔离方式。".into()); }
    if !input.exit_rule.is_empty() && node.is_none() { return Err("出口规则需要先设置代理节点。".into()); }
    Ok(Environment {
        clash_subscription: match &input.clash_subscription {
            Some(sub) => node::seal(&serde_json::to_string(sub).map_err(|e| e.to_string())?),
            None => String::new(),
        },
        name: name.to_string(), node: node.map(|n| n.sealed()), timezone, locale: input.locale.clone(), args, env, last_check,
        exit_rule: input.exit_rule.clone(), allow_cn: input.allow_cn, exit_baseline: None, isolation: input.isolation.clone(), separate_code: input.separate_code,
    })
}

/// Creates (`id` = None) or updates an environment and returns its id.
pub fn save(install: Option<&crate::install::Install>, id: Option<&str>, input: &EnvironmentInput) -> Result<String, String> {
    let mut env = build(input)?;
    if env.isolation == "sandboxie" { crate::sandbox::available()?; }
    settings::update_with(|s| {
        if let Some(id) = id { if !s.environments.contains_key(id) { return Err("这个环境配置已不存在。".into()); } }
        if s.environments.iter().any(|(k, e)| Some(k.as_str()) != id && e.name == env.name) { return Err(format!("已有名为“{}”的环境配置。", env.name)); }
        if install.is_some_and(|i| i.is_msix()) && env.customizes_launch() && id.is_some_and(|id| s.account(crate::paths::DEFAULT_ID).environment.as_deref() == Some(id)) {
            return Err("商店版默认账号正在使用此环境，而它无法应用代理、时区或启动参数。请先为默认账号取消此环境。".into());
        }
        let id = id.map(str::to_string).unwrap_or_else(|| new_id(s));
        let old = s.environments.get(&id).cloned();
        // A different node makes earlier launch checks of its accounts describe the wrong exit.
        let node_changed = old.as_ref().map(|old| old.node() != env.node()).unwrap_or(false);
        if !node_changed {
            // Same node: keep the bound exit; a fresh check of it may seed one.
            env.exit_baseline = old.as_ref().and_then(|old| old.exit_baseline.clone());
        }
        if env.exit_baseline.is_none() && !env.exit_rule.is_empty() {
            env.exit_baseline = env.last_check.as_ref().map(|c| c.exit.clone()).filter(|x| crate::guard::check(&env, x).is_ok());
        }
        // The rules an exit is judged by changed: an earlier cut no longer describes this
        // environment. The relay stays paused until the new exit passes (see `relay::sync_all`).
        let rules_changed = old.as_ref().is_some_and(|old| node_changed || old.exit_rule != env.exit_rule || old.allow_cn != env.allow_cn);
        for (acc_id, acc) in s.accounts.iter_mut().filter(|(_, a)| a.environment.as_deref() == Some(id.as_str())) {
            if node_changed { acc.last_exit = None; }
            if rules_changed { acc.clear_cut(acc_id, if node_changed { "环境节点修改" } else { "环境出口规则修改" }); }
        }
        s.environments.insert(id.clone(), env);
        Ok(id)
    })
}

/// Deletes an environment; its accounts keep no proxy and no stale network cut.
pub fn delete(id: &str) -> Result<(), String> {
    settings::update(|s| {
        s.environments.remove(id);
        for (acc_id, acc) in s.accounts.iter_mut().filter(|(_, a)| a.environment.as_deref() == Some(id)) {
            acc.environment = None;
            acc.relay_port = None;
            acc.last_exit = None;
            acc.clear_cut(acc_id, "删除环境");
        }
    })
}

/// One-time move of per-account settings (v3.0) into environments.
pub fn migrate() {
    let needs = |a: &settings::AccountConfig| a.environment.is_none() && (a.node.is_some() || !a.proxy_endpoint.is_empty() || !a.args.is_empty() || !a.env.is_empty() || !matches!(a.timezone.as_str(), "" | "proxy"));
    if !settings::load().accounts.values().any(needs) { return; }
    let _ = settings::update(|s| {
        let pending: Vec<String> = s.accounts.iter().filter(|(_, a)| needs(a)).map(|(id, _)| id.clone()).collect();
        for id in pending {
            let acc = s.account(&id);
            // Keep the sealed password as-is; convert a legacy entrance and seal nothing new.
            let node = acc.node.clone().or_else(|| NodeConfig::from_legacy(&acc.proxy_endpoint));
            let mut locale = String::new();
            let args: Vec<&str> = acc.args.split_whitespace().filter(|a| {
                match a.strip_prefix("--lang=") { Some(l) if LOCALES.contains(&l) && locale.is_empty() => { locale = l.to_string(); false } _ => true }
            }).collect();
            let mut name = format!("{} 的环境", account_name(s, &id));
            while s.environments.values().any(|e| e.name == name) { name.push('\u{2032}'); }
            let env = Environment { name, node, timezone: acc.timezone.clone(), locale, args: args.join(" "), env: acc.env.clone(), ..Default::default() };
            let env_id = new_id(s);
            s.environments.insert(env_id.clone(), env);
            let a = s.account_mut(&id);
            a.environment = Some(env_id);
            a.node = None;
            a.proxy_endpoint.clear();
            a.args.clear();
            a.env.clear();
            a.timezone.clear();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::AccountConfig;

    #[test]
    fn saved_subscription_can_switch_nodes_after_reopening() {
        let nodes: Vec<_> = ["first", "second"].iter().map(|name| NodeConfig {
            kind: "clash".into(), host: "example.org".into(), port: 443,
            password: serde_json::json!({"name": name, "type": "ss", "server": "example.org", "port": 443}).to_string(),
            ..Default::default()
        }).collect();
        let url = "https://example.org/sub";
        let mut draft = EnvironmentInput {
            name: "test".into(), node: Some(nodes[1].clone()),
            clash_subscription: Some(ClashSubscription { url: url.into(), nodes: nodes.clone() }),
            ..Default::default()
        };
        for selected in [1, 0] {
            let stored = serde_json::to_vec(&build(&draft).unwrap()).unwrap();
            let reopened: Environment = serde_json::from_slice(&stored).unwrap();
            draft = view(&Settings::default(), "test", &reopened).input;
            let subscription = draft.clash_subscription.as_ref().unwrap();
            assert_eq!(subscription.url, url);
            assert_eq!(subscription.nodes, nodes);
            assert_eq!(draft.node.as_ref().unwrap().password, nodes[selected].password);
            draft.node = Some(subscription.nodes[0].clone());
        }
    }

    #[test]
    fn effective_config_prefers_assigned_environment() {
        let mut s = Settings::default();
        s.environments.insert("e1".into(), Environment {
            name: "东京".into(),
            node: Some(NodeConfig { kind: "socks5".into(), host: "jp.example".into(), port: 1080, password: node::seal("pw"), username: "u".into(), ..Default::default() }),
            timezone: "Asia/Tokyo".into(), locale: "ja-JP".into(), args: "--disable-gpu".into(),
            env: BTreeMap::from([("FOO".into(), "1".into())]), ..Default::default()
        });
        s.accounts.insert("a".into(), AccountConfig { environment: Some("e1".into()), args: "--ignored".into(), ..Default::default() });
        let e = s.effective("a");
        assert_eq!(e.node.unwrap().password, "pw");
        assert_eq!(e.timezone, "Asia/Tokyo");
        assert_eq!(e.args, "--lang=ja-JP --disable-gpu");
        assert_eq!(e.env.get("FOO").map(String::as_str), Some("1"));
        // A missing environment means a plain, direct launch.
        s.accounts.insert("b".into(), AccountConfig { environment: Some("gone".into()), ..Default::default() });
        assert!(s.effective("b").node.is_none());
    }

    #[test]
    fn build_validates_input() {
        assert!(build(&EnvironmentInput { name: " ".into(), ..Default::default() }).is_err());
        assert!(build(&EnvironmentInput { name: "x".into(), locale: "xx".into(), ..Default::default() }).is_err());
        let node = NodeConfig { kind: "http".into(), host: "h".into(), port: 1, ..Default::default() };
        assert!(build(&EnvironmentInput { name: "x".into(), node: Some(node.clone()), args: "--proxy-server=a".into(), ..Default::default() }).is_err());
        let ok = build(&EnvironmentInput { name: "x".into(), node: Some(NodeConfig { password: "p".into(), username: "u".into(), ..node }), env: "A=1".into(), ..Default::default() }).unwrap();
        assert_ne!(ok.node.unwrap().password, "p");
        assert_eq!(ok.env.get("A").map(String::as_str), Some("1"));
    }

    #[test]
    fn detected_timezone_prefers_newest_confirmation() {
        let mut s = Settings::default();
        let exit = |tz: &str, at: u64| node::ExitInfo { timezone: tz.into(), checked_at: at, ..Default::default() };
        let node = NodeConfig { kind: "http".into(), host: "h".into(), port: 1, ..Default::default() };
        let mut e = Environment { name: "x".into(), node: Some(node), last_check: Some(NodeCheck { exit: exit("Asia/Tokyo", 10), ..Default::default() }), ..Default::default() };
        s.accounts.insert("a".into(), AccountConfig { environment: Some("e".into()), last_exit: Some(exit("America/Los_Angeles", 20)), ..Default::default() });
        s.accounts.insert("b".into(), AccountConfig { last_exit: Some(exit("Europe/Paris", 99)), ..Default::default() });
        assert_eq!(detected_timezone(&s, "e", &e).as_deref(), Some("America/Los_Angeles"));
        e.last_check = Some(NodeCheck { exit: exit("Asia/Tokyo", 30), ..Default::default() });
        assert_eq!(detected_timezone(&s, "e", &e).as_deref(), Some("Asia/Tokyo"));
        e.node = None;
        assert_eq!(detected_timezone(&s, "e", &e), None);
    }

    #[test]
    fn last_check_kept_only_with_node() {
        let check = NodeCheck { exit: node::ExitInfo { ip: "1.2.3.4".into(), timezone: "Asia/Tokyo".into(), checked_at: 1, ..Default::default() }, quality: None, risk: "r".into() };
        let node = NodeConfig { kind: "http".into(), host: "h".into(), port: 1, ..Default::default() };
        let with = build(&EnvironmentInput { name: "x".into(), node: Some(node), last_check: Some(check.clone()), ..Default::default() }).unwrap();
        assert_eq!(with.last_check, Some(check.clone()));
        let without = build(&EnvironmentInput { name: "x".into(), last_check: Some(check), ..Default::default() }).unwrap();
        assert_eq!(without.last_check, None);
    }
}
