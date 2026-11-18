//! Exit rules and the network kill switch.
//!
//! Every verified exit (at launch, in the account browser and periodically while an account
//! uses its relay) is checked against the account's environment:
//! - exits in regions where Claude is not offered (see `UNSUPPORTED`) are refused unless the
//!   environment allows them;
//! - an optional rule pins the exit to the first one seen (`exit_baseline`): same IP, city,
//!   region or country.
//!
//! A violation at launch refuses the launch. A violation while running pauses the account's
//! relay (see `relay::block`), which cuts the account off the network because it has no direct
//! route; it stays cut, across restarts, until the user resumes or rebinds.
//!
//! A check that cannot finish (check services down or rate limited, the node briefly
//! unreachable) is not a violation: the relay has no direct route, so an unverified exit
//! cannot reveal the real address. The host retries; only when checks keep failing is the
//! account cut, softly (see `relay::soft_block`), and that cut is lifted by itself once a
//! check passes again.
use crate::environment::Environment;
use crate::node::{ExitInfo, Inspection};
use crate::settings;
use std::sync::OnceLock;

pub const RULES: [&str; 5] = ["", "static", "city", "region", "country"];

fn rule_name(rule: &str) -> &'static str {
    match rule {
        "static" => "固定 IP",
        "city" => "同城市",
        "region" => "同省/州",
        "country" => "同国家",
        _ => "不限",
    }
}

pub fn describe(x: &ExitInfo) -> String {
    let place: Vec<&str> = [x.country.as_str(), x.region.as_str(), x.city.as_str()].into_iter().filter(|s| !s.is_empty()).collect();
    if place.is_empty() { x.ip.clone() } else { format!("{}（{}）", x.ip, place.join(" ")) }
}

/// ISO country codes of exits refused by default: Claude is not offered there, so an account
/// appearing from one of them is a misrouted node rather than an intended exit.
pub const UNSUPPORTED: [(&str, &str); 9] = [
    ("CN", "中国大陆"), ("HK", "中国香港"), ("MO", "中国澳门"), ("RU", "俄罗斯"), ("BY", "白俄罗斯"),
    ("IR", "伊朗"), ("KP", "朝鲜"), ("CU", "古巴"), ("SY", "叙利亚"),
];

/// Checks an exit against an environment's region block and exit rule.
pub fn check(env: &Environment, exit: &ExitInfo) -> Result<(), String> {
    if !env.allow_cn {
        if let Some((_, name)) = UNSUPPORTED.iter().find(|(code, _)| exit.country.trim().eq_ignore_ascii_case(code)) {
            return Err(format!("出口 {} 位于{name}，Claude 不在该地区提供服务，已拦截。", describe(exit)));
        }
    }
    let Some(base) = &env.exit_baseline else { return Ok(()) };
    let same = |a: &str, b: &str| a.trim().eq_ignore_ascii_case(b.trim());
    let country = same(&base.country, &exit.country);
    let region = country && same(&base.region, &exit.region);
    let ok = match env.exit_rule.as_str() {
        "static" => base.ip == exit.ip,
        "city" => region && same(&base.city, &exit.city),
        "region" => region,
        "country" => country,
        _ => true,
    };
    if ok { return Ok(()); }
    Err(format!("出口从 {} 变成了 {}，不符合“{}”规则。", describe(base), describe(exit), rule_name(&env.exit_rule)))
}

fn environment(env_id: Option<&str>) -> Environment {
    let s = settings::load();
    env_id.and_then(|id| s.environments.get(id)).cloned().unwrap_or_default()
}

/// Applies the rules of environment `env_id` (none = defaults: only the region block) to a
/// verified exit, binding the baseline the first time a rule sees an exit.
pub fn verify(env_id: Option<&str>, exit: &ExitInfo) -> Result<(), String> {
    let env = environment(env_id);
    check(&env, exit)?;
    bind_first(env_id, &env, exit)
}

fn bind_first(env_id: Option<&str>, env: &Environment, exit: &ExitInfo) -> Result<(), String> {
    if let Some(id) = env_id.filter(|_| !env.exit_rule.is_empty() && env.exit_baseline.is_none()) {
        settings::update(|s| if let Some(e) = s.environments.get_mut(id) { e.exit_baseline.get_or_insert_with(|| exit.clone()); })?;
    }
    Ok(())
}

/// Outcome of one route check judged against the exit rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The exit complies. `None` when only the IP (and the edge's country) was known: enough
    /// to pass the rules, not a full exit to remember.
    Pass(Option<ExitInfo>),
    /// The exit is confirmed to break the rules: cut now.
    Violation(String),
    /// The check could not decide (services failing, node unreachable): retry, do not cut yet.
    Unverified(String),
}

/// Checks the route the API took, which Claude Code depends on, when its edge answered.
pub fn check_api_route(env_id: Option<&str>, found: &Inspection) -> Result<(), String> {
    check_api(&environment(env_id), found)
}

fn check_api(env: &Environment, found: &Inspection) -> Result<(), String> {
    if let Some(reason) = found.api_split() { return Err(reason); }
    let Some(api) = found.api_ip else { return Ok(()) };
    if !env.allow_cn {
        if let Some((_, name)) = UNSUPPORTED.iter().find(|(code, _)| found.api_country.eq_ignore_ascii_case(code)) {
            return Err(format!("Claude API 的出口 {api} 位于{name}，Claude 不在该地区提供服务，已拦截。"));
        }
    }
    if env.exit_rule == "static" && found.ip.is_some_and(|ip| ip != api) {
        return Err(format!("Claude API 的出口 {api} 与 claude.ai 的出口不同，不符合“固定 IP”规则。"));
    }
    Ok(())
}

/// Judges a route check against environment `env_id`.
pub fn judge(env_id: Option<&str>, found: &Inspection) -> Verdict {
    let env = environment(env_id);
    if let Err(reason) = check_api(&env, found) { return Verdict::Violation(reason); }
    if let Some(exit) = &found.exit {
        if let Err(reason) = check(&env, exit) { return Verdict::Violation(reason); }
        return match bind_first(env_id, &env, exit) {
            Ok(()) => Verdict::Pass(Some(exit.clone())),
            Err(reason) => Verdict::Unverified(reason),
        };
    }
    judge_partial(&env, found)
}

/// Without a location, uses only what the exit IP (and the country claude.ai's edge saw)
/// proves: a changed IP breaks a fixed-IP rule, an edge country in a refused region is
/// refused, an unchanged IP or a matching country passes. Anything else stays undecided
/// instead of becoming a cut.
fn judge_partial(env: &Environment, found: &Inspection) -> Verdict {
    let unverified = || Verdict::Unverified(format!("无法核验代理出口：{}", found.failure()));
    let Some(ip) = found.ip else { return unverified() };
    let partial = ExitInfo { ip: ip.to_string(), country: found.edge_country.clone(), ..Default::default() };
    if !partial.country.is_empty() && !env.allow_cn {
        if let Some((_, name)) = UNSUPPORTED.iter().find(|(code, _)| partial.country.eq_ignore_ascii_case(code)) {
            return Verdict::Violation(format!("claude.ai 边缘节点判定出口 {} 位于{name}，Claude 不在该地区提供服务，已拦截。", describe(&partial)));
        }
    }
    if env.exit_rule.is_empty() {
        // Only the region block applies, and it needs a country.
        return if partial.country.is_empty() { unverified() } else { Verdict::Pass(None) };
    }
    let Some(base) = &env.exit_baseline else { return unverified() };
    // The baseline itself passed every rule, so the same IP passes them too.
    if base.ip == partial.ip { return Verdict::Pass(None); }
    match env.exit_rule.as_str() {
        "static" => Verdict::Violation(format!("出口从 {} 变成了 {}，不符合“固定 IP”规则。", describe(base), partial.ip)),
        // The edge's country database may disagree with the service the baseline came from,
        // so only agreement counts; a mismatch proves nothing.
        "country" if !partial.country.is_empty() && base.country.trim().eq_ignore_ascii_case(&partial.country) => Verdict::Pass(None),
        _ => unverified(),
    }
}

/// Binds environment `env_id` to its node's current exit and lifts the block of its accounts.
pub fn rebind(env_id: &str) -> Result<ExitInfo, String> {
    let _change = crate::relay::route_change();
    let s = settings::load();
    let env = s.environments.get(env_id).cloned().ok_or("这个环境配置已不存在。")?;
    let node = env.node().ok_or("这个环境没有代理节点。")?;
    let (upstream, _core) = crate::clash::resolve(&node)?;
    let exit = crate::node::inspect(&upstream.client(std::time::Duration::from_secs(15))?, &node)?;
    check(&Environment { exit_baseline: None, ..env }, &exit)?;
    let accounts: Vec<String> = s.accounts.iter().filter(|(_, a)| a.environment.as_deref() == Some(env_id)).map(|(id, _)| id.clone()).collect();
    settings::update(|s| if let Some(e) = s.environments.get_mut(env_id) { e.exit_baseline = Some(exit.clone()); })?;
    for id in accounts {
        if crate::relay::running(&id) {
            match crate::relay::inspect_route(&id, None).map(|(_, found)| judge(Some(env_id), &found)) {
                Ok(Verdict::Pass(_)) => {}
                Ok(Verdict::Violation(reason)) => { crate::relay::block(&id, &reason); continue; }
                Ok(Verdict::Unverified(reason)) | Err(reason) => { crate::relay::soft_block(&id, &reason); continue; }
            }
        }
        crate::relay::unblock(&id, "重新绑定出口");
    }
    Ok(exit)
}

/// Re-checks a blocked account's exit and restores its network if the exit is acceptable
/// again. Returns a line describing what was restored.
pub fn resume(id: &str) -> Result<String, String> {
    let _change = crate::relay::route_change();
    let s = settings::load();
    let eff = s.effective(id);
    if eff.unusable_node { return Err("这个账号的代理节点无法读取（密码不能解密或配置损坏），请重新保存它的环境配置。".into()); }
    let Some(node) = eff.node else {
        // No proxy any more (environment removed or reassigned): there is no exit to judge.
        crate::relay::unblock(id, "恢复网络（账号已不使用代理）");
        return Ok("该账号已不使用代理，已解除断网标记。".into());
    };
    // The relay may not be running (node failed to start, Hydra just restarted): check the
    // node itself instead of leaving the account cut with no way back.
    let exit = if crate::relay::running(id) { crate::relay::probe(id) } else {
        crate::clash::resolve(&node).and_then(|(upstream, _core)| crate::node::inspect(&upstream.client(std::time::Duration::from_secs(15))?, &node))
    }.map_err(|e| format!("无法核验代理出口：{e}"))?;
    verify(eff.environment.as_deref(), &exit)?;
    crate::relay::unblock(id, "恢复网络");
    Ok(describe(&exit))
}

type Notifier = Box<dyn Fn(&str, &str, bool) + Send + Sync>;
static NOTIFY: OnceLock<Notifier> = OnceLock::new();
static RESTORED: OnceLock<Box<dyn Fn(&str) + Send + Sync>> = OnceLock::new();

/// Registers how the host process tells the user an account was cut off (`id`, reason, and
/// whether the cut is soft, i.e. lifted by itself once a check passes).
pub fn on_block(f: impl Fn(&str, &str, bool) + Send + Sync + 'static) { let _ = NOTIFY.set(Box::new(f)); }

/// Registers what the host process does when a soft cut is lifted by itself.
pub fn on_restore(f: impl Fn(&str) + Send + Sync + 'static) { let _ = RESTORED.set(Box::new(f)); }

pub(crate) fn notify(id: &str, reason: &str, soft: bool) {
    if let Some(f) = NOTIFY.get() { f(id, reason, soft); }
}

pub(crate) fn notify_restored(id: &str) {
    if let Some(f) = RESTORED.get() { f(id); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(ip: &str, country: &str, region: &str, city: &str) -> ExitInfo {
        ExitInfo { ip: ip.into(), country: country.into(), region: region.into(), city: city.into(), ..Default::default() }
    }

    #[test]
    fn region_block_and_rules() {
        let tokyo = exit("1.1.1.1", "JP", "Tokyo", "Tokyo");
        let mut env = Environment::default();
        assert!(check(&env, &exit("2.2.2.2", "CN", "Beijing", "Beijing")).is_err());
        assert!(check(&env, &exit("2.2.2.2", "hk", "", "")).is_err());
        assert!(check(&env, &exit("2.2.2.2", "RU", "", "")).is_err());
        assert!(check(&env, &exit("2.2.2.2", "SG", "", "")).is_ok());
        env.allow_cn = true;
        assert!(check(&env, &exit("2.2.2.2", "CN", "", "")).is_ok());
        // A rule without a baseline yet accepts the exit (it becomes the baseline).
        env.exit_rule = "static".into();
        assert!(check(&env, &tokyo).is_ok());
        env.exit_baseline = Some(tokyo.clone());
        assert!(check(&env, &exit("1.1.1.2", "JP", "Tokyo", "Tokyo")).is_err());
        env.exit_rule = "city".into();
        assert!(check(&env, &exit("1.1.1.2", "jp", "tokyo", "Tokyo")).is_ok());
        assert!(check(&env, &exit("1.1.1.2", "JP", "Tokyo", "Shinjuku")).is_err());
        env.exit_rule = "region".into();
        assert!(check(&env, &exit("1.1.1.2", "JP", "Tokyo", "Shinjuku")).is_ok());
        assert!(check(&env, &exit("1.1.1.2", "JP", "Osaka", "Osaka")).is_err());
        env.exit_rule = "country".into();
        assert!(check(&env, &exit("1.1.1.2", "JP", "Osaka", "Osaka")).is_ok());
        assert!(check(&env, &exit("1.1.1.2", "US", "", "")).is_err());
        env.exit_rule.clear();
        assert!(check(&env, &exit("1.1.1.2", "US", "", "")).is_ok());
    }

    #[test]
    fn the_api_route_follows_the_exit_rules() {
        let found = |api: &str, country: &str| Inspection {
            api_ip: Some(api.parse().unwrap()),
            api_country: country.into(),
            ..partial(Some("192.0.2.1"), "JP")
        };
        let open = Environment::default();
        assert!(check_api(&open, &found("192.0.2.2", "JP")).is_ok());
        assert!(check_api(&open, &found("192.0.2.2", "US")).is_err());
        assert!(check_api(&open, &found("192.0.2.1", "HK")).is_err());
        assert!(check_api(&Environment { allow_cn: true, ..Default::default() }, &found("192.0.2.1", "HK")).is_ok());
        let fixed = Environment { exit_rule: "static".into(), ..Default::default() };
        assert!(check_api(&fixed, &found("192.0.2.1", "JP")).is_ok());
        assert!(check_api(&fixed, &found("192.0.2.2", "JP")).is_err());
        assert!(check_api(&fixed, &partial(Some("192.0.2.1"), "JP")).is_ok(), "no answer from the API edge decides nothing");
    }

    fn partial(ip: Option<&str>, edge: &str) -> Inspection {
        Inspection { ip: ip.map(|i| i.parse().unwrap()), edge_country: edge.into(), ..Default::default() }
    }

    #[test]
    fn failed_checks_are_never_violations_unless_proven() {
        let tokyo = exit("1.1.1.1", "JP", "Tokyo", "Tokyo");
        let mut env = Environment::default();
        let undecided = |v: Verdict| matches!(v, Verdict::Unverified(_));
        // Nothing answered: undecided, whatever the rules.
        assert!(undecided(judge_partial(&env, &partial(None, ""))));
        // No rule: the edge country alone decides the region block.
        assert_eq!(judge_partial(&env, &partial(Some("2.2.2.2"), "US")), Verdict::Pass(None));
        assert!(matches!(judge_partial(&env, &partial(Some("2.2.2.2"), "CN")), Verdict::Violation(_)));
        assert!(undecided(judge_partial(&env, &partial(Some("2.2.2.2"), ""))));
        env.allow_cn = true;
        assert_eq!(judge_partial(&env, &partial(Some("2.2.2.2"), "CN")), Verdict::Pass(None));
        env.allow_cn = false;
        // Rules with a baseline: the same IP passes all of them.
        env.exit_baseline = Some(tokyo);
        for rule in ["static", "city", "region", "country"] {
            env.exit_rule = rule.into();
            assert_eq!(judge_partial(&env, &partial(Some("1.1.1.1"), "")), Verdict::Pass(None), "{rule}");
        }
        // A new IP proves a fixed-IP violation, nothing about city or region.
        env.exit_rule = "static".into();
        assert!(matches!(judge_partial(&env, &partial(Some("1.1.1.2"), "JP")), Verdict::Violation(_)));
        env.exit_rule = "city".into();
        assert!(undecided(judge_partial(&env, &partial(Some("1.1.1.2"), "JP"))));
        // Country rule: agreement passes, disagreement between databases proves nothing.
        env.exit_rule = "country".into();
        assert_eq!(judge_partial(&env, &partial(Some("1.1.1.2"), "jp")), Verdict::Pass(None));
        assert!(undecided(judge_partial(&env, &partial(Some("1.1.1.2"), "US"))));
    }
}
