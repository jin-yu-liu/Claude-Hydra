//! Copy Desktop Claude Code session indexes between accounts.
//!
//! Only `claude-code-sessions/<account>/<org>/local_*.json` index files are copied; the
//! transcripts themselves stay where Claude Code wrote them. Originals are never moved or
//! overwritten. The source may keep running (indexes are only read, with a retry for a
//! half-written file); the target must be closed because Desktop loads its session list
//! once at startup, so Hydra closes it, copies, and launches it again.
use crate::{install::Install, profiles::{self, Profile}};
#[path = "session_metrics.rs"]
mod metrics;
use serde::Serialize;
use serde_json::Value;
use std::{fs::{self, OpenOptions}, io::Write, path::{Path, PathBuf}};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    id: String,
    title: String,
    cwd: Option<String>,
    cwd_exists: bool,
    last_activity_at: Option<u64>,
    model: Option<String>,
    turns: Option<u64>,
    #[serde(skip)]
    transcript_id: Option<String>,
    /// Whether the target account already has an index with the same file name.
    in_target: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    sessions: Vec<Session>,
    /// Why the target cannot receive sessions yet; `None` when copying is possible.
    target_problem: Option<String>,
    running: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferResult { copied: usize, skipped: usize, failed: usize }

struct Entry { session: Session, path: PathBuf, account: String, org: String }

pub(crate) fn root(install: &Install, p: &Profile) -> PathBuf {
    #[cfg(windows)]
    if p.is_default && install.is_msix() {
        if let (Some(local), Some(family)) = (std::env::var_os("LOCALAPPDATA"), install.family.as_deref()) {
            if let Some(root) = packaged_session_root(Path::new(&local), family) {
                return root;
            }
        }
    }
    install.data_dir(Path::new(&p.path)).join("claude-code-sessions")
}

pub(crate) fn roots(install: &Install, p: &Profile) -> Vec<PathBuf> {
    #[allow(unused_mut)]
    let mut paths = vec![root(install, p)];
    #[cfg(windows)]
    if p.is_default && install.is_msix() {
        let package = std::env::var_os("LOCALAPPDATA").zip(install.family.as_ref())
            .map(|(local, family)| PathBuf::from(local).join("Packages").join(family));
        for profile in crate::install::default_candidates(package.as_deref()) {
            let candidate = profile.join("claude-code-sessions");
            if !paths.contains(&candidate) { paths.push(candidate); }
        }
    }
    paths
}

fn collect_roots(paths: &[PathBuf]) -> Result<Vec<Entry>, String> {
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    for path in paths {
        entries.extend(collect(path)?.into_iter().filter(|e| seen.insert(e.session.id.clone())));
    }
    Ok(entries)
}

fn native_trash(root: &Path) -> PathBuf {
    root.with_file_name("hydra-session-library").join("trash").join("native")
}

#[cfg(windows)]
fn packaged_session_root(local: &Path, family: &str) -> Option<PathBuf> {
    let root = local.join("Claude-Data").join(family).join("claude-code-sessions");
    // An identity directory remains in place when its last index goes to the recycle bin.
    match stores(&root) {
        Ok(stores) if stores.is_empty() => None,
        // Keep an inaccessible root so the session operation reports the read error.
        _ => Some(root),
    }
}

fn dirs(path: &Path) -> Result<Vec<PathBuf>, String> {
    let listing = match fs::read_dir(path) {
        Ok(listing) => listing,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("无法读取会话目录 {}：{e}", path.display())),
    };
    let mut out = Vec::new();
    for e in listing {
        let e = e.map_err(|_| "无法读取会话目录。")?;
        if e.file_type().map_err(|_| "无法读取会话目录。")?.is_dir() { out.push(e.path()); }
    }
    out.sort();
    Ok(out)
}

fn stores(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for account in dirs(path)? { out.extend(dirs(&account)?); }
    Ok(out)
}

/// Restore only transcripts named by this Desktop profile when switching Code directories.
/// Keep project names intact: Desktop uses them to resolve the transcript for a working folder.
#[cfg(windows)]
pub(crate) fn recover_projects(session_roots: &[PathBuf], code: &Path, old_roots: &[PathBuf]) -> Result<(), String> {
    use std::collections::HashSet;
    let entries = collect_roots(session_roots)?;
    let ids: HashSet<_> = entries.into_iter().filter_map(|e| e.session.transcript_id)
        .filter(|id| uuid::Uuid::parse_str(id).is_ok()).collect();
    if ids.is_empty() { return Ok(()); }
    for root in old_roots {
        for project in dirs(&root.join("projects"))? {
            let target = code.join("projects").join(project.file_name().unwrap());
            for id in &ids {
                let name = format!("{id}.jsonl");
                let source = project.join(&name);
                if !source.is_file() { continue; }
                copy_missing_history(&source, &target.join(name)).map_err(|e| format!("恢复历史会话失败：{e}"))?;
                let sidecar = project.join(id);
                if sidecar.is_dir() {
                    copy_missing_history(&sidecar, &target.join(id)).map_err(|e| format!("恢复会话附件失败：{e}"))?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn copy_missing_history(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let meta = fs::symlink_metadata(from)?;
    if meta.file_attributes() & 0x400 != 0 { return Ok(()); } // Skip reparse points.
    if meta.is_dir() {
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            copy_missing_history(&entry.path(), &to.join(entry.file_name()))?;
        }
    } else if meta.is_file() && !to.try_exists()? {
        let parent = to.parent().unwrap();
        fs::create_dir_all(parent)?;
        let temp = parent.join(format!(".hydra-history-{}", uuid::Uuid::new_v4()));
        let result = fs::copy(from, &temp).and_then(|_| match fs::hard_link(&temp, to) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            result => result,
        });
        let _ = fs::remove_file(temp);
        result?;
    }
    Ok(())
}

fn text(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| v.get(*k).and_then(Value::as_str).filter(|x| !x.trim().is_empty()).map(str::to_owned))
}

fn collect(path: &Path) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    for store in stores(path)? {
        let Some(account) = store.parent().and_then(Path::file_name).and_then(|x| x.to_str()) else { continue };
        let Some(org) = store.file_name().and_then(|x| x.to_str()) else { continue };
        for entry in fs::read_dir(&store).map_err(|_| "无法读取会话目录。")? {
            let entry = entry.map_err(|_| "无法读取会话目录。")?;
            if !entry.file_type().map_err(|_| "无法读取会话文件。")?.is_file() { continue; }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("local_") || !name.ends_with(".json") { continue; }
            let json = fs::read(entry.path()).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).unwrap_or(Value::Null);
            let cwd = text(&json, &["cwd", "originCwd"]);
            let stats = metrics::index_metrics(&json);
            out.push(Entry {
                session: Session {
                    id: format!("{account}/{org}/{name}"),
                    title: text(&json, &["title", "name", "summary", "customTitle", "displayName"]).unwrap_or_else(|| name.clone()),
                    cwd_exists: cwd.as_deref().map(|c| Path::new(c).is_dir()).unwrap_or(false),
                    cwd,
                    last_activity_at: stats.time,
                    model: stats.model,
                    turns: stats.turns,
                    transcript_id: text(&json, &["cliSessionId"]),
                    in_target: false,
                },
                path: entry.path(),
                account: account.to_owned(),
                org: org.to_owned(),
            });
        }
    }
    out.sort_by(|a, b| b.session.last_activity_at.cmp(&a.session.last_activity_at).then_with(|| a.session.title.cmp(&b.session.title)));
    Ok(out)
}

/// The single identity store in the target account, or a user-facing reason why there isn't one.
fn target_store(install: &Install, target: &Profile) -> Result<PathBuf, String> {
    let mut found = Vec::new();
    for path in roots(install, target) {
        found = stores(&path)?;
        if !found.is_empty() { break; }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err("目标账号还没有会话目录。请先在目标账号的 Claude Code 中新建一个会话，再回来迁移。".into()),
        _ => Err("目标账号包含多个登录身份，无法确定会话应归属哪一个，Hydra 不会猜测。".into()),
    }
}

fn is_running(install: &Install, profiles: &[&Profile]) -> bool {
    let running = profiles::running_map(install);
    profiles.iter().any(|p| running.contains_key(&profiles::path_key(&p.path)))
}

// Imported chats belong to the selected Hydra profile. Keep them outside Claude's
// native index directory so Desktop never tries to open an export as a Code session.
fn library(install: &Install, p: &Profile, trash: bool, imported: bool) -> PathBuf {
    if !trash && !imported { return root(install, p); }
    let kind = if imported { "chats" } else { "code" };
    install.data_dir(Path::new(&p.path)).join("hydra-session-library").join(if trash { "trash" } else { "active" }).join(kind)
}

fn entries(install: &Install, p: &Profile, trash: bool) -> Result<Vec<Entry>, String> {
    let mut paths = roots(install, p);
    if trash {
        paths = paths.iter().map(|path| native_trash(path)).collect();
        paths.push(library(install, p, true, false)); // Previous releases used a shared recycle bin.
    }
    let mut native = collect_roots(&paths)?;
    let mut imports = collect(&library(install, p, trash, true))?;
    for entry in &mut imports { entry.session.id = format!("import/{}", entry.session.id); }
    native.extend(imports);
    Ok(native)
}

pub fn source_preview(install: &Install, source: &Profile, trash: bool) -> Result<Preview, String> {
    let mut sessions: Vec<_> = entries(install, source, trash)?.into_iter().map(|e| e.session).collect();
    let ids = sessions.iter().filter(|s| s.id.split('/').count() == 3).filter_map(|s| s.transcript_id.clone()).collect();
    let logs = metrics::lookup(&ids);
    for session in &mut sessions {
        if session.id.split('/').count() != 3 { continue; }
        if let Some(stats) = session.transcript_id.as_ref().and_then(|id| logs.get(id)) {
            session.turns = stats.turns.or(session.turns);
            session.model = stats.model.clone().or(session.model.take());
            session.last_activity_at = session.last_activity_at.max(stats.time);
        }
    }
    sessions.sort_by_key(|s| std::cmp::Reverse(s.last_activity_at));
    Ok(Preview { sessions, target_problem: None, running: is_running(install, &[source]) })
}

fn insert_file(dest: &Path, bytes: &[u8]) -> Result<bool, String> {
    let mut file = match OpenOptions::new().create_new(true).write(true).open(dest) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(err) => return Err(err.to_string()),
    };
    if let Err(err) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(dest);
        return Err(err.to_string());
    }
    Ok(true)
}

fn store_dir(root: &Path, account: &str, org: &str) -> Result<PathBuf, String> {
    let mut dir = root.to_path_buf();
    for part in [None, Some(account), Some(org)] {
        if let Some(part) = part { dir.push(part); }
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        if !fs::symlink_metadata(&dir).map_err(|e| e.to_string())?.file_type().is_dir() {
            return Err("会话目录不是普通目录。".into());
        }
    }
    Ok(dir)
}

pub fn recycle(install: &Install, p: &Profile, action: &str, id: &str) -> Result<(), String> {
    let trash = action != "delete";
    let items = entries(install, p, trash)?;
    if action == "empty" {
        let mut bins: Vec<_> = roots(install, p).iter().map(|path| native_trash(path)).collect();
        bins.extend([library(install, p, true, false), library(install, p, true, true)]);
        for bin in bins {
            for e in collect(&bin)? { fs::remove_file(e.path).map_err(|e| e.to_string())?; }
        }
        return Ok(());
    }
    if !matches!(action, "delete" | "restore") { return Err("未知操作。".into()); }
    let item = items.iter().find(|e| e.session.id == id).ok_or("会话已变更，请刷新。")?;
    let imported = item.session.id.starts_with("import/") && item.session.id.split('/').count() == 4;
    if !imported && is_running(install, &[p]) { return Err("请先退出该 Claude 账号，再修改本地会话。".into()); }
    let mut destination = library(install, p, !trash, imported);
    if !imported {
        let paths = roots(install, p);
        if !trash && paths.iter().filter(|root| root.join(id).is_file()).count() > 1 {
            return Err("新旧目录中都存在这条会话索引，请先确认需要保留的副本。".into());
        }
        if trash && paths.iter().any(|root| root.join(id).is_file()) {
            return Err("当前会话目录中已存在这条记录。".into());
        }
        for root in paths {
            let bin = native_trash(&root);
            if item.path.starts_with(&bin) { destination = root; break; }
            if item.path.starts_with(&root) { destination = bin; break; }
        }
    }
    let dest = store_dir(&destination, &item.account, &item.org)?
        .join(item.path.file_name().ok_or("无效会话文件名")?);
    // Refuse to replace an existing entry on both delete and restore.
    fs::hard_link(&item.path, &dest).map_err(|e| format!("无法移动会话（目标可能已存在）：{e}"))?;
    if let Err(err) = fs::remove_file(&item.path) {
        let _ = fs::remove_file(dest);
        return Err(err.to_string());
    }
    Ok(())
}

pub fn import_chats(install: &Install, p: &Profile, raw: &str) -> Result<TransferResult, String> {
    use sha2::{Digest, Sha256};
    let json: Value = serde_json::from_str(raw.trim_start_matches('\u{feff}')).map_err(|_| "JSON 格式无效。")?;
    let rows = match json { Value::Array(rows) => rows, row => vec![row] };
    if rows.is_empty() || rows.iter().any(|r| r.get("chat_messages").and_then(Value::as_array).is_none()) {
        return Err("请选择 Claude 导出的 conversations.json 或单个含 chat_messages 的聊天。".into());
    }
    let dir = store_dir(&library(install, p, false, true), "archive", "chats")?;
    let mut result = TransferResult { copied: 0, skipped: 0, failed: 0 };
    for row in rows {
        let bytes = serde_json::to_vec(&row).map_err(|e| e.to_string())?;
        let digest = Sha256::digest(row.get("uuid").and_then(Value::as_str).filter(|s| !s.is_empty())
            .map(str::as_bytes).unwrap_or(&bytes));
        match insert_file(&dir.join(format!("local_{digest:x}.json")), &bytes) {
            Ok(true) => result.copied += 1, Ok(false) => result.skipped += 1, Err(_) => result.failed += 1,
        }
    }
    Ok(result)
}

pub fn read_import(install: &Install, p: &Profile, id: &str) -> Result<String, String> {
    let item = entries(install, p, false)?.into_iter().find(|e| e.session.id == id && id.split('/').count() == 4)
        .ok_or("找不到导入的聊天。")?;
    fs::read_to_string(item.path).map_err(|e| e.to_string())
}

pub fn preview(install: &Install, source: &Profile, target: &Profile) -> Result<Preview, String> {
    if source.id == target.id { return Err("来源和目标账号不能相同。".into()); }
    let mut sessions: Vec<Session> = collect_roots(&roots(install, source))?.into_iter().map(|e| e.session).collect();
    let store = target_store(install, target);
    if let Ok(dest) = &store {
        let target_files = existing_target_files(install, target, dest)?;
        for s in &mut sessions {
            let name = s.id.rsplit('/').next().unwrap_or_default();
            s.in_target = target_files.contains(name);
        }
    }
    Ok(Preview { sessions, target_problem: store.err(), running: is_running(install, &[target]) })
}

fn existing_target_files(install: &Install, target: &Profile, dest: &Path) -> Result<std::collections::HashSet<String>, String> {
    let target_org = dest.file_name();
    let target_account = dest.parent().and_then(Path::file_name);
    Ok(collect_roots(&roots(install, target))?.into_iter()
        .filter(|e| Some(std::ffi::OsStr::new(&e.account)) == target_account && Some(std::ffi::OsStr::new(&e.org)) == target_org)
        .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned()).collect())
}

fn replace_values(v: &mut Value, old_account: &str, old_org: &str, account: &str, org: &str) {
    match v {
        Value::String(s) => { if s == old_account { *s = account.to_owned(); } else if s == old_org { *s = org.to_owned(); } }
        Value::Array(a) => for x in a { replace_values(x, old_account, old_org, account, org); },
        Value::Object(o) => for x in o.values_mut() { replace_values(x, old_account, old_org, account, org); },
        _ => (),
    }
}

/// Read and parse an index; Desktop may be rewriting it right now, so retry a torn read.
fn read_index(path: &Path) -> Option<Value> {
    for attempt in 0..3 {
        if attempt > 0 { std::thread::sleep(std::time::Duration::from_millis(150)); }
        if let Some(v) = fs::read(path).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) { return Some(v); }
    }
    None
}

/// Whether copying `ids` writes native indexes the target's running Desktop would miss.
pub fn needs_closed_target(install: &Install, target: &Profile, ids: &[String]) -> bool {
    ids.iter().any(|id| !(id.starts_with("import/") && id.split('/').count() == 4)) && is_running(install, &[target])
}

fn copy_into(available: &[Entry], dest: &Path, ids: &[String]) -> Result<TransferResult, String> {
    let account = dest.parent().and_then(Path::file_name).and_then(|v| v.to_str()).ok_or("目标账号路径无效。")?;
    let org = dest.file_name().and_then(|v| v.to_str()).ok_or("目标组织路径无效。")?;
    let mut result = TransferResult { copied: 0, skipped: 0, failed: 0 };
    for id in ids {
        let Some(entry) = available.iter().find(|x| &x.session.id == id) else { result.failed += 1; continue };
        let Some(name) = entry.path.file_name() else { result.failed += 1; continue };
        let Some(mut json) = read_index(&entry.path) else { result.failed += 1; continue };
        replace_values(&mut json, &entry.account, &entry.org, account, org);
        let Ok(data) = serde_json::to_vec_pretty(&json) else { result.failed += 1; continue };
        let file = dest.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&file) {
            Ok(mut f) => {
                if f.write_all(&data).and_then(|_| f.sync_all()).is_ok() { result.copied += 1 } else { drop(f); let _ = fs::remove_file(&file); result.failed += 1; }
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => result.skipped += 1,
            Err(_) => result.failed += 1,
        }
    }
    Ok(result)
}

pub fn copy(install: &Install, source: &Profile, target: &Profile, ids: &[String]) -> Result<TransferResult, String> {
    if source.id == target.id { return Err("来源和目标账号不能相同。".into()); }
    if ids.is_empty() { return Err("请选择会话。".into()); }
    let items = entries(install, source, false)?;
    let (imports, native): (Vec<_>, Vec<_>) = ids.iter().cloned()
        .partition(|id| id.starts_with("import/") && id.split('/').count() == 4);
    let mut result = TransferResult { copied: 0, skipped: 0, failed: 0 };
    if !native.is_empty() {
        if is_running(install, &[target]) { return Err(format!("目标账号「{}」正在运行，需要重启后才能迁移本地会话。", target.name)); }
        let dest = target_store(install, target)?;
        let existing = existing_target_files(install, target, &dest)?;
        let (present, missing): (Vec<_>, Vec<_>) = native.into_iter().partition(|id|
            items.iter().any(|e| &e.session.id == id) && existing.contains(id.rsplit('/').next().unwrap_or_default()));
        result = copy_into(&items, &dest, &missing)?;
        result.skipped += present.len();
    }
    if !imports.is_empty() {
        let dest = store_dir(&library(install, target, false, true), "archive", "chats")?;
        for id in imports {
            let Some(item) = items.iter().find(|e| e.session.id == id) else { result.failed += 1; continue };
            let bytes = fs::read(&item.path).map_err(|e| e.to_string())?;
            match insert_file(&dest.join(item.path.file_name().ok_or("无效文件名")?), &bytes) {
                Ok(true) => result.copied += 1, Ok(false) => result.skipped += 1, Err(_) => result.failed += 1,
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hydra-session-{name}-{}-{}", std::process::id(), crate::paths::now_millis()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn fixture(path: &Path, id: &str) -> Profile {
        Profile {
            id: id.into(), name: id.into(), badge: id.into(), path: path.join(id).to_string_lossy().into(),
            is_default: false, pid: None, last_used: None, color: 0, keep_running: false, signed_in: None, environment: None, blocked: None, blocked_soft: false,
        }
    }

    #[test]
    fn import_migrate_restore_and_empty_are_account_scoped() {
        let dir = temp("library");
        let install = Install { kind: "Classic".into(), exe: None, version: None, family: None, aumid: None, default_profile: dir.clone() };
        let a = fixture(&dir, "a");
        let b = fixture(&dir, "b");
        let raw = r#"[{"uuid":"1","name":"Demo","chat_messages":[{"sender":"human","text":"Hi"}]}]"#;
        assert_eq!(import_chats(&install, &a, raw).unwrap().copied, 1);
        assert_eq!(import_chats(&install, &a, raw).unwrap().skipped, 1);
        let id = source_preview(&install, &a, false).unwrap().sessions.remove(0).id;
        assert_eq!(copy(&install, &a, &b, std::slice::from_ref(&id)).unwrap().copied, 1);
        assert_eq!(copy(&install, &a, &b, std::slice::from_ref(&id)).unwrap().skipped, 1);
        recycle(&install, &a, "delete", &id).unwrap();
        assert!(entries(&install, &a, false).unwrap().is_empty());
        recycle(&install, &a, "restore", &id).unwrap();
        assert!(read_import(&install, &a, &id).unwrap().contains("Hi"));
        recycle(&install, &a, "delete", &id).unwrap();
        import_chats(&install, &a, raw).unwrap();
        assert!(recycle(&install, &a, "restore", &id).is_err());
        recycle(&install, &b, "delete", &id).unwrap();
        recycle(&install, &a, "empty", "").unwrap();
        assert!(entries(&install, &a, true).unwrap().is_empty());
        assert_eq!(entries(&install, &a, false).unwrap().len(), 1);
        assert_eq!(entries(&install, &b, true).unwrap().len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recycling_a_native_index_preserves_original_bytes_and_directory() {
        let dir = temp("native-trash");
        let install = Install { kind: "Classic".into(), exe: None, version: None, family: None, aumid: None, default_profile: dir.clone() };
        let p = fixture(&dir, "src");
        let store = store_dir(&root(&install, &p), "user", "org").unwrap();
        let path = store.join("local_demo.json");
        let raw = br#"{"title":"Demo","cwd":"project"}"#;
        fs::write(&path, raw).unwrap();
        let id = "user/org/local_demo.json";
        recycle(&install, &p, "delete", id).unwrap();
        assert!(!path.exists());
        recycle(&install, &p, "restore", id).unwrap();
        assert_eq!(fs::read(&path).unwrap(), raw);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn store_sessions_use_the_registered_package_family() {
        let local = temp("family-sessions");
        let family = "Claude_pzs8sxrjxfjjc";
        let root = local.join("Claude-Data").join(family).join("claude-code-sessions");
        let store = store_dir(&root, "user", "org").unwrap();
        fs::write(store.join("local_example.json"), "{}").unwrap();
        assert_eq!(collect(&packaged_session_root(&local, family).unwrap()).unwrap().len(), 1);
        let legacy = local.join("older").join("claude-code-sessions");
        let old = store_dir(&legacy, "user", "org").unwrap();
        fs::write(old.join("local_example.json"), "{}").unwrap();
        fs::write(old.join("local_older.json"), "{}").unwrap();
        let merged = collect_roots(&[root.clone(), legacy]).unwrap();
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|e| e.path == store.join("local_example.json")));
        assert!(packaged_session_root(&local, "Claude_other").is_none());
        assert!(!crate::install::valid_program_path(&root));
        fs::remove_dir_all(local).unwrap();
    }

    #[test]
    fn replacement_is_limited_to_complete_json_values() {
        let mut v = serde_json::json!({"account":"a", "nested":["org-a", "path/a/org-a"], "a":"a"});
        replace_values(&mut v, "a", "org-a", "b", "org-b");
        assert_eq!(v["account"], "b");
        assert_eq!(v["nested"][0], "org-b");
        assert_eq!(v["nested"][1], "path/a/org-a");
        assert_eq!(v["a"], "b");
    }

    #[test]
    fn detects_only_session_files_in_store() {
        let root = temp("detect");
        let store = root.join("account").join("org");
        fs::create_dir_all(&store).unwrap();
        fs::write(store.join("local_1.json"), br#"{"title":"Example","cwd":"/nope","lastActivityAt":5}"#).unwrap();
        fs::write(store.join("other.json"), b"{}").unwrap();
        let sessions = collect(&root).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session.title, "Example");
        assert_eq!(sessions[0].session.last_activity_at, Some(5));
        assert!(!sessions[0].session.cwd_exists);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn legacy_transcripts_follow_only_the_owning_profiles_indexes() {
        let root = temp("legacy-history");
        let source = root.join("legacy");
        let code = root.join("private");
        let project = source.join("projects").join("project");
        let index = root.join("claude-code-sessions/user/org");
        let id = uuid::Uuid::new_v4().to_string();
        fs::create_dir_all(project.join(&id)).unwrap();
        fs::create_dir_all(&index).unwrap();
        fs::write(index.join("local_test.json"), serde_json::json!({"cliSessionId": id}).to_string()).unwrap();
        let name = format!("{id}.jsonl");
        fs::write(project.join(&name), b"original").unwrap();
        fs::write(project.join(&id).join("attachment"), b"sidecar").unwrap();
        fs::write(project.join("other.jsonl"), b"unrelated").unwrap();
        let restore = || recover_projects(&[root.join("claude-code-sessions")], &code, std::slice::from_ref(&source)).unwrap();
        restore();
        let target = code.join("projects/project");
        assert_eq!(fs::read(target.join(&name)).unwrap(), b"original");
        assert_eq!(fs::read(target.join(&id).join("attachment")).unwrap(), b"sidecar");
        assert!(!target.join("other.jsonl").exists());
        fs::write(target.join(&name), b"continued").unwrap();
        restore();
        assert_eq!(fs::read(target.join(name)).unwrap(), b"continued");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copy_rewrites_identity_and_never_overwrites() {
        let src = temp("src");
        let dst = temp("dst");
        let from = src.join("acc-a").join("org-a");
        let to = dst.join("acc-b").join("org-b");
        fs::create_dir_all(&from).unwrap();
        fs::create_dir_all(&to).unwrap();
        fs::write(from.join("local_1.json"), br#"{"title":"One","account":"acc-a","org":"org-a"}"#).unwrap();
        fs::write(from.join("local_2.json"), br#"{"title":"Two"}"#).unwrap();
        fs::write(to.join("local_2.json"), br#"{"title":"Keep"}"#).unwrap();
        let entries = collect(&src).unwrap();
        let ids: Vec<String> = entries.iter().map(|e| e.session.id.clone()).chain(["acc-a/org-a/missing.json".to_string()]).collect();
        let r = copy_into(&entries, &to, &ids).unwrap();
        assert_eq!((r.copied, r.skipped, r.failed), (1, 1, 1));
        let copied: Value = serde_json::from_slice(&fs::read(to.join("local_1.json")).unwrap()).unwrap();
        assert_eq!(copied["account"], "acc-b");
        assert_eq!(copied["org"], "org-b");
        assert!(from.join("local_1.json").exists(), "source must be kept");
        let kept: Value = serde_json::from_slice(&fs::read(to.join("local_2.json")).unwrap()).unwrap();
        assert_eq!(kept["title"], "Keep");
        fs::remove_dir_all(src).unwrap();
        fs::remove_dir_all(dst).unwrap();
    }
}
