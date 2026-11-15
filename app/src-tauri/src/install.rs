//! Detection of the local Claude desktop installation.

use crate::settings::{self, CachedInstall, Settings};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Install {
    /// "Msix", "Classic", or "App" on macOS.
    pub kind: String,
    pub exe: Option<PathBuf>,
    pub version: Option<String>,
    pub family: Option<String>,
    pub aumid: Option<String>,
    pub default_profile: PathBuf,
}

impl Install {
    pub fn is_msix(&self) -> bool {
        self.kind == "Msix"
    }

    /// Checks whether a process image path belongs to the Claude desktop app
    /// (excluding the Claude Code CLI binary).
    pub fn is_desktop_exe(&self, image: &str) -> bool {
        let lower = image.replace('/', "\\").to_lowercase();
        if self.is_msix() {
            let Some(family) = &self.family else { return false };
            let family = family.to_lowercase();
            let Some((name, publisher)) = family.split_once('_') else { return false };
            // The package itself, or the copy sandboxed accounts run (see `sandbox::launch_exe`).
            let copies = format!("{}\\", crate::sandbox::apps_dir().to_string_lossy().trim_end_matches('\\').to_lowercase());
            return (lower.contains(&format!("\\windowsapps\\{name}_")) || lower.starts_with(&copies))
                && lower.contains(&format!("__{publisher}\\"))
                && lower.ends_with("\\claude.exe");
        }
        if cfg!(target_os = "macos") {
            return self
                .exe
                .as_ref()
                .map(|e| image == e.to_string_lossy() || image.starts_with(&format!("{} ", e.to_string_lossy())))
                .unwrap_or(false);
        }
        let Some(exe) = &self.exe else { return false };
        let Some(mut dir) = exe.parent().map(Path::to_path_buf) else { return false };
        if dir
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase().starts_with("app-"))
            .unwrap_or(false)
        {
            if let Some(p) = dir.parent() {
                dir = p.to_path_buf();
            }
        }
        let prefix = format!("{}\\", dir.to_string_lossy().trim_end_matches('\\').to_lowercase());
        lower.starts_with(&prefix)
    }

    /// Executable path used to launch an isolated account instance.
    pub fn launch_exe(&self) -> Option<PathBuf> {
        #[cfg(windows)]
        if self.is_msix() {
            let apps = local_app_data()?.join("Microsoft\\WindowsApps");
            if let Some(f) = &self.family {
                let a = apps.join(f).join("claude-desktop.exe");
                if a.exists() {
                    return Some(a);
                }
            }
            let a = apps.join("claude-desktop.exe");
            return a.exists().then_some(a);
        }
        self.exe.clone()
    }

    /// The folder that really holds the data of a profile launched with `path`.
    ///
    /// Store builds may virtualize `%APPDATA%` / `%LOCALAPPDATA%` writes into the package's
    /// `LocalCache`, or not (a folder that existed before the package was installed stays
    /// real, and newer builds exclude their data folders from virtualization). The two views
    /// can even be split, with a few files mirrored into `LocalCache` and the rest in the real
    /// folder. So every place the data could be is checked and the one Claude used is taken.
    pub fn data_dir(&self, path: &Path) -> PathBuf {
        // Only Store builds on Windows add further places to look.
        #[cfg_attr(not(windows), allow(unused_mut))]
        let mut candidates = vec![path.to_path_buf()];
        #[cfg(windows)]
        if let Some(cache) = self.package_cache() {
            for (var, sub) in [("APPDATA", "Roaming"), ("LOCALAPPDATA", "Local")] {
                let Some(base) = std::env::var_os(var).map(PathBuf::from) else { continue };
                if let Ok(rel) = path.strip_prefix(&base) {
                    candidates.push(cache.join(sub).join(rel));
                }
            }
        }
        best_data_dir(candidates).unwrap_or_else(|| path.to_path_buf())
    }

    /// `%LOCALAPPDATA%\Packages\<family>\LocalCache` of a Store build.
    #[cfg(windows)]
    fn package_cache(&self) -> Option<PathBuf> {
        if !self.is_msix() {
            return None;
        }
        Some(local_app_data()?.join("Packages").join(self.family.as_ref()?).join("LocalCache"))
    }
}

/// Of the folders that hold Claude data, the one Claude used last. A full Chromium profile
/// (`Local State`) wins over a folder holding only a few mirrored files.
pub fn best_data_dir(candidates: Vec<PathBuf>) -> Option<PathBuf> {
    const MARKERS: [&str; 5] = ["Local State", "config.json", "Preferences", "Network/Cookies", "window-state.json"];
    candidates
        .into_iter()
        .filter_map(|dir| {
            let newest = MARKERS
                .iter()
                .filter_map(|m| std::fs::metadata(dir.join(m)).ok()?.modified().ok())
                .max()?;
            Some(((dir.join("Local State").is_file(), newest), dir))
        })
        .max_by_key(|(score, _)| *score)
        .map(|(_, dir)| dir)
}

#[cfg(windows)]
fn local_app_data() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
}

#[cfg(windows)]
fn roaming_app_data() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(PathBuf::from)
}

/// Every place the default profile of a Windows build can live, preferred first when none
/// holds data yet: `%APPDATA%\Claude` (classic builds, and Store builds on machines that had it
/// before), the Store package's virtualized copy of it, and `%LOCALAPPDATA%\Claude-Data`,
/// where newer builds move their data out of the package.
#[cfg(windows)]
fn default_candidates(package: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(pkg) = package {
        out.push(pkg.join("LocalCache\\Roaming\\Claude"));
    }
    out.extend(roaming_app_data().map(|d| d.join("Claude")));
    out.extend(local_app_data().map(|d| d.join("Claude-Data")));
    out
}

fn classic(exe: PathBuf) -> Install {
    #[cfg(windows)]
    let default_profile = {
        let candidates = default_candidates(None);
        best_data_dir(candidates.clone()).unwrap_or_else(|| candidates[0].clone())
    };
    #[cfg(not(windows))]
    let default_profile = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join("Claude");
    Install {
        kind: if cfg!(target_os = "macos") { "App".into() } else { "Classic".into() },
        exe: Some(exe),
        version: None,
        family: None,
        aumid: None,
        default_profile,
    }
}

#[cfg(windows)]
fn msix(family: &str, version: Option<String>, exe: Option<PathBuf>) -> Option<Install> {
    let lad = local_app_data()?;
    let pkg = lad.join("Packages").join(family);
    if !pkg.is_dir() {
        return None;
    }
    let candidates = default_candidates(Some(&pkg));
    Some(Install {
        kind: "Msix".into(),
        exe: exe.filter(|e| e.exists()),
        version,
        family: Some(family.to_string()),
        aumid: Some(format!("{family}!Claude")),
        default_profile: best_data_dir(candidates.clone()).unwrap_or_else(|| candidates[0].clone()),
    })
}

pub fn resolve() -> Result<Install, String> {
    let s = settings::load();
    if let Some(p) = s.claude_path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        if p.exists() {
            return Ok(from_user_path(p));
        }
    }
    if let Some(i) = from_cache(&s) {
        return Ok(i);
    }
    let found = search()?;
    let _ = settings::update(|s| {
        s.install_cache = Some(to_cache(&found));
    });
    Ok(found)
}

fn from_user_path(p: PathBuf) -> Install {
    // The cache stores the executable (`Claude.app/Contents/MacOS/Claude`), while users may
    // pick the bundle itself; both must resolve to the bundle so the default profile is the
    // macOS one rather than the Windows `%APPDATA%` fallback (a relative `Claude` here).
    #[cfg(target_os = "macos")]
    if let Some(app) = mac_bundle(&p) {
        return mac_app(app);
    }
    classic(p)
}

/// The `.app` bundle that is `p` or contains it.
#[cfg(target_os = "macos")]
fn mac_bundle(p: &Path) -> Option<&Path> {
    p.ancestors().find(|a| a.extension().is_some_and(|e| e == "app"))
}

fn to_cache(i: &Install) -> CachedInstall {
    CachedInstall {
        kind: i.kind.clone(),
        exe: i.exe.as_ref().map(|e| e.to_string_lossy().to_string()),
        version: i.version.clone(),
        aumid: i.aumid.clone(),
        default_profile_path: i.default_profile.to_string_lossy().to_string(),
    }
}

fn from_cache(s: &Settings) -> Option<Install> {
    let c = s.install_cache.as_ref()?;
    let exe = c.exe.as_ref().map(PathBuf::from);
    #[cfg(windows)]
    if c.kind == "Msix" {
        let aumid = c.aumid.as_deref()?;
        let family = aumid.split('!').next()?;
        return msix(family, c.version.clone(), exe);
    }
    let exe = exe?;
    exe.exists().then(|| from_user_path(exe))
}

#[cfg(windows)]
fn search() -> Result<Install, String> {
    if let Some(lad) = local_app_data() {
        if let Ok(rd) = std::fs::read_dir(lad.join("Packages")) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("Claude_") && !name[7..].contains('_') {
                    if let Some(i) = msix(&name, None, None) {
                        if i.launch_exe().is_some() {
                            return Ok(i);
                        }
                    }
                }
            }
        }
    }
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(lad) = local_app_data() {
        dirs.push(lad.join("AnthropicClaude"));
        dirs.push(lad.join("Programs\\Claude"));
    }
    for v in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(p) = std::env::var_os(v) {
            dirs.push(PathBuf::from(p).join("Claude"));
        }
    }
    for dir in dirs {
        let exe = dir.join("Claude.exe");
        if exe.exists() {
            return Ok(classic(exe));
        }
        if let Ok(rd) = std::fs::read_dir(&dir) {
            let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
            for e in rd.flatten() {
                let cand = e.path().join("Claude.exe");
                if let Ok(m) = std::fs::metadata(&cand) {
                    let t = m.modified().unwrap_or(std::time::UNIX_EPOCH);
                    if best.as_ref().map(|b| t > b.0).unwrap_or(true) {
                        best = Some((t, cand));
                    }
                }
            }
            if let Some((_, exe)) = best {
                return Ok(classic(exe));
            }
        }
    }
    Err("未在此电脑上找到 Claude 桌面端。若装在非默认位置，请在“设置”中指定 Claude.exe 的路径。".into())
}

#[cfg(target_os = "macos")]
fn mac_app(app: &Path) -> Install {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    Install {
        kind: "App".into(),
        exe: Some(app.join("Contents/MacOS/Claude")),
        version: None,
        family: None,
        aumid: Some(app.to_string_lossy().to_string()),
        default_profile: home.join("Library/Application Support/Claude"),
    }
}

#[cfg(target_os = "macos")]
fn search() -> Result<Install, String> {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    for p in [PathBuf::from("/Applications/Claude.app"), home.join("Applications/Claude.app")] {
        if p.exists() {
            return Ok(mac_app(&p));
        }
    }
    Err("未找到 Claude.app。请安装 Claude 桌面端，或在“设置”中指定其路径。".into())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn search() -> Result<Install, String> {
    Err("此平台尚不支持。".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Install {
        Install {
            kind: "Msix".into(),
            exe: None,
            version: None,
            family: Some("Claude_pzs8sxrjxfjjc".into()),
            aumid: None,
            default_profile: PathBuf::new(),
        }
    }

    #[test]
    fn store_build_matches_any_version_but_not_the_cli() {
        let i = store();
        assert!(i.is_desktop_exe(r"C:\Program Files\WindowsApps\Claude_4.23118.0.0_x64__pzs8sxrjxfjjc\app\Claude.exe"));
        assert!(i.is_desktop_exe(r"C:\Program Files\WindowsApps\Claude_4.30000.0.0_x64__pzs8sxrjxfjjc\app\claude.exe"));
        assert!(!i.is_desktop_exe(r"C:\Users\u\AppData\Roaming\Claude\claude-code\2.1.0\claude.exe"));
        assert!(!i.is_desktop_exe(r"C:\Program Files\WindowsApps\Claude_4.1.0.0_x64__otherpublisher\app\Claude.exe"));
        let copy = crate::sandbox::apps_dir().join("Claude_5.1231.2.0_x64__pzs8sxrjxfjjc").join("Claude.exe");
        assert!(i.is_desktop_exe(&copy.to_string_lossy()));
        assert!(!i.is_desktop_exe(r"D:\elsewhere\Claude_5.1231.2.0_x64__pzs8sxrjxfjjc\Claude.exe"));
    }

    #[test]
    fn data_dir_prefers_the_full_profile_over_mirrored_files() {
        let root = std::env::temp_dir().join(format!("hydra-datadir-{}", crate::paths::now_millis()));
        let (mirror, real, empty) = (root.join("cache"), root.join("real"), root.join("empty"));
        std::fs::create_dir_all(&mirror).unwrap();
        std::fs::create_dir_all(real.join("Network")).unwrap();
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::write(real.join("Local State"), "{}").unwrap();
        std::fs::write(real.join("config.json"), "{}").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        // The Store's partial mirror is newer but holds only a few files.
        std::fs::write(mirror.join("config.json"), "{}").unwrap();
        let picked = best_data_dir(vec![empty.clone(), mirror.clone(), real.clone()]);
        assert_eq!(picked.as_deref(), Some(real.as_path()));
        // Two full profiles: the one used last wins.
        std::fs::write(mirror.join("Local State"), "{}").unwrap();
        assert_eq!(best_data_dir(vec![real.clone(), mirror.clone()]).as_deref(), Some(mirror.as_path()));
        assert_eq!(best_data_dir(vec![empty]), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn squirrel_build_matches_other_app_folders() {
        let i = classic(PathBuf::from(r"C:\Users\u\AppData\Local\AnthropicClaude\app-1.0.0\Claude.exe"));
        if cfg!(windows) {
            assert!(i.is_desktop_exe(r"C:\Users\u\AppData\Local\AnthropicClaude\app-1.2.0\Claude.exe"));
            assert!(!i.is_desktop_exe(r"C:\Users\u\.local\bin\claude.exe"));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mac_cached_exe_keeps_mac_default_profile() {
        let from_bundle = from_user_path(PathBuf::from("/Applications/Claude.app"));
        // The install cache stores the executable inside the bundle.
        let from_exe = from_user_path(PathBuf::from("/Applications/Claude.app/Contents/MacOS/Claude"));
        assert!(from_exe.default_profile.is_absolute());
        assert!(from_exe.default_profile.ends_with("Library/Application Support/Claude"));
        assert_eq!(from_exe.default_profile, from_bundle.default_profile);
        assert_eq!(from_exe.exe, from_bundle.exe);
    }
}
