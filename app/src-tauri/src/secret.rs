//! Secrets kept in `settings.json`.
//!
//! Windows seals them with DPAPI (the current user), macOS with a key that lives in the login
//! Keychain, and anywhere else the file's owner-only permissions are all there is. The sealed
//! text starts with its scheme, so a settings file copied between machines is *unreadable* rather
//! than silently misread: `try_unseal` returns `None` and the caller asks for the password again.
//!
//! - `dpapi:<base64>`   CryptProtectData output (Windows, current user, no UI prompt).
//! - `keychain:<base64>` v1 header, a 96-bit nonce and an AES-256-GCM ciphertext; the key itself
//!                       is 32 random bytes in the login Keychain (`Claude-Hydra` / `settings-key`).
//! - `plain:<text>`      no protection (legacy, or no key store available); migrated on macOS.
//!
//! The cipher round trip is unit-tested on every platform; the Keychain plumbing is macOS-only
//! and falls back to `plain:` (with a log line) when the Keychain cannot be used, so a Mac without
//! a usable login keychain still keeps its passwords rather than losing them.

// `Engine` is used by the DPAPI path and the tests; macOS and other builds only need `STANDARD`.
#[cfg_attr(not(windows), allow(unused_imports))]
use base64::{engine::general_purpose::STANDARD, Engine};

/// Seals a secret for `settings.json`.
pub fn seal(secret: &str) -> String {
    if secret.is_empty() { return String::new(); }
    #[cfg(windows)]
    if let Some(sealed) = dpapi::protect(secret.as_bytes()) {
        return format!("dpapi:{}", STANDARD.encode(sealed));
    }
    #[cfg(target_os = "macos")]
    if let Some(sealed) = keychain::seal(secret.as_bytes()) {
        return sealed;
    }
    #[cfg(target_os = "macos")]
    warn_fallback();
    format!("plain:{secret}")
}

/// `None` when the stored value cannot be decrypted by this user on this machine.
pub fn try_unseal(stored: &str) -> Option<String> {
    if let Some(rest) = stored.strip_prefix("plain:") { return Some(rest.to_string()); }
    #[cfg(windows)]
    if let Some(rest) = stored.strip_prefix("dpapi:") {
        let sealed = STANDARD.decode(rest).ok()?;
        return dpapi::unprotect(&sealed).and_then(|b| String::from_utf8(b).ok());
    }
    if let Some(rest) = stored.strip_prefix("keychain:") {
        #[cfg(target_os = "macos")]
        {
            return keychain::unseal(rest);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = rest;
            return None;
        }
    }
    if stored.starts_with("dpapi:") { return None; }
    Some(stored.to_string())
}

pub fn unseal(stored: &str) -> String { try_unseal(stored).unwrap_or_default() }

// ---- cipher -------------------------------------------------------------------------

fn cipher(key: &[u8; 32]) -> Option<aes_gcm::Aes256Gcm> {
    use aes_gcm::KeyInit;
    aes_gcm::Aes256Gcm::new_from_slice(key).ok()
}

/// AES-256-GCM with a fresh 96-bit nonce. `sealed` is `nonce || ciphertext || tag`.
pub fn sealed_with(key: &[u8; 32], plaintext: &[u8], nonce: &[u8; 12]) -> Option<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::Nonce;
    let cipher = cipher(key)?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(nonce), plaintext).ok()?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Some(out)
}

pub fn opened_with(key: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::Nonce;
    if sealed.len() < 12 + 16 { return None; }
    let cipher = cipher(key)?;
    cipher.decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..]).ok()
}

fn random_bytes(len: usize) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut out = vec![0u8; len];
        std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut out).ok()?;
        return Some(out);
    }
    #[cfg(not(unix))]
    {
        let mut out = Vec::with_capacity(len);
        while out.len() < len { out.extend_from_slice(uuid::Uuid::new_v4().as_bytes()); }
        out.truncate(len);
        Some(out)
    }
}

// ---- macOS Keychain -----------------------------------------------------------------

// Compiled on every platform so the Rust is checked where it is written; only the macOS build
// calls it.
#[allow(dead_code)]
mod keychain {
    use base64::Engine as _;

    const SERVICE: &str = "Claude-Hydra";
    const ACCOUNT: &str = "settings-key";
    /// Seal format version, first byte of the decoded value.
    const VERSION: u8 = 1;

    /// `security` exit status for "no such item" (errSecItemNotFound).
    const NOT_FOUND: i32 = 44;

    /// What the Keychain holds under our name.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Lookup {
        Found([u8; 32]),
        /// No item exists: the only case in which a new key may be created.
        Missing,
        /// The item may exist but could not be read (locked keychain, access denied, a damaged
        /// value, `security` failing). A new key here would overwrite the one every existing
        /// `keychain:` value was sealed with, so nothing is written.
        Unavailable,
    }

    /// Interprets `security find-generic-password -w`.
    pub fn lookup(status: Option<i32>, stdout: &[u8]) -> Lookup {
        use super::STANDARD;
        match status {
            Some(0) => std::str::from_utf8(stdout)
                .ok()
                .and_then(|text| STANDARD.decode(text.trim()).ok())
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .map_or(Lookup::Unavailable, Lookup::Found),
            Some(NOT_FOUND) => Lookup::Missing,
            _ => Lookup::Unavailable,
        }
    }

    /// The master key. Only a key that was read or created is remembered; a failure (say the
    /// keychain is still locked at login) is retried on the next call instead of being cached
    /// for the life of the process. `None` means the Keychain could not be used; the caller then
    /// falls back to the file's permissions instead of losing the password.
    pub fn master_key() -> Option<[u8; 32]> {
        use std::sync::Mutex;
        static KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);
        let mut cached = KEY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = *cached { return Some(key); }
        let key = match load_key() {
            Lookup::Found(key) => key,
            Lookup::Missing => {
                let key: [u8; 32] = super::random_bytes(32)?.try_into().ok()?;
                if !add_key(&key) { return None; }
                key
            }
            Lookup::Unavailable => return None,
        };
        *cached = Some(key);
        Some(key)
    }

    pub fn seal(data: &[u8]) -> Option<String> {
        use super::{random_bytes, sealed_with};
        let key = master_key()?;
        let nonce: [u8; 12] = random_bytes(12)?.try_into().ok()?;
        let sealed = sealed_with(&key, data, &nonce)?;
        let mut all = Vec::with_capacity(1 + sealed.len());
        all.push(VERSION);
        all.extend_from_slice(&sealed);
        Some(format!("keychain:{}", super::STANDARD.encode(all)))
    }

    pub fn unseal(text: &str) -> Option<String> {
        use super::{opened_with, STANDARD};
        let raw = STANDARD.decode(text).ok()?;
        let (version, rest) = raw.split_first()?;
        if *version != VERSION { return None; }
        let key = master_key()?;
        let opened = opened_with(&key, rest)?;
        String::from_utf8(opened).ok()
    }

    fn security(args: &[&str]) -> Option<std::process::Output> {
        let out = std::process::Command::new("/usr/bin/security").args(args).output().ok()?;
        Some(out)
    }

    fn load_key() -> Lookup {
        match security(&["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"]) {
            Some(out) => lookup(out.status.code(), &out.stdout),
            None => Lookup::Unavailable,
        }
    }

    /// Adds the key without `-U`: if an item appeared in the meantime, the add fails rather than
    /// replacing the key existing values were sealed with.
    fn add_key(key: &[u8; 32]) -> bool {
        use super::STANDARD;
        let encoded = STANDARD.encode(key);
        let out = security(&["add-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w", &encoded]);
        out.is_some_and(|o| o.status.success())
    }
}

#[cfg(target_os = "macos")]
fn warn_fallback() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        crate::paths::append_log("hydra-error.log", "settings secret: login Keychain unavailable, storing with file permissions only");
    });
}

// ---- legacy migration ---------------------------------------------------------------

/// Re-seals every `plain:` secret in the settings file, so a file written before a key store was
/// used moves into it. Only strings that actually got a stronger scheme are touched; a file that
/// cannot be re-sealed is left exactly as it was. Called on macOS at startup.
///
/// The read-modify-write holds the settings lock, so a launch saving `last_exit` (or any other
/// `settings::update`) at the same moment is neither lost nor overwritten with an older copy.
/// The key is fetched first, outside the lock: the Keychain may wait for the user to unlock it,
/// and the lock must not be held through that.
pub fn migrate_settings_file(path: &std::path::Path) {
    if !key_ready() { return; }
    let changed = crate::settings::with_lock(path, || {
        let Ok(bytes) = std::fs::read(path) else { return false };
        let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) else { return false };
        if !reseal_value(&mut value) { return false; }
        let Ok(text) = serde_json::to_vec_pretty(&value) else { return false };
        let tmp = path.with_extension(format!("json.{}.migrate.tmp", std::process::id()));
        if std::fs::write(&tmp, text).is_err() { return false; }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        if std::fs::rename(&tmp, path).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return false;
        }
        true
    });
    if changed {
        crate::paths::append_log("hydra.log", "settings secret: re-sealed plain-text secrets");
    }
}

/// Whether sealing can use a key store now (on macOS: the Keychain key is readable or was just
/// created). Elsewhere sealing never blocks.
fn key_ready() -> bool {
    #[cfg(target_os = "macos")]
    {
        return keychain::master_key().is_some();
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

/// Replaces `plain:` strings in place; returns whether anything changed.
fn reseal_value(value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => {
            let Some(rest) = text.strip_prefix("plain:") else { return false };
            if rest.is_empty() { return false; }
            let sealed = seal(rest);
            if !sealed.starts_with("plain:") {
                *text = sealed;
                true
            } else {
                false
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().fold(false, |changed, item| reseal_value(item) | changed),
        serde_json::Value::Object(map) => map.values_mut().fold(false, |changed, item| reseal_value(item) | changed),
        _ => false,
    }
}

// ---- DPAPI (Windows) ----------------------------------------------------------------

#[cfg(windows)]
mod dpapi {
    use std::ffi::c_void;
    #[repr(C)]
    struct Blob { len: u32, data: *mut u8 }
    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(input: *const Blob, description: *const u16, entropy: *const Blob, reserved: *mut c_void, prompt: *mut c_void, flags: u32, output: *mut Blob) -> i32;
        fn CryptUnprotectData(input: *const Blob, description: *mut *mut u16, entropy: *const Blob, reserved: *mut c_void, prompt: *mut c_void, flags: u32, output: *mut Blob) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" { fn LocalFree(mem: *mut c_void) -> *mut c_void; }
    const UI_FORBIDDEN: u32 = 1;
    fn run(data: &[u8], protect: bool) -> Option<Vec<u8>> {
        let input = Blob { len: data.len() as u32, data: data.as_ptr() as *mut u8 };
        let mut out = Blob { len: 0, data: std::ptr::null_mut() };
        let ok = unsafe {
            if protect { CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), UI_FORBIDDEN, &mut out) }
            else { CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), UI_FORBIDDEN, &mut out) }
        };
        if ok == 0 { return None; }
        unsafe { let v = std::slice::from_raw_parts(out.data, out.len as usize).to_vec(); LocalFree(out.data as *mut c_void); Some(v) }
    }
    pub fn protect(data: &[u8]) -> Option<Vec<u8>> { run(data, true) }
    pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> { run(data, false) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_values_keep_their_round_trip() {
        assert_eq!(try_unseal(&seal("s3cr:et")), Some("s3cr:et".into()));
        assert_eq!(seal(""), "");
        assert_eq!(try_unseal("legacy-value"), Some("legacy-value".into()));
        assert_eq!(try_unseal("plain:visible"), Some("visible".into()));
    }

    #[test]
    fn cipher_round_trip_and_tamper() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let sealed = sealed_with(&key, b"hello", &nonce).unwrap();
        assert_eq!(opened_with(&key, &sealed), Some(b"hello".to_vec()));
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert_eq!(opened_with(&key, &tampered), None, "a changed nonce must not decrypt");
        assert_eq!(opened_with(&[8u8; 32], &sealed), None, "another key must not decrypt");
        assert_eq!(opened_with(&key, &sealed[..20]), None, "a short value must not decrypt");
    }

    #[test]
    fn a_foreign_scheme_is_not_read() {
        assert_eq!(try_unseal("keychain:AAAAAAAA"), None);
        assert_eq!(try_unseal("dpapi:AAAA"), None);
    }

    #[test]
    fn keychain_creates_a_key_only_when_none_exists() {
        use keychain::{lookup, Lookup};
        let key = [5u8; 32];
        let encoded = format!("{}\n", STANDARD.encode(key));
        assert_eq!(lookup(Some(0), encoded.as_bytes()), Lookup::Found(key));
        assert_eq!(lookup(Some(44), b""), Lookup::Missing);
        // Locked keychain, denied access, a killed `security`, a damaged value: never "missing",
        // because a new key would replace the one existing values were sealed with.
        assert_eq!(lookup(Some(51), b""), Lookup::Unavailable);
        assert_eq!(lookup(Some(128), b""), Lookup::Unavailable);
        assert_eq!(lookup(None, b""), Lookup::Unavailable);
        assert_eq!(lookup(Some(0), b"not base64!"), Lookup::Unavailable);
        assert_eq!(lookup(Some(0), STANDARD.encode([1u8; 16]).as_bytes()), Lookup::Unavailable);
    }

    #[test]
    fn migration_waits_for_a_concurrent_settings_write() {
        let dir = std::env::temp_dir().join(format!("hydra-secret-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, r#"{"a":"plain:top"}"#).unwrap();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let writer = {
            let path = path.clone();
            std::thread::spawn(move || {
                crate::settings::with_lock(&path, || {
                    held_tx.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    std::fs::write(&path, r#"{"a":"plain:top","written":"meanwhile"}"#).unwrap();
                });
            })
        };
        held_rx.recv().unwrap();
        migrate_settings_file(&path);
        writer.join().unwrap();
        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["written"], "meanwhile", "the migration must not overwrite a write it waited for");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn migration_only_reseals_what_it_can_protect() {
        let dir = std::env::temp_dir().join(format!("hydra-secret-migrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, r#"{"a":"plain:top","b":{"c":["plain:inner","keep"]},"d":"plain:"}"#).unwrap();
        migrate_settings_file(&path);
        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let sealed = seal("top");
        if sealed.starts_with("plain:") {
            // No key store on this machine: the file must be left exactly as it was.
            assert_eq!(value["a"], "plain:top");
        } else {
            assert_eq!(try_unseal(value["a"].as_str().unwrap()), Some("top".into()));
            assert_eq!(try_unseal(value["b"]["c"][0].as_str().unwrap()), Some("inner".into()));
        }
        assert_eq!(value["b"]["c"][1], "keep");
        assert_eq!(value["d"], "plain:");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
