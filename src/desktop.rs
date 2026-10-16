//! Read and decrypt the Grok Bot **desktop app's** saved gateway session.
//!
//! Enabled by the `desktop-session` feature. This is opt-in: nothing here runs unless the
//! user explicitly asks gb to read the desktop session (`/login desktop`).
//!
//! Mirrors grok-bot-cli's `src/core/app-session.js`. The app stores
//! `gateway-descriptor.json` in its data dir; the payload is encrypted with the Chromium
//! "Safe Storage" (OSCrypt) scheme:
//! - **Linux v11**: key from the Secret Service password (`secret-tool`), PBKDF2-HMAC-SHA1,
//!   salt `saltysalt`, 1 iteration, 16-byte AES-128-CBC key, IV = 16 spaces.
//! - **Linux v10**: keyring-less "basic text" backend, password `peanuts`, otherwise as v11.
//! - **macOS v10**: key from the login Keychain item `Grok Bot Safe Storage`, 1003 iterations.
//! - **Windows v10** (compiled in only on Windows): AES-256-GCM with a DPAPI-wrapped key
//!   from `Local State`.
use crate::error::Error;
use crate::policy::Policy;
use crate::types::{Session, normalize_headers};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const PEANUTS: &str = "peanuts";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Macos,
    Windows,
}

impl Platform {
    pub fn current() -> Option<Platform> {
        match std::env::consts::OS {
            "linux" => Some(Platform::Linux),
            "macos" => Some(Platform::Macos),
            "windows" => Some(Platform::Windows),
            _ => None,
        }
    }
}

fn desktop_err(code: &str, msg: impl Into<String>) -> Error {
    Error::Desktop {
        code: code.into(),
        message: msg.into(),
    }
}

/// The app data directory ("Grok Bot") for a platform.
pub fn app_data_dir(
    home: &Path,
    platform: Platform,
    env: &dyn Fn(&str) -> Option<String>,
) -> PathBuf {
    match platform {
        Platform::Windows => {
            let appdata = env("APPDATA")
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join("AppData/Roaming"));
            appdata.join("Grok Bot")
        }
        Platform::Linux => {
            let config = env("XDG_CONFIG_HOME")
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"));
            config.join("Grok Bot")
        }
        Platform::Macos => home.join("Library/Application Support/Grok Bot"),
    }
}

/// Path to `gateway-descriptor.json`.
pub fn descriptor_path(
    home: &Path,
    platform: Platform,
    env: &dyn Fn(&str) -> Option<String>,
) -> PathBuf {
    app_data_dir(home, platform, env).join("gateway-descriptor.json")
}

/// One saved entry's ciphertext (base64). `key` is `"default"` for the v1 single-entry format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopEntry {
    pub key: String,
    pub encrypted: String,
}

/// Parse a descriptor's JSON into the list of encrypted entries (v1 → one, v2 → many).
pub fn parse_entries(descriptor_json: &str) -> Result<Vec<DesktopEntry>, Error> {
    let w: Value = serde_json::from_str(descriptor_json).map_err(|e| {
        desktop_err(
            "INVALID_DESCRIPTOR",
            format!("gateway-descriptor.json is not valid JSON: {e}"),
        )
    })?;
    if let Some(v) = w.get("version").and_then(Value::as_i64)
        && v != 1
        && v != 2
    {
        return Err(desktop_err(
            "UNSUPPORTED_VERSION",
            format!("Unsupported Grok Bot gateway descriptor version {v}."),
        ));
    }
    let enc = |v: &Value| v.as_str().filter(|s| !s.is_empty()).map(str::to_string);
    if w.get("version").and_then(Value::as_i64) == Some(2) {
        let obj = w.get("entries").and_then(Value::as_object);
        let mut out = vec![];
        if let Some(obj) = obj {
            for (k, v) in obj {
                if let Some(e) = enc(v.get("encrypted").unwrap_or(&Value::Null)) {
                    out.push(DesktopEntry {
                        key: k.clone(),
                        encrypted: e,
                    });
                }
            }
        }
        if out.is_empty() {
            return Err(desktop_err(
                "EMPTY_ENTRIES",
                "Grok Bot gateway descriptor has no saved gateway entries. Sign in from the desktop app first.",
            ));
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    } else {
        match enc(w.get("encrypted").unwrap_or(&Value::Null)) {
            Some(e) => Ok(vec![DesktopEntry {
                key: "default".into(),
                encrypted: e,
            }]),
            None => Err(desktop_err(
                "MISSING_ENCRYPTED_PAYLOAD",
                "Grok Bot gateway descriptor is missing an encrypted payload.",
            )),
        }
    }
}

fn b64(s: &str) -> Result<Vec<u8>, Error> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| {
            desktop_err(
                "INVALID_PAYLOAD",
                format!("payload is not valid base64: {e}"),
            )
        })
}

fn prefix3(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(3)]).into_owned()
}

fn safe_storage_key(password: &str, platform: Platform) -> [u8; 16] {
    use hmac::Hmac;
    use sha1::Sha1;
    let iterations: u32 = if platform == Platform::Linux { 1 } else { 1003 };
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2::<Hmac<Sha1>>(password.as_bytes(), b"saltysalt", iterations, &mut key)
        .expect("HMAC accepts any key length");
    key
}

/// Does this ciphertext need the OS keychain password? (Linux v10 "basic text" does not.)
pub fn needs_keychain(encrypted_b64: &str, platform: Platform) -> Result<bool, Error> {
    let bytes = b64(encrypted_b64)?;
    let p = prefix3(&bytes);
    Ok(!(platform == Platform::Linux && p == "v10"))
}

/// Decrypt a Safe Storage string (Linux/macOS). `password` is the keychain password; it is
/// ignored for the Linux v10 basic-text backend (which uses `peanuts`).
pub fn decrypt_safe_storage(
    encrypted_b64: &str,
    password: Option<&str>,
    platform: Platform,
) -> Result<String, Error> {
    use aes::Aes128;
    use cbc::Decryptor;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

    let encrypted = b64(encrypted_b64)?;
    let prefix = prefix3(&encrypted);
    let linux_basic = platform == Platform::Linux && prefix == "v10";
    let supported = prefix == "v10" || (platform == Platform::Linux && prefix == "v11");
    if !supported {
        return Err(desktop_err(
            "UNSUPPORTED_FORMAT",
            format!("Unsupported Grok Bot Safe Storage format (prefix {prefix:?})."),
        ));
    }
    let pw = if linux_basic {
        PEANUTS.to_string()
    } else {
        password
            .ok_or_else(|| {
                desktop_err("NO_KEYCHAIN_PASSWORD", "No OS keychain password available.")
            })?
            .to_string()
    };
    let key = safe_storage_key(&pw, platform);
    let iv = [0x20u8; 16];
    let mut buf = encrypted[3..].to_vec();
    let out = Decryptor::<Aes128>::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| {
            desktop_err(
                "DECRYPT_FAILED",
                "Could not decrypt the desktop session (wrong keychain password or corrupt data).",
            )
        })?;
    String::from_utf8(out.to_vec()).map_err(|_| {
        desktop_err(
            "DECRYPT_FAILED",
            "Decrypted desktop session was not valid UTF-8.",
        )
    })
}

/// Decrypt a Windows Safe Storage string: `v10` + 12-byte nonce + AES-256-GCM + 16-byte tag.
/// `key` is the DPAPI-unwrapped Local State key.
#[cfg(any(target_os = "windows", test))]
pub fn decrypt_windows(encrypted_b64: &str, key: &[u8]) -> Result<String, Error> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    let encrypted = b64(encrypted_b64)?;
    if prefix3(&encrypted) != "v10" || encrypted.len() < 15 + 16 {
        return Err(desktop_err(
            "UNSUPPORTED_FORMAT",
            "Unsupported Grok Bot Safe Storage format.",
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| desktop_err("DECRYPT_FAILED", "Bad Safe Storage key length."))?;
    let nonce = Nonce::from_slice(&encrypted[3..15]);
    let out = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &encrypted[15..],
                aad: b"",
            },
        )
        .map_err(|_| desktop_err("DECRYPT_FAILED", "Could not decrypt the desktop session."))?;
    String::from_utf8(out).map_err(|_| {
        desktop_err(
            "DECRYPT_FAILED",
            "Decrypted desktop session was not valid UTF-8.",
        )
    })
}

/// Turn a decrypted inner descriptor (`{baseUrl, token, headers?}`) into a validated [`Session`].
pub fn session_from_clear(clear: &str, policy: &Policy) -> Result<Session, Error> {
    let d: Value = serde_json::from_str(clear).map_err(|_| {
        desktop_err(
            "INCOMPLETE_DESCRIPTOR",
            "Decrypted desktop session is not valid JSON.",
        )
    })?;
    let base = d
        .get("baseUrl")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let token = d
        .get("token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let (Some(base), Some(token)) = (base, token) else {
        return Err(desktop_err(
            "INCOMPLETE_DESCRIPTOR",
            "Decrypted Grok Bot gateway descriptor is incomplete (no baseUrl/token).",
        ));
    };
    let gateway_url = policy.check_gateway(base).map_err(Error::Policy)?;
    let mut headers = BTreeMap::new();
    if let Some(Value::Object(m)) = d.get("headers") {
        headers = normalize_headers(
            m.iter()
                .filter(|(_, v)| v.is_string())
                .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())),
        );
    }
    Ok(Session {
        gateway_url,
        gateway_token: token.to_string(),
        headers,
    })
}

/// Environment-variable lookup (injectable for tests).
pub type EnvLookup = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// How to locate and unlock the desktop session. Fields are overridable for tests.
pub struct DesktopConfig {
    pub platform: Platform,
    pub home: PathBuf,
    /// Env lookup (defaults to `std::env::var`).
    pub env: EnvLookup,
    /// Supply the OS keychain password instead of running `secret-tool` / `security`.
    pub os_password: Option<String>,
}

impl DesktopConfig {
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            home: dirs_home(),
            env: Box::new(|k| std::env::var(k).ok()),
            os_password: None,
        }
    }

    pub fn descriptor_path(&self) -> PathBuf {
        descriptor_path(&self.home, self.platform, &self.env)
    }

    pub fn present(&self) -> bool {
        self.descriptor_path().exists()
    }

    /// The saved entries, or a clear error if the app/session is missing.
    pub fn entries(&self) -> Result<Vec<DesktopEntry>, Error> {
        let path = self.descriptor_path();
        if !path.exists() {
            let dir = app_data_dir(&self.home, self.platform, &self.env);
            return Err(if dir.exists() {
                desktop_err(
                    "NOT_SIGNED_IN",
                    format!(
                        "The Grok Bot desktop app is installed but has no saved gateway session ({}). Sign in from the desktop app first.",
                        path.display()
                    ),
                )
            } else {
                desktop_err(
                    "APP_NOT_FOUND",
                    format!(
                        "The Grok Bot desktop app data was not found at {}.",
                        dir.display()
                    ),
                )
            });
        }
        let json = std::fs::read_to_string(&path).map_err(|e| {
            desktop_err(
                "READ_FAILED",
                format!("Could not read {}: {e}", path.display()),
            )
        })?;
        parse_entries(&json)
    }

    /// Resolve one entry (by key, or the only one) to a validated [`Session`].
    pub fn load_entry(&self, key: Option<&str>, policy: &Policy) -> Result<Session, Error> {
        let entries = self.entries()?;
        let entry = match key {
            Some(k) => entries.iter().find(|e| e.key == k).ok_or_else(|| {
                desktop_err(
                    "NO_SUCH_ENTRY",
                    format!("No desktop session entry named '{k}'."),
                )
            })?,
            None if entries.len() == 1 => &entries[0],
            None => {
                let names = entries
                    .iter()
                    .map(|e| e.key.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(desktop_err(
                    "AMBIGUOUS_ENTRIES",
                    format!(
                        "The desktop app has several saved sessions: {names}. Choose one with /login desktop <name>."
                    ),
                ));
            }
        };
        let clear = self.decrypt(&entry.encrypted)?;
        session_from_clear(&clear, policy)
    }

    fn decrypt(&self, encrypted: &str) -> Result<String, Error> {
        match self.platform {
            Platform::Windows => self.decrypt_windows_entry(encrypted),
            _ => {
                let password = if needs_keychain(encrypted, self.platform)? {
                    Some(match &self.os_password {
                        Some(p) => p.clone(),
                        None => self.read_os_password()?,
                    })
                } else {
                    None
                };
                decrypt_safe_storage(encrypted, password.as_deref(), self.platform)
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn decrypt_windows_entry(&self, _: &str) -> Result<String, Error> {
        Err(desktop_err(
            "UNSUPPORTED_PLATFORM",
            "Windows desktop sessions can only be read on Windows.",
        ))
    }

    #[cfg(target_os = "windows")]
    fn decrypt_windows_entry(&self, encrypted: &str) -> Result<String, Error> {
        let key =
            windows_impl::local_state_key(&app_data_dir(&self.home, self.platform, &self.env))?;
        decrypt_windows(encrypted, &key)
    }

    #[cfg(not(target_os = "windows"))]
    fn read_os_password(&self) -> Result<String, Error> {
        use std::process::Command;
        let out = match self.platform {
            Platform::Linux => Command::new("secret-tool")
                .args([
                    "lookup",
                    "xdg:schema",
                    "chrome_libsecret_os_crypt_password_v2",
                    "application",
                    "Grok Bot",
                ])
                .output()
                .map_err(|e| {
                    desktop_err(
                        "SECRET_TOOL_MISSING",
                        format!("Could not run secret-tool (install libsecret-tools): {e}"),
                    )
                })?,
            Platform::Macos => Command::new("/usr/bin/security")
                .args(["find-generic-password", "-w", "-s", "Grok Bot Safe Storage"])
                .output()
                .map_err(|e| {
                    desktop_err(
                        "KEYCHAIN_FAILED",
                        format!("Could not run /usr/bin/security: {e}"),
                    )
                })?,
            Platform::Windows => unreachable!(),
        };
        if !out.status.success() {
            return Err(desktop_err(
                "KEYCHAIN_LOCKED",
                "The OS keychain did not return the Grok Bot Safe Storage password (is the keyring unlocked and the app signed in?).",
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
    }

    #[cfg(target_os = "windows")]
    fn read_os_password(&self) -> Result<String, Error> {
        unreachable!("windows uses DPAPI, not a keychain password")
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::{Error, desktop_err};
    use serde_json::Value;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    pub fn local_state_key(app_dir: &Path) -> Result<Vec<u8>, Error> {
        use base64::Engine;
        let path = app_dir.join("Local State");
        let json = std::fs::read_to_string(&path).map_err(|e| {
            desktop_err(
                "MISSING_SAFE_STORAGE_KEY",
                format!("Could not read {}: {e}", path.display()),
            )
        })?;
        let v: Value = serde_json::from_str(&json).map_err(|_| {
            desktop_err("MISSING_SAFE_STORAGE_KEY", "Local State is not valid JSON.")
        })?;
        let b64key = v
            .get("os_crypt")
            .and_then(|o| o.get("encrypted_key"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let blob = base64::engine::general_purpose::STANDARD
            .decode(b64key)
            .map_err(|_| {
                desktop_err(
                    "MISSING_SAFE_STORAGE_KEY",
                    "Local State encrypted_key is not base64.",
                )
            })?;
        if blob.len() < 5 || &blob[..5] != b"DPAPI" {
            return Err(desktop_err(
                "MISSING_SAFE_STORAGE_KEY",
                "Grok Bot Local State has no Safe Storage key.",
            ));
        }
        unprotect_dpapi(&blob[5..])
    }

    fn unprotect_dpapi(blob: &[u8]) -> Result<Vec<u8>, Error> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
        let script = "Add-Type -AssemblyName System.Security; $blob = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'CurrentUser'))";
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let exe = Path::new(&root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let mut child = Command::new(exe)
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| {
                desktop_err(
                    "DPAPI_FAILED",
                    format!("Could not run PowerShell for DPAPI: {e}"),
                )
            })?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b64.as_bytes())
            .map_err(|e| desktop_err("DPAPI_FAILED", e.to_string()))?;
        let out = child
            .wait_with_output()
            .map_err(|e| desktop_err("DPAPI_FAILED", e.to_string()))?;
        if !out.status.success() {
            return Err(desktop_err("DPAPI_FAILED", "DPAPI unprotect failed."));
        }
        base64::engine::general_purpose::STANDARD
            .decode(String::from_utf8_lossy(&out.stdout).trim())
            .map_err(|_| desktop_err("DPAPI_FAILED", "DPAPI output was not base64."))
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- fixture builders (encrypt the way the desktop app would) ---

    fn encrypt_cbc(clear: &str, password: &str, platform: Platform, prefix: &str) -> String {
        use aes::Aes128;
        use base64::Engine;
        use cbc::Encryptor;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
        let key = safe_storage_key(password, platform);
        let iv = [0x20u8; 16];
        let ct = Encryptor::<Aes128>::new(&key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(clear.as_bytes());
        let mut out = prefix.as_bytes().to_vec();
        out.extend_from_slice(&ct);
        base64::engine::general_purpose::STANDARD.encode(out)
    }

    fn inner(base: &str) -> String {
        format!(
            r#"{{"baseUrl":"{base}","token":"gw-secret","headers":{{"x-anyrun-network-token":"net"}}}}"#
        )
    }

    #[test]
    fn linux_v11_roundtrip_with_keychain_password() {
        let enc = encrypt_cbc(
            &inner("https://box.cursorvm.com"),
            "os-pw",
            Platform::Linux,
            "v11",
        );
        assert!(needs_keychain(&enc, Platform::Linux).unwrap());
        let clear = decrypt_safe_storage(&enc, Some("os-pw"), Platform::Linux).unwrap();
        let s = session_from_clear(&clear, &Policy::default()).unwrap();
        assert_eq!(s.gateway_url, "https://box.cursorvm.com");
        assert_eq!(s.gateway_token, "gw-secret");
        assert_eq!(
            s.headers.get("x-anyrun-network-token").map(String::as_str),
            Some("net")
        );
        // Wrong password fails, never panics.
        assert!(decrypt_safe_storage(&enc, Some("nope"), Platform::Linux).is_err());
    }

    #[test]
    fn linux_v10_basic_text_needs_no_keychain() {
        let enc = encrypt_cbc(
            &inner("https://box.cursorvm.com"),
            PEANUTS,
            Platform::Linux,
            "v10",
        );
        assert!(!needs_keychain(&enc, Platform::Linux).unwrap());
        let clear = decrypt_safe_storage(&enc, None, Platform::Linux).unwrap();
        assert_eq!(
            session_from_clear(&clear, &Policy::default())
                .unwrap()
                .gateway_token,
            "gw-secret"
        );
    }

    #[test]
    fn macos_v10_uses_1003_iterations() {
        let enc = encrypt_cbc(
            &inner("https://box.cursor.sh"),
            "mac-pw",
            Platform::Macos,
            "v10",
        );
        let clear = decrypt_safe_storage(&enc, Some("mac-pw"), Platform::Macos).unwrap();
        assert_eq!(
            session_from_clear(&clear, &Policy::default())
                .unwrap()
                .gateway_url,
            "https://box.cursor.sh"
        );
        // macOS key derivation differs from Linux (1003 vs 1 iteration).
        assert_ne!(
            safe_storage_key("x", Platform::Macos),
            safe_storage_key("x", Platform::Linux)
        );
    }

    #[test]
    fn windows_v10_gcm_roundtrip() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};
        use base64::Engine;
        let key = [7u8; 32];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = [1u8; 12];
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: inner("https://box.cursorvm.com").as_bytes(),
                    aad: b"",
                },
            )
            .unwrap();
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        let enc = base64::engine::general_purpose::STANDARD.encode(blob);
        let clear = decrypt_windows(&enc, &key).unwrap();
        assert_eq!(
            session_from_clear(&clear, &Policy::default())
                .unwrap()
                .gateway_token,
            "gw-secret"
        );
        assert!(decrypt_windows(&enc, &[0u8; 32]).is_err());
    }

    #[test]
    fn parse_v1_and_v2_entries() {
        let v1 = parse_entries(r#"{"version":1,"encrypted":"QUJD"}"#).unwrap();
        assert_eq!(
            v1,
            vec![DesktopEntry {
                key: "default".into(),
                encrypted: "QUJD".into()
            }]
        );
        let no_ver = parse_entries(r#"{"encrypted":"QUJD"}"#).unwrap();
        assert_eq!(no_ver.len(), 1);
        let v2 = parse_entries(
            r#"{"version":2,"entries":{"work":{"encrypted":"V1JL"},"home":{"encrypted":"SE9N"}}}"#,
        )
        .unwrap();
        assert_eq!(
            v2.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(),
            vec!["home", "work"]
        );
        assert!(matches!(
            parse_entries(r#"{"version":3}"#),
            Err(Error::Desktop { .. })
        ));
        assert!(matches!(
            parse_entries(r#"{"version":2,"entries":{}}"#),
            Err(Error::Desktop { .. })
        ));
        assert!(matches!(
            parse_entries(r#"{"version":1}"#),
            Err(Error::Desktop { .. })
        ));
    }

    #[test]
    fn session_rejects_disallowed_host_and_incomplete() {
        let clear = r#"{"baseUrl":"https://evil.example","token":"t"}"#;
        assert!(matches!(
            session_from_clear(clear, &Policy::default()),
            Err(Error::Policy(_))
        ));
        assert!(matches!(
            session_from_clear(
                r#"{"baseUrl":"https://x.cursorvm.com"}"#,
                &Policy::default()
            ),
            Err(Error::Desktop { .. })
        ));
    }

    #[test]
    fn config_entries_errors_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let cfg = DesktopConfig {
            platform: Platform::Linux,
            home: home.clone(),
            env: Box::new(move |_| None),
            os_password: None,
        };
        assert!(!cfg.present());
        assert!(matches!(cfg.entries(), Err(Error::Desktop { .. })));
    }

    #[test]
    fn config_load_entry_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join(".config/Grok Bot");
        std::fs::create_dir_all(&app).unwrap();
        let enc = encrypt_cbc(
            &inner("https://box.cursorvm.com"),
            "os-pw",
            Platform::Linux,
            "v11",
        );
        std::fs::write(
            app.join("gateway-descriptor.json"),
            format!(r#"{{"version":2,"entries":{{"only":{{"encrypted":"{enc}"}}}}}}"#),
        )
        .unwrap();
        let home = dir.path().to_path_buf();
        let cfg = DesktopConfig {
            platform: Platform::Linux,
            home,
            env: Box::new(|_| None),
            os_password: Some("os-pw".into()),
        };
        assert!(cfg.present());
        let s = cfg.load_entry(None, &Policy::default()).unwrap();
        assert_eq!(s.gateway_token, "gw-secret");
    }

    #[test]
    fn ambiguous_entries_need_a_choice() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join(".config/Grok Bot");
        std::fs::create_dir_all(&app).unwrap();
        let a = encrypt_cbc(
            &inner("https://a.cursorvm.com"),
            "p",
            Platform::Linux,
            "v11",
        );
        let b = encrypt_cbc(
            &inner("https://b.cursorvm.com"),
            "p",
            Platform::Linux,
            "v11",
        );
        std::fs::write(app.join("gateway-descriptor.json"), format!(r#"{{"version":2,"entries":{{"work":{{"encrypted":"{a}"}},"home":{{"encrypted":"{b}"}}}}}}"#)).unwrap();
        let cfg = DesktopConfig {
            platform: Platform::Linux,
            home: dir.path().to_path_buf(),
            env: Box::new(|_| None),
            os_password: Some("p".into()),
        };
        assert!(matches!(
            cfg.load_entry(None, &Policy::default()),
            Err(Error::Desktop { .. })
        ));
        assert_eq!(
            cfg.load_entry(Some("home"), &Policy::default())
                .unwrap()
                .gateway_url,
            "https://b.cursorvm.com"
        );
        assert!(matches!(
            cfg.load_entry(Some("nope"), &Policy::default()),
            Err(Error::Desktop { .. })
        ));
    }
}
