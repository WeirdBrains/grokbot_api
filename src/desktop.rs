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

/// Path to `sand-secrets.json` (the fallback source of a Cursor access token).
pub fn sand_secrets_path(
    home: &Path,
    platform: Platform,
    env: &dyn Fn(&str) -> Option<String>,
) -> PathBuf {
    app_data_dir(home, platform, env).join("sand-secrets.json")
}

/// One saved entry's ciphertext (base64). `key` is `"default"` for the v1 single-entry format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopEntry {
    pub key: String,
    pub encrypted: String,
}

/// What `/login desktop` resolved to.
pub enum DesktopCredential {
    /// A ready gateway session, decrypted from `gateway-descriptor.json`.
    Session(Session),
    /// A Cursor access token from `sand-secrets.json`, to exchange via EnsureSandBox.
    CursorToken(String),
}

/// A Cursor account found in `sand-secrets.json`, labeled for selection.
type SandAccountsRaw = (String, Vec<(String, serde_json::Map<String, Value>)>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandAccount {
    /// The opaque account id used as the stored entry key.
    pub key: String,
    /// A human label (the account email when available, else the key).
    pub label: String,
    /// Whether this is the app's active account.
    pub active: bool,
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

    /// Path to `sand-secrets.json` in the app data dir.
    pub fn sand_secrets_path(&self) -> PathBuf {
        sand_secrets_path(&self.home, self.platform, &self.env)
    }

    /// Whether the `sand-secrets.json` fallback exists.
    pub fn sand_present(&self) -> bool {
        self.sand_secrets_path().exists()
    }

    /// The decrypted `(active_key, [(account_key, fields)])` from `sand-secrets.json`.
    /// The field values stay encrypted here; only the outer structure is parsed.
    fn read_sand_accounts(&self) -> Result<SandAccountsRaw, Error> {
        let path = self.sand_secrets_path();
        let json = std::fs::read_to_string(&path).map_err(|e| {
            desktop_err(
                "READ_FAILED",
                format!("Could not read {}: {e}", path.display()),
            )
        })?;
        let top: Value = serde_json::from_str(&json).map_err(|e| {
            desktop_err(
                "INVALID_SAND",
                format!("sand-secrets.json is not valid JSON: {e}"),
            )
        })?;
        let ca_str = top
            .get("cursor-accounts")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                desktop_err(
                    "NOT_SIGNED_IN",
                    "sand-secrets.json has no cursor-accounts; sign in from the desktop app first.",
                )
            })?;
        let ca: Value = serde_json::from_str(ca_str).map_err(|e| {
            desktop_err(
                "INVALID_SAND",
                format!("sand-secrets.json cursor-accounts is not valid JSON: {e}"),
            )
        })?;
        let active = ca
            .get("active")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let accounts = ca
            .get("accounts")
            .and_then(Value::as_object)
            .filter(|m| !m.is_empty())
            .ok_or_else(|| desktop_err("NOT_SIGNED_IN", "The desktop app has no saved Cursor accounts; sign in from the desktop app first."))?;
        let mut out = vec![];
        for (k, v) in accounts {
            if let Value::Object(m) = v {
                out.push((k.clone(), m.clone()));
            }
        }
        Ok((active, out))
    }

    /// The Cursor accounts in `sand-secrets.json`, sorted by key. Built from plaintext
    /// metadata only (opaque account id, `active` marker): nothing is decrypted to list them,
    /// so no decrypted value (email, token) is ever shown.
    pub fn sand_accounts(&self) -> Result<Vec<SandAccount>, Error> {
        let (active, mut accts) = self.read_sand_accounts()?;
        accts.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(accts
            .into_iter()
            .enumerate()
            .map(|(i, (key, _))| SandAccount {
                label: format!("{}) {}…", i + 1, &key[..key.len().min(8)]),
                active: key == active,
                key,
            })
            .collect())
    }

    /// Resolve and decrypt the Cursor access token for one account in `sand-secrets.json`.
    /// `choice` is a 1-based number, a full account key, or a unique key prefix (4+ chars);
    /// `None` picks the only account. Only the chosen account's access token is decrypted.
    fn load_sand_token(&self, choice: Option<&str>) -> Result<String, Error> {
        let (_, mut accts) = self.read_sand_accounts()?;
        accts.sort_by(|a, b| a.0.cmp(&b.0));
        let listing = || {
            self.sand_accounts()
                .map(|sa| {
                    sa.into_iter()
                        .map(|s| {
                            if s.active {
                                format!("{} (active)", s.label)
                            } else {
                                s.label
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        };
        let idx = match choice {
            None if accts.len() == 1 => 0,
            None => {
                return Err(desktop_err(
                    "AMBIGUOUS_ENTRIES",
                    format!(
                        "The desktop app has several Cursor accounts: {}. Choose one with /login desktop <number> (tip: /account add <alias> first so each gets its own gb account).",
                        listing()
                    ),
                ));
            }
            Some(c) => {
                let c = c.trim();
                let by_num = c
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (1..=accts.len()).contains(n))
                    .map(|n| n - 1);
                let by_key = accts.iter().position(|(k, _)| k == c);
                let by_prefix = || {
                    let m: Vec<usize> = accts
                        .iter()
                        .enumerate()
                        .filter(|(_, (k, _))| c.len() >= 4 && k.starts_with(c))
                        .map(|(i, _)| i)
                        .collect();
                    (m.len() == 1).then(|| m[0])
                };
                by_key.or(by_num).or_else(by_prefix).ok_or_else(|| {
                    desktop_err(
                        "NO_SUCH_ENTRY",
                        format!("No desktop Cursor account '{c}'. Available: {}", listing()),
                    )
                })?
            }
        };
        let enc = accts[idx]
            .1
            .get("cursor-access-token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                desktop_err(
                    "INCOMPLETE_DESCRIPTOR",
                    "sand-secrets.json account has no cursor-access-token.",
                )
            })?;
        self.decrypt(enc)
    }

    /// The stable stored key for a sand choice (so a 401 re-read picks the same account).
    pub fn sand_key_for(&self, choice: Option<&str>) -> Result<Option<String>, Error> {
        let accts = self.sand_accounts()?;
        Ok(match choice {
            None if accts.len() == 1 => Some(accts[0].key.clone()),
            None => None,
            Some(c) => {
                let c = c.trim();
                accts
                    .iter()
                    .position(|a| a.key == c)
                    .or_else(|| {
                        c.parse::<usize>()
                            .ok()
                            .filter(|n| (1..=accts.len()).contains(n))
                            .map(|n| n - 1)
                    })
                    .or_else(|| {
                        let m: Vec<usize> = accts
                            .iter()
                            .enumerate()
                            .filter(|(_, a)| c.len() >= 4 && a.key.starts_with(c))
                            .map(|(i, _)| i)
                            .collect();
                        (m.len() == 1).then(|| m[0])
                    })
                    .map(|i| accts[i].key.clone())
            }
        })
    }

    /// Resolve a desktop credential: `gateway-descriptor.json` first, then the
    /// `sand-secrets.json` Cursor-token fallback. Only called from `/login desktop`.
    pub fn load_credential(
        &self,
        key: Option<&str>,
        policy: &Policy,
    ) -> Result<DesktopCredential, Error> {
        if self.descriptor_path().exists() {
            return self.load_entry(key, policy).map(DesktopCredential::Session);
        }
        if self.sand_present() {
            return self
                .load_sand_token(key)
                .map(DesktopCredential::CursorToken);
        }
        let dir = app_data_dir(&self.home, self.platform, &self.env);
        Err(if dir.exists() {
            desktop_err(
                "NOT_SIGNED_IN",
                format!(
                    "The Grok Bot desktop app is installed but has no saved session (no gateway-descriptor.json or sand-secrets.json in {}). Sign in from the desktop app first.",
                    dir.display()
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
        })
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

/// Semver-ish app version string (e.g. `"0.70.2"`), as used for `x-cursor-client-version`.
pub type AppVersion = String;

/// Locate the Grok Bot desktop install directory for this platform, if present.
pub fn find_install_dir(
    platform: Platform,
    env: &dyn Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    // Highest priority: explicit override (also used by tests).
    for key in ["GB_GROKBOT_APP_DIR", "GROKBOT_INSTALL_DIR"] {
        if let Some(p) = env(key).filter(|s| !s.is_empty()) {
            let pb = PathBuf::from(p);
            if pb.is_dir() {
                return Some(pb);
            }
        }
    }
    let candidates: Vec<PathBuf> = match platform {
        Platform::Linux => {
            let mut v = Vec::new();
            // Prefer the user's desktop file / symlink before hard-coded system paths.
            if let Some(home) = env("HOME") {
                let desk = PathBuf::from(&home).join(".local/share/applications/grok-bot.desktop");
                if let Some(exec) = read_desktop_exec(&desk)
                    && let Some(parent) = PathBuf::from(&exec).parent()
                {
                    v.push(parent.to_path_buf());
                }
                v.push(PathBuf::from(&home).join(".local/share/grok-bot"));
                v.push(PathBuf::from(&home).join(".local/opt/grokbot-linux-port-bin"));
            }
            if let Ok(p) = std::fs::canonicalize("/bin/grok-bot")
                && let Some(parent) = p.parent()
            {
                v.push(parent.to_path_buf());
            }
            for desk in [PathBuf::from("/usr/share/applications/grok-bot.desktop")] {
                if let Some(exec) = read_desktop_exec(&desk)
                    && let Some(parent) = PathBuf::from(&exec).parent()
                {
                    v.push(parent.to_path_buf());
                }
            }
            v.extend([
                PathBuf::from("/opt/grokbot-linux-port-bin"),
                PathBuf::from("/opt/Grok Bot"),
                PathBuf::from("/usr/lib/grok-bot"),
            ]);
            v
        }
        Platform::Macos => {
            let mut v = vec![PathBuf::from("/Applications/Grok Bot.app")];
            if let Some(home) = env("HOME") {
                v.push(PathBuf::from(home).join("Applications/Grok Bot.app"));
            }
            v
        }
        Platform::Windows => {
            let mut v = vec![];
            for key in ["LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"] {
                if let Some(base) = env(key) {
                    v.push(PathBuf::from(base).join("Grok Bot"));
                }
            }
            v
        }
    };
    candidates.into_iter().find(|p| p.is_dir())
}

fn read_desktop_exec(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Exec=") {
            let bin = rest.split_whitespace().next()?.to_string();
            return Some(bin);
        }
    }
    None
}

fn resources_dir(install: &Path, platform: Platform) -> PathBuf {
    match platform {
        Platform::Macos => install.join("Contents/Resources"),
        _ => install.join("resources"),
    }
}

fn version_from_package_json(bytes: &[u8]) -> Option<AppVersion> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    let ver = v.get("version")?.as_str()?.trim();
    normalize_semver(ver)
}

/// Strip a leading `v` and keep `MAJOR.MINOR.PATCH` (desktop app does the same).
pub fn normalize_semver(s: &str) -> Option<AppVersion> {
    let s = s.trim().trim_start_matches('v');
    let re_ok = s.split_once('-').map(|(a, _)| a).unwrap_or(s);
    let mut parts = re_ok.split('.');
    let (Some(a), Some(b), Some(c)) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    if a.chars().all(|c| c.is_ascii_digit())
        && b.chars().all(|c| c.is_ascii_digit())
        && c.chars().all(|c| c.is_ascii_digit())
    {
        Some(format!("{a}.{b}.{c}"))
    } else {
        None
    }
}

/// Read `package.json` (or `product.json`) `version` out of an Electron `.asar`.
pub fn version_from_asar(asar: &Path) -> Option<AppVersion> {
    let data = std::fs::read(asar).ok()?;
    if data.len() < 16 {
        return None;
    }
    // sizePickle: uint32 payload_size(=4) + uint32 header_len
    let header_len = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
    if data.len() < 8 + header_len {
        return None;
    }
    let header = &data[8..8 + header_len];
    if header.len() < 8 {
        return None;
    }
    let str_len = u32::from_le_bytes(header[4..8].try_into().ok()?) as usize;
    if header.len() < 8 + str_len {
        return None;
    }
    let meta: Value = serde_json::from_slice(&header[8..8 + str_len]).ok()?;
    let files = meta.get("files")?.as_object()?;
    for name in ["package.json", "product.json"] {
        let node = match files.get(name) {
            Some(n) => n,
            None => continue,
        };
        let off = node.get("offset")?.as_str()?.parse::<usize>().ok()?;
        let size = node.get("size")?.as_u64()? as usize;
        let data_start = 8 + header_len;
        let start = data_start.checked_add(off)?;
        let end = start.checked_add(size)?;
        if end > data.len() {
            continue;
        }
        if let Some(v) = version_from_package_json(&data[start..end]) {
            return Some(v);
        }
    }
    None
}

fn version_from_status_json(path: &Path) -> Option<AppVersion> {
    let v: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    normalize_semver(v.get("appVersion")?.as_str()?)
}

/// Detect the installed Grok Bot desktop app version (e.g. `"0.70.2"`).
///
/// Looks in the install dir's `resources/app/package.json`, `product.json`,
/// `resources/app.asar`, then (as a last resort) `desktop-status.json` in the
/// app data dir. Returns `None` when nothing is installed or readable.
pub fn detect_app_version(
    platform: Platform,
    home: &Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> Option<AppVersion> {
    if let Some(install) = find_install_dir(platform, env) {
        let res = resources_dir(&install, platform);
        for rel in [
            "app/package.json",
            "app/product.json",
            "package.json",
            "product.json",
        ] {
            let p = res.join(rel);
            if let Ok(bytes) = std::fs::read(&p)
                && let Some(v) = version_from_package_json(&bytes)
            {
                return Some(v);
            }
        }
        let asar = res.join("app.asar");
        if let Some(v) = version_from_asar(&asar) {
            return Some(v);
        }
        // Debian/FPM packages ship a changelog with the version.
        let changelog = install.join("changelog.gz");
        if changelog.exists() {
            // Avoid pulling in a gzip crate: the filename alone isn't enough; skip.
        }
    }
    // Last resort: the running app writes appVersion into its config dir.
    let status = app_data_dir(home, platform, env).join("desktop-status.json");
    version_from_status_json(&status)
}

impl DesktopConfig {
    /// Detect the installed desktop app version using this config's platform/home/env.
    pub fn detect_app_version(&self) -> Option<AppVersion> {
        detect_app_version(self.platform, &self.home, &self.env)
    }
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

    fn write_sand(app: &std::path::Path, accounts: &[(&str, &str)], active: &str) {
        use serde_json::{Map, Value, json};
        let mut m = Map::new();
        for (key, tok) in accounts {
            let enc_tok = encrypt_cbc(tok, "os-pw", Platform::Linux, "v11");
            let enc_prof = encrypt_cbc(
                r#"{"email":"u@example.com","name":"U"}"#,
                "os-pw",
                Platform::Linux,
                "v11",
            );
            m.insert(
                key.to_string(),
                json!({
                    "cursor-access-token": enc_tok,
                    "cursor-account-profile": enc_prof,
                    "cursor-refresh-token": enc_tok,
                    "cursor-selected-team-id": encrypt_cbc("t", "os-pw", Platform::Linux, "v11"),
                }),
            );
        }
        let ca = Value::Object({
            let mut o = Map::new();
            o.insert("active".into(), Value::String(active.into()));
            o.insert("accounts".into(), Value::Object(m));
            o
        });
        let top = json!({
            "version": 1,
            "cursor-machine-id": "x",
            "cursor-accounts": ca.to_string(),
            "local-exec-file-key": "y",
        });
        std::fs::write(app.join("sand-secrets.json"), top.to_string()).unwrap();
    }

    #[test]
    fn sand_secrets_single_account_yields_cursor_token() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join(".config/Grok Bot");
        std::fs::create_dir_all(&app).unwrap();
        write_sand(
            &app,
            &[(
                "acctaaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666",
                "cursor-tok-A",
            )],
            "acctaaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666",
        );
        let cfg = DesktopConfig {
            platform: Platform::Linux,
            home: dir.path().to_path_buf(),
            env: Box::new(|_| None),
            os_password: Some("os-pw".into()),
        };
        assert!(!cfg.present());
        assert!(cfg.sand_present());
        match cfg.load_credential(None, &Policy::default()).unwrap() {
            DesktopCredential::CursorToken(t) => assert_eq!(t, "cursor-tok-A"),
            DesktopCredential::Session(_) => panic!("expected CursorToken"),
        }
        let key = cfg.sand_key_for(None).unwrap().unwrap();
        assert!(key.starts_with("acctaaaa"));
    }

    #[test]
    fn sand_secrets_multi_needs_choice_by_number() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join(".config/Grok Bot");
        std::fs::create_dir_all(&app).unwrap();
        write_sand(
            &app,
            &[
                (
                    "aaaakey1111bbbb2222cccc3333dddd4444eeee5555ffff6666",
                    "tok-A",
                ),
                (
                    "zzzzkey1111bbbb2222cccc3333dddd4444eeee5555ffff6666",
                    "tok-Z",
                ),
            ],
            "zzzzkey1111bbbb2222cccc3333dddd4444eeee5555ffff6666",
        );
        let cfg = DesktopConfig {
            platform: Platform::Linux,
            home: dir.path().to_path_buf(),
            env: Box::new(|_| None),
            os_password: Some("os-pw".into()),
        };
        let list = cfg.sand_accounts().unwrap();
        assert_eq!(list.len(), 2);
        assert!(list[0].label.starts_with("1) "));
        assert!(list[1].active);
        assert!(matches!(
            cfg.load_credential(None, &Policy::default()),
            Err(Error::Desktop { code, .. }) if code == "AMBIGUOUS_ENTRIES"
        ));
        match cfg.load_credential(Some("2"), &Policy::default()).unwrap() {
            DesktopCredential::CursorToken(t) => assert_eq!(t, "tok-Z"),
            _ => panic!("expected CursorToken"),
        }
        assert_eq!(
            cfg.sand_key_for(Some("2")).unwrap().as_deref(),
            Some("zzzzkey1111bbbb2222cccc3333dddd4444eeee5555ffff6666")
        );
    }

    #[test]
    fn descriptor_wins_over_sand_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join(".config/Grok Bot");
        std::fs::create_dir_all(&app).unwrap();
        write_sand(
            &app,
            &[(
                "k1111111111111111111111111111111111111111111111111111",
                "tok",
            )],
            "k1111111111111111111111111111111111111111111111111111",
        );
        let enc = encrypt_cbc(
            &inner("https://box.cursorvm.com"),
            "os-pw",
            Platform::Linux,
            "v11",
        );
        std::fs::write(
            app.join("gateway-descriptor.json"),
            format!(r#"{{"version":1,"encrypted":"{enc}"}}"#),
        )
        .unwrap();
        let cfg = DesktopConfig {
            platform: Platform::Linux,
            home: dir.path().to_path_buf(),
            env: Box::new(|_| None),
            os_password: Some("os-pw".into()),
        };
        match cfg.load_credential(None, &Policy::default()).unwrap() {
            DesktopCredential::Session(s) => assert_eq!(s.gateway_token, "gw-secret"),
            DesktopCredential::CursorToken(_) => panic!("descriptor should win"),
        }
    }

    #[test]
    fn sand_secrets_absent_and_app_missing_are_clear() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = DesktopConfig {
            platform: Platform::Linux,
            home: dir.path().to_path_buf(),
            env: Box::new(|_| None),
            os_password: None,
        };
        assert!(matches!(
            cfg.load_credential(None, &Policy::default()),
            Err(Error::Desktop { code, .. }) if code == "APP_NOT_FOUND"
        ));
        std::fs::create_dir_all(dir.path().join(".config/Grok Bot")).unwrap();
        assert!(matches!(
            cfg.load_credential(None, &Policy::default()),
            Err(Error::Desktop { code, .. }) if code == "NOT_SIGNED_IN"
        ));
    }

    #[test]
    fn normalize_semver_strips_prerelease() {
        assert_eq!(normalize_semver("0.70.2").as_deref(), Some("0.70.2"));
        assert_eq!(normalize_semver("v0.70.2-dev").as_deref(), Some("0.70.2"));
        assert!(normalize_semver("nope").is_none());
    }

    #[test]
    fn detect_app_version_from_unpacked_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("opt/grokbot-linux-port-bin");
        let res = install.join("resources/app");
        std::fs::create_dir_all(&res).unwrap();
        std::fs::write(
            res.join("package.json"),
            r#"{"name":"sand","version":"0.70.2","productName":"Grok Bot"}"#,
        )
        .unwrap();
        // Point find_install_dir via a fake desktop Exec.
        let apps = dir.path().join("home/.local/share/applications");
        std::fs::create_dir_all(&apps).unwrap();
        std::fs::write(
            apps.join("grok-bot.desktop"),
            format!("[Desktop Entry]\nExec={}/grok-bot\n", install.display()),
        )
        .unwrap();
        let install_s = install.to_string_lossy().into_owned();
        let env = move |k: &str| match k {
            "GB_GROKBOT_APP_DIR" => Some(install_s.clone()),
            _ => None,
        };
        let v = detect_app_version(Platform::Linux, dir.path(), &env);
        assert_eq!(v.as_deref(), Some("0.70.2"));
    }

    #[test]
    fn detect_app_version_falls_back_to_desktop_status() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join(".config/Grok Bot");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(
            app.join("desktop-status.json"),
            r#"{"version":1,"pid":1,"appVersion":"0.70.2","startedAtMs":0,"signedIn":true}"#,
        )
        .unwrap();
        let v = detect_app_version(Platform::Linux, dir.path(), &|_| None);
        assert_eq!(v.as_deref(), Some("0.70.2"));
    }

    #[test]
    fn version_from_asar_roundtrip_fixture() {
        // Build a tiny asar with only package.json using the same layout Electron writes.
        let dir = tempfile::tempdir().unwrap();
        let pkg = br#"{"name":"sand","version":"1.2.3"}"#;
        let meta = format!(
            r#"{{"files":{{"package.json":{{"offset":"0","size":{}}}}}}}"#,
            pkg.len()
        );
        let meta_bytes = meta.as_bytes();
        // header pickle: uint32 payload_size, uint32 str_len, bytes, pad to 4
        let mut header = Vec::new();
        let str_len = meta_bytes.len() as u32;
        let pad = (4 - (str_len % 4)) % 4;
        let payload_size = 4 + str_len + pad; // uint32 str_len + string + pad
        header.extend_from_slice(&payload_size.to_le_bytes());
        header.extend_from_slice(&str_len.to_le_bytes());
        header.extend_from_slice(meta_bytes);
        header.extend(std::iter::repeat_n(0u8, pad as usize));
        // size pickle: uint32(=4) + uint32(header.len)
        let mut asar = Vec::new();
        asar.extend_from_slice(&4u32.to_le_bytes());
        asar.extend_from_slice(&(header.len() as u32).to_le_bytes());
        asar.extend_from_slice(&header);
        asar.extend_from_slice(pkg);
        let path = dir.path().join("app.asar");
        std::fs::write(&path, &asar).unwrap();
        assert_eq!(version_from_asar(&path).as_deref(), Some("1.2.3"));
    }
}
