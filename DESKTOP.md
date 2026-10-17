# Desktop app session (`desktop-session` feature)

[← README](README.md)

If the user is signed in to the Grok Bot desktop app, this module can reuse that login, so
they don't have to paste a token.

```toml
[dependencies]
grokbot_api = { version = "1", features = ["desktop-session"] }
```

> **Privacy:** this reads and decrypts the user's saved credentials. Only call it when the
> user explicitly asks, for example from a "sign in with the desktop app" command. Never log
> or display the decrypted values. `Debug` on `DesktopCredential` and `DesktopConfig` redacts
> them.

## Loading a credential

```rust,no_run
use grokbot_api::desktop::{DesktopConfig, DesktopCredential, Platform};
use grokbot_api::{Client, ClientOptions, Policy};

async fn from_desktop() -> grokbot_api::Result<Client> {
    let platform = Platform::current().expect("Linux, macOS or Windows");
    let cfg = DesktopConfig::new(platform);
    let mut opts = ClientOptions::default();
    if let Some(v) = cfg.detect_app_version() {
        opts.client_version = v; // send the same version as the installed app
    }
    match cfg.load_credential(None, &Policy::default())? {
        DesktopCredential::Session(session) => Client::new(session, opts),
        DesktopCredential::CursorToken(token) => Client::connect_cursor(&token, opts).await,
    }
}
```

`load_credential(key, policy)` tries the gateway session first, then the Cursor token:

1. **`gateway-descriptor.json`**, a saved gateway session, if it exists. The result is
   `DesktopCredential::Session`.
   - v1 descriptors have one entry (`"default"`); v2 descriptors can have several.
   - Pass `Some(name)` to choose one; with several and `None` you get `AMBIGUOUS_ENTRIES`.
   - `entries()` lists their names without decrypting anything.
   - The decrypted `{baseUrl, token, headers?}` must pass `policy.check_gateway`.
2. **Otherwise `sand-secrets.json`**, the app's Cursor accounts. The result is
   `DesktopCredential::CursorToken`; exchange it with `connect_cursor` or `ensure_sandbox`.
   - `sand_accounts()` lists accounts from plaintext metadata only. Each has a `key`, an
     `active` flag and a label like `1) 3f9a2c1b…`.
   - `key` may be a 1-based number, a full account key or a unique prefix of 4+ characters.
   - Only the chosen account's token is decrypted.
   - `sand_key_for(choice)` gives you the stable account key to save, so a later re-read
     picks the same account.

## Where the files are

| Platform | App data dir (`app_data_dir`) |
|---|---|
| Linux | `$XDG_CONFIG_HOME/Grok Bot`, else `~/.config/Grok Bot` |
| macOS | `~/Library/Application Support/Grok Bot` |
| Windows | `%APPDATA%\Grok Bot` |

`descriptor_path` and `sand_secrets_path` (free functions and `DesktopConfig` methods) return
the full paths. `present()` and `sand_present()` check that they exist.

## Encryption

Both files use Chromium's "Safe Storage" (OSCrypt) format, the same as other Electron apps:

| Scheme | Key |
|---|---|
| Linux `v11` | Secret Service password via `secret-tool lookup xdg:schema chrome_libsecret_os_crypt_password_v2 application "Grok Bot"`; PBKDF2-HMAC-SHA1, salt `saltysalt`, 1 iteration, AES-128-CBC, IV of 16 spaces |
| Linux `v10` | Keyring-less "basic text" backend: fixed password `peanuts`, otherwise as `v11` (no keychain access needed) |
| macOS `v10` | Login Keychain item `Grok Bot Safe Storage` via `/usr/bin/security find-generic-password -w -s "Grok Bot Safe Storage"`; 1003 iterations |
| Windows `v10` | AES-256-GCM with the DPAPI-protected key from `Local State` (Windows builds only) |

The lower-level functions are public for tools and tests:
- `parse_entries`
- `needs_keychain`
- `decrypt_safe_storage`
- `decrypt_windows`
- `session_from_clear`
- `DesktopConfig::local_state_key` (Windows only)

## Testing and customising

Every `DesktopConfig` field is public, so tests can point it at a temporary directory:

```rust
use grokbot_api::desktop::{DesktopConfig, Platform};

let mut cfg = DesktopConfig::new(Platform::Linux);
cfg.home = std::env::temp_dir().join("fake-home");
cfg.env = Box::new(|_| None);                 // ignore the real environment
cfg.os_password = Some("test-password".into()); // skip the keychain entirely
// or: cfg.keychain_program = Some("/path/to/fake-secret-tool".into());
assert!(!cfg.present());
```

`keychain_program` replaces `secret-tool` / `/usr/bin/security`. It receives the same
arguments and must print the password on stdout.

## App version detection

`detect_app_version(platform, home, env)` (or `cfg.detect_app_version()`) returns the
installed app's version, e.g. `"0.70.2"`, for `ClientOptions::client_version`.

It finds the install directory with `find_install_dir`:
- `GROKBOT_APP_DIR` or `GROKBOT_INSTALL_DIR` if set to a directory;
- otherwise the usual install locations:
  - Linux: `~/.local/share/grok-bot`, `/opt/Grok Bot`, `/usr/lib/grok-bot`, the
    `/bin/grok-bot` launcher, and `grok-bot.desktop` entries.
  - macOS: `/Applications/Grok Bot.app`, `~/Applications/Grok Bot.app`.
  - Windows: `Grok Bot` under `%LOCALAPPDATA%` or Program Files.

The version comes from the first of these that has one:
1. `package.json` or `product.json` in the resources dir (`resources/app/…`; on macOS,
   `Contents/Resources/app/…`)
2. `app.asar` in the resources dir (`version_from_asar`)
3. `desktop-status.json` in the app data dir

`normalize_semver` strips a leading `v` and keeps `MAJOR.MINOR.PATCH`.

## Error codes

Failures are `Error::Desktop { code, message }`. Match on `code`, which is stable:

| Code | Meaning |
|---|---|
| `APP_NOT_FOUND` | No app data dir |
| `NOT_SIGNED_IN` | App installed but no saved session or accounts |
| `READ_FAILED` | A file couldn't be read |
| `INVALID_DESCRIPTOR`, `UNSUPPORTED_VERSION`, `EMPTY_ENTRIES`, `MISSING_ENCRYPTED_PAYLOAD`, `INVALID_PAYLOAD` | Malformed `gateway-descriptor.json` |
| `INVALID_SAND` | Malformed `sand-secrets.json` |
| `NO_SUCH_ENTRY`, `AMBIGUOUS_ENTRIES` | The requested entry or account doesn't exist, or one must be chosen |
| `INCOMPLETE_DESCRIPTOR` | Decrypted data lacks the URL, token or access token |
| `UNSUPPORTED_FORMAT` | Ciphertext prefix isn't `v10` / `v11` |
| `NO_KEYCHAIN_PASSWORD`, `SECRET_TOOL_MISSING`, `KEYCHAIN_FAILED`, `KEYCHAIN_LOCKED` | Couldn't get the keychain password |
| `DECRYPT_FAILED` | Wrong key or corrupt data |
| `UNSUPPORTED_PLATFORM` | e.g. reading a Windows session on Linux |
| `MISSING_SAFE_STORAGE_KEY`, `DPAPI_FAILED` | Windows `Local State` key problems |

A decrypted gateway URL that fails the policy is reported as `Error::Policy` instead.
