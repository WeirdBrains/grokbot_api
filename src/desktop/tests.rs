use super::*;

// --- fixture builders (encrypt the way the desktop app would) ---

fn encrypt_cbc(clear: &str, password: &str, platform: Platform, prefix: &str) -> String {
    use aes::Aes128;
    use base64::Engine;
    use cbc::Encryptor;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
    let key = safe_storage_key(password, platform);
    let iv = [0x20u8; 16];
    let ct = Encryptor::<Aes128>::new(&key.into(), &iv.into())
        .encrypt_padded_vec::<Pkcs7>(clear.as_bytes());
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
            &Nonce::try_from(&nonce[..]).unwrap(),
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
        keychain_program: None,
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
        keychain_program: None,
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
        keychain_program: None,
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
        keychain_program: None,
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
        keychain_program: None,
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
        keychain_program: None,
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
        keychain_program: None,
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

// --- coverage of error paths, platforms, the keychain program and version detection ---

fn encrypt_bytes(clear: &[u8], password: &str, platform: Platform, prefix: &str) -> String {
    use aes::Aes128;
    use base64::Engine;
    use cbc::Encryptor;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
    let key = safe_storage_key(password, platform);
    let ct = Encryptor::<Aes128>::new(&key.into(), &[0x20u8; 16].into())
        .encrypt_padded_vec::<Pkcs7>(clear);
    let mut out = prefix.as_bytes().to_vec();
    out.extend_from_slice(&ct);
    base64::engine::general_purpose::STANDARD.encode(out)
}

fn cfg_at(home: &Path, platform: Platform, os_password: Option<&str>) -> DesktopConfig {
    DesktopConfig {
        platform,
        home: home.to_path_buf(),
        env: Box::new(|_| None),
        os_password: os_password.map(str::to_string),
        keychain_program: None,
    }
}

fn code(e: Error) -> String {
    match e {
        Error::Desktop { code, .. } => code,
        other => panic!("expected a desktop error, got {other:?}"),
    }
}

fn linux_app(dir: &Path) -> PathBuf {
    let app = dir.join(".config/Grok Bot");
    std::fs::create_dir_all(&app).unwrap();
    app
}

#[test]
fn platform_current_matches_the_build() {
    #[cfg(target_os = "linux")]
    assert_eq!(Platform::current(), Some(Platform::Linux));
    #[cfg(target_os = "macos")]
    assert_eq!(Platform::current(), Some(Platform::Macos));
    #[cfg(target_os = "windows")]
    assert_eq!(Platform::current(), Some(Platform::Windows));
}

#[test]
fn app_data_dirs_per_platform() {
    let home = Path::new("/h");
    let none = |_: &str| None;
    let env = |k: &str| match k {
        "APPDATA" => Some("/appdata".to_string()),
        "XDG_CONFIG_HOME" => Some("/xdg".to_string()),
        _ => None,
    };
    let empty = |_: &str| Some(String::new());
    assert_eq!(
        app_data_dir(home, Platform::Windows, &env),
        Path::new("/appdata/Grok Bot")
    );
    assert_eq!(
        app_data_dir(home, Platform::Windows, &none),
        Path::new("/h/AppData/Roaming/Grok Bot")
    );
    assert_eq!(
        app_data_dir(home, Platform::Linux, &env),
        Path::new("/xdg/Grok Bot")
    );
    assert_eq!(
        app_data_dir(home, Platform::Linux, &empty),
        Path::new("/h/.config/Grok Bot")
    );
    assert_eq!(
        app_data_dir(home, Platform::Macos, &env),
        Path::new("/h/Library/Application Support/Grok Bot")
    );
    assert_eq!(
        sand_secrets_path(home, Platform::Linux, &none),
        Path::new("/h/.config/Grok Bot/sand-secrets.json")
    );
    assert_eq!(
        descriptor_path(home, Platform::Macos, &none),
        Path::new("/h/Library/Application Support/Grok Bot/gateway-descriptor.json")
    );
}

#[test]
fn descriptor_parsing_errors() {
    assert_eq!(
        code(parse_entries("{not json").unwrap_err()),
        "INVALID_DESCRIPTOR"
    );
    assert_eq!(
        code(parse_entries(r#"{"version":3}"#).unwrap_err()),
        "UNSUPPORTED_VERSION"
    );
    assert_eq!(
        code(parse_entries(r#"{"version":2}"#).unwrap_err()),
        "EMPTY_ENTRIES"
    );
    assert_eq!(
        code(parse_entries(r#"{"encrypted":""}"#).unwrap_err()),
        "MISSING_ENCRYPTED_PAYLOAD"
    );
    let v2 = parse_entries(
        r#"{"version":2,"entries":{"a":{"encrypted":""},"b":{},"c":{"encrypted":"QQ=="}}}"#,
    )
    .unwrap();
    assert_eq!(v2.len(), 1);
    assert_eq!(v2[0].key, "c");
}

#[test]
fn safe_storage_decrypt_errors() {
    assert_eq!(
        code(needs_keychain("%%%", Platform::Linux).unwrap_err()),
        "INVALID_PAYLOAD"
    );
    let v11 = encrypt_cbc("x", "pw", Platform::Linux, "v11");
    assert!(needs_keychain(&v11, Platform::Macos).unwrap());
    assert_eq!(
        code(decrypt_safe_storage(&v11, Some("pw"), Platform::Macos).unwrap_err()),
        "UNSUPPORTED_FORMAT",
        "v11 is Linux-only"
    );
    let v12 = encrypt_cbc("x", "pw", Platform::Linux, "v12");
    assert_eq!(
        code(decrypt_safe_storage(&v12, Some("pw"), Platform::Linux).unwrap_err()),
        "UNSUPPORTED_FORMAT"
    );
    assert_eq!(
        code(decrypt_safe_storage(&v11, None, Platform::Linux).unwrap_err()),
        "NO_KEYCHAIN_PASSWORD"
    );
    let binary = encrypt_bytes(&[0xff, 0xfe, 0x00], "pw", Platform::Linux, "v11");
    assert_eq!(
        code(decrypt_safe_storage(&binary, Some("pw"), Platform::Linux).unwrap_err()),
        "DECRYPT_FAILED"
    );
}

#[test]
fn windows_decrypt_errors() {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    assert_eq!(
        code(decrypt_windows(&b64(b"v10short"), &[0; 32]).unwrap_err()),
        "UNSUPPORTED_FORMAT"
    );
    let mut long = b"v11".to_vec();
    long.extend_from_slice(&[0u8; 40]);
    assert_eq!(
        code(decrypt_windows(&b64(&long), &[0; 32]).unwrap_err()),
        "UNSUPPORTED_FORMAT"
    );
    long[..3].copy_from_slice(b"v10");
    let e = decrypt_windows(&b64(&long), &[0; 5]).unwrap_err();
    assert!(e.to_string().contains("key length"), "{e}");
    let key = [9u8; 32];
    let ct = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(&Nonce::from([2u8; 12]), &[0xffu8, 0xfe][..])
        .unwrap();
    let mut blob = b"v10".to_vec();
    blob.extend_from_slice(&[2u8; 12]);
    blob.extend_from_slice(&ct);
    assert!(
        decrypt_windows(&b64(&blob), &key)
            .unwrap_err()
            .to_string()
            .contains("UTF-8")
    );
}

#[test]
fn clear_descriptor_errors_and_header_filtering() {
    assert_eq!(
        code(session_from_clear("nope", &Policy::default()).unwrap_err()),
        "INCOMPLETE_DESCRIPTOR"
    );
    let s = session_from_clear(
        r#"{"baseUrl":"https://x.cursorvm.com","token":"t","headers":{"X-A":"1","X-N":2,"X-E":""}}"#,
        &Policy::default(),
    )
    .unwrap();
    assert_eq!(s.headers.len(), 1);
    assert_eq!(s.headers["x-a"], "1");
}

#[test]
fn entries_errors() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg_at(dir.path(), Platform::Linux, None);
    assert_eq!(code(cfg.entries().unwrap_err()), "APP_NOT_FOUND");
    let app = linux_app(dir.path());
    assert_eq!(code(cfg.entries().unwrap_err()), "NOT_SIGNED_IN");
    std::fs::create_dir(app.join("gateway-descriptor.json")).unwrap();
    assert_eq!(code(cfg.entries().unwrap_err()), "READ_FAILED");
}

#[cfg(not(target_os = "windows"))]
#[test]
fn windows_sessions_need_windows() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("AppData/Roaming/Grok Bot");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(
        app.join("gateway-descriptor.json"),
        r#"{"encrypted":"djEwAAAA"}"#,
    )
    .unwrap();
    let cfg = cfg_at(dir.path(), Platform::Windows, None);
    assert_eq!(
        code(cfg.load_entry(None, &Policy::default()).unwrap_err()),
        "UNSUPPORTED_PLATFORM"
    );
}

fn sand_raw(app: &Path, top: &str) {
    std::fs::write(app.join("sand-secrets.json"), top).unwrap();
}

#[test]
fn sand_secrets_structure_errors() {
    let dir = tempfile::tempdir().unwrap();
    let app = linux_app(dir.path());
    let cfg = cfg_at(dir.path(), Platform::Linux, Some("os-pw"));
    let load = |c: &DesktopConfig| code(c.load_credential(None, &Policy::default()).unwrap_err());

    std::fs::create_dir(app.join("sand-secrets.json")).unwrap();
    assert_eq!(load(&cfg), "READ_FAILED");
    std::fs::remove_dir(app.join("sand-secrets.json")).unwrap();

    sand_raw(&app, "{oops");
    assert_eq!(load(&cfg), "INVALID_SAND");
    sand_raw(&app, r#"{"version":1}"#);
    assert_eq!(load(&cfg), "NOT_SIGNED_IN");
    sand_raw(&app, r#"{"cursor-accounts":"{oops"}"#);
    assert_eq!(load(&cfg), "INVALID_SAND");
    sand_raw(&app, r#"{"cursor-accounts":"{\"accounts\":{}}"}"#);
    assert_eq!(load(&cfg), "NOT_SIGNED_IN");
    sand_raw(&app, r#"{"cursor-accounts":"{\"accounts\":{\"k1\":{}}}"}"#);
    assert_eq!(
        load(&cfg),
        "INCOMPLETE_DESCRIPTOR",
        "account without an access token"
    );
    // Non-object accounts are skipped when listing.
    sand_raw(
        &app,
        r#"{"cursor-accounts":"{\"accounts\":{\"bad\":5,\"good\":{}}}"}"#,
    );
    let list = cfg.sand_accounts().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].key, "good");
    assert!(!list[0].active, "no active marker");
}

#[test]
fn sand_account_choices() {
    let dir = tempfile::tempdir().unwrap();
    let app = linux_app(dir.path());
    write_sand(
        &app,
        &[
            ("aaaa1xxxxxxxx", "tok-1"),
            ("aaaa2yyyyyyyy", "tok-2"),
            ("zzzz3zzzzzzzz", "tok-3"),
        ],
        "aaaa2yyyyyyyy",
    );
    let cfg = cfg_at(dir.path(), Platform::Linux, Some("os-pw"));
    let tok = |choice: &str| match cfg.load_credential(Some(choice), &Policy::default()) {
        Ok(DesktopCredential::CursorToken(t)) => Ok(t),
        Ok(DesktopCredential::Session(_)) => panic!("expected a Cursor token"),
        Err(e) => Err(e),
    };
    assert_eq!(tok("aaaa2yyyyyyyy").unwrap(), "tok-2", "full key");
    assert_eq!(tok(" zzzz ").unwrap(), "tok-3", "unique prefix");
    assert_eq!(tok("1").unwrap(), "tok-1", "1-based number");
    for bad in ["aaaa", "zz", "9", "0", "nope"] {
        let e = tok(bad).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("(active)"),
            "listing marks the active account: {msg}"
        );
        assert_eq!(code(e), "NO_SUCH_ENTRY", "{bad}");
    }
    assert_eq!(
        cfg.sand_key_for(None).unwrap(),
        None,
        "several accounts need a choice"
    );
    assert_eq!(
        cfg.sand_key_for(Some("aaaa1xxxxxxxx")).unwrap().as_deref(),
        Some("aaaa1xxxxxxxx")
    );
    assert_eq!(
        cfg.sand_key_for(Some("zzzz")).unwrap().as_deref(),
        Some("zzzz3zzzzzzzz")
    );
    assert_eq!(
        cfg.sand_key_for(Some("aaaa")).unwrap(),
        None,
        "ambiguous prefix"
    );
    assert_eq!(cfg.sand_key_for(Some("7")).unwrap(), None);
}

#[test]
fn debug_output_redacts_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = cfg_at(dir.path(), Platform::Linux, Some("hunter2"));
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("Linux") && !dbg.contains("hunter2"), "{dbg}");
    let tok = DesktopCredential::CursorToken("cursor-secret".into());
    assert_eq!(format!("{tok:?}"), r#"CursorToken("<redacted>")"#);
    let s = DesktopCredential::Session(Session::new("https://x.cursorvm.com", "gw-secret"));
    let dbg = format!("{s:?}");
    assert!(
        dbg.contains("x.cursorvm.com") && !dbg.contains("gw-secret"),
        "{dbg}"
    );
}

#[test]
fn new_uses_the_real_home() {
    let cfg = DesktopConfig::new(Platform::Linux);
    assert_eq!(
        cfg.home,
        PathBuf::from(std::env::var("HOME").unwrap_or_default())
    );
    assert!(cfg.os_password.is_none() && cfg.keychain_program.is_none());
    assert!(
        cfg.descriptor_path()
            .ends_with("Grok Bot/gateway-descriptor.json")
    );
    assert!(
        cfg.sand_secrets_path()
            .ends_with("Grok Bot/sand-secrets.json")
    );
}

#[cfg(unix)]
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

#[cfg(unix)]
#[test]
fn keychain_program_supplies_the_password() {
    let dir = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    // Answers like secret-tool (Linux) or security (macOS), checking the arguments.
    let ok = script(
        bin.path(),
        "keychain",
        r#"case "$1 $5" in
  "lookup Grok Bot") echo os-pw ;;
  "find-generic-password ") [ "$4" = "Grok Bot Safe Storage" ] && echo mac-pw ;;
  *) exit 3 ;;
esac"#,
    );
    let locked = script(bin.path(), "locked", "exit 1");
    let missing = bin.path().join("does-not-exist");

    let app = linux_app(dir.path());
    let enc = encrypt_cbc(
        &inner("https://box.cursorvm.com"),
        "os-pw",
        Platform::Linux,
        "v11",
    );
    std::fs::write(
        app.join("gateway-descriptor.json"),
        format!(r#"{{"encrypted":"{enc}"}}"#),
    )
    .unwrap();
    let mut cfg = cfg_at(dir.path(), Platform::Linux, None);
    cfg.keychain_program = Some(ok.clone());
    assert_eq!(
        cfg.load_entry(None, &Policy::default())
            .unwrap()
            .gateway_token,
        "gw-secret"
    );
    cfg.keychain_program = Some(locked.clone());
    assert_eq!(
        code(cfg.load_entry(None, &Policy::default()).unwrap_err()),
        "KEYCHAIN_LOCKED"
    );
    cfg.keychain_program = Some(missing.clone());
    assert_eq!(
        code(cfg.load_entry(None, &Policy::default()).unwrap_err()),
        "SECRET_TOOL_MISSING"
    );

    let mac_app = dir.path().join("Library/Application Support/Grok Bot");
    std::fs::create_dir_all(&mac_app).unwrap();
    let enc = encrypt_cbc(
        &inner("https://box.cursor.sh"),
        "mac-pw",
        Platform::Macos,
        "v10",
    );
    std::fs::write(
        mac_app.join("gateway-descriptor.json"),
        format!(r#"{{"encrypted":"{enc}"}}"#),
    )
    .unwrap();
    let mut mac = cfg_at(dir.path(), Platform::Macos, None);
    mac.keychain_program = Some(ok);
    assert_eq!(
        mac.load_entry(None, &Policy::default())
            .unwrap()
            .gateway_url,
        "https://box.cursor.sh"
    );
    mac.keychain_program = Some(missing);
    assert_eq!(
        code(mac.load_entry(None, &Policy::default()).unwrap_err()),
        "KEYCHAIN_FAILED"
    );
}

// --- install-dir and version detection ---

fn env_map(pairs: &[(&str, &Path)]) -> impl Fn(&str) -> Option<String> + Send + Sync + use<> {
    let m: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string_lossy().into_owned()))
        .collect();
    move |k: &str| m.get(k).cloned()
}

#[test]
fn install_dir_override_must_be_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, "").unwrap();
    let inst = dir.path().join("inst");
    std::fs::create_dir(&inst).unwrap();
    let env = env_map(&[
        ("GB_GROKBOT_APP_DIR", &file),
        ("GROKBOT_INSTALL_DIR", &inst),
    ]);
    assert_eq!(find_install_dir(Platform::Macos, &env), Some(inst));
}

#[test]
fn linux_install_dir_from_home_and_desktop_file() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let env = env_map(&[("HOME", h)]);
    let user_dir = h.join(".local/share/grok-bot");
    std::fs::create_dir_all(&user_dir).unwrap();
    assert_eq!(
        find_install_dir(Platform::Linux, &env),
        Some(user_dir.clone())
    );
    // A desktop file without Exec is ignored; one with Exec wins.
    let apps = h.join(".local/share/applications");
    std::fs::create_dir_all(&apps).unwrap();
    std::fs::write(
        apps.join("grok-bot.desktop"),
        "[Desktop Entry]\nName=Grok Bot\n",
    )
    .unwrap();
    assert_eq!(find_install_dir(Platform::Linux, &env), Some(user_dir));
    let custom = h.join("apps/GrokBot");
    std::fs::create_dir_all(&custom).unwrap();
    std::fs::write(
        apps.join("grok-bot.desktop"),
        format!("[Desktop Entry]\n  Exec={}/grok-bot %U\n", custom.display()),
    )
    .unwrap();
    assert_eq!(find_install_dir(Platform::Linux, &env), Some(custom));
}

#[test]
fn macos_and_windows_install_dirs() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let env = env_map(&[("HOME", h), ("LOCALAPPDATA", h)]);
    assert_eq!(find_install_dir(Platform::Macos, &env), None);
    assert_eq!(find_install_dir(Platform::Windows, &env), None);
    assert_eq!(find_install_dir(Platform::Macos, &|_| None), None);
    let mac = h.join("Applications/Grok Bot.app");
    std::fs::create_dir_all(&mac).unwrap();
    assert_eq!(find_install_dir(Platform::Macos, &env), Some(mac));
    let win = h.join("Grok Bot");
    std::fs::create_dir_all(&win).unwrap();
    assert_eq!(find_install_dir(Platform::Windows, &env), Some(win));
}

fn build_asar(meta: &str, payload: &[u8]) -> Vec<u8> {
    let m = meta.as_bytes();
    let str_len = m.len() as u32;
    let pad = (4 - (str_len % 4)) % 4;
    let mut header = Vec::new();
    header.extend_from_slice(&(4 + str_len + pad).to_le_bytes());
    header.extend_from_slice(&str_len.to_le_bytes());
    header.extend_from_slice(m);
    header.extend(std::iter::repeat_n(0u8, pad as usize));
    let mut asar = Vec::new();
    asar.extend_from_slice(&4u32.to_le_bytes());
    asar.extend_from_slice(&(header.len() as u32).to_le_bytes());
    asar.extend_from_slice(&header);
    asar.extend_from_slice(payload);
    asar
}

#[test]
fn asar_edge_cases() {
    let dir = tempfile::tempdir().unwrap();
    let read = |bytes: &[u8]| {
        let p = dir.path().join("t.asar");
        std::fs::write(&p, bytes).unwrap();
        version_from_asar(&p)
    };
    assert_eq!(version_from_asar(&dir.path().join("missing.asar")), None);
    assert_eq!(read(b"short"), None);
    let mut huge = vec![0u8; 16];
    huge[4..8].copy_from_slice(&1_000u32.to_le_bytes());
    assert_eq!(read(&huge), None, "header longer than the file");
    let mut tiny = vec![0u8; 16];
    tiny[4..8].copy_from_slice(&4u32.to_le_bytes());
    assert_eq!(
        read(&tiny),
        None,
        "header shorter than its own length fields"
    );
    let mut bad_len = vec![0u8; 20];
    bad_len[4..8].copy_from_slice(&12u32.to_le_bytes());
    bad_len[12..16].copy_from_slice(&500u32.to_le_bytes());
    assert_eq!(read(&bad_len), None, "string longer than the header");
    assert_eq!(read(&build_asar("not json!!", b"")), None);
    assert_eq!(read(&build_asar(r#"{"nofiles":1}"#, b"")), None);

    let product = br#"{"version":"v3.4.5-beta"}"#;
    let meta = format!(
        r#"{{"files":{{"package.json":{{"offset":"0","size":99999}},"product.json":{{"offset":"0","size":{}}}}}}}"#,
        product.len()
    );
    assert_eq!(
        read(&build_asar(&meta, product)).as_deref(),
        Some("3.4.5"),
        "skips an out-of-range entry"
    );
    let only_product = format!(
        r#"{{"files":{{"product.json":{{"offset":"0","size":{}}}}}}}"#,
        product.len()
    );
    assert_eq!(
        read(&build_asar(&only_product, product)).as_deref(),
        Some("3.4.5")
    );
    let bad = br#"{"version":"latest"}"#;
    let meta = format!(
        r#"{{"files":{{"package.json":{{"offset":"0","size":{}}}}}}}"#,
        bad.len()
    );
    assert_eq!(read(&build_asar(&meta, bad)), None);
    assert_eq!(
        read(&build_asar(
            r#"{"files":{"package.json":{"offset":0,"size":1}}}"#,
            b"x"
        )),
        None
    );
}

#[test]
fn semver_normalization() {
    assert_eq!(normalize_semver(" v2.0.1 ").as_deref(), Some("2.0.1"));
    assert_eq!(normalize_semver("1.2"), None);
    assert_eq!(normalize_semver("1.x.3"), None);
    assert_eq!(normalize_semver("1.2.x"), None);
    assert_eq!(normalize_semver("a.2.3"), None);
}

#[test]
fn detect_version_from_each_source() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let env = env_map(&[("HOME", h), ("LOCALAPPDATA", h)]);

    // macOS: Contents/Resources/app/product.json.
    let res = h.join("Applications/Grok Bot.app/Contents/Resources/app");
    std::fs::create_dir_all(&res).unwrap();
    std::fs::write(res.join("product.json"), r#"{"version":"0.80.1"}"#).unwrap();
    assert_eq!(
        detect_app_version(Platform::Macos, h, &env).as_deref(),
        Some("0.80.1")
    );

    // Windows: an unreadable package.json, then app.asar.
    let wres = h.join("Grok Bot/resources");
    std::fs::create_dir_all(&wres).unwrap();
    std::fs::write(wres.join("package.json"), "garbage").unwrap();
    let pkg = br#"{"version":"0.81.0"}"#;
    let meta = format!(
        r#"{{"files":{{"package.json":{{"offset":"0","size":{}}}}}}}"#,
        pkg.len()
    );
    std::fs::write(wres.join("app.asar"), build_asar(&meta, pkg)).unwrap();
    let mut cfg = cfg_at(h, Platform::Windows, None);
    cfg.env = Box::new(env_map(&[("LOCALAPPDATA", h)]));
    assert_eq!(cfg.detect_app_version().as_deref(), Some("0.81.0"));

    // Installed but unreadable, and no desktop-status.json: None.
    std::fs::remove_file(wres.join("app.asar")).unwrap();
    assert_eq!(detect_app_version(Platform::Windows, h, &env), None);
    // desktop-status.json without appVersion: still None.
    let status_dir = h.join("AppData/Roaming/Grok Bot");
    std::fs::create_dir_all(&status_dir).unwrap();
    std::fs::write(status_dir.join("desktop-status.json"), r#"{"pid":1}"#).unwrap();
    assert_eq!(detect_app_version(Platform::Windows, h, &env), None);
    std::fs::write(
        status_dir.join("desktop-status.json"),
        r#"{"appVersion":"0.82.0"}"#,
    )
    .unwrap();
    assert_eq!(
        detect_app_version(Platform::Windows, h, &env).as_deref(),
        Some("0.82.0")
    );
}

#[test]
fn linux_basic_text_descriptor_loads_without_a_keychain() {
    let dir = tempfile::tempdir().unwrap();
    let app = linux_app(dir.path());
    let enc = encrypt_cbc(
        &inner("https://box.cursorvm.com"),
        PEANUTS,
        Platform::Linux,
        "v10",
    );
    std::fs::write(
        app.join("gateway-descriptor.json"),
        format!(r#"{{"encrypted":"{enc}"}}"#),
    )
    .unwrap();
    let mut cfg = cfg_at(dir.path(), Platform::Linux, None);
    // Would fail if consulted: proves the keychain is never asked for v10.
    cfg.keychain_program = Some(dir.path().join("no-such-program"));
    assert_eq!(
        cfg.load_entry(None, &Policy::default())
            .unwrap()
            .gateway_token,
        "gw-secret"
    );
}
