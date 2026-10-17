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
