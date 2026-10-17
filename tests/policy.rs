//! The credential host allowlist and error classification.
use grokbot_api::*;

#[test]
fn gateway_allowlist_matrix() {
    let p = Policy::default();
    for ok in [
        "https://cursor.sh",
        "https://API2.Cursor.Sh/",
        "  https://box.us1.cursorvm.com/  ",
        "https://a.b.cursor.com:8443/base/",
    ] {
        assert!(p.check_gateway(ok).is_ok(), "{ok}");
    }
    assert_eq!(
        p.check_gateway(" https://x.cursor.com/ ").unwrap(),
        "https://x.cursor.com"
    );
    for bad in [
        "https://cursorvm.com",
        "https://evilcursor.com",
        "https://cursor.com.evil.net",
        "ws://x.cursor.sh",
        "https://user@x.cursor.sh",
        "https://:pw@x.cursor.sh",
        "",
    ] {
        assert!(p.check_gateway(bad).is_err(), "{bad}");
    }
}

#[test]
fn error_messages_explain_the_rejection() {
    let p = Policy::default();
    assert_eq!(p.check_gateway("nope").unwrap_err(), "Invalid gateway URL.");
    assert_eq!(p.check_backend("nope").unwrap_err(), "Invalid backend URL.");
    assert!(
        p.check_gateway("http://x.cursor.sh")
            .unwrap_err()
            .contains("only https")
    );
    assert!(
        p.check_gateway("https://u:p@x.cursor.sh")
            .unwrap_err()
            .contains("userinfo")
    );
    let e = p.check_gateway("http://localhost:1").unwrap_err();
    assert!(e.contains(ALLOW_LOCAL_ENV), "{e}");
    let e = p.check_backend("http://localhost:1").unwrap_err();
    assert!(e.contains("EnsureSandBox must be https"), "{e}");
    assert!(
        p.check_gateway("https://evil.example")
            .unwrap_err()
            .contains("*.cursorvm.com")
    );
    let e = p.check_backend("https://x.cursorvm.com").unwrap_err();
    assert!(e.contains("Expected *.cursor.sh / *.cursor.com."), "{e}");
}

#[test]
fn loopback_rules() {
    let local = Policy::local_testing();
    assert!(local.allow_local_gateway && local.allow_local_backend);
    assert!(local.check_gateway("https://[::1]:8443").is_ok());
    assert!(local.check_backend("http://127.0.0.1:9").is_ok());
    let e = local.check_gateway("ftp://localhost/").unwrap_err();
    assert!(e.contains("local URLs must use http or https"), "{e}");
    assert!(
        local.check_gateway("http://192.168.1.10").is_err(),
        "LAN hosts are not loopback"
    );
}

#[test]
fn error_status_and_delivery() {
    let http = |status| Error::Http {
        method: "m".into(),
        status,
        message: "x".into(),
    };
    assert_eq!(http(404).status(), Some(404));
    assert_eq!(http(404).delivery(), Delivery::Rejected);
    assert_eq!(http(500).delivery(), Delivery::Unknown);
    assert!(!http(403).is_unauthorized());
    let others = [
        Error::Policy("p".into()),
        Error::Validation("v".into()),
        Error::Transport {
            method: "m".into(),
            message: "t".into(),
        },
        Error::TooLarge {
            method: "m".into(),
            limit: 1,
        },
        Error::Desktop {
            code: "C".into(),
            message: "d".into(),
        },
        Error::InvalidResponse {
            method: "m".into(),
            message: "i".into(),
        },
    ];
    let delivery: Vec<_> = others.iter().map(Error::delivery).collect();
    assert_eq!(
        delivery,
        [
            Delivery::Rejected,
            Delivery::Rejected,
            Delivery::Unknown,
            Delivery::Unknown,
            Delivery::Unknown,
            Delivery::Unknown
        ]
    );
    assert!(
        others
            .iter()
            .all(|e| e.status().is_none() && !e.is_unauthorized())
    );
    let shown: Vec<_> = others.iter().map(ToString::to_string).collect();
    assert_eq!(
        shown,
        [
            "p",
            "v",
            "m failed: t",
            "m: gateway response too large (over 1 bytes)",
            "d",
            "m: i"
        ]
    );
}
