//! EnsureSandBox, Cursor backend calls, and the 401/417 re-authentication flow.
mod common;

use common::*;
use grokbot_api::*;
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{body_json, header, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn ensure_sandbox_sends_custom_client_identity() {
    let server = MockServer::start().await;
    Mock::given(path(ENSURE))
        .and(header("x-cursor-client-version", "9.9.9"))
        .and(header("x-cursor-client-type", "custom"))
        .and(header("x-sand-box-namespace", "staging"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"gatewayUrl": server.uri(), "gatewayToken": "gw"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let o = ClientOptions {
        client_version: "9.9.9".into(),
        client_type: "custom".into(),
        sandbox_namespace: "staging".into(),
        ..opts(&server)
    };
    let s = ensure_sandbox("cur-tok", &o).await.unwrap();
    assert!(s.headers.is_empty());
}

#[tokio::test]
async fn ensure_sandbox_gateway_headers_win_over_network_token() {
    let server = MockServer::start().await;
    Mock::given(path(ENSURE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "gateway_url": server.uri(),
            "gateway_token": "gw",
            "gatewayHeaders": {"X-Box": "b1", "X-Num": 7, "X-Null": null, "X-Empty": ""},
            "anyrunNetworkToken": "ignored-because-headers-present"
        })))
        .mount(&server)
        .await;
    let s = ensure_sandbox("cur-tok", &opts(&server)).await.unwrap();
    assert_eq!(s.headers.get("x-box").map(String::as_str), Some("b1"));
    assert_eq!(s.headers.get("x-num").map(String::as_str), Some("7"));
    assert!(!s.headers.contains_key("x-null"));
    assert!(!s.headers.contains_key("x-empty"));
    assert!(!s.headers.contains_key("x-anyrun-network-token"));
}

#[tokio::test]
async fn ensure_sandbox_network_token_aliases() {
    for key in ["anyrun_network_token", "networkToken"] {
        let server = MockServer::start().await;
        Mock::given(path(ENSURE))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"gatewayUrl": server.uri(), "gatewayToken": "gw", key: "net"}),
            ))
            .mount(&server)
            .await;
        let s = ensure_sandbox("cur-tok", &opts(&server)).await.unwrap();
        assert_eq!(
            s.headers.get("x-anyrun-network-token").map(String::as_str),
            Some("net"),
            "{key}"
        );
    }
}

#[tokio::test]
async fn ensure_sandbox_http_error_is_redacted() {
    let server = MockServer::start().await;
    Mock::given(path(ENSURE))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"message": "token cur-tok expired; Bearer cur-tok"})),
        )
        .mount(&server)
        .await;
    let e = ensure_sandbox("cur-tok", &opts(&server)).await.unwrap_err();
    assert_eq!(e.status(), Some(401));
    assert!(e.is_unauthorized());
    let msg = e.to_string();
    assert!(msg.starts_with("EnsureSandBox failed: 401"), "{msg}");
    assert!(!msg.contains("cur-tok"), "{msg}");
    assert!(msg.contains("<redacted>"), "{msg}");
}

#[tokio::test]
async fn ensure_sandbox_rejects_empty_gateway_fields() {
    let server = MockServer::start().await;
    Mock::given(path(ENSURE))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"gatewayUrl": "", "gatewayToken": "gw"})),
        )
        .mount(&server)
        .await;
    let e = ensure_sandbox("cur-tok", &opts(&server)).await.unwrap_err();
    assert!(matches!(e, Error::InvalidResponse { .. }), "{e:?}");
    assert!(e.to_string().contains("dashboard API key"));
}

#[tokio::test]
async fn ensure_sandbox_disallowed_backend_sends_nothing() {
    let o = ClientOptions {
        backend_base: "https://evil.example".into(),
        ..ClientOptions::default()
    };
    assert!(matches!(
        ensure_sandbox("cur-tok", &o).await,
        Err(Error::Policy(_))
    ));
}

#[tokio::test]
async fn connect_cursor_builds_a_reexchanging_client() {
    let server = MockServer::start().await;
    Mock::given(path(ENSURE))
        .and(header("authorization", "Bearer cur-tok"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"gatewayUrl": server.uri(), "gatewayToken": "gw-1"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let c = Client::connect_cursor("cur-tok", opts(&server))
        .await
        .unwrap();
    assert_eq!(c.session().gateway_token, "gw-1");
    let dbg = format!("{c:?}");
    assert!(dbg.contains("has_cursor_token: true"), "{dbg}");
    assert!(!dbg.contains("gw-1") && !dbg.contains("cur-tok"), "{dbg}");
    assert!(c.take_refreshed_session().is_none());
}

#[tokio::test]
async fn expired_session_417_reexchanges_and_retries() {
    let server = MockServer::start().await;
    Mock::given(path("/api/deleteAgent"))
        .and(header("authorization", "Bearer old"))
        .respond_with(ResponseTemplate::new(417))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path(ENSURE))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"gatewayUrl": server.uri(), "gatewayToken": "new"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/deleteAgent"))
        .and(header("authorization", "Bearer new"))
        .and(body_json(json!({"id": "a1"})))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let c = cursor_client(&server, "old");
    // An empty 2xx body is returned as `{}`.
    assert_eq!(c.delete_agent("a1").await.unwrap(), json!({}));
    assert_eq!(c.take_refreshed_session().unwrap().gateway_token, "new");
}

#[tokio::test]
async fn reexchange_happens_once_even_if_retry_fails() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "nope"})))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(path(ENSURE))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"gatewayUrl": server.uri(), "gatewayToken": "new"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let e = cursor_client(&server, "old")
        .list_agents()
        .await
        .unwrap_err();
    assert_eq!(e.status(), Some(401));
}

#[tokio::test]
async fn reexchange_failure_is_returned() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(path(ENSURE))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "revoked"})))
        .expect(1)
        .mount(&server)
        .await;
    let e = cursor_client(&server, "old")
        .list_agents()
        .await
        .unwrap_err();
    match e {
        Error::Http {
            method,
            status,
            message,
        } => {
            assert_eq!((method.as_str(), status), ("EnsureSandBox", 403));
            assert_eq!(message, "revoked");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn reexchange_respects_backend_policy() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&server)
        .await;
    // Loopback gateway allowed, loopback backend not: the Cursor token must not be sent.
    let o = ClientOptions {
        policy: Policy {
            allow_local_gateway: true,
            allow_local_backend: false,
        },
        backend_base: server.uri(),
        ..Default::default()
    };
    let c = Client::with_cursor_token(Session::new(server.uri(), "old"), "cur-tok", o).unwrap();
    assert!(matches!(c.list_agents().await, Err(Error::Policy(_))));
}

#[tokio::test]
async fn plain_client_does_not_reexchange() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(ResponseTemplate::new(417))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path(ENSURE))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let e = client(&server).list_agents().await.unwrap_err();
    assert!(e.is_unauthorized());
}

#[tokio::test]
async fn grokbot_service_call_success_and_errors() {
    let server = MockServer::start().await;
    Mock::given(path("/aiserver.v1.GrokBotService/Echo"))
        .and(header("authorization", "Bearer cur-tok"))
        .and(header("connect-protocol-version", "1"))
        .and(body_json(json!({"x": 1})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"y": 2})))
        .mount(&server)
        .await;
    Mock::given(path("/aiserver.v1.GrokBotService/Fail"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"error": {"detail": "cur-tok bad"}})),
        )
        .mount(&server)
        .await;
    let o = opts(&server);
    assert_eq!(
        grokbot_service_call("cur-tok", "Echo", &json!({"x": 1}), &o)
            .await
            .unwrap(),
        json!({"y": 2})
    );
    let e = grokbot_service_call("cur-tok", "Fail", &json!({}), &o)
        .await
        .unwrap_err();
    assert_eq!(e.status(), Some(500));
    assert_eq!(e.delivery(), Delivery::Unknown);
    assert!(!e.to_string().contains("cur-tok"), "{e}");
    let bad = ClientOptions {
        backend_base: "http://example.com".into(),
        ..ClientOptions::default()
    };
    assert!(matches!(
        grokbot_service_call("cur-tok", "Echo", &json!({}), &bad).await,
        Err(Error::Policy(_))
    ));
}

#[tokio::test]
async fn header_values_and_tokens_are_redacted_from_gateway_errors() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            "plain text: gw-tok net-secret cur-tok Authorization: Bearer whatever",
        ))
        .mount(&server)
        .await;
    let s = Session::new(server.uri(), "gw-tok")
        .with_headers([("x-anyrun-network-token".into(), "net-secret".into())].into());
    let c = Client::with_cursor_token(s, "cur-tok", opts(&server)).unwrap();
    let msg = c.list_agents().await.unwrap_err().to_string();
    for secret in ["gw-tok", "net-secret", "cur-tok", "whatever"] {
        assert!(!msg.contains(secret), "{secret} leaked: {msg}");
    }
    assert!(
        msg.contains("plain text"),
        "non-JSON body is used as the message: {msg}"
    );
}

#[tokio::test]
async fn long_error_messages_are_truncated() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"message": "x".repeat(1000)})),
        )
        .mount(&server)
        .await;
    match client(&server).list_agents().await.unwrap_err() {
        Error::Http { message, .. } => assert_eq!(message.len(), 300),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn timeouts_are_transport_errors() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(500)))
        .mount(&server)
        .await;
    let o = ClientOptions {
        timeout: Duration::from_millis(50),
        ..opts(&server)
    };
    let c = Client::new(Session::new(server.uri(), "gw-tok"), o).unwrap();
    let e = c.list_agents().await.unwrap_err();
    assert!(matches!(e, Error::Transport { .. }), "{e:?}");
    assert!(e.to_string().starts_with("listAgents failed:"));
}

#[tokio::test]
async fn custom_response_cap() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"agents": []})))
        .mount(&server)
        .await;
    let o = ClientOptions {
        max_response_bytes: 4,
        ..opts(&server)
    };
    let c = Client::new(Session::new(server.uri(), "gw-tok"), o).unwrap();
    let e = c.list_agents().await.unwrap_err();
    assert_eq!(
        e.to_string(),
        "listAgents: gateway response too large (over 4 bytes)"
    );
    assert_eq!(e.delivery(), Delivery::Unknown);
}

#[test]
fn session_debug_redacts_secrets() {
    let s = Session::new("https://box.cursorvm.com", "gw-secret")
        .with_headers([("X-Net".into(), "net-secret".into())].into());
    let dbg = format!("{s:?}");
    assert!(
        dbg.contains("box.cursorvm.com") && dbg.contains("x-net"),
        "{dbg}"
    );
    assert!(
        !dbg.contains("gw-secret") && !dbg.contains("net-secret"),
        "{dbg}"
    );
}

#[test]
fn client_options_defaults() {
    let o = ClientOptions::default();
    assert_eq!(o.backend_base, DEFAULT_BACKEND_BASE);
    assert_eq!(o.timeout, TIMEOUT);
    assert_eq!(o.max_response_bytes, MAX_RESPONSE_BYTES);
    assert_eq!(o.client_version, DEFAULT_CLIENT_VERSION);
    assert_eq!(o.client_type, DEFAULT_CLIENT_TYPE);
    assert_eq!(o.sandbox_namespace, DEFAULT_SANDBOX_NAMESPACE);
}
