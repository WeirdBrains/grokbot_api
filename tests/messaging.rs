//! sendPrompt delivery classification and promptAcceptanceStatus.
mod common;

use common::*;
use grokbot_api::*;
use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn send_with(body: Option<Value>, raw: Option<&str>) -> Result<SendReceipt> {
    let server = MockServer::start().await;
    let mut t = ResponseTemplate::new(200);
    if let Some(b) = body {
        t = t.set_body_json(b);
    }
    if let Some(r) = raw {
        t = t.set_body_string(r);
    }
    Mock::given(path("/api/sendPrompt"))
        .respond_with(t)
        .mount(&server)
        .await;
    client(&server)
        .send_prompt(&SendPrompt::new("a", "hi"))
        .await
}

#[tokio::test]
async fn refused_sends_are_rejected_422() {
    let e = send_with(
        Some(json!({"status": "refused", "message": "too long"})),
        None,
    )
    .await
    .unwrap_err();
    assert_eq!((e.status(), e.delivery()), (Some(422), Delivery::Rejected));
    assert_eq!(e.to_string(), "sendPrompt failed: 422 too long");
    let e = send_with(Some(json!({"value": {"accepted": false}})), None)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("prompt refused by the gateway"),
        "{e}"
    );
}

#[tokio::test]
async fn unrecognised_2xx_bodies_are_unknown() {
    for r in [
        send_with(None, None).await.unwrap(),
        send_with(None, Some("<html>ok</html>")).await.unwrap(),
        send_with(Some(json!({"accepted": "yes"})), None)
            .await
            .unwrap(),
    ] {
        assert_eq!(
            (r.delivery, r.message_id.as_deref()),
            (Delivery::Unknown, None)
        );
    }
}

#[tokio::test]
async fn wrapped_message_id_is_accepted() {
    let r = send_with(
        Some(json!({"status": "ok", "value": {"messageId": "m7"}})),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        (r.delivery, r.message_id.as_deref()),
        (Delivery::Accepted, Some("m7"))
    );
    assert_eq!(r.raw["value"]["messageId"], "m7");
}

#[tokio::test]
async fn acceptance_status_outcomes() {
    let server = MockServer::start().await;
    let cases = [
        (
            "n1",
            json!({"outcome": "found", "record": {"status": "accepted"}}),
            AcceptanceStatus::Accepted,
        ),
        (
            "n2",
            json!({"outcome": "found", "record": {"status": "pending"}}),
            AcceptanceStatus::Pending,
        ),
        (
            "n3",
            json!({"outcome": "found", "record": {"status": "rejected", "rejectionCode": ""}}),
            AcceptanceStatus::Rejected(None),
        ),
        (
            "n4",
            json!({"outcome": "found", "record": {"status": "not-found"}}),
            AcceptanceStatus::NotFound,
        ),
        (
            "n5",
            json!({"status": "ok", "value": {"outcome": "unknown-durability"}}),
            AcceptanceStatus::Unknown,
        ),
        (
            "n6",
            json!({"status": "accepted"}),
            AcceptanceStatus::Accepted,
        ),
        (
            "n7",
            json!({"outcome": "found", "record": {"status": "weird"}}),
            AcceptanceStatus::Unknown,
        ),
    ];
    for (nonce, body, _) in &cases {
        Mock::given(path("/api/promptAcceptanceStatus"))
            .and(body_partial_json(
                json!({"agentId": "a", "clientNonce": nonce}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(&server)
            .await;
    }
    let c = client(&server);
    for (nonce, _, want) in cases {
        assert_eq!(
            c.prompt_acceptance_status("a", nonce).await.unwrap(),
            want,
            "{nonce}"
        );
    }
}

#[tokio::test]
async fn acceptance_status_errors_propagate() {
    let server = MockServer::start().await;
    Mock::given(path("/api/promptAcceptanceStatus"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;
    let e = client(&server)
        .prompt_acceptance_status("a", "n")
        .await
        .unwrap_err();
    assert_eq!(e.status(), Some(502));
}

#[test]
fn delivery_display() {
    assert_eq!(Delivery::Accepted.to_string(), "accepted");
    assert_eq!(Delivery::Rejected.to_string(), "rejected");
    assert_eq!(Delivery::Unknown.to_string(), "unknown");
}

#[test]
fn send_prompt_builder() {
    let p = SendPrompt::new("a", "b");
    assert_eq!((p.agent_id.as_str(), p.prompt.as_str()), ("a", "b"));
    assert!(p.client_nonce.is_none() && p.reply_to_id.is_none());
}
