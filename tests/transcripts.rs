//! Transcript paging, history walking, entry parsing, approvals and sanitizing.
mod common;

use common::*;
use grokbot_api::*;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn page(entries: Value, next: Option<u64>) -> ResponseTemplate {
    let mut b = json!({ "entries": entries });
    if let Some(n) = next {
        b["nextBeforeSeq"] = json!(n);
    }
    ResponseTemplate::new(200).set_body_json(b)
}

#[tokio::test]
async fn tail_passes_before_seq_and_clamps_limit() {
    let server = MockServer::start().await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_json(json!({"id": "a", "limit": 1, "beforeSeq": 42})))
        .respond_with(page(json!([{"id": "e", "text": "t"}]), Some(41)))
        .expect(1)
        .mount(&server)
        .await;
    let t = client(&server)
        .transcript_tail("a", 0, Some(42))
        .await
        .unwrap();
    assert_eq!(t.next_before_seq, Some(41));
    assert_eq!(t.raw["entries"][0]["id"], "e");
}

#[tokio::test]
async fn history_stops_on_an_empty_page() {
    let server = MockServer::start().await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .respond_with(page(json!([]), Some(5)))
        .expect(1)
        .mount(&server)
        .await;
    let t = client(&server)
        .transcript_history("a", 50, 100)
        .await
        .unwrap();
    assert!(t.entries.is_empty());
    assert_eq!(t.raw["pages"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn history_keeps_the_newest_max_entries() {
    let server = MockServer::start().await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_json(json!({"id": "a", "limit": 200})))
        .respond_with(page(json!([{"id": "3"}, {"id": "4"}]), Some(3)))
        .mount(&server)
        .await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_json(json!({"id": "a", "limit": 200, "beforeSeq": 3})))
        .respond_with(page(json!([{"id": "1"}, {"id": "2"}]), Some(1)))
        .mount(&server)
        .await;
    let t = client(&server)
        .transcript_history("a", 500, 3)
        .await
        .unwrap();
    let ids: Vec<_> = t.entries.iter().map(|e| e.id.clone().unwrap()).collect();
    assert_eq!(ids, ["2", "3", "4"]);
    assert_eq!(t.next_before_seq, Some(3), "where the walk stopped");
}

#[tokio::test]
async fn history_dedupes_ids_but_keeps_idless_entries() {
    let server = MockServer::start().await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_json(json!({"id": "a", "limit": 2})))
        .respond_with(page(json!([{"id": "b"}, {"text": "no id"}]), Some(9)))
        .mount(&server)
        .await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_json(json!({"id": "a", "limit": 2, "beforeSeq": 9})))
        .respond_with(page(
            json!([{"id": "a"}, {"id": "b"}, {"text": "no id"}]),
            None,
        ))
        .mount(&server)
        .await;
    let t = client(&server)
        .transcript_history("a", 2, 100)
        .await
        .unwrap();
    let got: Vec<_> = t
        .entries
        .iter()
        .map(|e| e.id.clone().unwrap_or_else(|| e.text.clone()))
        .collect();
    assert_eq!(got, ["a", "b", "no id", "no id"]);
}

#[tokio::test]
async fn history_propagates_page_errors() {
    let server = MockServer::start().await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    assert_eq!(
        client(&server)
            .transcript_history("a", 2, 10)
            .await
            .unwrap_err()
            .status(),
        Some(500)
    );
}

#[tokio::test]
async fn missing_entries_field_is_an_empty_page() {
    let server = MockServer::start().await;
    Mock::given(path("/api/getAgentThread"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"nextBeforeSeq": "x"})))
        .mount(&server)
        .await;
    let t = client(&server).thread("a", "root").await.unwrap();
    assert!(t.entries.is_empty() && t.next_before_seq.is_none());
}

#[test]
fn entry_text_shapes() {
    let t = |v: Value| Entry::from_value(&v).text;
    assert_eq!(t(json!("not an object")), "");
    assert_eq!(t(json!({"message": "plain message"})), "plain message");
    assert_eq!(t(json!({"content": "string content"})), "string content");
    assert_eq!(t(json!({"content": {"text": "obj text"}})), "obj text");
    assert_eq!(t(json!({"content": {"k": 1}})), r#"{"k":1}"#);
    assert_eq!(t(json!({"content": [{"other": 1}, null, "", "a"]})), "a");
    assert_eq!(t(json!({"content": 5, "preview": "p"})), "p");
    assert_eq!(t(json!({"text": "", "prompt": "", "preview": ""})), "");
    let e = Entry::from_value(&json!({"sender": "Human", "id": 3}));
    assert_eq!(e.role, "Human");
    assert!(e.is_from_user());
    assert_eq!(e.id, None, "non-string ids are ignored");
    assert!(Entry::from_value(&json!({"type": "prompt"})).is_from_user());
}

fn card(kind: &str, card_key: &str, card: Value) -> Entry {
    Entry::from_value(&json!({
        "id": "e1", "kind": "send-message",
        "message": {"type": kind, card_key: card}
    }))
}

#[test]
fn auto_review_approval_with_truncated_details() {
    let long = "x".repeat(3000);
    let e = card(
        "auto-review-approval",
        "approval",
        json!({"status": "pending", "requestId": "r9", "summary": long, "target": "prod", "ignored": "y"}),
    );
    let a = e.approval().unwrap();
    assert_eq!(a.kind, ApprovalKind::AutoReview);
    assert_eq!(a.request_id, "r9");
    assert!(a.truncated);
    assert_eq!(a.details["summary"].chars().count(), 2048);
    assert_eq!(a.details["target"], "prod");
    assert!(!a.details.contains_key("ignored"));
}

#[test]
fn approvals_that_do_not_count() {
    let pending = json!({"status": "pending", "requestId": "r"});
    assert!(
        card("auto-review-approval", "ask", pending.clone())
            .approval()
            .is_none(),
        "wrong card key"
    );
    assert!(
        card("something-else", "ask", pending.clone())
            .approval()
            .is_none()
    );
    assert!(
        card("local-tool-permission", "ask", json!({"status": "pending"}))
            .approval()
            .is_none()
    );
    assert!(
        card(
            "local-tool-permission",
            "ask",
            json!({"status": "pending", "requestId": "r".repeat(1025)})
        )
        .approval()
        .is_none()
    );
    assert!(
        Entry::from_value(&json!({"id": "e", "kind": "send-message"}))
            .approval()
            .is_none()
    );
    assert!(
        Entry::from_value(&json!({"id": "e", "kind": "user-prompt",
        "message": {"type": "local-tool-permission", "ask": pending.clone()}}))
        .approval()
        .is_none()
    );
    assert!(
        Entry::from_value(&json!({"kind": "send-message",
        "message": {"type": "local-tool-permission", "ask": pending}}))
        .approval()
        .is_none(),
        "no entry id"
    );
    let ok = card(
        "local-tool-permission",
        "ask",
        json!({"status": "pending", "requestId": "r"}),
    )
    .approval()
    .unwrap();
    assert!(!ok.truncated && ok.details.is_empty());
}

#[test]
fn sanitize_escape_sequences() {
    assert_eq!(
        sanitize_text("a\u{1b}]8;;http://x\u{1b}\\link\u{1b}]8;;\u{1b}\\b"),
        "alinkb"
    );
    assert_eq!(
        sanitize_text("x\u{1b}(By"),
        "xBy",
        "unknown escapes drop only ESC and the next char"
    );
    assert_eq!(sanitize_text("tail\u{1b}"), "tail");
    assert_eq!(sanitize_text("\u{1b}[1;2"), "", "unterminated CSI");
    assert_eq!(sanitize_text("\u{1b}]title"), "", "unterminated OSC");
    assert_eq!(sanitize_text("é\r\u{7f}ok"), "éok");
}
