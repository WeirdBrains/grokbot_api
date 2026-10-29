//! Attachment upload flow against a local wiremock server (fake tokens only).
mod common;
use common::*;
use grokbot_api::{Error, SendPrompt, UploadFailure, UploadMode, UploadRefusal};
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, header_exists, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SVC: &str = "/aiserver.v1.GrokBotService/";

async fn backend(server: &MockServer, m: &str, body: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path(format!("{SVC}{m}")))
        .and(header("authorization", "Bearer cur-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn single_put_upload_then_send() {
    let s = MockServer::start().await;
    let put_url = format!("{}/bucket/obj?X-Amz-Signature=SIG", s.uri());
    Mock::given(method("POST"))
        .and(path(format!("{SVC}BeginGrokBotAttachmentUpload")))
        .and(body_partial_json(
            json!({"agentId":"a1","fileName":"t.png","sizeBytes":"4",
            "supportsStoreAttachmentRefs":true,"supportsMultipart":true}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "mode":"GROK_BOT_ATTACHMENT_UPLOAD_MODE_SINGLE_PUT","uploadToken":"ut",
            "put":{"url":put_url,"headers":{"x-amz-checksum-sha256":"abc"}}})))
        .expect(1)
        .mount(&s)
        .await;
    Mock::given(method("PUT"))
        .and(path("/bucket/obj"))
        .and(header("x-amz-checksum-sha256", "abc"))
        .respond_with(|r: &Request| {
            assert!(
                r.headers.get("authorization").is_none(),
                "bearer leaked to PUT"
            );
            assert_eq!(r.body, b"\x89PNG");
            ResponseTemplate::new(200)
        })
        .expect(1)
        .mount(&s)
        .await;
    backend(
        &s,
        "CompleteGrokBotAttachmentUpload",
        json!({"alias":"att_1","fileName":"t.png","sizeBytes":"4","contentType":"image/png"}),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/api/sendPrompt"))
        .and(body_partial_json(
            json!({"attachmentPaths":["att_1"],"attachmentNames":["t.png"]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted":true})))
        .expect(1)
        .mount(&s)
        .await;
    let c = cursor_client(&s, "gw");
    let mut seen = vec![];
    let up = c
        .upload_attachment("a1", None, "t.png", b"\x89PNG", |p| seen.push(p.sent))
        .await
        .unwrap();
    assert_eq!(up.alias, "att_1");
    assert_eq!(up.content_type, "image/png");
    assert_eq!(seen, vec![0, 4]);
    let mut req = SendPrompt::new("a1", "hi");
    req.attachment_paths = vec![up.alias];
    req.attachment_names = vec![up.name];
    c.send_prompt(&req).await.unwrap();
}

#[tokio::test]
async fn use_box_and_refused_are_typed() {
    let s = MockServer::start().await;
    backend(
        &s,
        "BeginGrokBotAttachmentUpload",
        json!({"mode":"USE_BOX","useBoxReason":"box agent"}),
    )
    .await;
    let c = cursor_client(&s, "gw");
    match c.upload_attachment("a", None, "f.txt", b"x", |_| {}).await {
        Err(Error::Attachment(UploadFailure::UseBox { reason })) => assert_eq!(reason, "box agent"),
        other => panic!("{other:?}"),
    }
    let s = MockServer::start().await;
    backend(
        &s,
        "BeginGrokBotAttachmentUpload",
        json!({"mode":4,"refusal":"GROK_BOT_ATTACHMENT_UPLOAD_REFUSAL_TOO_LARGE","limitBytes":"1"}),
    )
    .await;
    let c = cursor_client(&s, "gw");
    let e = c
        .upload_attachment("a", None, "f.txt", b"xx", |_| {})
        .await
        .unwrap_err();
    assert!(matches!(
        e,
        Error::Attachment(UploadFailure::Refused {
            reason: UploadRefusal::TooLarge,
            limit_bytes: Some(1)
        })
    ));
    assert!(e.to_string().contains("too large"));
}

#[tokio::test]
async fn needs_cursor_session() {
    let s = MockServer::start().await;
    let e = client(&s)
        .upload_attachment("a", None, "f.txt", b"x", |_| {})
        .await
        .unwrap_err();
    assert!(matches!(
        e,
        Error::Attachment(UploadFailure::NoCursorSession)
    ));
}

#[tokio::test]
async fn failed_put_aborts_and_hides_signature() {
    let s = MockServer::start().await;
    backend(
        &s,
        "BeginGrokBotAttachmentUpload",
        json!({"mode":"SINGLE_PUT","uploadToken":"ut",
        "put":{"url":format!("{}/o?sig=SECRETSIG", s.uri())}}),
    )
    .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{SVC}AbortGrokBotAttachmentUpload")))
        .and(body_partial_json(json!({"uploadToken":"ut"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&s)
        .await;
    let e = cursor_client(&s, "gw")
        .upload_attachment("a", None, "f.txt", b"x", |_| {})
        .await
        .unwrap_err();
    assert_eq!(e.status(), Some(403));
    assert!(!e.to_string().contains("SECRETSIG"));
}

#[tokio::test]
async fn non_https_put_is_refused() {
    let s = MockServer::start().await;
    backend(
        &s,
        "BeginGrokBotAttachmentUpload",
        json!({"mode":"SINGLE_PUT","uploadToken":"ut",
        "put":{"url":"http://evil.example/o"}}),
    )
    .await;
    backend(&s, "AbortGrokBotAttachmentUpload", json!({})).await;
    let e = cursor_client(&s, "gw")
        .upload_attachment("a", None, "f.txt", b"x", |_| {})
        .await
        .unwrap_err();
    assert!(matches!(e, Error::Policy(_)), "{e:?}");
}

#[tokio::test]
async fn multipart_upload() {
    let s = MockServer::start().await;
    backend(
        &s,
        "BeginGrokBotAttachmentUpload",
        json!({"mode":"MULTIPART","uploadToken":"ut","partSizeBytes":"3","partCount":2}),
    )
    .await;
    let u = s.uri();
    Mock::given(method("POST"))
        .and(path(format!("{SVC}PresignGrokBotAttachmentUploadParts")))
        .and(header_exists("authorization"))
        .respond_with(move |r: &Request| {
            let b: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
            assert_eq!(b["parts"].as_array().unwrap().len(), 2);
            ResponseTemplate::new(200).set_body_json(json!({"parts":[
                {"partNumber":1,"offsetBytes":"0","sizeBytes":"3","target":{"url":format!("{u}/p1")}},
                {"partNumber":2,"offsetBytes":"3","sizeBytes":"2","target":{"url":format!("{u}/p2")}}]}))
        })
        .mount(&s)
        .await;
    Mock::given(method("PUT"))
        .and(path("/p1"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&s)
        .await;
    Mock::given(method("PUT"))
        .and(path("/p2"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&s)
        .await;
    backend(&s, "CompleteGrokBotAttachmentUpload", json!({"alias":"m"})).await;
    let mut seen = vec![];
    let up = cursor_client(&s, "gw")
        .upload_attachment("a", None, "f.txt", b"hello", |p| seen.push(p.sent))
        .await
        .unwrap();
    assert_eq!((up.alias.as_str(), up.name.as_str()), ("m", "f.txt"));
    assert_eq!(seen, vec![0, 3, 5]);
}

#[tokio::test]
async fn resolve_reads() {
    let s = MockServer::start().await;
    backend(&s, "ResolveGrokBotAttachmentReads", json!({"reads":[
        {"path":"att_1","outcome":"GROK_BOT_ATTACHMENT_READ_OUTCOME_STORE","url":"https://h/x?sig=1",
         "contentType":"image/png","sizeBytes":"4","etag":"e"},
        {"path":"/box/p","outcome":"NOT_IN_STORE"}]})).await;
    let r = cursor_client(&s, "gw")
        .resolve_attachment_reads("a", None, &["att_1".into(), "/box/p".into()])
        .await
        .unwrap();
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].outcome, grokbot_api::ReadOutcome::Store);
    assert_eq!(r[0].size_bytes, Some(4));
    assert_eq!(r[1].outcome, grokbot_api::ReadOutcome::NotInStore);
    assert!(!format!("{:?}", r[0]).contains("sig="));
    let _ = UploadMode::SinglePut;
}

#[tokio::test]
async fn presence_calls() {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("{SVC}ReportGrokBotDesktopActivity")))
        .and(body_partial_json(json!({"installId":"i1","active":true})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"leaseMs":"90000"})))
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{SVC}ReportGrokBotClientPresence")))
        .and(body_partial_json(
            json!({"agentId":"a","viewing":true,"surface":"desktop",
            "trigger":1}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"presenceTtlMs":120000})))
        .mount(&s)
        .await;
    let c = cursor_client(&s, "gw");
    assert_eq!(
        c.report_desktop_activity("i1", true)
            .await
            .unwrap()
            .as_secs(),
        90
    );
    assert_eq!(
        c.report_client_presence("a", true, true, None)
            .await
            .unwrap()
            .as_secs(),
        120
    );
    assert!(
        client(&s)
            .report_desktop_activity("i1", true)
            .await
            .is_err()
    );
}
