//! Tests against a local wiremock server. No real network.
use grokbot_api::*;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn opts(server: &MockServer) -> ClientOptions {
    ClientOptions {
        policy: Policy::local_testing(),
        backend_base: server.uri(),
        ..Default::default()
    }
}

async fn client(server: &MockServer) -> Client {
    let s = Session::new(server.uri(), "gw-tok")
        .with_headers([("X-Extra".to_string(), "1".to_string())].into());
    Client::new(s, opts(server)).unwrap()
}

#[tokio::test]
async fn list_agents_sends_auth_and_extra_headers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/listAgents"))
        .and(header("authorization", "Bearer gw-tok"))
        .and(header("x-extra", "1"))
        .and(header("content-type", "application/json"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"agents": [
            {"id": "a1", "name": "Helper", "description": "d"},
            {"agentId": "a2", "title": "T", "isHiddenFromSidebar": true},
            {"id": "g1", "name": "Team", "memberAgentIds": ["a1"]},
            {"name": "no id"}
        ]})))
        .expect(1)
        .mount(&server)
        .await;
    let agents = client(&server).await.list_agents().await.unwrap();
    assert_eq!(agents.len(), 3);
    assert_eq!(agents[1].id, "a2");
    assert_eq!(agents[1].display_name(), "T");
    assert_eq!(agents[1].hidden_from_sidebar, Some(true));
    assert!(agents[2].is_group);
}

#[tokio::test]
async fn bare_array_list() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id": "x", "name": "X"}])))
        .mount(&server)
        .await;
    assert_eq!(
        client(&server).await.list_agents().await.unwrap()[0].name,
        "X"
    );
}

#[tokio::test]
async fn send_prompt_receipt_and_delivery_states() {
    let server = MockServer::start().await;
    Mock::given(path("/api/sendPrompt"))
        .and(body_partial_json(
            json!({"agentId": "a1", "prompt": "hi", "clientNonce": "n1", "replyToId": "r0"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"messageId": "m1"})))
        .mount(&server)
        .await;
    Mock::given(path("/api/sendPrompt"))
        .and(body_partial_json(json!({"prompt": "boom"})))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({"error": "overloaded"})))
        .mount(&server)
        .await;
    Mock::given(path("/api/sendPrompt"))
        .and(body_partial_json(json!({"prompt": "bad"})))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"message": "nope"})))
        .mount(&server)
        .await;
    Mock::given(path("/api/sendPrompt"))
        .and(body_partial_json(
            json!({"prompt": "real", "clientNonce": "n9"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted": true})))
        .mount(&server)
        .await;
    Mock::given(path("/api/sendPrompt"))
        .and(body_partial_json(json!({"prompt": "noreceipt"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let c = client(&server).await;
    let r = c
        .send_prompt(&SendPrompt {
            agent_id: "a1".into(),
            prompt: "hi".into(),
            client_nonce: Some("n1".into()),
            reply_to_id: Some("r0".into()),
        })
        .await
        .unwrap();
    assert_eq!(
        (r.message_id.as_deref(), r.delivery),
        (Some("m1"), Delivery::Accepted)
    );

    let e = c
        .send_prompt(&SendPrompt::new("a1", "boom"))
        .await
        .unwrap_err();
    assert_eq!(e.delivery(), Delivery::Unknown);
    assert!(e.to_string().contains("503 overloaded"));
    let e = c
        .send_prompt(&SendPrompt::new("a1", "bad"))
        .await
        .unwrap_err();
    assert_eq!(e.delivery(), Delivery::Rejected);
    let r = c
        .send_prompt(&SendPrompt {
            agent_id: "a1".into(),
            prompt: "real".into(),
            client_nonce: Some("n9".into()),
            reply_to_id: None,
        })
        .await
        .unwrap();
    assert_eq!(
        (r.message_id.as_deref(), r.delivery),
        (Some("n9"), Delivery::Accepted),
        "the gateway's real success shape is accepted"
    );
    let r = c
        .send_prompt(&SendPrompt::new("a1", "noreceipt"))
        .await
        .unwrap();
    assert_eq!(r.delivery, Delivery::Unknown);
    assert_eq!(r.client_nonce.len(), 36, "uuid generated");
}

#[tokio::test]
async fn network_error_is_delivery_unknown() {
    let uri = "http://127.0.0.1:1".to_string(); // nothing listening
    let c = Client::new(
        Session::new(uri, "t"),
        ClientOptions {
            policy: Policy::local_testing(),
            ..Default::default()
        },
    )
    .unwrap();
    let e = c.send_prompt(&SendPrompt::new("a", "x")).await.unwrap_err();
    assert!(matches!(e, Error::Transport { .. }), "{e:?}");
    assert_eq!(e.delivery(), Delivery::Unknown);
}

#[tokio::test]
async fn transcript_and_thread() {
    let server = MockServer::start().await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_json(json!({"id": "a1", "limit": 200})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entries": [
            {"id": "e1", "kind": "user-prompt", "prompt": "hi"},
            {"id": "e2", "kind": "send-message", "message": {"type": "text", "content": "hello"}}
        ]})))
        .mount(&server)
        .await;
    Mock::given(path("/api/getAgentThread"))
        .and(body_json(json!({"id": "a1", "rootId": "e1"})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"entries": [{"id": "t1", "text": "x"}]})),
        )
        .mount(&server)
        .await;
    let c = client(&server).await;
    let t = c.transcript_tail("a1", 9999, None).await.unwrap(); // clamped to 200
    assert_eq!(t.entries.len(), 2);
    assert!(t.entries[0].is_from_user());
    assert_eq!(t.entries[1].text, "hello");
    assert_eq!(c.thread("a1", "e1").await.unwrap().entries[0].text, "x");
}

#[tokio::test]
async fn transcript_history_pages_with_before_seq() {
    let server = MockServer::start().await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_json(json!({"id": "a1", "limit": 2})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entries": [
                {"id": "a", "kind": "send-message", "message": {"content": "older"}},
                {"id": "b", "kind": "send-message", "message": {"content": "newer"}}
            ],
            "nextBeforeSeq": 10
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_json(json!({"id": "a1", "limit": 2, "beforeSeq": 10})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "entries": [
                {"id": "z", "kind": "send-message", "message": {"content": "oldest"}}
            ]
        })))
        .mount(&server)
        .await;
    let c = client(&server).await;
    let t = c.transcript_history("a1", 2, 100).await.unwrap();
    let texts: Vec<_> = t.entries.iter().map(|e| e.text.as_str()).collect();
    assert_eq!(texts, ["oldest", "older", "newer"]);
}

#[tokio::test]
async fn all_mutating_methods_send_expected_bodies() {
    let server = MockServer::start().await;
    let ok = || ResponseTemplate::new(200).set_body_json(json!({"ok": true}));
    let cases: Vec<(&str, Value)> = vec![
        (
            "createAgent",
            json!({"name": "N", "description": "", "title": "", "avatarShape": "hex", "avatarColor": "", "origin": "user"}),
        ),
        (
            "updateAgent",
            json!({"id": "a1", "profile": {"name": "N2", "description": "D", "avatarColor": "red"}}),
        ),
        ("deleteAgent", json!({"id": "a1"})),
        (
            "setAgentNotifyOnUpdates",
            json!({"id": "a1", "isEnabled": true}),
        ),
        (
            "setAgentHiddenFromSidebar",
            json!({"id": "a1", "isHidden": false}),
        ),
        (
            "createGroup",
            json!({"name": "G", "description": "", "memberAgentIds": ["a1", "a2"]}),
        ),
        (
            "setGroupMembers",
            json!({"id": "g1", "memberAgentIds": ["a1"]}),
        ),
        ("getAgentWorkflows", json!({"id": "a1"})),
        (
            "importAgentWorkflowText",
            json!({"id": "a1", "markdown": "# skill"}),
        ),
        (
            "deleteAgentWorkflow",
            json!({"id": "a1", "workflowId": "w1"}),
        ),
        (
            "resolveLocalToolPermission",
            json!({"agentId": "a1", "entryId": "e1", "requestId": "r1", "resolution": "allow-once"}),
        ),
        (
            "resolveAutoReviewApproval",
            json!({"agentId": "a1", "entryId": "e1", "requestId": "r1", "resolution": "denied"}),
        ),
    ];
    for (m, body) in &cases {
        Mock::given(path(format!("/api/{m}")))
            .and(body_json(body.clone()))
            .respond_with(ok())
            .expect(1)
            .mount(&server)
            .await;
    }
    let c = client(&server).await;
    c.create_agent(&CreateAgent {
        name: "N".into(),
        avatar_shape: "hex".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    c.update_agent(
        "a1",
        &AgentProfile {
            name: " N2 ".into(),
            description: "D".into(),
            avatar_color: Some("red".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    c.delete_agent("a1").await.unwrap();
    c.set_agent_notify_on_updates("a1", true).await.unwrap();
    c.set_agent_hidden_from_sidebar("a1", false).await.unwrap();
    c.create_group(&CreateGroup {
        name: "G".into(),
        member_agent_ids: vec!["a1".into(), "a2".into(), "a1".into()],
        ..Default::default()
    })
    .await
    .unwrap();
    c.set_group_members("g1", &["a1".into()]).await.unwrap();
    c.get_agent_workflows("a1").await.unwrap();
    c.import_agent_workflow_text("a1", "# skill").await.unwrap();
    c.delete_agent_workflow("a1", "w1").await.unwrap();
    c.resolve_local_tool_permission("a1", "e1", "r1", LocalToolResolution::AllowOnce)
        .await
        .unwrap();
    c.resolve_auto_review_approval("a1", "e1", "r1", AutoReviewResolution::Denied)
        .await
        .unwrap();
    // `expect(1)` on each mock is verified when the server drops.
}

#[tokio::test]
async fn workflows_and_import_parsing() {
    let server = MockServer::start().await;
    Mock::given(path("/api/getAgentWorkflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"workflows": [
            {"id": "w1", "name": "S", "source": "plugin", "pluginId": "p"}, {"id": 7}, {"name": "no id"}]})))
        .mount(&server)
        .await;
    Mock::given(path("/api/importAgentWorkflowText"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "workflows": [{"id": "w2", "name": "New"}],
            "result": {"imported": [{"id": "w2", "name": "New"}], "skipped": [{"reason": "dup"}]}})))
        .mount(&server)
        .await;
    let c = client(&server).await;
    let w = c.get_agent_workflows("a").await.unwrap();
    assert_eq!(w.len(), 2);
    assert_eq!(w[0].plugin_id.as_deref(), Some("p"));
    assert_eq!(w[1].id, "7");
    assert_eq!(w[1].source, "workflow");
    let r = c.import_agent_workflow_text("a", "x").await.unwrap();
    assert_eq!(r.imported[0].id, "w2");
    assert_eq!(r.skipped[0].reason, "dup");
}

#[tokio::test]
async fn local_validation_never_hits_server() {
    let server = MockServer::start().await;
    let c = client(&server).await;
    assert!(matches!(
        c.create_agent(&CreateAgent::default()).await,
        Err(Error::Validation(_))
    ));
    let bad = CreateAgent {
        name: "x".into(),
        avatar_shape: "triangle".into(),
        ..Default::default()
    };
    assert!(matches!(
        c.create_agent(&bad).await,
        Err(Error::Validation(_))
    ));
    let too_many: Vec<String> = (0..7).map(|i| i.to_string()).collect();
    assert!(c.set_group_members("g", &too_many).await.is_err());
    assert!(c.set_group_members("g", &[]).await.is_err());
    assert!(c.import_agent_workflow_text("a", "  ").await.is_err());
    assert_eq!(
        c.send_prompt(&SendPrompt::new("a", ""))
            .await
            .unwrap_err()
            .delivery(),
        Delivery::Rejected
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn ensure_sandbox_headers_and_session() {
    let server = MockServer::start().await;
    Mock::given(path("/aiserver.v1.GrokBotService/EnsureSandBox"))
        .and(header("authorization", "Bearer cur-tok"))
        .and(header("connect-protocol-version", "1"))
        .and(header("x-cursor-client-type", "sand"))
        .and(header("x-cursor-client-version", "0.70.2"))
        .and(header("x-sand-box-namespace", "prod"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "gateway_url": format!("{}/", server.uri()), "gateway_token": "gw", "anyrunNetworkToken": "net"})))
        .mount(&server)
        .await;
    let s = ensure_sandbox("cur-tok", &opts(&server)).await.unwrap();
    assert_eq!(s.gateway_url, server.uri());
    assert_eq!(s.gateway_token, "gw");
    assert_eq!(
        s.headers.get("x-anyrun-network-token").map(String::as_str),
        Some("net")
    );
}

#[tokio::test]
async fn ensure_sandbox_errors() {
    let server = MockServer::start().await;
    Mock::given(path("/aiserver.v1.GrokBotService/EnsureSandBox"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"gatewayUrl": "https://evil.example", "gatewayToken": "x"})),
        )
        .mount(&server)
        .await;
    // Gateway URL from EnsureSandBox must pass the allowlist too.
    let o = ClientOptions {
        policy: Policy {
            allow_local_gateway: false,
            allow_local_backend: true,
        },
        backend_base: server.uri(),
        ..Default::default()
    };
    assert!(matches!(
        ensure_sandbox("t", &o).await,
        Err(Error::Policy(_))
    ));
    // Default policy refuses a loopback backend outright (token never sent).
    let o = ClientOptions {
        policy: Policy::default(),
        backend_base: server.uri(),
        ..Default::default()
    };
    assert!(matches!(
        ensure_sandbox("t", &o).await,
        Err(Error::Policy(_))
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);

    let server = MockServer::start().await;
    Mock::given(path("/aiserver.v1.GrokBotService/EnsureSandBox"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": 1})))
        .mount(&server)
        .await;
    assert!(matches!(
        ensure_sandbox("t", &opts(&server)).await,
        Err(Error::InvalidResponse { .. })
    ));
}

#[tokio::test]
async fn unauthorized_triggers_one_reexchange_and_retry() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .and(header("authorization", "Bearer old"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": "expired old"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/aiserver.v1.GrokBotService/EnsureSandBox"))
        .and(header("authorization", "Bearer cur"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"gatewayUrl": server.uri(), "gatewayToken": "new"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/listAgents"))
        .and(header("authorization", "Bearer new"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id": "a"}])))
        .expect(1)
        .mount(&server)
        .await;
    let c =
        Client::with_cursor_token(Session::new(server.uri(), "old"), "cur", opts(&server)).unwrap();
    assert_eq!(c.list_agents().await.unwrap().len(), 1);
    assert_eq!(c.take_refreshed_session().unwrap().gateway_token, "new");
    assert!(c.take_refreshed_session().is_none());
    assert_eq!(c.session().gateway_token, "new");
}

#[tokio::test]
async fn unauthorized_without_cursor_token_is_returned_and_redacted() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"message": "token gw-tok is invalid"})),
        )
        .mount(&server)
        .await;
    let e = client(&server).await.list_agents().await.unwrap_err();
    assert!(e.is_unauthorized());
    assert!(!e.to_string().contains("gw-tok"), "{e}");
}

#[tokio::test]
async fn redirects_refused_and_size_capped() {
    let server = MockServer::start().await;
    Mock::given(path("/api/listAgents"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "https://evil.example/"))
        .mount(&server)
        .await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .respond_with(move |_: &Request| {
            ResponseTemplate::new(200).set_body_string("x".repeat(MAX_RESPONSE_BYTES + 10))
        })
        .mount(&server)
        .await;
    let c = client(&server).await;
    assert!(matches!(
        c.list_agents().await,
        Err(Error::Transport { .. })
    ));
    assert!(matches!(
        c.transcript_tail("a", 1, None).await,
        Err(Error::TooLarge { .. })
    ));
}

#[tokio::test]
async fn policy_blocks_disallowed_gateway() {
    assert!(matches!(
        Client::new(
            Session::new("https://evil.example", "t"),
            ClientOptions::default()
        ),
        Err(Error::Policy(_))
    ));
    assert!(
        Client::new(
            Session::new("https://box.us1.cursorvm.com", "t"),
            ClientOptions::default()
        )
        .is_ok()
    );
}

#[tokio::test]
async fn team_agents_listed_from_backend_and_routed_with_viewer_session() {
    let server = MockServer::start().await;
    Mock::given(path("/aiserver.v1.GrokBotService/ListGrokBotTeamAgents"))
        .and(header("authorization", "Bearer cur"))
        .and(header("connect-protocol-version", "1"))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entries": [
            {"agent": {"agentId": "mine", "name": "Rocky", "viewerIsOwner": true, "viewerSessionId": "x"}},
            {"agent": {"agentId": "chomp", "name": "Chomp", "viewerIsOwner": false,
                       "visibility": "GROK_BOT_AGENT_VISIBILITY_TEAM", "viewerSessionId": "vs1"}}
        ]})))
        .expect(1)
        .mount(&server)
        .await;
    // Shared agent: transcript and send carry the viewer session.
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_partial_json(
            json!({"id": "chomp", "sessionId": "vs1"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entries": []})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/sendPrompt"))
        .and(body_partial_json(
            json!({"agentId": "chomp", "sessionId": "vs1"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted": true})))
        .expect(1)
        .mount(&server)
        .await;
    // Own agent: no sessionId.
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_json(json!({"id": "mine", "limit": 5})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entries": []})))
        .expect(1)
        .mount(&server)
        .await;
    let c =
        Client::with_cursor_token(Session::new(server.uri(), "gw"), "cur", opts(&server)).unwrap();
    let team = c.list_team_agents().await.unwrap().unwrap();
    assert_eq!(team.len(), 2);
    assert!(!team[1].viewer_is_owner && team[1].team_visible);
    c.transcript_tail("chomp", 5, None).await.unwrap();
    c.transcript_tail("mine", 5, None).await.unwrap();
    c.send_prompt(&SendPrompt::new("chomp", "hi"))
        .await
        .unwrap();

    // A plain gateway session has no Cursor token: no team list, no backend call.
    let plain = Client::new(Session::new(server.uri(), "gw"), opts(&server)).unwrap();
    assert!(plain.list_team_agents().await.unwrap().is_none());
}
