//! Agents, groups, team agents, and workflows (skills).
mod common;

use common::*;
use grokbot_api::*;
use serde_json::json;
use wiremock::matchers::{body_json, body_partial_json, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn respond(server: &MockServer, method: &str, body: serde_json::Value) {
    Mock::given(path(format!("/api/{method}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn list_agents_response_shapes() {
    let server = MockServer::start().await;
    respond(
        &server,
        "listAgents",
        json!({"agent": {"id": "solo", "notifyOnAgentUpdates": false}}),
    )
    .await;
    let c = client(&server);
    let list = c.list_agents().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].notify_on_updates, Some(false));
    assert_eq!(list[0].display_name(), "solo", "falls back to the id");

    let server = MockServer::start().await;
    respond(&server, "listAgents", json!({"unexpected": true})).await;
    assert!(client(&server).list_agents().await.unwrap().is_empty());
}

#[test]
fn agent_parsing_details() {
    let a = Agent::from_value(&json!({
        "id": "g", "name": "", "title": "", "isGroup": false, "memberIds": ["x", 5],
        "avatarShape": "hex", "avatarColor": "red", "notifyOnUpdatesEnabled": true,
        "hiddenFromSidebar": true
    }))
    .unwrap();
    assert!(!a.is_group, "explicit isGroup wins over members");
    assert_eq!(a.member_ids, vec!["x"]);
    assert_eq!(
        (a.avatar_shape.as_str(), a.avatar_color.as_str()),
        ("hex", "red")
    );
    assert_eq!(
        (a.notify_on_updates, a.hidden_from_sidebar),
        (Some(true), Some(true))
    );
    assert!(Agent::from_value(&json!({"id": ""})).is_none());
}

#[tokio::test]
async fn create_agent_returns_the_created_agent() {
    let server = MockServer::start().await;
    Mock::given(path("/api/createAgent"))
        .and(body_json(
            json!({"name": "Bot", "description": "d", "title": "t",
            "avatarShape": "", "avatarColor": "blue", "origin": "user"}),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"agent": {"id": "new1", "name": "Bot"}})),
        )
        .mount(&server)
        .await;
    let c = client(&server);
    let a = c
        .create_agent(&CreateAgent {
            name: "Bot".into(),
            description: "d".into(),
            title: "t".into(),
            avatar_shape: "  ".into(),
            avatar_color: " blue ".into(),
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a.id, "new1");
}

#[tokio::test]
async fn create_agent_without_echo_is_none() {
    let server = MockServer::start().await;
    respond(&server, "createAgent", json!({"ok": true})).await;
    let r = client(&server)
        .create_agent(&CreateAgent {
            name: "x".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(r.is_none());
}

#[tokio::test]
async fn update_agent_optional_fields_and_validation() {
    let server = MockServer::start().await;
    Mock::given(path("/api/updateAgent"))
        .and(body_json(
            json!({"id": "a1", "profile": {"name": "N", "description": "",
            "title": "T", "avatarShape": "leaf"}}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    let p = AgentProfile {
        name: "N".into(),
        title: Some("T".into()),
        avatar_shape: Some("leaf".into()),
        ..Default::default()
    };
    assert_eq!(c.update_agent("a1", &p).await.unwrap(), json!({"ok": true}));

    for bad in [
        AgentProfile {
            name: " ".into(),
            ..Default::default()
        },
        AgentProfile {
            name: "n".into(),
            avatar_shape: Some("cube".into()),
            ..Default::default()
        },
        AgentProfile {
            name: "n".into(),
            avatar_color: Some("pink".into()),
            ..Default::default()
        },
    ] {
        let e = c.update_agent("a1", &bad).await.unwrap_err();
        assert!(matches!(e, Error::Validation(_)), "{e:?}");
        assert_eq!(e.delivery(), Delivery::Rejected);
    }
}

#[tokio::test]
async fn avatar_validation_lists_allowed_values() {
    let server = MockServer::start().await;
    let e = client(&server)
        .create_agent(&CreateAgent {
            name: "n".into(),
            avatar_color: "pink".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    let msg = e.to_string();
    assert!(msg.contains("Unknown avatar color \"pink\""), "{msg}");
    for c in AVATAR_COLORS {
        assert!(msg.contains(c), "{msg}");
    }
    assert!(AVATAR_SHAPES.contains(&"hex"));
}

#[tokio::test]
async fn groups_validate_members_and_return_the_group() {
    let server = MockServer::start().await;
    respond(
        &server,
        "createGroup",
        json!({"id": "g1", "memberIds": ["a", "b"]}),
    )
    .await;
    respond(
        &server,
        "setGroupMembers",
        json!({"agent": {"id": "g1", "memberIds": ["a"]}}),
    )
    .await;
    let c = client(&server);
    let g = c
        .create_group(&CreateGroup {
            name: "G".into(),
            member_agent_ids: vec!["a".into(), "".into(), "b".into()],
            ..Default::default()
        })
        .await
        .unwrap()
        .unwrap();
    assert!(g.is_group);
    let g = c
        .set_group_members("g1", &["a".into()])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(g.member_ids, vec!["a"]);

    let seven: Vec<String> = (0..=MAX_GROUP_MEMBERS).map(|i| format!("m{i}")).collect();
    let e = c
        .create_group(&CreateGroup {
            member_agent_ids: seven,
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert!(e.to_string().contains("at most 6"), "{e}");
    let e = c.create_group(&CreateGroup::default()).await.unwrap_err();
    assert!(e.to_string().contains("at least one"), "{e}");
}

#[tokio::test]
async fn notify_and_hidden_flags() {
    let server = MockServer::start().await;
    Mock::given(path("/api/setAgentNotifyOnUpdates"))
        .and(body_json(json!({"id": "a", "isEnabled": false})))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/setAgentHiddenFromSidebar"))
        .and(body_json(json!({"id": "a", "isHidden": true})))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    c.set_agent_notify_on_updates("a", false).await.unwrap();
    c.set_agent_hidden_from_sidebar("a", true).await.unwrap();
}

#[tokio::test]
async fn team_agents_parsing_and_session_routing() {
    let server = MockServer::start().await;
    Mock::given(path("/aiserver.v1.GrokBotService/ListGrokBotTeamAgents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entries": [
            {"agent": {"agentId": "room1", "kind": "GROK_BOT_AGENT_KIND_ROOM",
                       "viewerIsOwner": false, "viewerSessionId": "  vs-room  ",
                       "ownerDisplayName": " Pat "}},
            {"agent": {"agentId": "shared-no-session", "viewerIsOwner": false}},
            {"agent": {"name": "missing id"}},
            {"notAnAgent": {}}
        ]})))
        .mount(&server)
        .await;
    Mock::given(path("/api/promptAcceptanceStatus"))
        .and(body_json(
            json!({"agentId": "room1", "clientNonce": "n", "sessionId": "vs-room"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"outcome": "not-found"})))
        .expect(1)
        .mount(&server)
        .await;
    let c = cursor_client(&server, "gw");
    let team = c.list_team_agents().await.unwrap().unwrap();
    assert_eq!(team.len(), 2);
    assert!(team[0].is_room && !team[0].team_visible);
    assert_eq!(team[0].viewer_session_id.as_deref(), Some("vs-room"));
    assert_eq!(team[0].owner_display_name.as_deref(), Some("Pat"));
    assert_eq!(team[1].viewer_session_id, None);
    assert_eq!(
        c.prompt_acceptance_status("room1", "n").await.unwrap(),
        AcceptanceStatus::NotFound
    );
    assert!(TeamAgent::list(&json!({})).is_empty());
}

#[tokio::test]
async fn team_agents_backend_error() {
    let server = MockServer::start().await;
    Mock::given(path("/aiserver.v1.GrokBotService/ListGrokBotTeamAgents"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "not on a team"})))
        .mount(&server)
        .await;
    let e = cursor_client(&server, "gw")
        .list_team_agents()
        .await
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "ListGrokBotTeamAgents failed: 403 not on a team"
    );
}

#[tokio::test]
async fn manual_agent_session_is_sent() {
    let server = MockServer::start().await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .and(body_partial_json(json!({"id": "x", "sessionId": "s1"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"entries": []})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    c.set_agent_session("x", "s1");
    c.transcript_tail("x", 10, None).await.unwrap();
}

#[tokio::test]
async fn workflows_shapes_and_import_results() {
    let server = MockServer::start().await;
    respond(
        &server,
        "getAgentWorkflows",
        json!([
            {"id": "w1", "source": "managed", "sourceRef": "ref", "description": "d"},
            {"id": true}, {"id": ""}
        ]),
    )
    .await;
    Mock::given(path("/api/importAgentWorkflowText"))
        .and(body_partial_json(json!({"markdown": "# one"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"result": {"skipped": [{}]}})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/api/importAgentWorkflowText"))
        .and(body_partial_json(json!({"markdown": "# two"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;
    let c = client(&server);
    let w = c.get_agent_workflows("a").await.unwrap();
    assert_eq!(w.len(), 1);
    assert_eq!(
        (w[0].source.as_str(), w[0].source_ref.as_deref()),
        ("managed", Some("ref"))
    );
    let r = c.import_agent_workflow_text("a", "# one").await.unwrap();
    assert_eq!(r.skipped[0].reason, "rejected", "default reason");
    assert!(r.imported.is_empty() && r.workflows.is_empty());
    assert_eq!(
        c.import_agent_workflow_text("a", "# two").await.unwrap(),
        ImportResult::default()
    );
}

#[tokio::test]
async fn workflow_import_length_limit() {
    let server = MockServer::start().await;
    let c = client(&server);
    let too_long = "x".repeat(SKILL_MAX_BODY_LENGTH + 1);
    let e = c
        .import_agent_workflow_text("a", &too_long)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("exceeds 100000 characters"), "{e}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn delete_workflow_and_resolutions() {
    let server = MockServer::start().await;
    Mock::given(path("/api/resolveLocalToolPermission"))
        .and(body_partial_json(json!({"resolution": "deny"})))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/api/resolveAutoReviewApproval"))
        .and(body_partial_json(json!({"resolution": "approved"})))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    c.resolve_local_tool_permission("a", "e", "r", LocalToolResolution::Deny)
        .await
        .unwrap();
    c.resolve_auto_review_approval("a", "e", "r", AutoReviewResolution::Approved)
        .await
        .unwrap();
    assert_eq!(LocalToolResolution::AllowOnce.as_str(), "allow-once");
    assert_eq!(AutoReviewResolution::Denied.as_str(), "denied");
}

#[tokio::test]
async fn call_raw_reaches_any_method() {
    let server = MockServer::start().await;
    Mock::given(path("/api/someFutureMethod"))
        .and(body_json(json!({"a": [1, 2]})))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;
    let v = client(&server)
        .call_raw("someFutureMethod", json!({"a": [1, 2]}))
        .await
        .unwrap();
    assert_eq!(v, json!({"raw": "not json"}));
}
