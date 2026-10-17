//! A complete, offline tour of the client against a local mock gateway.
//!
//! ```sh
//! cargo run --example mock_gateway
//! ```
//!
//! Nothing leaves your machine: a wiremock server plays the gateway, and the token is fake.
use grokbot_api::{AcceptanceStatus, Client, ClientOptions, Delivery, Policy, SendPrompt, Session};
use serde_json::json;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::main]
async fn main() -> grokbot_api::Result<()> {
    let gateway = MockServer::start().await;
    let reply = |body: serde_json::Value| ResponseTemplate::new(200).set_body_json(body);
    Mock::given(path("/api/listAgents"))
        .respond_with(reply(json!({"agents": [
            {"id": "helper", "name": "Helper", "description": "Answers questions"},
            {"id": "team", "name": "Team", "memberAgentIds": ["helper"]}
        ]})))
        .mount(&gateway)
        .await;
    Mock::given(path("/api/sendPrompt"))
        .respond_with(reply(json!({"accepted": true})))
        .mount(&gateway)
        .await;
    Mock::given(path("/api/promptAcceptanceStatus"))
        .respond_with(reply(
            json!({"outcome": "found", "record": {"status": "accepted"}}),
        ))
        .mount(&gateway)
        .await;
    Mock::given(path("/api/getAgentTranscriptTail"))
        .respond_with(reply(json!({"entries": [
            {"id": "e1", "kind": "user-prompt", "prompt": "What is 2 + 2?"},
            {"id": "e2", "kind": "send-message", "message": {"type": "text", "content": "4"}},
            {"id": "e3", "kind": "send-message", "message": {"type": "local-tool-permission",
                "ask": {"status": "pending", "requestId": "r1", "command": "ls ~"}}}
        ]})))
        .mount(&gateway)
        .await;

    // A loopback gateway is only allowed with an explicit policy.
    let opts = ClientOptions {
        policy: Policy::local_testing(),
        ..ClientOptions::default()
    };
    let client = Client::new(Session::new(gateway.uri(), "fake-token"), opts)?;

    println!("Agents:");
    for agent in client.list_agents().await? {
        let kind = if agent.is_group { "group" } else { "bot" };
        println!("  {:<8} {:<6} {}", agent.id, kind, agent.display_name());
    }

    let receipt = client
        .send_prompt(&SendPrompt::new("helper", "What is 2 + 2?"))
        .await?;
    println!(
        "\nSent: delivery={} nonce={}",
        receipt.delivery, receipt.client_nonce
    );
    // When delivery is Unknown (timeout, 5xx), ask the gateway instead of resending blindly.
    let status = client
        .prompt_acceptance_status("helper", &receipt.client_nonce)
        .await?;
    println!("Acceptance status: {status:?}");
    assert!(receipt.delivery == Delivery::Accepted && status == AcceptanceStatus::Accepted);

    println!("\nTranscript:");
    for entry in client.transcript_tail("helper", 50, None).await?.entries {
        let who = if entry.is_from_user() { "you" } else { "bot" };
        if let Some(approval) = entry.approval() {
            // Never approve automatically: show it to the user and let them decide.
            println!(
                "  [{who}] approval needed ({:?}): {:?}",
                approval.kind, approval.details
            );
        } else {
            println!("  [{who}] {}", grokbot_api::sanitize_text(&entry.text));
        }
    }
    Ok(())
}
