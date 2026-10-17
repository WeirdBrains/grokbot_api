# Wire protocol reference

[← README](README.md)

The Grok Bot gateway is undocumented. This page describes what this crate sends, based on
how the official desktop app and CLI behave. It may change without notice.

## Transport

- **Gateway calls:** `POST {gateway_url}/api/<method>`.
  - Headers: `content-type: application/json`, `authorization: Bearer <gateway token>`,
    plus the session's extra headers (for example `x-anyrun-network-token`).
  - The body is a JSON object.
- **Responses:** the body is parsed as JSON.
  - An empty body becomes `{}`.
  - A non-JSON body becomes `{"raw": "<text>"}`.
  - On error, the message comes from `message`, then `error`, then `raw`.
- **Limits:**
  - Redirects are never followed.
  - Bodies are capped (2 MiB by default).
  - Requests time out (30 s by default).
  - The `User-Agent` is `grokbot_api/<version>`.
- **Expired sessions:** the gateway answers **417** with an empty body. See
  [SESSIONS.md](SESSIONS.md#re-authentication-401-and-417).
- **Cursor backend:** Connect-JSON unary calls,
  `POST {backend}/aiserver.v1.GrokBotService/<Method>`. See
  [SESSIONS.md](SESSIONS.md#2-a-cursor-access-token-ensuresandbox).

## Gateway methods

| Method | Request body | Rust |
|---|---|---|
| `listAgents` | `{}` | `list_agents` |
| `createAgent` | `{name, description, title, avatarShape, avatarColor, origin: "user"}` | `create_agent` |
| `updateAgent` | `{id, profile: {name, description, title?, avatarShape?, avatarColor?}}` | `update_agent` |
| `deleteAgent` | `{id}` | `delete_agent` |
| `setAgentNotifyOnUpdates` | `{id, isEnabled}` | `set_agent_notify_on_updates` |
| `setAgentHiddenFromSidebar` | `{id, isHidden}` | `set_agent_hidden_from_sidebar` |
| `createGroup` | `{name, description, memberAgentIds}` | `create_group` |
| `setGroupMembers` | `{id, memberAgentIds}` | `set_group_members` |
| `sendPrompt` | `{agentId, prompt, clientNonce, replyToId?, sessionId?}` | `send_prompt` |
| `promptAcceptanceStatus` | `{agentId, clientNonce, sessionId?}` | `prompt_acceptance_status` |
| `getAgentTranscriptTail` | `{id, limit, beforeSeq?, sessionId?}` | `transcript_tail`, `transcript_history` |
| `getAgentThread` | `{id, rootId}` | `thread` |
| `getAgentWorkflows` | `{id}` | `get_agent_workflows` |
| `importAgentWorkflowText` | `{id, markdown}` | `import_agent_workflow_text` |
| `deleteAgentWorkflow` | `{id, workflowId}` | `delete_agent_workflow` |
| `resolveLocalToolPermission` | `{agentId, entryId, requestId, resolution}` | `resolve_local_tool_permission` |
| `resolveAutoReviewApproval` | `{agentId, entryId, requestId, resolution}` | `resolve_auto_review_approval` |

## Cursor backend methods

| Method | Rust |
|---|---|
| `EnsureSandBox` | `ensure_sandbox`, `Client::connect_cursor`, automatic re-exchange |
| `ListGrokBotTeamAgents` | `Client::list_team_agents` |
| any other | `grokbot_service_call` |

## Methods without a typed wrapper

`Client::call_raw(method, body)` sends any gateway method and returns the raw JSON. It
applies the same policy checks, redaction and 401/417 re-exchange as the typed methods:

```rust,no_run
use grokbot_api::Client;
use serde_json::json;

async fn raw(client: &Client) -> grokbot_api::Result<()> {
    let v = client.call_raw("listAgents", json!({})).await?;
    println!("{v:#}");
    Ok(())
}
```

## Testing against a mock

Point a `Session` at a local mock server and use `Policy::local_testing()`. The
[`mock_gateway` example](examples/mock_gateway.rs) and the `tests/` directory use
[wiremock](https://crates.io/crates/wiremock).

```rust,no_run
use grokbot_api::{Client, ClientOptions, Policy, Session};

fn mock_client(mock_url: &str) -> grokbot_api::Result<Client> {
    let opts = ClientOptions {
        policy: Policy::local_testing(),
        backend_base: mock_url.to_string(), // EnsureSandBox goes to the mock too
        ..Default::default()
    };
    Client::new(Session::new(mock_url, "test-token"), opts)
}
```
