# grokbot_api

**Unofficial** async Rust client for the Grok Bot gateway.

> The gateway is private and **undocumented**. This crate mirrors what
> [grok-bot-cli](https://github.com/ScriptedAlchemy/grok-bot-cli) does
> (`src/core/gateway.js`, `headers.js`, `url-policy.js`, `transcript.js`, `grok-approvals.js`).
> Field names were checked against that source, but the API **may change without notice**.

## Protocol

`POST {gateway_url}/api/<method>`, JSON body, headers `content-type: application/json`,
`authorization: Bearer <gateway_token>`, plus session headers. Redirects are refused, there is a 30 s timeout and a 2 MiB cap. Errors come back as `{message}` or `{error}`.

| Method | Client fn | Body |
|---|---|---|
| listAgents | `list_agents` | `{}` → `{agents:[…]}` or `[…]` |
| sendPrompt | `send_prompt` | `{agentId, prompt, clientNonce, replyToId?}` → `{messageId}` |
| getAgentTranscriptTail | `transcript_tail` | `{id, limit 1..=200}` → `{entries}` |
| getAgentThread | `thread` | `{id, rootId}` |
| createAgent | `create_agent` | `{name, description, title, avatarShape, avatarColor, origin:"user"}` |
| updateAgent | `update_agent` | `{id, profile:{name, description, title?, avatarShape?, avatarColor?}}` |
| deleteAgent | `delete_agent` | `{id}` |
| setAgentNotifyOnUpdates | `set_agent_notify_on_updates` | `{id, isEnabled}` |
| setAgentHiddenFromSidebar | `set_agent_hidden_from_sidebar` | `{id, isHidden}` |
| createGroup | `create_group` | `{name, description, memberAgentIds}` (1–6) |
| setGroupMembers | `set_group_members` | `{id, memberAgentIds}` |
| getAgentWorkflows | `get_agent_workflows` | `{id}` |
| importAgentWorkflowText | `import_agent_workflow_text` | `{id, markdown}` (≤100 000 chars) |
| deleteAgentWorkflow | `delete_agent_workflow` | `{id, workflowId}` |
| resolveLocalToolPermission | `resolve_local_tool_permission` | `{agentId, entryId, requestId, resolution:"allow-once"\|"deny"}` |
| resolveAutoReviewApproval | `resolve_auto_review_approval` | `{agentId, entryId, requestId, resolution:"approved"\|"denied"}` |
| *(any)* | `call_raw` | raw JSON |

**EnsureSandBox:** `ensure_sandbox` / `Client::connect_cursor` send
`POST {backend}/aiserver.v1.GrokBotService/EnsureSandBox` with body `{}` and headers `connect-protocol-version: 1`,
`authorization: Bearer <cursor token>`, `x-cursor-client-type: sand`, `x-cursor-client-version: 0.20.0`, `x-sand-box-namespace: prod`.
The response gives `gatewayUrl|gateway_url`, `gatewayToken|gateway_token`, and `gatewayHeaders|gateway_headers`, or
`anyrunNetworkToken` (sent as `x-anyrun-network-token`). A client built with a Cursor token re-exchanges once on 401;
read the new session with `take_refreshed_session()`.

**Errors:** `Error::{Policy, Validation, Http, Transport, TooLarge, InvalidResponse, Desktop}`. `Error::delivery()` returns
`Rejected` for policy, validation and 4xx errors, and `Unknown` for 5xx, network and timeout errors, where you should read the transcript before resending.

**Desktop session (feature `desktop-session`, off by default):** `grokbot_api::desktop` reads the Grok Bot desktop app's
`gateway-descriptor.json`, mirroring grok-bot-cli's `app-session.js`. It supports v1 and v2 descriptors, Linux v10/v11
(secret-tool), macOS Keychain and Windows DPAPI with AES-256-GCM. `DesktopConfig::new(platform).load_entry(entry, &policy)`
returns a policy-checked `Session`. `load_credential` prefers the descriptor and falls back to decrypting `sand-secrets.json`'s `cursor-accounts` into a Cursor access token (`DesktopCredential::CursorToken`). Errors are `Error::Desktop { code, message }`, where `code` is one of `APP_NOT_FOUND`,
`NOT_SIGNED_IN`, `SECRET_TOOL_MISSING`, `AMBIGUOUS_ENTRIES`, `NO_SUCH_ENTRY`, `DECRYPT_FAILED` and so on. Only call it on an explicit user request.

**Client identity:** `ClientOptions::{client_version, client_type, sandbox_namespace}` are sent on EnsureSandBox
(`x-cursor-client-version` / `x-cursor-client-type` / `x-sand-box-namespace`). Defaults are `0.70.2` / `sand` / `prod`.
With the `desktop-session` feature, `desktop::detect_app_version` reads the installed app's `package.json` /
`app.asar` (and `desktop-status.json` as a fallback).

**Policy:** `Policy::check_gateway` / `check_backend` implement the host allowlist (see the workspace README).

**Transcripts:** `Entry { id, role, text, raw }`, `Entry::is_from_user()` (heuristic), `Entry::approval()` for pending
approval cards (never approve automatically), and `sanitize_text` to strip terminal escapes.

```rust,no_run
use grokbot_api::{Client, ClientOptions, SendPrompt};
# async fn demo() -> grokbot_api::Result<()> {
let client = Client::connect_cursor("<cursor access token>", ClientOptions::default()).await?;
let bot = &client.list_agents().await?[0];
let receipt = client.send_prompt(&SendPrompt::new(&bot.id, "hello")).await?;
let tail = client.transcript_tail(&bot.id, 40).await?;
# Ok(()) }
```
