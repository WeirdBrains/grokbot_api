use crate::error::{Delivery, Error, Result};
use crate::policy::Policy;
use crate::transcript::Transcript;
use crate::types::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Mutex, RwLock};
use std::time::Duration;

/// Default Cursor backend for EnsureSandBox.
pub const DEFAULT_BACKEND_BASE: &str = "https://api2.cursor.sh";
/// Per-request deadline.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Response body cap.
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Default `x-cursor-client-version` (Grok Bot 0.70.x era). Prefer detecting the
/// installed desktop app version via [`crate::desktop::detect_app_version`].
pub const DEFAULT_CLIENT_VERSION: &str = "0.70.2";
/// Default `x-cursor-client-type` (matches the desktop app's `SAND_CLIENT_TYPE`).
pub const DEFAULT_CLIENT_TYPE: &str = "sand";
/// Default `x-sand-box-namespace` for production EnsureSandBox.
pub const DEFAULT_SANDBOX_NAMESPACE: &str = "prod";

#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub policy: Policy,
    /// Cursor backend base URL for EnsureSandBox (must pass [`Policy::check_backend`]).
    pub backend_base: String,
    pub timeout: Duration,
    pub max_response_bytes: usize,
    /// Sent as `x-cursor-client-version` on EnsureSandBox.
    pub client_version: String,
    /// Sent as `x-cursor-client-type` on EnsureSandBox.
    pub client_type: String,
    /// Sent as `x-sand-box-namespace` on EnsureSandBox.
    pub sandbox_namespace: String,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            policy: Policy::from_env(),
            backend_base: DEFAULT_BACKEND_BASE.into(),
            timeout: TIMEOUT,
            max_response_bytes: MAX_RESPONSE_BYTES,
            client_version: DEFAULT_CLIENT_VERSION.into(),
            client_type: DEFAULT_CLIENT_TYPE.into(),
            sandbox_namespace: DEFAULT_SANDBOX_NAMESPACE.into(),
        }
    }
}

fn http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("grokbot_api/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::Transport {
            method: "client".into(),
            message: e.to_string(),
        })
}

/// Replace secrets and bearer values in error text.
fn redact(text: &str, secrets: &[&str]) -> String {
    let mut s = text.to_string();
    for sec in secrets.iter().filter(|s| s.len() >= 4) {
        s = s.replace(sec, "<redacted>");
    }
    // "Bearer xyz" -> "Bearer <redacted>"
    let mut out = String::new();
    let mut rest = s.as_str();
    while let Some(i) = rest.to_lowercase().find("bearer ") {
        out.push_str(&rest[..i + 7]);
        out.push_str("<redacted>");
        let tail = &rest[i + 7..];
        let end = tail
            .find(|c: char| c.is_whitespace() || c == '"' || c == ',')
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// POST JSON with a body cap; returns (status, parsed body). Non-JSON bodies become `{"raw": text}`.
async fn post(
    http: &reqwest::Client,
    url: &str,
    headers: &BTreeMap<String, String>,
    body: &Value,
    method: &str,
    cap: usize,
    secrets: &[&str],
) -> Result<(u16, Value)> {
    let mut rb = http
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string());
    for (k, v) in headers {
        rb = rb.header(k, v);
    }
    let transport = |e: reqwest::Error| Error::Transport {
        method: method.into(),
        message: redact(&e.to_string(), secrets),
    };
    let mut res = rb.send().await.map_err(transport)?;
    let status = res.status().as_u16();
    if res.status().is_redirection() {
        return Err(Error::Transport {
            method: method.into(),
            message: format!("refused redirect (HTTP {status})"),
        });
    }
    let mut buf = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(transport)? {
        buf.extend_from_slice(&chunk);
        if buf.len() > cap {
            return Err(Error::TooLarge {
                method: method.into(),
                limit: cap,
            });
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let data = if text.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }))
    };
    Ok((status, data))
}

fn detail(data: &Value) -> String {
    ["message", "error", "raw"]
        .iter()
        .find_map(|k| {
            data.get(*k).map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string())
            })
        })
        .unwrap_or_default()
}

fn pick<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .find_map(|k| v.get(*k).filter(|x| !x.is_null() && x.as_str() != Some("")))
}

/// Exchange a Cursor access token for a gateway session via
/// `POST {backend}/aiserver.v1.GrokBotService/EnsureSandBox`.
///
/// Do not pass a Cursor dashboard API key; those do not work.
pub async fn ensure_sandbox(access_token: &str, opts: &ClientOptions) -> Result<Session> {
    let base = opts
        .policy
        .check_backend(&opts.backend_base)
        .map_err(Error::Policy)?;
    let http = http_client(opts.timeout)?;
    ensure_sandbox_with(&http, &base, access_token, opts).await
}

async fn ensure_sandbox_with(
    http: &reqwest::Client,
    base: &str,
    access_token: &str,
    opts: &ClientOptions,
) -> Result<Session> {
    const M: &str = "EnsureSandBox";
    let url = format!("{base}/aiserver.v1.GrokBotService/EnsureSandBox");
    let headers: BTreeMap<String, String> = [
        ("connect-protocol-version", "1".to_string()),
        ("authorization", format!("Bearer {access_token}")),
        ("x-cursor-client-type", opts.client_type.clone()),
        ("x-cursor-client-version", opts.client_version.clone()),
        ("x-sand-box-namespace", opts.sandbox_namespace.clone()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let (status, body) = post(
        http,
        &url,
        &headers,
        &json!({}),
        M,
        opts.max_response_bytes,
        &[access_token],
    )
    .await?;
    if !(200..300).contains(&status) {
        return Err(Error::Http {
            method: M.into(),
            status,
            message: redact(&detail(&body), &[access_token]),
        });
    }
    let as_str = |v: &Value| {
        v.as_str()
            .map(str::to_string)
            .unwrap_or_else(|| v.to_string())
    };
    let (Some(u), Some(t)) = (
        pick(&body, &["gatewayUrl", "gateway_url"]),
        pick(&body, &["gatewayToken", "gateway_token"]),
    ) else {
        return Err(Error::InvalidResponse {
            method: M.into(),
            message:
                "returned no gatewayUrl/gatewayToken (a Cursor dashboard API key will not work)"
                    .into(),
        });
    };
    let gateway_url = opts
        .policy
        .check_gateway(&as_str(u))
        .map_err(Error::Policy)?;
    let mut headers = BTreeMap::new();
    if let Some(Value::Object(m)) = pick(&body, &["gatewayHeaders", "gateway_headers"]) {
        headers = normalize_headers(
            m.iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k.clone(), as_str(v))),
        );
    }
    if headers.is_empty()
        && let Some(tok) = pick(
            &body,
            &["anyrunNetworkToken", "anyrun_network_token", "networkToken"],
        )
    {
        headers.insert("x-anyrun-network-token".into(), as_str(tok));
    }
    Ok(Session {
        gateway_url,
        gateway_token: as_str(t),
        headers,
    })
}

struct State {
    session: Session,
    cursor_token: Option<String>,
}

/// Async gateway client. Cheap to share behind an `Arc`; methods take `&self`.
pub struct Client {
    http: reqwest::Client,
    opts: ClientOptions,
    state: RwLock<State>,
    refreshed: Mutex<Option<Session>>,
}

impl Client {
    /// Client for an existing gateway session. The URL is checked against the policy on every call.
    pub fn new(session: Session, opts: ClientOptions) -> Result<Self> {
        opts.policy
            .check_gateway(&session.gateway_url)
            .map_err(Error::Policy)?;
        Ok(Self {
            http: http_client(opts.timeout)?,
            opts,
            state: RwLock::new(State {
                session,
                cursor_token: None,
            }),
            refreshed: Mutex::new(None),
        })
    }

    /// Like [`Client::new`], but keeps the Cursor access token so a 401 triggers one
    /// EnsureSandBox re-exchange and a retry.
    pub fn with_cursor_token(
        session: Session,
        cursor_token: impl Into<String>,
        opts: ClientOptions,
    ) -> Result<Self> {
        let c = Self::new(session, opts)?;
        c.state.write().unwrap().cursor_token = Some(cursor_token.into());
        Ok(c)
    }

    /// EnsureSandBox then build a client that can re-exchange.
    pub async fn connect_cursor(access_token: &str, opts: ClientOptions) -> Result<Self> {
        let session = ensure_sandbox(access_token, &opts).await?;
        Self::with_cursor_token(session, access_token, opts)
    }

    pub fn session(&self) -> Session {
        self.state.read().unwrap().session.clone()
    }

    /// The new session if a 401 re-exchange happened since the last call (persist it).
    pub fn take_refreshed_session(&self) -> Option<Session> {
        self.refreshed.lock().unwrap().take()
    }

    async fn call_once(
        &self,
        s: &Session,
        cursor: Option<&str>,
        method: &str,
        body: &Value,
    ) -> Result<Value> {
        let base = self
            .opts
            .policy
            .check_gateway(&s.gateway_url)
            .map_err(Error::Policy)?;
        let mut headers = s.headers.clone();
        headers.insert(
            "authorization".into(),
            format!("Bearer {}", s.gateway_token),
        );
        let mut secrets = vec![s.gateway_token.as_str()];
        secrets.extend(cursor);
        secrets.extend(s.headers.values().map(String::as_str));
        let url = format!("{base}/api/{method}");
        let (status, data) = post(
            &self.http,
            &url,
            &headers,
            body,
            method,
            self.opts.max_response_bytes,
            &secrets,
        )
        .await?;
        if !(200..300).contains(&status) {
            let msg: String = detail(&data).chars().take(300).collect();
            return Err(Error::Http {
                method: method.into(),
                status,
                message: redact(&msg, &secrets),
            });
        }
        Ok(data)
    }

    /// Call any gateway method with a raw JSON body. Handles 401 re-exchange.
    pub async fn call_raw(&self, method: &str, body: Value) -> Result<Value> {
        let (session, cursor) = {
            let st = self.state.read().unwrap();
            (st.session.clone(), st.cursor_token.clone())
        };
        match self
            .call_once(&session, cursor.as_deref(), method, &body)
            .await
        {
            Err(e) if e.is_unauthorized() && cursor.is_some() => {
                let tok = cursor.unwrap();
                let base = self
                    .opts
                    .policy
                    .check_backend(&self.opts.backend_base)
                    .map_err(Error::Policy)?;
                let fresh = ensure_sandbox_with(&self.http, &base, &tok, &self.opts).await?;
                {
                    let mut st = self.state.write().unwrap();
                    st.session = fresh.clone();
                }
                *self.refreshed.lock().unwrap() = Some(fresh.clone());
                self.call_once(&fresh, Some(&tok), method, &body).await
            }
            r => r,
        }
    }

    // ------------------------------------------------------------------ agents

    /// `listAgents {}` → bots and groups (hidden ones included; check `hidden_from_sidebar`).
    pub async fn list_agents(&self) -> Result<Vec<Agent>> {
        Ok(Agent::list(&self.call_raw("listAgents", json!({})).await?))
    }

    /// `createAgent {name, description, title, avatarShape, avatarColor, origin: "user"}`.
    pub async fn create_agent(&self, input: &CreateAgent) -> Result<Option<Agent>> {
        if input.name.trim().is_empty() {
            return Err(Error::Validation("Name cannot be blank.".into()));
        }
        let shape = check_avatar("shape", &input.avatar_shape, AVATAR_SHAPES)?;
        let color = check_avatar("color", &input.avatar_color, AVATAR_COLORS)?;
        let data = self
            .call_raw(
                "createAgent",
                json!({ "name": input.name, "description": input.description, "title": input.title,
                        "avatarShape": shape, "avatarColor": color, "origin": "user" }),
            )
            .await?;
        Ok(Agent::one(&data))
    }

    /// `updateAgent {id, profile: {name, description, title?, avatarShape?, avatarColor?}}`.
    pub async fn update_agent(&self, id: &str, profile: &AgentProfile) -> Result<Value> {
        if profile.name.trim().is_empty() {
            return Err(Error::Validation("Name cannot be blank.".into()));
        }
        let mut p = json!({ "name": profile.name.trim(), "description": profile.description });
        if let Some(t) = &profile.title {
            p["title"] = json!(t);
        }
        if let Some(sh) = &profile.avatar_shape {
            p["avatarShape"] = json!(check_avatar("shape", sh, AVATAR_SHAPES)?);
        }
        if let Some(c) = &profile.avatar_color {
            p["avatarColor"] = json!(check_avatar("color", c, AVATAR_COLORS)?);
        }
        self.call_raw("updateAgent", json!({ "id": id, "profile": p }))
            .await
    }

    /// `deleteAgent {id}`.
    pub async fn delete_agent(&self, id: &str) -> Result<Value> {
        self.call_raw("deleteAgent", json!({ "id": id })).await
    }

    /// `setAgentNotifyOnUpdates {id, isEnabled}`.
    pub async fn set_agent_notify_on_updates(&self, id: &str, enabled: bool) -> Result<Value> {
        self.call_raw(
            "setAgentNotifyOnUpdates",
            json!({ "id": id, "isEnabled": enabled }),
        )
        .await
    }

    /// `setAgentHiddenFromSidebar {id, isHidden}`.
    pub async fn set_agent_hidden_from_sidebar(&self, id: &str, hidden: bool) -> Result<Value> {
        self.call_raw(
            "setAgentHiddenFromSidebar",
            json!({ "id": id, "isHidden": hidden }),
        )
        .await
    }

    // ------------------------------------------------------------------ groups

    /// `createGroup {name, description, memberAgentIds}` (1..=6 distinct members, no nested groups).
    pub async fn create_group(&self, input: &CreateGroup) -> Result<Option<Agent>> {
        let ids = check_members(&input.member_agent_ids)?;
        let data = self
            .call_raw(
                "createGroup",
                json!({ "name": input.name, "description": input.description, "memberAgentIds": ids }),
            )
            .await?;
        Ok(Agent::one(&data))
    }

    /// `setGroupMembers {id, memberAgentIds}`.
    pub async fn set_group_members(
        &self,
        group_id: &str,
        member_agent_ids: &[String],
    ) -> Result<Option<Agent>> {
        let ids = check_members(member_agent_ids)?;
        let data = self
            .call_raw(
                "setGroupMembers",
                json!({ "id": group_id, "memberAgentIds": ids }),
            )
            .await?;
        Ok(Agent::one(&data))
    }

    // ------------------------------------------------------------------ chat

    /// `sendPrompt {agentId, prompt, clientNonce, replyToId?}` → receipt only.
    ///
    /// On error use [`Error::delivery`]: `Unknown` means read the transcript before resending.
    pub async fn send_prompt(&self, req: &SendPrompt) -> Result<SendReceipt> {
        if req.prompt.is_empty() {
            return Err(Error::Validation("Prompt is empty.".into()));
        }
        let nonce = req
            .client_nonce
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut body =
            json!({ "agentId": req.agent_id, "prompt": req.prompt, "clientNonce": nonce });
        if let Some(r) = &req.reply_to_id {
            body["replyToId"] = json!(r);
        }
        let raw = self.call_raw("sendPrompt", body).await?;
        let (delivery, message_id) = classify_send(&raw, &nonce)?;
        Ok(SendReceipt {
            message_id,
            client_nonce: nonce,
            delivery,
            raw,
        })
    }

    /// `promptAcceptanceStatus {agentId, clientNonce}`: the gateway's own lookup of
    /// whether a prompt with this nonce landed (what the desktop app uses when a send's
    /// outcome is uncertain). Returns the raw status object.
    pub async fn prompt_acceptance_status(
        &self,
        agent_id: &str,
        client_nonce: &str,
    ) -> Result<Value> {
        self.call_raw(
            "promptAcceptanceStatus",
            json!({ "agentId": agent_id, "clientNonce": client_nonce }),
        )
        .await
    }

    /// `getAgentTranscriptTail {id, limit, beforeSeq?}` (limit clamped to 1..=200).
    ///
    /// Omitting `before_seq` returns the newest page. When the response includes
    /// `nextBeforeSeq`, pass it here to walk older pages (as the desktop app does).
    pub async fn transcript_tail(
        &self,
        id: &str,
        limit: u32,
        before_seq: Option<u64>,
    ) -> Result<Transcript> {
        let limit = limit.clamp(1, 200);
        let mut body = json!({ "id": id, "limit": limit });
        if let Some(seq) = before_seq {
            body["beforeSeq"] = json!(seq);
        }
        Ok(Transcript::from_value(
            self.call_raw("getAgentTranscriptTail", body).await?,
        ))
    }

    /// Walk `getAgentTranscriptTail` pages until the chat is exhausted or `max_entries`
    /// is reached. Newest page first; returned entries are oldest → newest.
    pub async fn transcript_history(
        &self,
        id: &str,
        page_size: u32,
        max_entries: usize,
    ) -> Result<Transcript> {
        let page_size = page_size.clamp(1, 200);
        let mut all: Vec<crate::transcript::Entry> = Vec::new();
        let mut before = None;
        let mut raw_pages = Vec::new();
        loop {
            let page = self.transcript_tail(id, page_size, before).await?;
            raw_pages.push(page.raw.clone());
            if page.entries.is_empty() {
                break;
            }
            // Each page is oldest→newest; older pages are prepended (desktop app does the same).
            all.splice(0..0, page.entries.iter().cloned());
            if all.len() >= max_entries {
                let overflow = all.len() - max_entries;
                all.drain(0..overflow); // keep the newest max_entries
                break;
            }
            match page.next_before_seq {
                Some(seq) => before = Some(seq),
                None => break,
            }
        }
        let mut seen = std::collections::HashSet::new();
        all.retain(|e| match &e.id {
            Some(eid) => seen.insert(eid.clone()),
            None => true,
        });
        Ok(Transcript {
            entries: all,
            next_before_seq: before,
            raw: json!({ "pages": raw_pages }),
        })
    }

    /// `getAgentThread {id, rootId}`.
    pub async fn thread(&self, id: &str, root_id: &str) -> Result<Transcript> {
        Ok(Transcript::from_value(
            self.call_raw("getAgentThread", json!({ "id": id, "rootId": root_id }))
                .await?,
        ))
    }

    // ------------------------------------------------------------------ workflows (skills)

    /// `getAgentWorkflows {id}`. The library is shared per box; `id` is any bot id.
    pub async fn get_agent_workflows(&self, id: &str) -> Result<Vec<Workflow>> {
        Ok(Workflow::list(
            &self
                .call_raw("getAgentWorkflows", json!({ "id": id }))
                .await?,
        ))
    }

    /// `importAgentWorkflowText {id, markdown}`.
    pub async fn import_agent_workflow_text(
        &self,
        id: &str,
        markdown: &str,
    ) -> Result<ImportResult> {
        if markdown.trim().is_empty() {
            return Err(Error::Validation("Skill markdown is empty.".into()));
        }
        if markdown.chars().count() > SKILL_MAX_BODY_LENGTH {
            return Err(Error::Validation(format!(
                "Skill markdown exceeds {SKILL_MAX_BODY_LENGTH} characters."
            )));
        }
        let data = self
            .call_raw(
                "importAgentWorkflowText",
                json!({ "id": id, "markdown": markdown }),
            )
            .await?;
        let r = data.get("result");
        let arr = |k: &str| {
            r.and_then(|r| r.get(k))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        Ok(ImportResult {
            workflows: Workflow::list(&data),
            imported: arr("imported")
                .iter()
                .filter_map(Workflow::from_value)
                .collect(),
            skipped: arr("skipped")
                .iter()
                .map(|s| SkippedImport {
                    reason: s
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("rejected")
                        .to_string(),
                })
                .collect(),
        })
    }

    /// `deleteAgentWorkflow {id, workflowId}`.
    pub async fn delete_agent_workflow(&self, id: &str, workflow_id: &str) -> Result<Value> {
        self.call_raw(
            "deleteAgentWorkflow",
            json!({ "id": id, "workflowId": workflow_id }),
        )
        .await
    }

    // ------------------------------------------------------------------ approvals

    /// `resolveLocalToolPermission {agentId, entryId, requestId, resolution: "allow-once"|"deny"}`.
    /// Only call on an explicit user decision.
    pub async fn resolve_local_tool_permission(
        &self,
        agent_id: &str,
        entry_id: &str,
        request_id: &str,
        resolution: LocalToolResolution,
    ) -> Result<Value> {
        self.call_raw(
            "resolveLocalToolPermission",
            json!({ "agentId": agent_id, "entryId": entry_id, "requestId": request_id, "resolution": resolution.as_str() }),
        )
        .await
    }

    /// `resolveAutoReviewApproval {agentId, entryId, requestId, resolution: "approved"|"denied"}`.
    /// Only call on an explicit user decision.
    pub async fn resolve_auto_review_approval(
        &self,
        agent_id: &str,
        entry_id: &str,
        request_id: &str,
        resolution: AutoReviewResolution,
    ) -> Result<Value> {
        self.call_raw(
            "resolveAutoReviewApproval",
            json!({ "agentId": agent_id, "entryId": entry_id, "requestId": request_id, "resolution": resolution.as_str() }),
        )
        .await
    }
}

fn check_avatar(kind: &str, v: &str, allowed: &[&str]) -> Result<String> {
    let t = v.trim();
    if t.is_empty() || allowed.contains(&t) {
        Ok(t.to_string())
    } else {
        Err(Error::Validation(format!(
            "Unknown avatar {kind} \"{v}\". Use: {}",
            allowed.join(" ")
        )))
    }
}

fn check_members(ids: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = vec![];
    for id in ids {
        if !id.is_empty() && !out.contains(id) {
            out.push(id.clone());
        }
    }
    if out.is_empty() {
        return Err(Error::Validation(
            "A group needs at least one existing member agent.".into(),
        ));
    }
    if out.len() > MAX_GROUP_MEMBERS {
        return Err(Error::Validation(format!(
            "A group can have at most {MAX_GROUP_MEMBERS} members."
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redaction() {
        assert_eq!(
            redact("bad token sekrit1 x", &["sekrit1"]),
            "bad token <redacted> x"
        );
        assert_eq!(
            redact("Authorization: Bearer abc.def, more", &[]),
            "Authorization: Bearer <redacted>, more"
        );
    }
}

/// Classify a 2xx `sendPrompt` body.
///
/// The gateway (per the desktop app) answers a successful send with
/// `{accepted: true}` (box/temporal acceptance or a duplicate of the same nonce) and
/// a refused one with `{status: "refused", message}`; it does not return a separate
/// message id; the message id is the client nonce. Older/alternative shapes with a
/// string `messageId` are also accepted, and a `{status, value}` wrapper is unwrapped.
fn classify_send(raw: &Value, nonce: &str) -> Result<(Delivery, Option<String>)> {
    let inner = raw.get("value").filter(|v| v.is_object()).unwrap_or(raw);
    let pick = |k: &str| inner.get(k).or_else(|| raw.get(k));
    let message_id = pick("messageId")
        .and_then(Value::as_str)
        .map(str::to_string);
    let refused = raw.get("status").and_then(Value::as_str) == Some("refused")
        || pick("accepted").and_then(Value::as_bool) == Some(false);
    if refused {
        let msg = pick("message")
            .and_then(Value::as_str)
            .unwrap_or("prompt refused by the gateway");
        return Err(Error::Http {
            method: "sendPrompt".into(),
            status: 422,
            message: msg.chars().take(300).collect(),
        });
    }
    if message_id.is_some() || pick("accepted").and_then(Value::as_bool) == Some(true) {
        return Ok((
            Delivery::Accepted,
            Some(message_id.unwrap_or_else(|| nonce.to_string())),
        ));
    }
    Ok((Delivery::Unknown, None))
}

#[cfg(test)]
mod send_classify_tests {
    use super::*;
    #[test]
    fn classify_shapes() {
        let ok = |v: Value| classify_send(&v, "n1").unwrap();
        assert_eq!(
            ok(json!({"accepted": true})),
            (Delivery::Accepted, Some("n1".into()))
        );
        assert_eq!(
            ok(json!({"status": "ok", "value": {"accepted": true}})),
            (Delivery::Accepted, Some("n1".into()))
        );
        assert_eq!(
            ok(json!({"messageId": "m1"})),
            (Delivery::Accepted, Some("m1".into()))
        );
        assert_eq!(ok(json!({})), (Delivery::Unknown, None));
        assert_eq!(ok(json!(null)), (Delivery::Unknown, None));
        let e =
            classify_send(&json!({"status": "refused", "message": "too long"}), "n").unwrap_err();
        assert_eq!(e.delivery(), Delivery::Rejected);
        assert!(e.to_string().contains("too long"));
        assert_eq!(
            classify_send(&json!({"accepted": false}), "n")
                .unwrap_err()
                .delivery(),
            Delivery::Rejected
        );
    }
}
