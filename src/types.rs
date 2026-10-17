//! Request and response types for the gateway methods.
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

/// Avatar shapes accepted by `createAgent` / `updateAgent`.
pub const AVATAR_SHAPES: &[&str] = &[
    "blob", "pebble", "bean", "egg", "squircle", "tablet", "capsule", "cylinder", "hex", "gem",
    "crystal", "wedge", "shield", "dome", "arch", "cloud", "teardrop", "leaf",
];
/// Avatar colors accepted by `createAgent` / `updateAgent`.
pub const AVATAR_COLORS: &[&str] = &[
    "black", "brown", "red", "orange", "yellow", "green", "cyan", "blue", "violet", "magenta",
    "gray",
];
/// Most member agents a group may have (`createGroup` / `setGroupMembers`).
pub const MAX_GROUP_MEMBERS: usize = 6;
/// Grok Bot truncates workflow (skill) bodies over this many characters, so
/// [`Client::import_agent_workflow_text`](crate::Client::import_agent_workflow_text)
/// rejects longer input.
pub const SKILL_MAX_BODY_LENGTH: usize = 100_000;

/// A gateway connection: base URL, bearer token and extra headers.
///
/// `Debug` output redacts the token and header values.
///
/// ```
/// use grokbot_api::Session;
///
/// let s = Session::new("https://box.us1.cursorvm.com", "gateway-token")
///     .with_headers([("X-Anyrun-Network-Token".to_string(), "net".to_string())].into());
/// assert!(s.headers.contains_key("x-anyrun-network-token")); // keys are lower-cased
/// assert!(!format!("{s:?}").contains("gateway-token"));
/// ```
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Session {
    /// Gateway base URL, e.g. `https://<box>.cursorvm.com` (no trailing slash).
    pub gateway_url: String,
    /// Bearer token sent as `authorization: Bearer <token>`.
    pub gateway_token: String,
    /// Extra headers sent on every call (keys lower-case), e.g. `x-anyrun-network-token`.
    pub headers: BTreeMap<String, String>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: BTreeMap<&str, &str> = self
            .headers
            .keys()
            .map(|k| (k.as_str(), "<redacted>"))
            .collect();
        f.debug_struct("Session")
            .field("gateway_url", &self.gateway_url)
            .field("gateway_token", &"<redacted>")
            .field("headers", &headers)
            .finish()
    }
}

impl Session {
    /// A session with no extra headers.
    pub fn new(gateway_url: impl Into<String>, gateway_token: impl Into<String>) -> Self {
        Self {
            gateway_url: gateway_url.into(),
            gateway_token: gateway_token.into(),
            headers: BTreeMap::new(),
        }
    }

    /// Replace the extra headers. Keys are lower-cased and empty values dropped.
    pub fn with_headers(mut self, headers: BTreeMap<String, String>) -> Self {
        self.headers = normalize_headers(headers);
        self
    }
}

pub(crate) fn normalize_headers<I: IntoIterator<Item = (String, String)>>(
    h: I,
) -> BTreeMap<String, String> {
    h.into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect()
}

/// A bot or group as returned by `listAgents`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Agent {
    /// Agent id (`id`, or `agentId`).
    pub id: String,
    /// Display name (may be empty).
    pub name: String,
    /// Title (may be empty).
    pub title: String,
    /// Description (may be empty).
    pub description: String,
    /// One of [`AVATAR_SHAPES`], or empty.
    pub avatar_shape: String,
    /// One of [`AVATAR_COLORS`], or empty.
    pub avatar_color: String,
    /// `notifyOnUpdatesEnabled` / `notifyOnAgentUpdates`, when present.
    pub notify_on_updates: Option<bool>,
    /// `isHiddenFromSidebar` / `hiddenFromSidebar`, when present.
    pub hidden_from_sidebar: Option<bool>,
    /// `isGroup`, or inferred from a non-empty member list.
    pub is_group: bool,
    /// `memberIds` / `memberAgentIds`.
    pub member_ids: Vec<String>,
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

impl Agent {
    /// Parse one agent record (mirrors grok-bot-cli `asRecord`). Returns `None` without an id.
    ///
    /// ```
    /// use grokbot_api::Agent;
    /// use serde_json::json;
    ///
    /// let a = Agent::from_value(&json!({"agentId": "a1", "title": "Helper", "memberIds": ["b"]})).unwrap();
    /// assert_eq!((a.id.as_str(), a.display_name(), a.is_group), ("a1", "Helper", true));
    /// assert!(Agent::from_value(&json!({"name": "no id"})).is_none());
    /// ```
    pub fn from_value(v: &Value) -> Option<Agent> {
        let id = s(v, "id").or_else(|| s(v, "agentId"))?;
        let members = v
            .get("memberIds")
            .or_else(|| v.get("memberAgentIds"))
            .and_then(Value::as_array);
        let member_ids: Vec<String> = members
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let is_group = match v.get("isGroup").and_then(Value::as_bool) {
            Some(b) => b,
            None => !member_ids.is_empty(),
        };
        let b = |a: &str, b: &str| {
            v.get(a)
                .and_then(Value::as_bool)
                .or_else(|| v.get(b).and_then(Value::as_bool))
        };
        Some(Agent {
            id,
            name: s(v, "name").unwrap_or_default(),
            title: s(v, "title").unwrap_or_default(),
            description: s(v, "description").unwrap_or_default(),
            avatar_shape: s(v, "avatarShape").unwrap_or_default(),
            avatar_color: s(v, "avatarColor").unwrap_or_default(),
            notify_on_updates: b("notifyOnUpdatesEnabled", "notifyOnAgentUpdates"),
            hidden_from_sidebar: b("isHiddenFromSidebar", "hiddenFromSidebar"),
            is_group,
            member_ids,
        })
    }

    /// `name`, else `title`, else `id`.
    pub fn display_name(&self) -> &str {
        [&self.name, &self.title]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or(&self.id)
    }

    pub(crate) fn list(data: &Value) -> Vec<Agent> {
        let list = if let Some(a) = data.as_array() {
            a.clone()
        } else if let Some(a) = data.get("agents").and_then(Value::as_array) {
            a.clone()
        } else if let Some(one) = data.get("agent") {
            vec![one.clone()]
        } else {
            vec![]
        };
        list.iter().filter_map(Agent::from_value).collect()
    }

    pub(crate) fn one(data: &Value) -> Option<Agent> {
        Agent::from_value(data.get("agent").unwrap_or(data))
    }
}

/// A `sendPrompt` request.
///
/// ```
/// use grokbot_api::SendPrompt;
///
/// let mut req = SendPrompt::new("agent-id", "hello");
/// req.client_nonce = Some("my-idempotency-key".into()); // optional; a UUID is generated otherwise
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SendPrompt {
    /// The bot or group to send to.
    pub agent_id: String,
    /// The prompt text (must not be empty).
    pub prompt: String,
    /// Idempotency nonce; a v4 UUID is generated when `None`. Reuse it to ask
    /// [`Client::prompt_acceptance_status`](crate::Client::prompt_acceptance_status) or to resend safely.
    pub client_nonce: Option<String>,
    /// Reply in a thread rooted at this entry id.
    pub reply_to_id: Option<String>,
}

impl SendPrompt {
    /// A prompt to `agent_id` with a generated nonce and no thread.
    pub fn new(agent_id: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            prompt: prompt.into(),
            ..Default::default()
        }
    }
}

/// The receipt for a `sendPrompt` call. Replies arrive later in the transcript.
#[derive(Debug, Clone, PartialEq)]
pub struct SendReceipt {
    /// The message id: the gateway's `messageId`, or the client nonce when the gateway
    /// answers `{accepted: true}`. `None` when delivery is unknown.
    pub message_id: Option<String>,
    /// The nonce that was sent (generated if the request had none).
    pub client_nonce: String,
    /// [`Delivery::Accepted`](crate::Delivery::Accepted), or
    /// [`Delivery::Unknown`](crate::Delivery::Unknown) for a 2xx without a recognisable receipt.
    pub delivery: crate::Delivery,
    /// The raw response body.
    pub raw: Value,
}

/// A `createAgent` request (sent with `origin: "user"`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CreateAgent {
    /// Name (required, must not be blank).
    pub name: String,
    /// Description.
    pub description: String,
    /// Title.
    pub title: String,
    /// One of [`AVATAR_SHAPES`], or empty for the server default.
    pub avatar_shape: String,
    /// One of [`AVATAR_COLORS`], or empty for the server default.
    pub avatar_color: String,
}

/// An `updateAgent` profile. `name` and `description` are always sent; `None` fields are left unchanged.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AgentProfile {
    /// Name (required, must not be blank; trimmed before sending).
    pub name: String,
    /// Description.
    pub description: String,
    /// New title.
    pub title: Option<String>,
    /// New avatar shape (one of [`AVATAR_SHAPES`]).
    pub avatar_shape: Option<String>,
    /// New avatar color (one of [`AVATAR_COLORS`]).
    pub avatar_color: Option<String>,
}

/// A `createGroup` request.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CreateGroup {
    /// Group name.
    pub name: String,
    /// Group description.
    pub description: String,
    /// 1 to [`MAX_GROUP_MEMBERS`] member agent ids (duplicates and empty ids are dropped).
    pub member_agent_ids: Vec<String>,
}

/// A workflow ("skill") from `getAgentWorkflows`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Workflow {
    /// Workflow id (numeric ids are converted to strings).
    pub id: String,
    /// Name.
    pub name: String,
    /// Description.
    pub description: String,
    /// `workflow` (library, the default), `managed`, `plugin`, or `automation`.
    pub source: String,
    /// `sourceRef`, when present.
    pub source_ref: Option<String>,
    /// `pluginId`, for plugin workflows.
    pub plugin_id: Option<String>,
}

impl Workflow {
    pub(crate) fn from_value(v: &Value) -> Option<Workflow> {
        let id = match v.get("id")? {
            Value::String(s) if !s.is_empty() => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => return None,
        };
        Some(Workflow {
            id,
            name: s(v, "name").unwrap_or_default(),
            description: s(v, "description").unwrap_or_default(),
            source: s(v, "source").unwrap_or_else(|| "workflow".into()),
            source_ref: s(v, "sourceRef"),
            plugin_id: s(v, "pluginId"),
        })
    }

    pub(crate) fn list(data: &Value) -> Vec<Workflow> {
        let list = data
            .as_array()
            .or_else(|| data.get("workflows").and_then(Value::as_array));
        list.map(|a| a.iter().filter_map(Workflow::from_value).collect())
            .unwrap_or_default()
    }
}

/// A workflow the server declined to import.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SkippedImport {
    /// The server's reason (`"rejected"` if none was given).
    pub reason: String,
}

/// The result of `importAgentWorkflowText`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ImportResult {
    /// The library after import, if echoed.
    pub workflows: Vec<Workflow>,
    /// Workflows that were imported.
    pub imported: Vec<Workflow>,
    /// Workflows that were skipped, with reasons.
    pub skipped: Vec<SkippedImport>,
}

/// A `resolveLocalToolPermission` decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalToolResolution {
    /// Allow this one tool call (`"allow-once"`).
    AllowOnce,
    /// Deny it (`"deny"`).
    Deny,
}

impl LocalToolResolution {
    /// The wire value: `"allow-once"` or `"deny"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowOnce => "allow-once",
            Self::Deny => "deny",
        }
    }
}

/// A `resolveAutoReviewApproval` decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoReviewResolution {
    /// Approve (`"approved"`).
    Approved,
    /// Deny (`"denied"`).
    Denied,
}

impl AutoReviewResolution {
    /// The wire value: `"approved"` or `"denied"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }
}

/// One agent from the Cursor backend's `GrokBotService/ListGrokBotTeamAgents`: your own
/// agents plus team agents shared with you (which the box gateway's `listAgents` omits).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TeamAgent {
    /// Gateway agent id (`agentId`); equals the gateway `listAgents` id for your own agents.
    pub agent_id: String,
    /// Name.
    pub name: String,
    /// Description.
    pub description: String,
    /// False for a team agent owned by someone else.
    pub viewer_is_owner: bool,
    /// Visibility is `GROK_BOT_AGENT_VISIBILITY_TEAM`.
    pub team_visible: bool,
    /// Your session with a shared agent; sent as `sessionId` to the gateway.
    pub viewer_session_id: Option<String>,
    /// The owner's display name, for shared agents.
    pub owner_display_name: Option<String>,
    /// Kind is `GROK_BOT_AGENT_KIND_ROOM`.
    pub is_room: bool,
}

impl TeamAgent {
    /// Parse a `ListGrokBotTeamAgentsResponse` (`{entries: [{agent: {...}}]}`). Entries
    /// without an `agentId` are skipped.
    ///
    /// ```
    /// use grokbot_api::TeamAgent;
    /// use serde_json::json;
    ///
    /// let list = TeamAgent::list(&json!({"entries": [{"agent": {
    ///     "agentId": "chomp", "name": "Chomp", "viewerIsOwner": false,
    ///     "visibility": "GROK_BOT_AGENT_VISIBILITY_TEAM", "viewerSessionId": "vs1"}}]}));
    /// assert!(!list[0].viewer_is_owner && list[0].team_visible);
    /// ```
    pub fn list(v: &Value) -> Vec<TeamAgent> {
        let s = |a: &Value, k: &str| a.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let opt = |a: &Value, k: &str| {
            a.get(k)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
        };
        v.get("entries")
            .and_then(Value::as_array)
            .map(|es| {
                es.iter()
                    .filter_map(|e| e.get("agent"))
                    .filter(|a| !s(a, "agentId").is_empty())
                    .map(|a| TeamAgent {
                        agent_id: s(a, "agentId"),
                        name: s(a, "name"),
                        description: s(a, "description"),
                        viewer_is_owner: a.get("viewerIsOwner").and_then(Value::as_bool)
                            != Some(false),
                        team_visible: s(a, "visibility") == "GROK_BOT_AGENT_VISIBILITY_TEAM",
                        viewer_session_id: opt(a, "viewerSessionId"),
                        owner_display_name: opt(a, "ownerDisplayName"),
                        is_room: s(a, "kind") == "GROK_BOT_AGENT_KIND_ROOM",
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}
