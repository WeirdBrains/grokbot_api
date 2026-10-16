use serde_json::Value;
use std::collections::BTreeMap;

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
pub const MAX_GROUP_MEMBERS: usize = 6;
/// Grok Bot truncates workflow (skill) bodies over this many characters.
pub const SKILL_MAX_BODY_LENGTH: usize = 100_000;

/// Gateway connection: base URL, bearer token and extra headers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Session {
    pub gateway_url: String,
    pub gateway_token: String,
    /// Extra headers sent on every call (keys lower-case), e.g. `x-anyrun-network-token`.
    pub headers: BTreeMap<String, String>,
}

impl Session {
    pub fn new(gateway_url: impl Into<String>, gateway_token: impl Into<String>) -> Self {
        Self {
            gateway_url: gateway_url.into(),
            gateway_token: gateway_token.into(),
            headers: BTreeMap::new(),
        }
    }

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
    pub id: String,
    pub name: String,
    pub title: String,
    pub description: String,
    pub avatar_shape: String,
    pub avatar_color: String,
    /// `notifyOnUpdatesEnabled` / `notifyOnAgentUpdates`, when present.
    pub notify_on_updates: Option<bool>,
    /// `isHiddenFromSidebar` / `hiddenFromSidebar`, when present.
    pub hidden_from_sidebar: Option<bool>,
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
    /// Parse one agent record (mirrors grok-bot-cli `asRecord`). Returns None without an id.
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

/// `sendPrompt` request.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SendPrompt {
    pub agent_id: String,
    pub prompt: String,
    /// Idempotency nonce; a v4 UUID is generated when None.
    pub client_nonce: Option<String>,
    /// Reply in a thread rooted at this entry id.
    pub reply_to_id: Option<String>,
}

impl SendPrompt {
    pub fn new(agent_id: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            prompt: prompt.into(),
            ..Default::default()
        }
    }
}

/// `sendPrompt` receipt. Only a `messageId` counts as accepted.
#[derive(Debug, Clone, PartialEq)]
pub struct SendReceipt {
    pub message_id: Option<String>,
    pub client_nonce: String,
    pub delivery: crate::Delivery,
    pub raw: Value,
}

/// `createAgent` request (sent with `origin: "user"`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CreateAgent {
    pub name: String,
    pub description: String,
    pub title: String,
    pub avatar_shape: String,
    pub avatar_color: String,
}

/// `updateAgent` profile. `name` and `description` are always sent.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AgentProfile {
    pub name: String,
    pub description: String,
    pub title: Option<String>,
    pub avatar_shape: Option<String>,
    pub avatar_color: Option<String>,
}

/// `createGroup` request.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CreateGroup {
    pub name: String,
    pub description: String,
    pub member_agent_ids: Vec<String>,
}

/// A workflow ("skill") from `getAgentWorkflows`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub description: String,
    /// `workflow` (library), `managed`, `plugin`, or `automation`.
    pub source: String,
    pub source_ref: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SkippedImport {
    pub reason: String,
}

/// `importAgentWorkflowText` result.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ImportResult {
    /// The library after import, if echoed.
    pub workflows: Vec<Workflow>,
    pub imported: Vec<Workflow>,
    pub skipped: Vec<SkippedImport>,
}

/// `resolveLocalToolPermission` resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalToolResolution {
    AllowOnce,
    Deny,
}

impl LocalToolResolution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowOnce => "allow-once",
            Self::Deny => "deny",
        }
    }
}

/// `resolveAutoReviewApproval` resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoReviewResolution {
    Approved,
    Denied,
}

impl AutoReviewResolution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }
}
