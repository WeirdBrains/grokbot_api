//! Transcript entries (`getAgentTranscriptTail` / `getAgentThread`), parsed like
//! grok-bot-cli's `transcript.js` / `format.js` / `grok-approvals.js`.
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Transcript {
    pub entries: Vec<Entry>,
    /// Present when more older entries exist; pass as `before_seq` on the next page.
    pub next_before_seq: Option<u64>,
    pub raw: Value,
}

impl Transcript {
    pub(crate) fn from_value(v: Value) -> Self {
        let entries = v
            .get("entries")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(Entry::from_value).collect())
            .unwrap_or_default();
        let next_before_seq = v
            .get("nextBeforeSeq")
            .and_then(|x| x.as_u64().or_else(|| x.as_i64().map(|n| n as u64)));
        Transcript {
            entries,
            next_before_seq,
            raw: v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Entry {
    /// Source entry id (may be missing).
    pub id: Option<String>,
    /// First of `role`, `kind`, `sender`, `type`; `"msg"` if none.
    pub role: String,
    /// Best text body (see `entryText` in grok-bot-cli). Not sanitized.
    pub text: String,
    pub raw: Value,
}

fn to_safe_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Number(_) | Value::Bool(_) => v.to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn entry_text(e: &Value) -> String {
    if !e.is_object() {
        return String::new();
    }
    for k in ["text", "prompt", "message"] {
        if let Some(s) = e.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            return s.to_string();
        }
    }
    match e.get("content") {
        Some(Value::String(s)) => return s.clone(),
        Some(Value::Array(parts)) => {
            return parts
                .iter()
                .map(|p| match p {
                    Value::String(s) => s.clone(),
                    Value::Object(_) => p
                        .get("text")
                        .and_then(Value::as_str)
                        .or_else(|| p.get("content").and_then(Value::as_str))
                        .unwrap_or("")
                        .to_string(),
                    _ => String::new(),
                })
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
        }
        Some(c @ Value::Object(_)) => {
            return c
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| to_safe_text(c));
        }
        _ => {}
    }
    // Bot replies: `{ kind: "send-message", message: { type, content } }`.
    if let Some(s) = e
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
    {
        return s.to_string();
    }
    e.get("preview")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

impl Entry {
    pub fn from_value(v: &Value) -> Entry {
        let role = ["role", "kind", "sender", "type"]
            .iter()
            .find_map(|k| v.get(*k).and_then(Value::as_str).filter(|s| !s.is_empty()))
            .unwrap_or("msg")
            .to_string();
        Entry {
            id: v.get("id").and_then(Value::as_str).map(str::to_string),
            role,
            text: entry_text(v),
            raw: v.clone(),
        }
    }

    /// Heuristic: the role names a user/human/prompt entry. The gateway's role vocabulary is
    /// undocumented; bot replies are known to use `kind: "send-message"`.
    pub fn is_from_user(&self) -> bool {
        let r = self.role.to_lowercase();
        r.contains("user") || r.contains("human") || r.contains("prompt")
    }

    /// A pending Grok approval card carried by this entry, if any.
    pub fn approval(&self) -> Option<Approval> {
        Approval::from_entry(&self.raw)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalKind {
    /// `message.type == "auto-review-approval"` → resolve with `resolveAutoReviewApproval`.
    AutoReview,
    /// `message.type == "local-tool-permission"` → resolve with `resolveLocalToolPermission`.
    LocalToolPermission,
}

/// A pending approval request found in a transcript (see grok-bot-cli `grokApproval`).
/// Never approve automatically: approvals need an explicit user decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Approval {
    pub entry_id: String,
    pub request_id: String,
    pub kind: ApprovalKind,
    /// reason, command, summary, action, description, target, machineId, surface, workingDirectory (≤2048 chars each).
    pub details: BTreeMap<String, String>,
    pub truncated: bool,
}

impl Approval {
    fn from_entry(e: &Value) -> Option<Approval> {
        if e.get("kind").and_then(Value::as_str) != Some("send-message") {
            return None;
        }
        let msg = e.get("message")?;
        let (kind, card) = match msg.get("type").and_then(Value::as_str)? {
            "auto-review-approval" => (ApprovalKind::AutoReview, msg.get("approval")?),
            "local-tool-permission" => (ApprovalKind::LocalToolPermission, msg.get("ask")?),
            _ => return None,
        };
        if card.get("status").and_then(Value::as_str) != Some("pending") {
            return None;
        }
        let ok = |s: &str| !s.is_empty() && s.len() <= 1024;
        let request_id = card
            .get("requestId")
            .and_then(Value::as_str)
            .filter(|s| ok(s))?
            .to_string();
        let entry_id = e
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| ok(s))?
            .to_string();
        let mut details = BTreeMap::new();
        let mut truncated = false;
        for k in [
            "reason",
            "command",
            "summary",
            "action",
            "description",
            "target",
            "machineId",
            "surface",
            "workingDirectory",
        ] {
            if let Some(t) = card.get(k).and_then(Value::as_str) {
                truncated |= t.chars().count() > 2048;
                details.insert(k.to_string(), t.chars().take(2048).collect());
            }
        }
        Some(Approval {
            entry_id,
            request_id,
            kind,
            details,
            truncated,
        })
    }
}

/// Strip ANSI escape sequences and control characters (except `\n` and `\t`) so
/// server text cannot drive the terminal.
pub fn sanitize_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            match it.next() {
                Some('[') => {
                    // CSI: parameters/intermediates then a final byte @..~
                    for d in it.by_ref() {
                        if ('@'..='~').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC: until BEL or ESC \
                    while let Some(d) = it.next() {
                        if d == '\u{7}' {
                            break;
                        }
                        if d == '\u{1b}' {
                            it.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        if c == '\n' || c == '\t' || !(c.is_control()) {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entry_text_variants() {
        let t = |v: Value| Entry::from_value(&v).text;
        assert_eq!(t(json!({"text": "a", "preview": "p"})), "a");
        assert_eq!(t(json!({"prompt": "b"})), "b");
        assert_eq!(
            t(json!({"content": [ "x", {"text": "y"}, {"content": "z"}, 3 ]})),
            "x\ny\nz"
        );
        assert_eq!(
            t(json!({"kind": "send-message", "message": {"type": "text", "content": "reply"}})),
            "reply"
        );
        assert_eq!(t(json!({"preview": "only preview"})), "only preview");
        let e = Entry::from_value(&json!({"id": "e1", "kind": "user-prompt", "prompt": "hi"}));
        assert_eq!(e.id.as_deref(), Some("e1"));
        assert!(e.is_from_user());
        assert!(!Entry::from_value(&json!({"kind": "send-message"})).is_from_user());
        assert_eq!(Entry::from_value(&json!({})).role, "msg");
    }

    #[test]
    fn approvals() {
        let e = Entry::from_value(&json!({
            "id": "e9", "kind": "send-message",
            "message": {"type": "local-tool-permission", "ask": {"status": "pending", "requestId": "r1", "command": "rm -rf /"}}
        }));
        let a = e.approval().unwrap();
        assert_eq!((a.entry_id.as_str(), a.request_id.as_str()), ("e9", "r1"));
        assert_eq!(a.kind, ApprovalKind::LocalToolPermission);
        assert_eq!(a.details["command"], "rm -rf /");
        let done = Entry::from_value(&json!({"id": "e", "kind": "send-message",
            "message": {"type": "auto-review-approval", "approval": {"status": "approved", "requestId": "r"}}}));
        assert!(done.approval().is_none());
    }

    #[test]
    fn sanitize() {
        assert_eq!(
            sanitize_text("a\u{1b}[31mred\u{1b}[0m\u{1b}]0;title\u{7}b\u{0}\n\tc"),
            "aredb\n\tc"
        );
    }
}
