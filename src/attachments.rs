//! Prompt attachments: upload a file to the Grok Bot attachment store and get an alias
//! to send with [`SendPrompt::attachment_paths`](crate::SendPrompt::attachment_paths).
//!
//! The flow is `BeginGrokBotAttachmentUpload` → HTTPS `PUT` of the bytes to the presigned
//! URL(s) the backend returned → `CompleteGrokBotAttachmentUpload`, which returns the
//! alias. All four backend calls need a Cursor access token (a client built with
//! [`Client::connect_cursor`](crate::Client::connect_cursor) or
//! [`Client::with_cursor_token`](crate::Client::with_cursor_token)).
//!
//! The presigned `PUT` never carries a bearer token: only the headers the backend
//! returned are sent, only to the exact URL it returned, and only over `https`
//! (loopback http is allowed with [`Policy::allow_local_backend`](crate::Policy)).
//! Errors name the upload host, never the URL's query string or signature.
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::client::{Client, grokbot_service_call};
use crate::error::{Error, Result};

/// Image size limit the desktop app enforces before uploading (the server is final).
pub const MAX_IMAGE_BYTES: u64 = 25 * 1024 * 1024;
/// Size limit for non-image, non-video files.
pub const MAX_FILE_BYTES: u64 = 250 * 1024 * 1024;
/// Size limit for video.
pub const MAX_VIDEO_BYTES: u64 = 1024 * 1024 * 1024;
/// Most attachments the desktop app stages on one prompt.
pub const MAX_ATTACHMENTS_PER_PROMPT: usize = 6;

const PRESIGN_BATCH: usize = 64;
const PUT_ATTEMPTS: u32 = 3;

/// The broad kind of a file, from its extension (drives the client-side size limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentKind {
    /// avif bmp gif ico jpeg jpg png svg webp heic heif
    Image,
    /// m4v mp4 mov ogv webm
    Video,
    /// aac flac m4a mp3 oga ogg opus wav weba
    Audio,
    /// Anything else.
    File,
}

impl AttachmentKind {
    /// Classify a file name by extension (case-insensitive).
    pub fn from_name(name: &str) -> Self {
        let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
        match ext.as_deref() {
            Some(
                "avif" | "bmp" | "gif" | "ico" | "jpeg" | "jpg" | "png" | "svg" | "webp" | "heic"
                | "heif",
            ) => Self::Image,
            Some("m4v" | "mp4" | "mov" | "ogv" | "webm") => Self::Video,
            Some("aac" | "flac" | "m4a" | "mp3" | "oga" | "ogg" | "opus" | "wav" | "weba") => {
                Self::Audio
            }
            _ => Self::File,
        }
    }

    /// The client-side size limit for this kind.
    pub fn limit_bytes(self) -> u64 {
        match self {
            Self::Image => MAX_IMAGE_BYTES,
            Self::Video => MAX_VIDEO_BYTES,
            _ => MAX_FILE_BYTES,
        }
    }
}

/// Check a file name and size the way the desktop app does before uploading.
pub fn validate_attachment(name: &str, size: u64) -> Result<()> {
    if name.is_empty() || name.chars().count() > 255 || name.contains(['/', '\\', '\0']) {
        return Err(Error::Validation(format!(
            "Invalid attachment file name {name:?}."
        )));
    }
    if size == 0 {
        return Err(Error::Validation(format!("{name} is empty.")));
    }
    let limit = AttachmentKind::from_name(name).limit_bytes();
    if size > limit {
        return Err(Error::Validation(format!(
            "{name} is {} MiB; the limit for this type is {} MiB.",
            size.div_ceil(1024 * 1024),
            limit / (1024 * 1024)
        )));
    }
    Ok(())
}

fn enum_value(v: Option<&Value>, prefix: &str, names: &[&str]) -> usize {
    match v {
        Some(Value::Number(n)) => n.as_u64().map(|n| n as usize).unwrap_or(0),
        Some(Value::String(s)) => {
            if let Ok(n) = s.parse::<usize>() {
                return n;
            }
            let short = s.strip_prefix(prefix).unwrap_or(s);
            names.iter().position(|n| *n == short).unwrap_or(0)
        }
        _ => 0,
    }
}

macro_rules! proto_enum {
    ($(#[$m:meta])* $name:ident, $prefix:literal, [$($(#[$vm:meta])* $var:ident = $wire:literal),+ $(,)?]) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub enum $name {
            /// Not set (proto value 0) or a value this crate does not know.
            #[default]
            Unspecified,
            $($(#[$vm])* $var),+
        }
        impl $name {
            const NAMES: &'static [&'static str] = &["UNSPECIFIED", $($wire),+];
            /// Parse a Connect-JSON value: the full proto name (`
            #[doc = $prefix]
            /// …`), the short name, or the number.
            pub fn from_json(v: Option<&Value>) -> Self {
                let all = [Self::Unspecified, $(Self::$var),+];
                all.get(enum_value(v, $prefix, Self::NAMES)).copied().unwrap_or_default()
            }
            /// The short proto name, e.g. `UNSPECIFIED`.
            pub fn as_str(self) -> &'static str {
                let all = [Self::Unspecified, $(Self::$var),+];
                Self::NAMES[all.iter().position(|x| *x == self).unwrap_or(0)]
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
        }
    };
}

proto_enum!(
    /// How the backend wants the file uploaded (`GrokBotAttachmentUploadMode`).
    UploadMode, "GROK_BOT_ATTACHMENT_UPLOAD_MODE_", [
    /// The agent only takes files through the desktop app's host link.
    UseBox = "USE_BOX",
    /// One PUT of the whole body.
    SinglePut = "SINGLE_PUT",
    /// Presigned parts.
    Multipart = "MULTIPART",
    /// Refused; see the refusal.
    Refused = "REFUSED",
]);

proto_enum!(
    /// Why an upload was refused (`GrokBotAttachmentUploadRefusal`).
    UploadRefusal, "GROK_BOT_ATTACHMENT_UPLOAD_REFUSAL_", [
    /// Over the size limit (see `limit_bytes`).
    TooLarge = "TOO_LARGE",
    /// The agent's attachment store is full.
    AgentFull = "AGENT_FULL",
    /// The upload session expired.
    Expired = "EXPIRED",
    /// Not all bytes arrived.
    Incomplete = "INCOMPLETE",
    /// The stored size differs from the declared size.
    SizeMismatch = "SIZE_MISMATCH",
    /// Declared as an image but is not one.
    NotAnImage = "NOT_AN_IMAGE",
    /// The target changed during the upload.
    TargetChanged = "TARGET_CHANGED",
    /// The file type is not accepted.
    UnsupportedType = "UNSUPPORTED_TYPE",
]);

proto_enum!(
    /// Where an attachment can be read from (`GrokBotAttachmentReadOutcome`).
    ReadOutcome, "GROK_BOT_ATTACHMENT_READ_OUTCOME_", [
    /// In the store; `url` is a presigned https GET.
    Store = "STORE",
    /// Not in the store (e.g. a box path).
    NotInStore = "NOT_IN_STORE",
    /// The agent has no storage.
    NoStorage = "NO_STORAGE",
]);

impl UploadRefusal {
    /// A human-readable explanation.
    pub fn describe(self, limit_bytes: Option<u64>) -> String {
        match self {
            Self::TooLarge => match limit_bytes {
                Some(l) if l > 0 => format!(
                    "the file is too large (limit {} MiB)",
                    l.div_ceil(1024 * 1024)
                ),
                _ => "the file is too large".into(),
            },
            Self::AgentFull => "this bot's attachment storage is full".into(),
            Self::Expired => "the upload session expired".into(),
            Self::Incomplete => "the upload was incomplete".into(),
            Self::SizeMismatch => "the uploaded size did not match".into(),
            Self::NotAnImage => "the file is not a valid image".into(),
            Self::TargetChanged => "the upload target changed; try again".into(),
            Self::UnsupportedType => "this file type is not accepted".into(),
            Self::Unspecified => "the upload was refused".into(),
        }
    }
}

fn num(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}
fn s(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// A presigned request target (`GrokBotAttachmentUploadRequestTarget`).
#[derive(Clone, PartialEq, Default)]
pub struct UploadTarget {
    /// The presigned URL. Treat it as a secret: it carries a signature.
    pub url: String,
    /// Headers that must be sent with the request.
    pub headers: BTreeMap<String, String>,
    /// When the URL expires (ms since epoch), if given.
    pub expires_at_ms: Option<u64>,
}

impl fmt::Debug for UploadTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadTarget")
            .field("host", &url_host(&self.url))
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl UploadTarget {
    fn parse(v: Option<&Value>) -> Option<Self> {
        let v = v?;
        let url = s(v, "url");
        if url.is_empty() {
            return None;
        }
        let headers = v
            .get("headers")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            url,
            headers,
            expires_at_ms: num(v.get("expiresAtMs")),
        })
    }
}

/// `BeginGrokBotAttachmentUpload` response.
#[derive(Clone, PartialEq, Default)]
pub struct BeginUpload {
    /// What to do next.
    pub mode: UploadMode,
    /// Why `USE_BOX` was chosen, if given.
    pub use_box_reason: String,
    /// Set when `mode` is `REFUSED`.
    pub refusal: UploadRefusal,
    /// The applicable size limit, if given.
    pub limit_bytes: Option<u64>,
    /// Opaque upload state for presign/complete/abort. Treat it as a secret.
    pub upload_token: String,
    /// When the upload session expires (ms since epoch).
    pub session_expires_at_ms: Option<u64>,
    /// The single-PUT target.
    pub put: Option<UploadTarget>,
    /// Multipart part size.
    pub part_size_bytes: Option<u64>,
    /// Multipart part count.
    pub part_count: Option<u64>,
}

impl fmt::Debug for BeginUpload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BeginUpload")
            .field("mode", &self.mode)
            .field("use_box_reason", &self.use_box_reason)
            .field("refusal", &self.refusal)
            .field("limit_bytes", &self.limit_bytes)
            .field("put", &self.put)
            .field("part_size_bytes", &self.part_size_bytes)
            .field("part_count", &self.part_count)
            .finish_non_exhaustive()
    }
}

impl BeginUpload {
    /// Parse a Connect-JSON response.
    pub fn from_value(v: &Value) -> Self {
        Self {
            mode: UploadMode::from_json(v.get("mode")),
            use_box_reason: s(v, "useBoxReason"),
            refusal: UploadRefusal::from_json(v.get("refusal")),
            limit_bytes: num(v.get("limitBytes")),
            upload_token: s(v, "uploadToken"),
            session_expires_at_ms: num(v.get("sessionExpiresAtMs")),
            put: UploadTarget::parse(v.get("put")),
            part_size_bytes: num(v.get("partSizeBytes")),
            part_count: num(v.get("partCount")),
        }
    }
}

/// One presigned part (`GrokBotAttachmentUploadPart`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UploadPart {
    /// 1-based part number.
    pub part_number: u32,
    /// Offset in the file.
    pub offset_bytes: u64,
    /// Part length.
    pub size_bytes: u64,
    /// Where to PUT it.
    pub target: Option<UploadTarget>,
}

/// `PresignGrokBotAttachmentUploadParts` response.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PresignedParts {
    /// Set when refused.
    pub refusal: UploadRefusal,
    /// Presigned parts.
    pub parts: Vec<UploadPart>,
    /// A fresh single-PUT target (when called with no parts).
    pub put: Option<UploadTarget>,
}

/// `CompleteGrokBotAttachmentUpload` response.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CompletedUpload {
    /// Set when refused.
    pub refusal: UploadRefusal,
    /// The limit, with `TOO_LARGE`.
    pub limit_bytes: Option<u64>,
    /// The alias to put in `attachmentPaths`.
    pub alias: String,
    /// Stored file name.
    pub file_name: String,
    /// Stored size.
    pub size_bytes: Option<u64>,
    /// Detected content type.
    pub content_type: String,
}

/// A successfully uploaded attachment, ready for [`SendPrompt`](crate::SendPrompt).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UploadedAttachment {
    /// The alias for `attachment_paths`.
    pub alias: String,
    /// The name for `attachment_names`.
    pub name: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Content type reported by the backend.
    pub content_type: String,
}

/// One resolved read (`GrokBotAttachmentRead`).
#[derive(Clone, PartialEq, Default)]
pub struct AttachmentRead {
    /// The path or alias that was asked about.
    pub path: String,
    /// Where it lives.
    pub outcome: ReadOutcome,
    /// Presigned https GET (for `STORE`). Treat it as a secret.
    pub url: String,
    /// When `url` expires.
    pub expires_at_ms: Option<u64>,
    /// Content type.
    pub content_type: String,
    /// Size in bytes.
    pub size_bytes: Option<u64>,
    /// ETag.
    pub etag: String,
}

impl fmt::Debug for AttachmentRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentRead")
            .field("path", &self.path)
            .field("outcome", &self.outcome)
            .field("host", &url_host(&self.url))
            .field("content_type", &self.content_type)
            .field("size_bytes", &self.size_bytes)
            .finish_non_exhaustive()
    }
}

/// Progress of [`Client::upload_attachment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadProgress {
    /// Bytes acknowledged so far.
    pub sent: u64,
    /// Total bytes.
    pub total: u64,
}

/// Why [`Client::upload_attachment`] could not produce an alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadFailure {
    /// The client has no Cursor access token.
    NoCursorSession,
    /// The backend refused (`REFUSED`, or a refusal on presign/complete).
    Refused {
        /// The reason.
        reason: UploadRefusal,
        /// The limit, for `TOO_LARGE`.
        limit_bytes: Option<u64>,
    },
    /// The agent only takes files through the desktop app.
    UseBox {
        /// The backend's reason text.
        reason: String,
    },
}

impl fmt::Display for UploadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCursorSession => f.write_str(
                "attachments need a Cursor sign-in (connect with a Cursor access token)",
            ),
            Self::Refused {
                reason,
                limit_bytes,
            } => write!(f, "upload refused: {}", reason.describe(*limit_bytes)),
            Self::UseBox { reason } if reason.is_empty() => {
                f.write_str("this bot only takes files through the desktop app")
            }
            Self::UseBox { reason } => write!(
                f,
                "this bot only takes files through the desktop app ({reason})"
            ),
        }
    }
}

/// The host of a URL, without credentials, path or query.
pub fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or_default();
    auth.rsplit('@').next().unwrap_or_default().to_string()
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// SHA-256 as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn refused(reason: UploadRefusal, limit_bytes: Option<u64>) -> Error {
    Error::Attachment(UploadFailure::Refused {
        reason,
        limit_bytes,
    })
}

impl Client {
    fn cursor_token(&self) -> Result<String> {
        self.cursor_token_opt()
            .ok_or(Error::Attachment(UploadFailure::NoCursorSession))
    }

    async fn backend(&self, method: &str, body: Value) -> Result<Value> {
        let tok = self.cursor_token()?;
        grokbot_service_call(&tok, method, &body, self.options()).await
    }

    fn session_for(&self, agent_id: &str, session_id: Option<&str>) -> Option<String> {
        session_id
            .map(str::to_string)
            .or_else(|| self.agent_session_id(agent_id))
    }

    /// `BeginGrokBotAttachmentUpload`. `session_id` defaults to the agent's viewer session.
    pub async fn begin_attachment_upload(
        &self,
        agent_id: &str,
        session_id: Option<&str>,
        file_name: &str,
        size_bytes: u64,
        sha256_hex: Option<&str>,
    ) -> Result<BeginUpload> {
        let mut body = json!({
            "agentId": agent_id,
            "fileName": file_name,
            "sizeBytes": size_bytes.to_string(),
            "supportsStoreAttachmentRefs": true,
            "supportsMultipart": true,
        });
        if let Some(sid) = self.session_for(agent_id, session_id) {
            body["sessionId"] = json!(sid);
        }
        if let Some(h) = sha256_hex {
            body["sha256Hex"] = json!(h);
        }
        let v = self.backend("BeginGrokBotAttachmentUpload", body).await?;
        Ok(BeginUpload::from_value(&v))
    }

    /// `PresignGrokBotAttachmentUploadParts`: `parts` are `(part_number, sha256)`. With no
    /// parts it re-presigns the single PUT.
    pub async fn presign_attachment_upload_parts(
        &self,
        upload_token: &str,
        parts: &[(u32, [u8; 32])],
    ) -> Result<PresignedParts> {
        let parts: Vec<Value> = parts
            .iter()
            .map(|(n, c)| json!({"partNumber": n, "checksumSha256": b64(c)}))
            .collect();
        let v = self
            .backend(
                "PresignGrokBotAttachmentUploadParts",
                json!({"uploadToken": upload_token, "parts": parts}),
            )
            .await?;
        Ok(PresignedParts {
            refusal: UploadRefusal::from_json(v.get("refusal")),
            parts: v
                .get("parts")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|p| UploadPart {
                            part_number: num(p.get("partNumber")).unwrap_or(0) as u32,
                            offset_bytes: num(p.get("offsetBytes")).unwrap_or(0),
                            size_bytes: num(p.get("sizeBytes")).unwrap_or(0),
                            target: UploadTarget::parse(p.get("target")),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            put: UploadTarget::parse(v.get("put")),
        })
    }

    /// `CompleteGrokBotAttachmentUpload`.
    pub async fn complete_attachment_upload(&self, upload_token: &str) -> Result<CompletedUpload> {
        let v = self
            .backend(
                "CompleteGrokBotAttachmentUpload",
                json!({"uploadToken": upload_token}),
            )
            .await?;
        Ok(CompletedUpload {
            refusal: UploadRefusal::from_json(v.get("refusal")),
            limit_bytes: num(v.get("limitBytes")),
            alias: s(&v, "alias"),
            file_name: s(&v, "fileName"),
            size_bytes: num(v.get("sizeBytes")),
            content_type: s(&v, "contentType"),
        })
    }

    /// `AbortGrokBotAttachmentUpload` (best effort cleanup).
    pub async fn abort_attachment_upload(&self, upload_token: &str) -> Result<()> {
        self.backend(
            "AbortGrokBotAttachmentUpload",
            json!({"uploadToken": upload_token}),
        )
        .await
        .map(|_| ())
    }

    /// `ResolveGrokBotAttachmentReads`: presigned GETs for attachment paths/aliases.
    pub async fn resolve_attachment_reads(
        &self,
        agent_id: &str,
        session_id: Option<&str>,
        paths: &[String],
    ) -> Result<Vec<AttachmentRead>> {
        let mut body = json!({"agentId": agent_id, "paths": paths});
        if let Some(sid) = self.session_for(agent_id, session_id) {
            body["sessionId"] = json!(sid);
        }
        let v = self.backend("ResolveGrokBotAttachmentReads", body).await?;
        Ok(v.get("reads")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|r| AttachmentRead {
                        path: s(r, "path"),
                        outcome: ReadOutcome::from_json(r.get("outcome")),
                        url: s(r, "url"),
                        expires_at_ms: num(r.get("expiresAtMs")),
                        content_type: s(r, "contentType"),
                        size_bytes: num(r.get("sizeBytes")),
                        etag: s(r, "etag"),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn check_presigned(&self, url: &str) -> Result<()> {
        let host = url_host(url);
        let local = matches!(
            host.rsplit_once(':').map(|(h, _)| h).unwrap_or(&host),
            "localhost" | "127.0.0.1" | "[::1]"
        );
        if url.starts_with("https://")
            || (local && self.options().policy.allow_local_backend && url.starts_with("http://"))
        {
            Ok(())
        } else {
            Err(Error::Policy(format!(
                "Refused presigned URL on {host}: must be https."
            )))
        }
    }

    async fn put_bytes(&self, t: &UploadTarget, body: &[u8]) -> Result<()> {
        const M: &str = "attachment PUT";
        self.check_presigned(&t.url)?;
        let host = url_host(&t.url);
        if let Some((_, v)) = t
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            && v.parse::<usize>().ok() != Some(body.len())
        {
            return Err(Error::Validation(format!(
                "{M} to {host}: content-length header does not match the body"
            )));
        }
        // Fresh client: no default auth, no redirects, timeout scaled to size.
        let secs = 30 + body.len() as u64 / (256 * 1024);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(secs))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Transport {
                method: M.into(),
                message: format!("{host}: {}", e.without_url()),
            })?;
        let mut last = None;
        for attempt in 0..PUT_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(500u64 << attempt.min(3))).await;
            }
            let mut rb = http.put(&t.url).body(body.to_vec());
            for (k, v) in &t.headers {
                if k.eq_ignore_ascii_case("authorization") || k.eq_ignore_ascii_case("host") {
                    continue;
                }
                rb = rb.header(k, v);
            }
            match rb.send().await {
                Ok(r) if r.status().is_success() => return Ok(()),
                Ok(r) => {
                    let status = r.status().as_u16();
                    let e = Error::Http {
                        method: M.into(),
                        status,
                        message: format!("upload to {host} failed"),
                    };
                    if status < 500 && status != 429 {
                        return Err(e);
                    }
                    last = Some(e);
                }
                Err(e) => {
                    last = Some(Error::Transport {
                        method: M.into(),
                        message: format!("{host}: {}", e.without_url()),
                    })
                }
            }
        }
        Err(last.unwrap())
    }

    /// Upload `data` as `file_name` for `agent_id` and return the alias.
    ///
    /// Handles `SINGLE_PUT` and `MULTIPART`, calls `progress` as bytes are acknowledged,
    /// and aborts the upload on any failure after Begin. Refusals, `USE_BOX` and a missing
    /// Cursor session come back as [`Error::Attachment`].
    pub async fn upload_attachment(
        &self,
        agent_id: &str,
        session_id: Option<&str>,
        file_name: &str,
        data: &[u8],
        mut progress: impl FnMut(UploadProgress) + Send,
    ) -> Result<UploadedAttachment> {
        self.cursor_token()?;
        validate_attachment(file_name, data.len() as u64)?;
        let total = data.len() as u64;
        let hash = (data.len() <= 64 * 1024 * 1024).then(|| sha256_hex(data));
        let begin = self
            .begin_attachment_upload(agent_id, session_id, file_name, total, hash.as_deref())
            .await?;
        match begin.mode {
            UploadMode::UseBox => {
                return Err(Error::Attachment(UploadFailure::UseBox {
                    reason: begin.use_box_reason,
                }));
            }
            UploadMode::Refused => return Err(refused(begin.refusal, begin.limit_bytes)),
            UploadMode::Unspecified => {
                return Err(Error::InvalidResponse {
                    method: "BeginGrokBotAttachmentUpload".into(),
                    message: "no upload mode".into(),
                });
            }
            _ => {}
        }
        if begin.upload_token.is_empty() {
            return Err(Error::InvalidResponse {
                method: "BeginGrokBotAttachmentUpload".into(),
                message: "no uploadToken".into(),
            });
        }
        let token = begin.upload_token.clone();
        progress(UploadProgress { sent: 0, total });
        let res = self.upload_body(&begin, data, &mut progress).await;
        let res = match res {
            Ok(()) => self.complete_attachment_upload(&token).await.and_then(|c| {
                if c.refusal != UploadRefusal::Unspecified {
                    Err(refused(c.refusal, c.limit_bytes))
                } else if c.alias.is_empty() {
                    Err(Error::InvalidResponse {
                        method: "CompleteGrokBotAttachmentUpload".into(),
                        message: "no alias".into(),
                    })
                } else {
                    Ok(UploadedAttachment {
                        alias: c.alias,
                        name: if c.file_name.is_empty() {
                            file_name.to_string()
                        } else {
                            c.file_name
                        },
                        size_bytes: c.size_bytes.unwrap_or(total),
                        content_type: c.content_type,
                    })
                }
            }),
            Err(e) => Err(e),
        };
        if res.is_err() {
            let _ = self.abort_attachment_upload(&token).await;
        }
        res
    }

    async fn upload_body(
        &self,
        begin: &BeginUpload,
        data: &[u8],
        progress: &mut (impl FnMut(UploadProgress) + Send),
    ) -> Result<()> {
        let total = data.len() as u64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if begin.mode == UploadMode::SinglePut {
            let put = match &begin.put {
                Some(p) if p.expires_at_ms.is_none_or(|e| e > now + 30_000) => p.clone(),
                _ => {
                    let p = self
                        .presign_attachment_upload_parts(&begin.upload_token, &[])
                        .await?;
                    if p.refusal != UploadRefusal::Unspecified {
                        return Err(refused(p.refusal, None));
                    }
                    p.put.ok_or_else(|| Error::InvalidResponse {
                        method: "PresignGrokBotAttachmentUploadParts".into(),
                        message: "no put target".into(),
                    })?
                }
            };
            self.put_bytes(&put, data).await?;
            progress(UploadProgress { sent: total, total });
            return Ok(());
        }
        let size = begin.part_size_bytes.unwrap_or(0);
        let count = begin.part_count.unwrap_or(0);
        if size == 0 || count != total.div_ceil(size) {
            return Err(Error::InvalidResponse {
                method: "BeginGrokBotAttachmentUpload".into(),
                message: "part layout mismatch".into(),
            });
        }
        let mut sent = 0;
        let numbers: Vec<u32> = (1..=count as u32).collect();
        for batch in numbers.chunks(PRESIGN_BATCH) {
            let sums: Vec<(u32, [u8; 32])> = batch
                .iter()
                .map(|n| {
                    let off = (*n as u64 - 1) * size;
                    let end = (off + size).min(total);
                    (*n, Sha256::digest(&data[off as usize..end as usize]).into())
                })
                .collect();
            let p = self
                .presign_attachment_upload_parts(&begin.upload_token, &sums)
                .await?;
            if p.refusal != UploadRefusal::Unspecified {
                return Err(refused(p.refusal, None));
            }
            for n in batch {
                let part = p
                    .parts
                    .iter()
                    .find(|x| x.part_number == *n)
                    .and_then(|x| x.target.as_ref())
                    .ok_or_else(|| Error::InvalidResponse {
                        method: "PresignGrokBotAttachmentUploadParts".into(),
                        message: format!("no target for part {n}"),
                    })?;
                let off = (*n as u64 - 1) * size;
                let end = (off + size).min(total);
                self.put_bytes(part, &data[off as usize..end as usize])
                    .await?;
                sent += end - off;
                progress(UploadProgress { sent, total });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enums_accept_full_short_and_numeric() {
        for v in [
            json!("GROK_BOT_ATTACHMENT_UPLOAD_MODE_SINGLE_PUT"),
            json!("SINGLE_PUT"),
            json!(2),
            json!("2"),
        ] {
            assert_eq!(UploadMode::from_json(Some(&v)), UploadMode::SinglePut);
        }
        assert_eq!(
            UploadMode::from_json(Some(&json!("WHAT"))),
            UploadMode::Unspecified
        );
        assert_eq!(
            UploadRefusal::from_json(Some(&json!(
                "GROK_BOT_ATTACHMENT_UPLOAD_REFUSAL_AGENT_FULL"
            ))),
            UploadRefusal::AgentFull
        );
        assert_eq!(ReadOutcome::from_json(Some(&json!(1))), ReadOutcome::Store);
    }
    #[test]
    fn base64_and_host() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
        assert_eq!(
            url_host("https://u:p@bucket.s3.aws.com/k?X-Amz-Signature=abc"),
            "bucket.s3.aws.com"
        );
    }
    #[test]
    fn validation() {
        assert!(validate_attachment("a.png", 10).is_ok());
        assert!(validate_attachment("a.png", 0).is_err());
        assert!(validate_attachment("a/b.png", 1).is_err());
        assert!(validate_attachment("a.png", MAX_IMAGE_BYTES + 1).is_err());
        assert!(validate_attachment("a.pdf", MAX_IMAGE_BYTES + 1).is_ok());
        assert!(validate_attachment("a.mp4", MAX_FILE_BYTES + 1).is_ok());
        assert_eq!(AttachmentKind::from_name("X.JPG"), AttachmentKind::Image);
    }
    #[test]
    fn debug_hides_url_and_token() {
        let b = BeginUpload::from_value(&json!({
            "mode": "SINGLE_PUT", "uploadToken": "secret-tok",
            "put": {"url": "https://h.example/k?sig=SECRET", "headers": {"x": "y"}}
        }));
        let d = format!("{b:?}");
        assert!(!d.contains("SECRET") && !d.contains("secret-tok"));
        assert!(d.contains("h.example"));
    }
}
