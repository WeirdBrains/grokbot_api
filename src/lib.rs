//! # grokbot_api
//!
//! **Unofficial** async client for the Grok Bot gateway.
//!
//! The gateway is private and **undocumented**. Everything here was reverse-engineered
//! from [grok-bot-cli](https://github.com/ScriptedAlchemy/grok-bot-cli)
//! (`src/core/gateway.js`, `headers.js`, `url-policy.js`, `transcript.js`) and may change
//! without notice.
//!
//! ## Protocol
//! Every call is `POST {gateway_url}/api/<method>` with a JSON body and headers
//! `content-type: application/json`, `authorization: Bearer <gateway_token>`, plus any
//! extra session headers. Redirects are refused, there is a 30 s timeout and a 2 MiB
//! response cap. Errors come back as `{ "message" }` or `{ "error" }`.
//!
//! There is no streaming. After [`Client::send_prompt`] (which only returns a receipt),
//! poll [`Client::transcript_tail`] for replies.
//!
//! ## Getting a session
//! - Directly: a gateway URL + gateway token ([`Session::new`]).
//! - From a Cursor access token: [`ensure_sandbox`] / [`Client::connect_cursor`] call
//!   `aiserver.v1.GrokBotService/EnsureSandBox`. A client built this way re-exchanges
//!   automatically when the gateway answers 401.
//!
//! - From the desktop app's saved session (opt-in `desktop-session` feature): see [`desktop`].
//!
//! Credentials are only ever sent to hosts allowed by [`Policy`].

mod client;
#[cfg(feature = "desktop-session")]
pub mod desktop;
mod error;
mod policy;
mod transcript;
mod types;

pub use client::{
    AcceptanceStatus, Client, ClientOptions, DEFAULT_BACKEND_BASE, DEFAULT_CLIENT_TYPE,
    DEFAULT_CLIENT_VERSION, DEFAULT_SANDBOX_NAMESPACE, MAX_RESPONSE_BYTES, TIMEOUT, ensure_sandbox,
};
pub use error::{Delivery, Error, Result};
pub use policy::{ALLOW_LOCAL_ENV, Policy};
pub use transcript::{Approval, ApprovalKind, Entry, Transcript, sanitize_text};
pub use types::{
    AVATAR_COLORS, AVATAR_SHAPES, Agent, AgentProfile, AutoReviewResolution, CreateAgent,
    CreateGroup, ImportResult, LocalToolResolution, MAX_GROUP_MEMBERS, SKILL_MAX_BODY_LENGTH,
    SendPrompt, SendReceipt, Session, SkippedImport, Workflow,
};
