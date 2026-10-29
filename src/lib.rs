#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod attachments;
mod client;
#[cfg(feature = "desktop-session")]
#[cfg_attr(docsrs, doc(cfg(feature = "desktop-session")))]
pub mod desktop;
mod error;
mod policy;
mod presence;
mod transcript;
mod types;

pub mod guide;

pub use attachments::{
    AttachmentKind, AttachmentRead, ReadOutcome, UploadFailure, UploadMode, UploadProgress,
    UploadRefusal, UploadedAttachment,
};
pub use client::{
    AcceptanceStatus, Client, ClientOptions, DEFAULT_BACKEND_BASE, DEFAULT_CLIENT_TYPE,
    DEFAULT_CLIENT_VERSION, DEFAULT_SANDBOX_NAMESPACE, MAX_RESPONSE_BYTES, TIMEOUT, ensure_sandbox,
    grokbot_service_call,
};
pub use error::{Delivery, Error, Result};
pub use policy::{ALLOW_LOCAL_ENV, Policy};
pub use presence::BoxIntent;
pub use transcript::{Approval, ApprovalKind, Entry, Transcript, sanitize_text};
pub use types::{
    AVATAR_COLORS, AVATAR_SHAPES, Agent, AgentProfile, AutoReviewResolution, CreateAgent,
    CreateGroup, ImportResult, LocalToolResolution, MAX_GROUP_MEMBERS, SKILL_MAX_BODY_LENGTH,
    SendPrompt, SendReceipt, Session, SkippedImport, TeamAgent, Workflow,
};
