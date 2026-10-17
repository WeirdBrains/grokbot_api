//! Topic guides.
//!
//! Each submodule renders one of the Markdown guides that ship with the crate (the same
//! files linked from the README). They contain no code; their examples are compiled as
//! doctests.
//!
//! | Guide | Topic |
//! |---|---|
//! | [`sessions`] | Gateway sessions, EnsureSandBox, 401/417 re-authentication, `ClientOptions` |
//! | [`policy`] | Which hosts may receive credentials |
//! | [`agents`] | Bots, groups and team agents |
//! | [`messaging`] | Sending prompts and delivery states |
//! | [`transcripts`] | Paging transcripts and parsing entries |
//! | [`approvals`] | Detecting and resolving approval cards |
//! | [`workflows`] | Skills (workflows) |
//! | [`errors`] | Error variants and secret redaction |
//! | `desktop` | Reading the desktop app's session (`desktop-session` feature) |
//! | [`protocol`] | Wire protocol reference |
//!
//! Links between guides point at the Markdown files in the repository.

#[doc = include_str!("../SESSIONS.md")]
pub mod sessions {}

#[doc = include_str!("../POLICY.md")]
pub mod policy {}

#[doc = include_str!("../AGENTS.md")]
pub mod agents {}

#[doc = include_str!("../MESSAGING.md")]
pub mod messaging {}

#[doc = include_str!("../TRANSCRIPTS.md")]
pub mod transcripts {}

#[doc = include_str!("../APPROVALS.md")]
pub mod approvals {}

#[doc = include_str!("../WORKFLOWS.md")]
pub mod workflows {}

#[doc = include_str!("../ERRORS.md")]
pub mod errors {}

#[cfg(feature = "desktop-session")]
#[cfg_attr(docsrs, doc(cfg(feature = "desktop-session")))]
#[doc = include_str!("../DESKTOP.md")]
pub mod desktop {}

#[doc = include_str!("../PROTOCOL.md")]
pub mod protocol {}
