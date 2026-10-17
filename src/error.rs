//! The crate's error type and the delivery classification used after `sendPrompt`.
use std::fmt;

/// Shorthand for `std::result::Result<T, grokbot_api::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Whether a prompt reached the gateway.
///
/// Returned on [`SendReceipt::delivery`](crate::SendReceipt::delivery) and derived from a
/// failed send with [`Error::delivery`]. See the `MESSAGING.md` guide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The gateway acknowledged the prompt (`{accepted: true}` or a `messageId`).
    Accepted,
    /// The request was refused before or by the server (policy, validation, 4xx). Safe to fix and resend.
    Rejected,
    /// The request may have landed (network error, timeout, 5xx, or no receipt).
    /// Read the transcript, or ask [`Client::prompt_acceptance_status`](crate::Client::prompt_acceptance_status),
    /// before resending.
    Unknown,
}

impl fmt::Display for Delivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Delivery::Accepted => "accepted",
            Delivery::Rejected => "rejected",
            Delivery::Unknown => "unknown",
        })
    }
}

/// Everything that can go wrong talking to the gateway, the Cursor backend, or the
/// desktop app's saved session.
///
/// Error messages never contain the gateway token, the Cursor access token, or session
/// header values: they are replaced with `<redacted>`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The URL is not allowed to receive credentials (see [`crate::Policy`]). Nothing was sent.
    #[error("{0}")]
    Policy(String),
    /// Input rejected locally before sending. Nothing was sent.
    #[error("{0}")]
    Validation(String),
    /// The server answered with a non-2xx status (or `sendPrompt` was refused; reported as 422).
    #[error("{method} failed: {status} {message}")]
    Http {
        /// The gateway or backend method, e.g. `listAgents` or `EnsureSandBox`.
        method: String,
        /// The HTTP status code.
        status: u16,
        /// The server's `message` / `error` text (truncated, secrets redacted).
        message: String,
    },
    /// Network error, timeout, or a refused redirect. Delivery is unknown.
    #[error("{method} failed: {message}")]
    Transport {
        /// The method being called.
        method: String,
        /// What went wrong (secrets redacted).
        message: String,
    },
    /// The response body exceeded the configured cap ([`crate::MAX_RESPONSE_BYTES`] by default).
    #[error("{method}: gateway response too large (over {limit} bytes)")]
    TooLarge {
        /// The method being called.
        method: String,
        /// The cap that was exceeded, in bytes.
        limit: usize,
    },
    /// Reading the desktop app's saved session failed (`desktop-session` feature).
    #[error("{message}")]
    Desktop {
        /// A stable machine-readable code such as `APP_NOT_FOUND`, `NOT_SIGNED_IN`,
        /// `AMBIGUOUS_ENTRIES` or `DECRYPT_FAILED` (see the `DESKTOP.md` guide).
        code: String,
        /// A human-readable explanation.
        message: String,
    },
    /// The response was not the expected shape.
    #[error("{method}: {message}")]
    InvalidResponse {
        /// The method being called.
        method: String,
        /// What was missing or malformed.
        message: String,
    },
}

impl Error {
    /// The HTTP status, for [`Error::Http`] only.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Http { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The session/credential was rejected. The gateway answers an expired session
    /// with 417 (empty body) rather than 401, so both mean "re-authenticate".
    pub fn is_unauthorized(&self) -> bool {
        matches!(self.status(), Some(401) | Some(417))
    }

    /// The delivery state implied by this error if it came from `sendPrompt`:
    /// [`Delivery::Rejected`] for policy, validation and 4xx errors, otherwise
    /// [`Delivery::Unknown`].
    pub fn delivery(&self) -> Delivery {
        match self {
            Error::Policy(_) | Error::Validation(_) => Delivery::Rejected,
            Error::Http { status, .. } if *status < 500 => Delivery::Rejected,
            _ => Delivery::Unknown,
        }
    }
}

#[cfg(test)]
mod auth_tests {
    use super::*;
    fn http(status: u16) -> Error {
        Error::Http {
            status,
            method: "listAgents".into(),
            message: String::new(),
        }
    }
    #[test]
    fn expired_session_417_counts_as_unauthorized() {
        assert!(http(401).is_unauthorized());
        assert!(http(417).is_unauthorized());
        assert!(!http(400).is_unauthorized());
        assert!(!http(500).is_unauthorized());
    }
}
