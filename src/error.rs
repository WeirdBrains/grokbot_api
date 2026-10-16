use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// Whether a prompt reached the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The gateway returned a `messageId` receipt.
    Accepted,
    /// The request was refused before or by the server (policy, validation, 4xx). Safe to fix and resend.
    Rejected,
    /// The request may have landed (network error, timeout, 5xx, or no receipt).
    /// Read the transcript before resending.
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The URL is not allowed to receive credentials (see [`crate::Policy`]).
    #[error("{0}")]
    Policy(String),
    /// Input rejected locally before sending.
    #[error("{0}")]
    Validation(String),
    /// The server answered with a non-2xx status.
    #[error("{method} failed: {status} {message}")]
    Http {
        method: String,
        status: u16,
        message: String,
    },
    /// Network error, timeout, or redirect refusal. Delivery is unknown.
    #[error("{method} failed: {message}")]
    Transport { method: String, message: String },
    /// Response body exceeded [`crate::MAX_RESPONSE_BYTES`].
    #[error("{method}: gateway response too large (over {limit} bytes)")]
    TooLarge { method: String, limit: usize },
    /// Reading the desktop app's saved session failed (`desktop-session` feature).
    #[error("{message}")]
    Desktop { code: String, message: String },
    /// The response was not the expected shape.
    #[error("{method}: {message}")]
    InvalidResponse { method: String, message: String },
}

impl Error {
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Http { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn is_unauthorized(&self) -> bool {
        self.status() == Some(401)
    }

    /// Delivery state if this error came from `sendPrompt`.
    pub fn delivery(&self) -> Delivery {
        match self {
            Error::Policy(_) | Error::Validation(_) => Delivery::Rejected,
            Error::Http { status, .. } if *status < 500 => Delivery::Rejected,
            _ => Delivery::Unknown,
        }
    }
}
