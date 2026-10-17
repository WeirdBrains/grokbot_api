//! Credential URL policy: credentials are only ever sent to expected hosts.
//!
//! Mirrors grok-bot-cli's `url-policy.js`:
//! - Gateway: https on `cursor.sh`, `cursor.com`, `*.cursor.sh`, `*.cursor.com`, `*.cursorvm.com`.
//! - Backend (EnsureSandBox, receives the Cursor access token): https on `*.cursor.sh` / `*.cursor.com`
//!   only, never `*.cursorvm.com`.
//! - Loopback gateways (`localhost`, `127.0.0.1`, `::1`, http or https) only when
//!   `GROKBOT_ALLOW_LOCAL_GATEWAY=1`. Loopback backends are never allowed outside tests.
//! - URLs carrying userinfo are always rejected.

/// Environment variable read by [`Policy::from_env`]: `1`, `true` or `yes` allows
/// loopback gateways (e.g. a local mock server).
pub const ALLOW_LOCAL_ENV: &str = "GROKBOT_ALLOW_LOCAL_GATEWAY";

/// Which URLs may receive credentials.
///
/// The default policy only allows the hosted Grok Bot gateway and Cursor backend over
/// https. Every [`Client`](crate::Client) call re-checks the gateway URL, and
/// [`ensure_sandbox`](crate::ensure_sandbox) checks both the backend URL and the gateway
/// URL it gets back. See the `POLICY.md` guide.
///
/// ```
/// use grokbot_api::Policy;
///
/// let p = Policy::default();
/// assert_eq!(p.check_gateway("https://box.us1.cursorvm.com/").unwrap(), "https://box.us1.cursorvm.com");
/// assert!(p.check_gateway("https://example.com").is_err());
/// assert!(p.check_backend("https://box.us1.cursorvm.com").is_err()); // never send the Cursor token to a box
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Policy {
    /// Allow `localhost` / `127.0.0.1` / `::1` gateways over http or https.
    pub allow_local_gateway: bool,
    /// Allow a loopback EnsureSandBox backend. Never set from the environment; for tests only.
    pub allow_local_backend: bool,
}

impl Policy {
    /// The default policy, plus loopback gateways when [`ALLOW_LOCAL_ENV`] is `1`/`true`/`yes`.
    /// The loopback *backend* is never enabled from the environment.
    pub fn from_env() -> Self {
        let v = std::env::var(ALLOW_LOCAL_ENV)
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        Self {
            allow_local_gateway: matches!(v.as_str(), "1" | "true" | "yes"),
            allow_local_backend: false,
        }
    }

    /// Allow loopback gateway **and** backend. Intended for tests against a local mock server.
    pub fn local_testing() -> Self {
        Self {
            allow_local_gateway: true,
            allow_local_backend: true,
        }
    }

    /// Validate a gateway URL; returns it trimmed and without a trailing slash.
    ///
    /// Allowed: https on `cursor.sh`, `cursor.com`, `*.cursor.sh`, `*.cursor.com`,
    /// `*.cursorvm.com`; loopback only with [`Policy::allow_local_gateway`]. URLs with
    /// userinfo are always rejected. The error is a human-readable reason.
    pub fn check_gateway(&self, raw: &str) -> Result<String, String> {
        check(raw, Kind::Gateway, *self)
    }

    /// Validate the EnsureSandBox backend base URL (which receives the Cursor access token).
    ///
    /// Allowed: https on `cursor.sh`, `cursor.com`, `*.cursor.sh`, `*.cursor.com` only (never
    /// `*.cursorvm.com`); loopback only with [`Policy::allow_local_backend`].
    pub fn check_backend(&self, raw: &str) -> Result<String, String> {
        check(raw, Kind::Backend, *self)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Gateway,
    Backend,
}

fn is_local(h: &str) -> bool {
    matches!(
        h.trim_start_matches('[').trim_end_matches(']'),
        "localhost" | "127.0.0.1" | "::1"
    )
}

fn is_cursor_api(h: &str) -> bool {
    h == "cursor.sh" || h == "cursor.com" || h.ends_with(".cursor.sh") || h.ends_with(".cursor.com")
}

fn check(raw: &str, kind: Kind, p: Policy) -> Result<String, String> {
    let label = if kind == Kind::Backend {
        "backend URL"
    } else {
        "gateway URL"
    };
    let url = reqwest::Url::parse(raw.trim()).map_err(|_| format!("Invalid {label}."))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("Rejected {label}: userinfo is not allowed."));
    }
    let host = url.host_str().unwrap_or("").to_lowercase();
    let scheme = url.scheme();
    let out = raw.trim().trim_end_matches('/').to_string();
    if is_local(&host) {
        let allowed = match kind {
            Kind::Gateway => p.allow_local_gateway,
            Kind::Backend => p.allow_local_backend,
        };
        if !allowed {
            return Err(match kind {
                Kind::Gateway => format!(
                    "Rejected {label} host \"{host}\". Set {ALLOW_LOCAL_ENV}=1 to permit loopback gateways."
                ),
                Kind::Backend => format!(
                    "Rejected {label} host \"{host}\". EnsureSandBox must be https on *.cursor.sh / *.cursor.com."
                ),
            });
        }
        if scheme != "http" && scheme != "https" {
            return Err(format!(
                "Rejected {label}: local URLs must use http or https."
            ));
        }
        return Ok(out);
    }
    if scheme != "https" {
        return Err(format!(
            "Rejected {label}: only https is allowed (got {scheme})."
        ));
    }
    let ok = match kind {
        Kind::Backend => is_cursor_api(&host),
        Kind::Gateway => is_cursor_api(&host) || host.ends_with(".cursorvm.com"),
    };
    if !ok {
        let expected = if kind == Kind::Backend {
            "*.cursor.sh / *.cursor.com"
        } else {
            "*.cursor.sh / *.cursor.com / *.cursorvm.com"
        };
        return Err(format!(
            "Rejected {label} host \"{host}\". Expected {expected}."
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_allowlist() {
        let p = Policy::default();
        assert_eq!(
            p.check_gateway("https://x.us12.cursorvm.com/").unwrap(),
            "https://x.us12.cursorvm.com"
        );
        assert!(p.check_gateway("https://api2.cursor.sh").is_ok());
        assert!(p.check_gateway("https://cursor.com").is_ok());
        assert!(
            p.check_gateway("http://x.cursorvm.com").is_err(),
            "http rejected"
        );
        assert!(p.check_gateway("https://evil.com").is_err());
        assert!(p.check_gateway("https://cursor.sh.evil.com").is_err());
        assert!(p.check_gateway("https://evilcursor.sh").is_err());
        assert!(
            p.check_gateway("https://u:p@x.cursor.sh").is_err(),
            "userinfo rejected"
        );
        assert!(
            p.check_gateway("http://127.0.0.1:9").is_err(),
            "loopback needs opt-in"
        );
        assert!(p.check_gateway("not a url").is_err());
        let local = Policy {
            allow_local_gateway: true,
            allow_local_backend: false,
        };
        assert!(local.check_gateway("http://127.0.0.1:9").is_ok());
        assert!(local.check_gateway("http://[::1]:9").is_ok());
        assert!(local.check_gateway("http://localhost").is_ok());
    }

    #[test]
    fn backend_allowlist() {
        let p = Policy {
            allow_local_gateway: true,
            allow_local_backend: false,
        };
        assert!(p.check_backend("https://api2.cursor.sh").is_ok());
        assert!(
            p.check_backend("https://x.cursorvm.com").is_err(),
            "box hosts never get the cursor token"
        );
        assert!(
            p.check_backend("http://127.0.0.1:1").is_err(),
            "local gateway opt-in doesn't cover backend"
        );
        assert!(p.check_backend("http://api2.cursor.sh").is_err());
    }
}
