# Credential policy

[← README](README.md)

`Policy` decides which URLs may receive credentials. Nothing is sent to a URL that fails
the check: the call returns `Error::Policy` with a readable reason.

## Rules

| URL | Gateway (`check_gateway`) | Backend (`check_backend`, receives the Cursor token) |
|---|---|---|
| `https://cursor.sh`, `https://cursor.com`, `https://*.cursor.sh`, `https://*.cursor.com` | allowed | allowed |
| `https://*.cursorvm.com` (Grok Bot boxes) | allowed | **never** |
| `http://` on any public host | rejected | rejected |
| `localhost`, `127.0.0.1`, `[::1]` (http or https) | only with `allow_local_gateway` | only with `allow_local_backend` |
| URLs with userinfo (`https://user:pw@…`) | always rejected | always rejected |
| anything else | rejected | rejected |

Host matching is exact or by suffix after a dot, so `cursor.com.evil.net` and
`evilcursor.com` are rejected. Successful checks return the URL trimmed and without a
trailing slash.

## Where it is enforced

- `Client::new` / `with_cursor_token`: the session's gateway URL.
- Every gateway call re-checks the gateway URL.
- `ensure_sandbox`, `grokbot_service_call` and automatic re-exchange: the backend URL,
  *and* the gateway URL that EnsureSandBox returns.
- `desktop::session_from_clear`: the gateway URL decrypted from the desktop app.

In addition, redirects are never followed (a 3xx is an `Error::Transport`), so a server
cannot bounce credentials elsewhere.

## Loopback gateways

```rust
use grokbot_api::Policy;

// Default: hosted endpoints only.
assert!(Policy::default().check_gateway("http://localhost:8080").is_err());

// Environment opt-in for the gateway only: GB_ALLOW_LOCAL_GATEWAY=1 (or true / yes).
let from_env = Policy::from_env();
assert!(!from_env.allow_local_backend); // never enabled from the environment

// Tests against a mock server: loopback gateway *and* backend.
let p = Policy::local_testing();
assert!(p.check_backend("http://127.0.0.1:9000").is_ok());
```

`ClientOptions::default()` uses `Policy::from_env()`. The loopback backend can only be
enabled in code (`allow_local_backend: true` or `Policy::local_testing()`), so an
environment variable can never redirect your Cursor token.
