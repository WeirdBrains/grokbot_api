# Errors

[← README](README.md)

Every fallible call returns `grokbot_api::Result<T>`, which is `Result<T, grokbot_api::Error>`.

| Variant | When | Anything sent? |
|---|---|---|
| `Policy(reason)` | A URL is not allowed to receive credentials ([POLICY.md](POLICY.md)) | No |
| `Validation(reason)` | Bad input caught locally: blank name, unknown avatar, empty prompt, bad group size, empty or oversized skill | No |
| `Http { method, status, message }` | Non-2xx from the gateway or backend; also a refused `sendPrompt` (status 422) | Yes |
| `Transport { method, message }` | Connection failure, timeout, or a refused redirect | Maybe |
| `TooLarge { method, limit }` | Response body over `max_response_bytes` | Yes |
| `InvalidResponse { method, message }` | Response missing required fields (e.g. EnsureSandBox without a gateway URL/token) | Yes |
| `Desktop { code, message }` | Desktop session problems ([DESKTOP.md](DESKTOP.md#error-codes)) | No |

## Helpers

- **`status()`**: the HTTP status, for `Http` only.
- **`is_unauthorized()`**: true for 401 **and 417**. The gateway answers an expired session
  with 417. See [re-authentication](SESSIONS.md#re-authentication-401-and-417).
- **`delivery()`**: whether a failed `send_prompt` might have landed: `Rejected` or
  `Unknown`. See [MESSAGING.md](MESSAGING.md#when-a-send-fails-delivery).

```rust
use grokbot_api::{Delivery, Error};

let expired = Error::Http { method: "listAgents".into(), status: 417, message: String::new() };
assert!(expired.is_unauthorized());
assert_eq!(expired.delivery(), Delivery::Rejected);

let timeout = Error::Transport { method: "sendPrompt".into(), message: "timed out".into() };
assert_eq!(timeout.delivery(), Delivery::Unknown); // check before resending
```

## Secrets never appear in errors

Before an error is built, the crate removes these from error text and replaces them with
`<redacted>`:

- the gateway token
- the Cursor access token
- session header values
- anything following `Bearer `

Gateway error messages are also cut to 300 characters. You can log `Error` values safely. The
`Debug` output of `Session`, `Client`, `DesktopCredential` and `DesktopConfig` also hides
secrets:

```rust
let s = grokbot_api::Session::new("https://box.cursorvm.com", "super-secret-token");
assert!(!format!("{s:?}").contains("super-secret-token"));
```
