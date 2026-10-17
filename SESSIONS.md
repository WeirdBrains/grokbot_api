# Sessions and authentication

[← README](README.md)

Every gateway call needs a `Session`: the gateway base URL, a bearer token, and sometimes
extra headers. There are three ways to get one.

## 1. A gateway URL and token

If you already have a gateway session, for example one you saved earlier:

```rust,no_run
use grokbot_api::{Client, ClientOptions, Session};

fn client() -> grokbot_api::Result<Client> {
    let session = Session::new("https://<box>.cursorvm.com", "<gateway token>")
        .with_headers([("x-anyrun-network-token".to_string(), "<token>".to_string())].into());
    Client::new(session, ClientOptions::default())
}
```

`with_headers` lower-cases header names and drops empty values. `Client::new` checks the URL
against the [credential policy](POLICY.md) and returns `Error::Policy` if it isn't allowed.

## 2. A Cursor access token (EnsureSandBox)

`ensure_sandbox` exchanges a Cursor **access token** for a gateway session by calling the
Cursor backend. A Cursor dashboard API key does not work.

```rust,no_run
use grokbot_api::{Client, ClientOptions, Session, ensure_sandbox};

// Just the session (e.g. to store it):
async fn session(token: &str) -> grokbot_api::Result<Session> {
    ensure_sandbox(token, &ClientOptions::default()).await
}

// Or a client that remembers the token and re-exchanges when the session expires:
async fn client(token: &str) -> grokbot_api::Result<Client> {
    Client::connect_cursor(token, ClientOptions::default()).await
}
```

What is sent:

- `POST {backend_base}/aiserver.v1.GrokBotService/EnsureSandBox` with body `{}`
  (`backend_base` defaults to `https://api2.cursor.sh`).
- Headers:
  - `connect-protocol-version: 1`
  - `authorization: Bearer <cursor token>`
  - `x-cursor-client-type`
  - `x-cursor-client-version`
  - `x-sand-box-namespace`

What is read from the response:

- `gatewayUrl` / `gateway_url` and `gatewayToken` / `gateway_token` (both required).
- `gatewayHeaders` / `gateway_headers`: extra headers for every gateway call.
- Otherwise `anyrunNetworkToken` / `anyrun_network_token` / `networkToken`, which becomes
  the `x-anyrun-network-token` header.

Errors:

- The backend URL and the returned gateway URL both have to pass the policy, so the
  Cursor token is never sent anywhere else.
- A response without a gateway URL or token gives `Error::InvalidResponse`.

If you already have both a session and a Cursor token (say, from storage), use
`Client::with_cursor_token(session, token, opts)`.

## 3. The desktop app's saved login

With the `desktop-session` feature you can reuse the Grok Bot desktop app's credentials.
See [DESKTOP.md](DESKTOP.md).

## Re-authentication (401 and 417)

The gateway answers an expired session with **417** (empty body) rather than 401, so
`Error::is_unauthorized()` treats both as "re-authenticate".

- **A client built from a Cursor token** (`connect_cursor` / `with_cursor_token`) handles it
  automatically. On the first 401/417 it runs EnsureSandBox once, swaps in the new session and
  retries the call.
  - If the retry fails too, that error is returned; the client never loops.
  - Call `take_refreshed_session()` after calls to get the new session and persist it. It
    returns `Some` once per refresh. `client.session()` always returns the current session.
- **A plain session** client returns the error. Check `e.is_unauthorized()` and get a new
  session.

```rust,no_run
use grokbot_api::{Client, Session};

async fn count(client: &Client, save: impl Fn(&Session)) -> grokbot_api::Result<usize> {
    let agents = client.list_agents().await?;
    if let Some(fresh) = client.take_refreshed_session() {
        save(&fresh); // so the next run starts with a valid session
    }
    Ok(agents.len())
}
```

## `ClientOptions`

| Field | Default | Meaning |
|---|---|---|
| `policy` | `Policy::from_env()` | Which URLs may receive credentials ([POLICY.md](POLICY.md)) |
| `backend_base` | `https://api2.cursor.sh` (`DEFAULT_BACKEND_BASE`) | Cursor backend for EnsureSandBox and `grokbot_service_call` |
| `timeout` | 30 s (`TIMEOUT`) | Per-request deadline |
| `max_response_bytes` | 2 MiB (`MAX_RESPONSE_BYTES`) | Response body cap |
| `client_version` | `0.70.2` (`DEFAULT_CLIENT_VERSION`) | `x-cursor-client-version` on backend calls |
| `client_type` | `sand` (`DEFAULT_CLIENT_TYPE`) | `x-cursor-client-type` |
| `sandbox_namespace` | `prod` (`DEFAULT_SANDBOX_NAMESPACE`) | `x-sand-box-namespace` |

The backend may expect a recent `client_version`. With the `desktop-session` feature,
`desktop::detect_app_version` reads the installed desktop app's version so you can send the
same one.

## Other Cursor backend calls

`grokbot_service_call(token, method, &body, &opts)` calls any unary
`aiserver.v1.GrokBotService/<method>` with the same headers and returns the JSON. The token
is redacted from errors. `Client::list_team_agents` is built on it (see
[AGENTS.md](AGENTS.md#team-agents)).
