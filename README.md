# grokbot_api

[![crates.io](https://img.shields.io/crates/v/grokbot_api.svg)](https://crates.io/crates/grokbot_api)
[![docs.rs](https://img.shields.io/docsrs/grokbot_api)](https://docs.rs/grokbot_api)
[![CI](https://github.com/WeirdBrains/grokbot_api/actions/workflows/ci.yml/badge.svg)](https://github.com/WeirdBrains/grokbot_api/actions/workflows/ci.yml)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](./LICENSE)

**Version 1.0.0** · **Tests:** 117 unit and integration tests and 36 doctests, all passing ·
**Coverage:** 99% of lines (`cargo llvm-cov --all-features`) · **MSRV:** Rust 1.89

An **unofficial** async Rust client for the Grok Bot gateway: the private API behind the
Grok Bot desktop app that lists your bots, sends them prompts and reads their replies.

It gives you typed calls for every known gateway method, plus the pieces needed to use them:
- **Sessions.** Turn a Cursor access token into a gateway session with EnsureSandBox, and
  re-authenticate automatically when the session expires.
- **Safety.** A host allowlist ensures credentials only go to Cursor hosts, and error
  messages never contain secrets.
- **Delivery.** Each send reports whether the prompt landed: accepted, rejected or unknown.
- **Transcripts.** Page through chat history and detect approval cards.
- **Desktop app (opt-in).** Reuse the desktop app's saved login.

> **Unofficial and undocumented.** The gateway has no public documentation. This crate
> mirrors what [grok-bot-cli](https://github.com/ScriptedAlchemy/grok-bot-cli) and the
> desktop app do, and the API **may change without notice**. It is not affiliated with or
> endorsed by the makers of Grok Bot or Cursor.

## Install

```toml
[dependencies]
grokbot_api = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }

# Optional: read the Grok Bot desktop app's saved session.
# grokbot_api = { version = "1", features = ["desktop-session"] }
```

Or `cargo add grokbot_api tokio --features tokio/macros,tokio/rt-multi-thread`.
The client uses `reqwest` with rustls; it needs a Tokio runtime.

## Examples

List your bots with a gateway session:

```rust,no_run
use grokbot_api::{Client, ClientOptions, Session};

#[tokio::main]
async fn main() -> grokbot_api::Result<()> {
    let session = Session::new("https://<box>.cursorvm.com", "<gateway token>");
    let client = Client::new(session, ClientOptions::default())?;
    for agent in client.list_agents().await? {
        println!("{}  {}", agent.id, agent.display_name());
    }
    Ok(())
}
```

Log in with a Cursor access token, send a prompt and read the transcript:

```rust,no_run
use grokbot_api::{Client, ClientOptions, Delivery, SendPrompt};

#[tokio::main]
async fn main() -> grokbot_api::Result<()> {
    // EnsureSandBox exchanges the token; the client re-exchanges on 401/417.
    let client = Client::connect_cursor("<cursor access token>", ClientOptions::default()).await?;
    let bot = &client.list_agents().await?[0];

    let receipt = client.send_prompt(&SendPrompt::new(&bot.id, "hello")).await?;
    assert_eq!(receipt.delivery, Delivery::Accepted);

    // Replies arrive asynchronously: poll the transcript.
    for entry in client.transcript_tail(&bot.id, 20, None).await?.entries {
        let who = if entry.is_from_user() { "you" } else { "bot" };
        println!("[{who}] {}", grokbot_api::sanitize_text(&entry.text));
    }
    Ok(())
}
```

Check where credentials may be sent (no network):

```rust
use grokbot_api::Policy;

let policy = Policy::default();
assert!(policy.check_gateway("https://box.us1.cursorvm.com").is_ok());
assert!(policy.check_gateway("https://example.com").is_err());
```

More in [`examples/`](./examples). `cargo run --example mock_gateway` runs the whole flow
offline against a mock server.

## Table of contents

| Guide | What it covers |
|---|---|
| [Sessions and authentication](SESSIONS.md) | Gateway sessions, EnsureSandBox, client identity, 401/417 re-authentication, `ClientOptions` |
| [Credential policy](POLICY.md) | The host allowlist, loopback gateways, `GB_ALLOW_LOCAL_GATEWAY` |
| [Agents, groups and team agents](AGENTS.md) | Listing, creating, updating and deleting bots; groups; team bots shared with you |
| [Sending prompts and delivery](MESSAGING.md) | `send_prompt`, nonces, `Delivery`, `promptAcceptanceStatus`, waiting for replies |
| [Transcripts](TRANSCRIPTS.md) | Tail pages, `beforeSeq` paging, full history, threads, entry parsing, sanitizing |
| [Approvals](APPROVALS.md) | Detecting approval cards and resolving them (on a user's decision only) |
| [Workflows (skills)](WORKFLOWS.md) | Listing, importing and deleting skills |
| [Errors, limits and redaction](ERRORS.md) | `Error` variants, delivery mapping, timeouts, size caps, secret redaction |
| [Desktop session](DESKTOP.md) | The opt-in `desktop-session` feature: reading the desktop app's saved login |
| [Wire protocol](PROTOCOL.md) | Endpoints, headers, every method's request body, `call_raw` |

On docs.rs the same guides are in the
[`guide` module](https://docs.rs/grokbot_api/latest/grokbot_api/guide/).

## Development

```sh
cargo test --all-features                 # unit, integration and doc tests (mock servers only)
cargo clippy --all-targets --all-features -- -D warnings
cargo llvm-cov --all-features --summary-only
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
```

The tests never contact the real gateway and use only fake tokens. A few branches are
not covered:
- code that only runs on another OS (the Windows DPAPI path)
- fixed system install paths such as `/opt/Grok Bot`
- `reqwest` client construction failures

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

BSD 3-Clause. See [LICENSE](./LICENSE).
