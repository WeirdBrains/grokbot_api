# Sending prompts and delivery

[← README](README.md)

The gateway has **no streaming**. `send_prompt` returns a receipt only; the bot's reply
shows up later in the transcript ([TRANSCRIPTS.md](TRANSCRIPTS.md)).

## Sending

```rust,no_run
use grokbot_api::{Client, Delivery, SendPrompt};

async fn ask(client: &Client, bot: &str) -> grokbot_api::Result<()> {
    let mut req = SendPrompt::new(bot, "Summarise today's issues");
    req.client_nonce = Some("job-42-attempt".into()); // optional idempotency key
    req.reply_to_id = None; // Some(entry_id) replies in a thread

    let receipt = client.send_prompt(&req).await?;
    match receipt.delivery {
        Delivery::Accepted => println!("accepted as {:?}", receipt.message_id),
        Delivery::Unknown => println!("2xx without a receipt; check before resending"),
        Delivery::Rejected => unreachable!("rejections are returned as errors"),
    }
    Ok(())
}
```

`SendPrompt` fields:

- `agent_id`
- `prompt`: must not be empty, or you get `Error::Validation` and nothing is sent.
- `client_nonce`: a v4 UUID is generated when `None`.
- `reply_to_id`

The request body is `{agentId, prompt, clientNonce, replyToId?, sessionId?}`. `sessionId` is
added for shared team agents (see [AGENTS.md](AGENTS.md#team-agents)).

## The receipt

`SendReceipt` fields:

- `message_id`
- `client_nonce`: what was sent.
- `delivery`
- `raw`: the response body.

| Response (2xx) | Result |
|---|---|
| `{accepted: true}` (the gateway's real success shape) | `Accepted`; `message_id` = the client nonce |
| `{messageId: "..."}` (older shape) | `Accepted` with that id |
| either wrapped as `{status, value: {...}}` | unwrapped, same as above |
| `{status: "refused", message}` or `{accepted: false}` | `Err(Error::Http { status: 422, .. })`, delivery `Rejected` |
| anything else (empty, HTML, unknown JSON) | `Ok` with `Delivery::Unknown` |

## When a send fails: `Delivery`

`Error::delivery()` tells you whether the prompt may have landed:

| Error | `delivery()` | What to do |
|---|---|---|
| `Policy`, `Validation` | `Rejected` | Nothing was sent; fix and resend |
| `Http` with status < 500 (incl. refusals) | `Rejected` | The server refused it; fix and resend |
| `Http` 5xx, `Transport` (network, timeout, redirect), `TooLarge`, `InvalidResponse` | `Unknown` | It may have landed: check before resending |

## Did it land? `prompt_acceptance_status`

When delivery is unknown, ask the gateway about the nonce. The desktop app does the same.

```rust,no_run
use grokbot_api::{AcceptanceStatus, Client};

async fn check(client: &Client, bot: &str, nonce: &str) -> grokbot_api::Result<bool> {
    Ok(match client.prompt_acceptance_status(bot, nonce).await? {
        AcceptanceStatus::Accepted | AcceptanceStatus::Pending => true, // don't resend
        AcceptanceStatus::NotFound => false,                           // never arrived: resend
        AcceptanceStatus::Rejected(code) => {
            eprintln!("refused: {code:?}");
            false
        }
        AcceptanceStatus::Unknown => true, // can't tell: read the transcript
    })
}
```

| Gateway response | `AcceptanceStatus` |
|---|---|
| `{outcome: "found", record: {status: "accepted"}}` | `Accepted` |
| `… status: "pending"` | `Pending` (ask again shortly) |
| `… status: "rejected", rejectionCode?` | `Rejected(Some(code))` (empty code → `None`) |
| `{outcome: "not-found"}` or record status `not-found` | `NotFound` (safe to resend) |
| `{outcome: "unknown-durability"}` or anything unrecognised | `Unknown` |

A `{status, value}` wrapper and a bare record (no `outcome`) are accepted too.
`AcceptanceStatus::from_value` parses a raw response.

## Waiting for the reply

Poll `transcript_tail` and look for new entries that aren't from the user. The
[`chat` example](examples/chat.rs) shows the full pattern: remember the last entry id
before sending, then poll every couple of seconds.
