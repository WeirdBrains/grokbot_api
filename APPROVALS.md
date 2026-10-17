# Approvals

[← README](README.md)

Sometimes a bot needs permission to continue, for example to run a command on your
machine or to pass an auto-review gate. It posts an **approval card** in the transcript and
waits. This crate finds pending cards and lets you resolve them.

> **Never approve automatically.** These calls allow real actions. Only resolve a card on an
> explicit decision by the user, after showing them the details.

## Finding pending cards

```rust,no_run
use grokbot_api::Client;

async fn pending(client: &Client, bot: &str) -> grokbot_api::Result<()> {
    for entry in client.transcript_tail(bot, 50, None).await?.entries {
        if let Some(card) = entry.approval() {
            println!("{:?} request {} in entry {}", card.kind, card.request_id, card.entry_id);
            for (k, v) in &card.details {
                println!("  {k}: {v}");
            }
            if card.truncated {
                println!("  (some details were cut at 2048 characters)");
            }
        }
    }
    Ok(())
}
```

`Entry::approval()` returns `Some` only when all of these hold:

- The entry is `kind: "send-message"` with a string `id` of 1–1024 characters.
- `message.type` is one of:
  - `"local-tool-permission"`, with the card in `message.ask` → `ApprovalKind::LocalToolPermission`
  - `"auto-review-approval"`, with the card in `message.approval` → `ApprovalKind::AutoReview`
- The card's `status` is `"pending"`; resolved cards are ignored.
- The card has a `requestId` of 1–1024 characters.

`details` holds any of these card fields, each cut to 2048 characters (`truncated` is set
if anything was cut):
- `reason`, `command`, `summary`
- `action`, `description`, `target`
- `machineId`, `surface`, `workingDirectory`

## Resolving

```rust,no_run
use grokbot_api::{Approval, ApprovalKind, AutoReviewResolution, Client, LocalToolResolution};

async fn resolve(client: &Client, bot: &str, card: &Approval, user_said_yes: bool) -> grokbot_api::Result<()> {
    match card.kind {
        ApprovalKind::LocalToolPermission => {
            let r = if user_said_yes { LocalToolResolution::AllowOnce } else { LocalToolResolution::Deny };
            client.resolve_local_tool_permission(bot, &card.entry_id, &card.request_id, r).await?;
        }
        ApprovalKind::AutoReview => {
            let r = if user_said_yes { AutoReviewResolution::Approved } else { AutoReviewResolution::Denied };
            client.resolve_auto_review_approval(bot, &card.entry_id, &card.request_id, r).await?;
        }
    }
    Ok(())
}
```

| Method | Body |
|---|---|
| `resolveLocalToolPermission` | `{agentId, entryId, requestId, resolution: "allow-once" \| "deny"}` |
| `resolveAutoReviewApproval` | `{agentId, entryId, requestId, resolution: "approved" \| "denied"}` |
