# Transcripts

[← README](README.md)

## The newest page

```rust,no_run
use grokbot_api::{Client, sanitize_text};

async fn show(client: &Client, bot: &str) -> grokbot_api::Result<()> {
    let page = client.transcript_tail(bot, 50, None).await?;
    for e in &page.entries {
        let who = if e.is_from_user() { "you" } else { "bot" };
        println!("[{who}] {}", sanitize_text(&e.text));
    }
    if let Some(older) = page.next_before_seq {
        let _previous_page = client.transcript_tail(bot, 50, Some(older)).await?;
    }
    Ok(())
}
```

`transcript_tail(id, limit, before_seq)` calls `getAgentTranscriptTail`:

- `limit` is clamped to 1..=200.
- With `before_seq: None` you get the newest page. Pass the page's `next_before_seq` to get
  the page before it (the desktop app pages the same way).
- Entries in a page are oldest first.

## The whole history

```rust,no_run
use grokbot_api::{Client, Transcript};

async fn everything(client: &Client, bot: &str) -> grokbot_api::Result<Transcript> {
    client.transcript_history(bot, 200, 1_000).await // up to the newest 1,000 entries
}
```

`transcript_history(id, page_size, max_entries)` walks pages from newest to oldest:

- It stops at an empty page, at a page without `nextBeforeSeq`, or once it has
  `max_entries`. At the cap it keeps the **newest** entries.
- The result is oldest to newest. Entries are de-duplicated by id; entries without an id
  are kept.
- `next_before_seq` is where the walk stopped. `raw` is `{"pages": [...]}`.

## Threads

`thread(id, root_id)` calls `getAgentThread` and returns the replies under one entry. To
reply in a thread, set `SendPrompt::reply_to_id`.

## Entries

The entry format is undocumented, so `Entry` keeps the raw record and derives a few
convenience fields.

- **`id`**: the entry id, if it's a string.
- **`role`**: the first non-empty `role`, `kind`, `sender` or `type`, else `"msg"`.
  - User prompts use kinds like `user-prompt`.
  - Bot replies use `send-message`.
- **`text`**: the first match of:
  1. `text`, `prompt` or `message`, if it's a string
  2. `content` as a string
  3. `content` as an array of strings or `{text}` / `{content}` parts, joined with newlines
  4. `content.text`, or the `content` object as compact JSON
  5. `message.content` (bot replies)
  6. `preview`
- **`raw`**: the full record.

`is_from_user()` is a heuristic: the role contains `user`, `human` or `prompt`.
`Entry::from_value` parses a raw entry and never fails. `approval()` finds approval cards;
see [APPROVALS.md](APPROVALS.md).

## Displaying text safely

Transcript text comes from a server and from LLM output. `sanitize_text` removes ANSI
escape sequences (CSI and OSC, including hyperlinks) and control characters except `\n`
and `\t`, so a message can't move the cursor, retitle the terminal or hide text:

```rust
assert_eq!(grokbot_api::sanitize_text("\u{1b}[2J\u{1b}]0;pwned\u{7}hi\r"), "hi");
```
