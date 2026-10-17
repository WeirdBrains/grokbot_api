//! Send one prompt and wait for the bot's reply by polling the transcript.
//!
//! ```sh
//! GROKBOT_GATEWAY_URL=https://<box>.cursorvm.com GROKBOT_GATEWAY_TOKEN=... \
//!     cargo run --example chat -- <agent-id> "Hello there"
//! ```
//!
//! The gateway has no streaming: `send_prompt` only returns a receipt, and replies show
//! up in `getAgentTranscriptTail`.
use grokbot_api::{Client, ClientOptions, Delivery, SendPrompt, Session, sanitize_text};
use std::time::Duration;

#[tokio::main]
async fn main() -> grokbot_api::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(agent), Some(prompt)) = (args.next(), args.next()) else {
        eprintln!("usage: chat <agent-id> <prompt>");
        std::process::exit(2);
    };
    let (Ok(url), Ok(token)) = (
        std::env::var("GROKBOT_GATEWAY_URL"),
        std::env::var("GROKBOT_GATEWAY_TOKEN"),
    ) else {
        eprintln!("Set GROKBOT_GATEWAY_URL and GROKBOT_GATEWAY_TOKEN.");
        std::process::exit(2);
    };
    let client = Client::new(Session::new(url, token), ClientOptions::default())?;

    // Remember the newest entry so we only print what arrives after our prompt.
    let before = client.transcript_tail(&agent, 1, None).await?;
    let last_seen = before.entries.last().and_then(|e| e.id.clone());

    let receipt = match client.send_prompt(&SendPrompt::new(&agent, prompt)).await {
        Ok(r) => r,
        Err(e) if e.delivery() == Delivery::Unknown => {
            eprintln!(
                "The prompt may or may not have arrived ({e}); check the transcript before resending."
            );
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    println!("sent ({})", receipt.delivery);

    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let tail = client.transcript_tail(&agent, 20, None).await?;
        let new: Vec<_> = match &last_seen {
            Some(id) => tail
                .entries
                .iter()
                .skip_while(|e| e.id.as_ref() != Some(id))
                .skip(1)
                .collect(),
            None => tail.entries.iter().collect(),
        };
        let replies: Vec<_> = new
            .iter()
            .filter(|e| !e.is_from_user() && !e.text.is_empty())
            .collect();
        if !replies.is_empty() {
            for r in replies {
                println!("{}", sanitize_text(&r.text));
            }
            return Ok(());
        }
    }
    println!("no reply yet; try again later");
    Ok(())
}
