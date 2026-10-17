//! Print an agent's full chat history (walking older pages with `beforeSeq`).
//!
//! ```sh
//! GROKBOT_GATEWAY_URL=https://<box>.cursorvm.com GROKBOT_GATEWAY_TOKEN=... \
//!     cargo run --example transcript_history -- <agent-id> [max-entries]
//! ```
use grokbot_api::{Client, ClientOptions, Session, sanitize_text};

#[tokio::main]
async fn main() -> grokbot_api::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(agent) = args.next() else {
        eprintln!("usage: transcript_history <agent-id> [max-entries]");
        std::process::exit(2);
    };
    let max: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(500);
    let (Ok(url), Ok(token)) = (
        std::env::var("GROKBOT_GATEWAY_URL"),
        std::env::var("GROKBOT_GATEWAY_TOKEN"),
    ) else {
        eprintln!("Set GROKBOT_GATEWAY_URL and GROKBOT_GATEWAY_TOKEN.");
        std::process::exit(2);
    };
    let client = Client::new(Session::new(url, token), ClientOptions::default())?;
    let history = client.transcript_history(&agent, 200, max).await?;
    for e in &history.entries {
        let who = if e.is_from_user() {
            "you"
        } else {
            e.role.as_str()
        };
        println!("[{who}] {}", sanitize_text(&e.text));
    }
    if history.next_before_seq.is_some() {
        println!("… older entries not shown (raise max-entries)");
    }
    Ok(())
}
