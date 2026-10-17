//! List your bots and groups (and, with a Cursor token, team bots shared with you).
//!
//! Credentials come from the environment and are never printed:
//!
//! ```sh
//! # with a gateway session
//! GROKBOT_GATEWAY_URL=https://<box>.cursorvm.com GROKBOT_GATEWAY_TOKEN=... \
//!     cargo run --example list_agents
//! # or with a Cursor access token (exchanged via EnsureSandBox)
//! CURSOR_ACCESS_TOKEN=... cargo run --example list_agents
//! ```
use grokbot_api::{Client, ClientOptions, Session};

async fn connect() -> grokbot_api::Result<Client> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    match (
        env("GROKBOT_GATEWAY_URL"),
        env("GROKBOT_GATEWAY_TOKEN"),
        env("CURSOR_ACCESS_TOKEN"),
    ) {
        (_, _, Some(cursor)) => Client::connect_cursor(&cursor, ClientOptions::default()).await,
        (Some(url), Some(token), None) => {
            Client::new(Session::new(url, token), ClientOptions::default())
        }
        _ => {
            eprintln!("Set GROKBOT_GATEWAY_URL + GROKBOT_GATEWAY_TOKEN, or CURSOR_ACCESS_TOKEN.");
            std::process::exit(2);
        }
    }
}

#[tokio::main]
async fn main() -> grokbot_api::Result<()> {
    let client = connect().await?;
    for agent in client.list_agents().await? {
        let hidden = if agent.hidden_from_sidebar == Some(true) {
            " (hidden)"
        } else {
            ""
        };
        let kind = if agent.is_group { "group" } else { "bot" };
        println!("{}  {kind:<5} {}{hidden}", agent.id, agent.display_name());
    }
    // Only clients built from a Cursor token can list team agents.
    if let Some(team) = client.list_team_agents().await? {
        for a in team.iter().filter(|a| !a.viewer_is_owner) {
            let owner = a.owner_display_name.as_deref().unwrap_or("someone");
            println!("{}  team  {} (shared by {owner})", a.agent_id, a.name);
        }
    }
    Ok(())
}
