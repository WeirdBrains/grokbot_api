//! Reuse the Grok Bot desktop app's saved session (feature `desktop-session`).
//!
//! ```sh
//! cargo run --example desktop_session --features desktop-session
//! ```
//!
//! This reads and decrypts the desktop app's credentials, so only run it on your own
//! machine, on purpose. It prints which credential was found, never the secret itself.
use grokbot_api::desktop::{DesktopConfig, DesktopCredential, Platform};
use grokbot_api::{Client, ClientOptions, Policy};

#[tokio::main]
async fn main() -> grokbot_api::Result<()> {
    let Some(platform) = Platform::current() else {
        eprintln!("unsupported OS");
        std::process::exit(2);
    };
    let cfg = DesktopConfig::new(platform);
    let mut opts = ClientOptions::default();
    if let Some(version) = cfg.detect_app_version() {
        println!("desktop app version: {version}");
        opts.client_version = version;
    }
    let entry = std::env::args().nth(1); // a descriptor entry or account choice, if several
    let client = match cfg.load_credential(entry.as_deref(), &Policy::default())? {
        DesktopCredential::Session(session) => {
            println!("found a saved gateway session for {}", session.gateway_url);
            Client::new(session, opts)?
        }
        DesktopCredential::CursorToken(token) => {
            println!("found a Cursor account; exchanging it via EnsureSandBox");
            Client::connect_cursor(&token, opts).await?
        }
    };
    println!("{} agents", client.list_agents().await?.len());
    Ok(())
}
