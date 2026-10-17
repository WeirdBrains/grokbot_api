//! Check URLs against the credential policy (offline).
//!
//! ```sh
//! cargo run --example policy_check -- https://box.us1.cursorvm.com https://example.com
//! ```
use grokbot_api::Policy;

fn main() {
    let urls: Vec<String> = std::env::args().skip(1).collect();
    let urls = if urls.is_empty() {
        vec![
            "https://box.us1.cursorvm.com".to_string(),
            "https://api2.cursor.sh".to_string(),
            "http://localhost:8080".to_string(),
            "https://example.com".to_string(),
        ]
    } else {
        urls
    };
    // Honors GROKBOT_ALLOW_LOCAL_GATEWAY=1 for loopback gateways.
    let policy = Policy::from_env();
    for url in urls {
        let show = |r: Result<String, String>| match r {
            Ok(u) => format!("ok ({u})"),
            Err(e) => format!("rejected: {e}"),
        };
        println!("{url}");
        println!("  as gateway: {}", show(policy.check_gateway(&url)));
        println!("  as backend: {}", show(policy.check_backend(&url)));
    }
}
