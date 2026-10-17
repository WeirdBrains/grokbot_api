//! Shared helpers for the integration tests. Everything runs against a local wiremock
//! server; nothing talks to the real gateway, and every token is a fake string.
#![allow(dead_code)]

use grokbot_api::{Client, ClientOptions, Policy, Session};
use wiremock::MockServer;

/// Options that allow the loopback mock server as both gateway and backend.
pub fn opts(server: &MockServer) -> ClientOptions {
    ClientOptions {
        policy: Policy::local_testing(),
        backend_base: server.uri(),
        ..Default::default()
    }
}

/// A plain gateway client (no Cursor token) with token `gw-tok`.
pub fn client(server: &MockServer) -> Client {
    Client::new(Session::new(server.uri(), "gw-tok"), opts(server)).unwrap()
}

/// A client that can re-exchange with Cursor token `cur-tok`.
pub fn cursor_client(server: &MockServer, gateway_token: &str) -> Client {
    Client::with_cursor_token(
        Session::new(server.uri(), gateway_token),
        "cur-tok",
        opts(server),
    )
    .unwrap()
}

/// Path of the EnsureSandBox endpoint.
pub const ENSURE: &str = "/aiserver.v1.GrokBotService/EnsureSandBox";
