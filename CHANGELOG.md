# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-10-17

First standalone release. The crate was previously developed inside the
[grokbot-tui](https://github.com/m3talsmith/gb) workspace; that history is preserved.
Requires Rust 1.89 or newer.

### Added

- `Client` with typed methods for every known gateway call:
  - agents: create, update, delete, notify, hide
  - groups
  - prompts and acceptance status
  - transcripts: tail, history, threads
  - workflows
  - approvals
- `Client::call_raw` for any other gateway method.
- `ensure_sandbox`, `Client::connect_cursor` and automatic one-shot re-exchange on
  401/417, with `take_refreshed_session` for persisting the new session.
- `Client::list_team_agents`, with viewer sessions remembered for shared agents.
- `Policy` credential host allowlist, enforced on every request.
- Redirects are refused, response sizes capped, and secrets redacted from errors and
  `Debug` output.
- `Delivery` / `AcceptanceStatus` for safe resend decisions.
- `Entry::approval` approval-card detection and `sanitize_text`.
- Optional `desktop-session` feature to read the Grok Bot desktop app's saved session
  (Linux, macOS, Windows), including `DesktopConfig::keychain_program` and app version
  detection.
- Topic guides (`*.md`, also on docs.rs under `guide`), runnable examples, and a mock-server
  test suite.

[Unreleased]: https://github.com/WeirdBrains/grokbot_api/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/WeirdBrains/grokbot_api/releases/tag/v1.0.0
