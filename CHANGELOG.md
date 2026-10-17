# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-17

Requires Rust 1.89 or newer.

### Changed

- Updated dependencies to their latest releases:
  - reqwest 0.13 (TLS via the `rustls` feature)
  - aes 0.9, cbc 0.2, aes-gcm 0.11 (the RustCrypto `cipher` 0.5 stack)
  - pbkdf2 0.13, hmac 0.13, sha1 0.11, base64 0.23
- Minimum supported Rust version raised from 1.88 to 1.89 (required by aes 0.9).
- **Renamed environment variables** to neutral names, with no aliases:
  - `GB_ALLOW_LOCAL_GATEWAY` → `GROKBOT_ALLOW_LOCAL_GATEWAY` (the value of `ALLOW_LOCAL_ENV`)
  - `GB_GROKBOT_APP_DIR` → `GROKBOT_APP_DIR`
  - `GROKBOT_INSTALL_DIR` is unchanged.
- The desktop `AMBIGUOUS_ENTRIES` error messages no longer refer to another application's
  commands. They say how to choose: by entry name, or by account number, full key or
  unique prefix.
- Windows desktop decryption reports a malformed nonce as `DECRYPT_FAILED` instead of
  relying on a panicking conversion.

### Fixed

- `cargo doc` without the `desktop-session` feature no longer fails on a broken link.

## [1.0.0] - 2026-10-17

First standalone release. The crate was previously developed inside the
[grokbot-tui](https://github.com/m3talsmith/gb) workspace; that history is preserved.

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

[Unreleased]: https://github.com/WeirdBrains/grokbot_api/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/WeirdBrains/grokbot_api/compare/7a27c41...v1.1.0
[1.0.0]: https://github.com/WeirdBrains/grokbot_api/tree/7a27c41
