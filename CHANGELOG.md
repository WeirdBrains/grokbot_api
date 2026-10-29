# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] - 2026-10-29

### Added

- Prompt attachments (new `attachments` module), on the Cursor backend's
  `aiserver.v1.GrokBotService`. They need a client with a Cursor access token
  (`Client::connect_cursor` / `Client::with_cursor_token`):
  - `Client::upload_attachment`: begin, presigned PUT (single or multipart), complete,
    with progress callbacks and abort on failure. Returns an `UploadedAttachment` with the alias.
  - Low-level `begin_attachment_upload`, `presign_attachment_upload_parts`,
    `complete_attachment_upload`, `abort_attachment_upload` and `resolve_attachment_reads`.
  - `UploadMode`, `UploadRefusal` and `ReadOutcome` parse the full proto name, the short name or the number.
  - `Error::Attachment(UploadFailure)` for refusals, desktop-only (`USE_BOX`) bots and
    clients without a Cursor session.
  - `validate_attachment`, `AttachmentKind` and the desktop app's limits: 25 MiB images,
    250 MiB other files, 1 GiB video, 6 per prompt.
- `SendPrompt::attachment_paths` and `attachment_names`, sent as `attachmentPaths` /
  `attachmentNames` when set.
- `Client::has_cursor_session`.

### Security

- Presigned upload URLs are used only exactly as returned, only over https (loopback http
  only with `Policy::allow_local_backend`), without redirects and without any bearer token.
  Errors and `Debug` output show the host only, never the query string or signature.

### Note

- `SendPrompt` gained two public fields. Code that builds it with a struct literal needs
  `..Default::default()` (or `SendPrompt::new`).

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
[1.2.0]: https://github.com/WeirdBrains/grokbot_api/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/WeirdBrains/grokbot_api/compare/7a27c41...v1.1.0
[1.0.0]: https://github.com/WeirdBrains/grokbot_api/tree/7a27c41
