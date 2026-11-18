# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: SemVer.

## [Unreleased]

### Added
- `updsign` CLI: `keygen`, `pub`, `sign`, `verify`, `manifest add|rm|list`.
- Signature over a canonical message binding a configurable context, version,
  build, platform, digest, size and notes digest.
- Key files with group/world access are refused (POSIX).
- Strict manifest parser with a fuzz target; relative-URL-only rule.
- Dart package `signed_updater`: pinned keys (with rotation sets), streaming
  download with size cap and re-hash, rollback protection with a persisted
  high-water mark, same-origin-only redirects, pluggable installers
  (Windows, Linux, macOS, generic command).
- Go-generated cross-verification fixtures consumed by the Dart tests.
- Threat model and key-rotation documents.
