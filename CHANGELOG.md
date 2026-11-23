# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `infected` flag in scan results (True when clamscan exits with code 1);
  clamscan exit codes other than 0/1 are reported as scan failure.

## [0.1.0] - 2026-11-23

### Added
- Input limits: max base64 length (`MAX_B64_LEN`, default ~28M chars), max scan timeout (`SCAN_TIMEOUT`, default 120s), max output chars (`MAX_OUTPUT_CHARS`, default 4096).
- Filename sanitization (basename, no separators/control chars/leading dot/`..`, 255-char cap).
- Subprocess timeout and output truncation for clamscan output.
- Generic client-facing errors (no internal exception details).
- Temp file written with 0600 permissions and always cleaned up.
- Migration to mcp 2.x `MCPServer`, SSE transport (default 127.0.0.1:8000).
- Test suite (unit + optional integration tests with real clamscan, `-m integration`).
- CI workflow: lock check, ruff lint/format, pytest, pip-audit, gitleaks.
- README security/usage/env-var documentation.
