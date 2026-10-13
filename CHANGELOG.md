# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-10-13

### Added
- Google Apps Script serverless engine (`gas/Code.gs`) for `Users`, `Licenses`, and `KV_Database` sheets.
- Salted SHA-256 user authentication manager (`internal/auth`).
- Hardware ID (HWID) device-locking and expiry license validator (`internal/license`).
- NoSQL key-value document store (`internal/db`).
- Embedded emerald-dark management dashboard (`web/dist/index.html`) via `//go:embed`.
- Mechanical unit test suites and single binary packaging (`sheet-license-broker.exe`).
