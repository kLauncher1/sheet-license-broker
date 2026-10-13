# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-10-13

### Added
- Direct Google Apps Script Web App HTTPS proxy client with automatic redirect handling and exponential backoff retry policies (`internal/gas/client.go`).
- Thread-safe local caching engine with TTL and offline fallback grace mode for Google API quota protection and network resilience (`internal/gas/cache.go`).
- Unified proxy coordinator mediating between remote Google Sheets backend, in-memory caches, and local standalone fallback engines (`internal/proxy/proxy.go`).
- Zero-click Google Apps Script Clasp CLI deployment configuration and automation script (`gas/.clasp.json.example`, `gas/README.md`, `scripts/deploy_clasp.mjs`).
- Live backend connection status badge, local cache size metrics, and interactive latency ping verification in the embedded web dashboard (`web/dist/index.html`).
- Automated GitHub Actions CI workflow for Go vetting, unit test execution, and asset link integrity verification (`.github/workflows/ci.yml`).

### Changed
- Refactored `main.go` to dispatch all licensing, user authentication, and KV storage operations through the proxy layer.
- Added `/api/proxy/ping` and `/api/proxy/status` API endpoints for real-time remote diagnostics.

## [0.1.0] - 2026-10-13

### Added
- Google Apps Script serverless engine (`gas/Code.gs`) for `Users`, `Licenses`, and `KV_Database` sheets.
- Salted SHA-256 user authentication manager (`internal/auth`).
- Hardware ID (HWID) device-locking and expiry license validator (`internal/license`).
- NoSQL key-value document store (`internal/db`).
- Embedded emerald-dark management dashboard (`web/dist/index.html`) via `//go:embed`.
- Mechanical unit test suites and single binary packaging (`sheet-license-broker.exe`).
