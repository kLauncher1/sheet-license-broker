# Changelog

All notable changes to this project will be documented in this file.

## [0.7.0] - 2026-10-14

### Added
- Dynamic feature flag entitlement and usage-based tier metering engine (`internal/feature/feature.go`, `internal/feature/feature_test.go`) supporting standard subscription tiers (`free`, `pro`, `enterprise`), custom feature overrides per license, thread-safe atomic consumption counters, and daily quota threshold enforcement.
- Dedicated modular feature and usage routes (`routes_feature.go`, `routes_feature_test.go`) wiring `GET /api/features`, `POST /api/features/check`, `POST /api/usage/record`, and `GET /api/usage/stats` while maintaining modular line limits.
- Proxy layer integration (`internal/proxy/feature.go`, `internal/proxy/feature_test.go`) coordinating feature checks, entitlement resolution, and consumption recording across local memory caches and remote Google Sheets.
- Google Apps Script backend update (`gas/Code.gs`) adding automatic initialization and persistence for `FeatureFlags` and `Usage_Metering` sheets, with actions `features_list`, `usage_record`, `usage_get`, and tier-aware license creation.
- Cloudflare Edge Worker gateway enhancements (`edge/cloudflare/worker.js`) returning tier and feature flags directly on edge KV cache hits.
- Multi-language client SDK extensions across Go (`sdk/go`), Python (`sdk/python`), TypeScript / Node.js (`sdk/typescript`), and C# (`sdk/csharp`) adding `IsFeatureEnabled`, `RecordUsage`, and `GetUsage` methods.
- Embedded administration dashboard update (`web/dist/index.html`) featuring an interactive "Features & Metering" tab with live entitlement evaluator, tier catalog matrix, and usage simulation tools.
- Version bump to 0.7.0 across core binary, manifests, documentation, and client libraries.

## [0.6.0] - 2026-10-14

### Added
- Dual-sheet active-standby high-availability replication coordinator (`internal/replication/replication.go`, `internal/replication/replication_test.go`) supporting seamless automatic failover on Google Workspace quota or network errors, periodic health probing, and asynchronous mutation replication.
- Deterministic, collision-free bidirectional dataset reconciliation engine (`internal/replication/merge.go`) implementing Last-Write-Wins (LWW) and security-preserving merge rules (revocations always supersede active licenses; device bans union-merge; latest timestamps resolve concurrent updates).
- Encrypted local disk fallback spool queue (`internal/queue/spool.go`, `internal/queue/spool_test.go`) utilizing AES-256-GCM authenticated encryption for zero-loss offline logging and mutation buffering during network disruptions, with automatic drain workers on connection recovery.
- Prometheus-compatible enterprise metrics endpoint (`internal/metrics/metrics.go`, `internal/metrics/metrics_test.go`, `/metrics`) exposing request rates, verification outcomes, backend health status, queue depth, and runtime memory telemetry in standard Prometheus exposition format.
- Automated security incident webhook dispatchers for Discord and Slack alert channels (`internal/webhook/alerts.go`, `internal/webhook/alerts_test.go`) featuring rich embed formatting, severity tagging, and IP/HWID contextual data.
- High-Availability, Replication, and Spool management tab in embedded administration dashboard (`web/dist/index.html`) with interactive reconciliation controls, spool drainage, and live telemetry widgets.
- Dedicated modular HA routes (`routes_ha.go`, `routes_ha_test.go`) keeping root application routing below modular architectural ceilings.
- New API endpoints: `GET /metrics`, `GET /api/ha/status`, `POST /api/ha/reconcile`, `POST /api/ha/spool/drain`, `POST /api/ha/failover`, and `POST /api/alerts/test`.

## [0.5.0] - 2026-10-14

### Added
- Multi-tenant isolation engine (`internal/tenant/tenant.go`, `internal/tenant/tenant_test.go`) supporting application namespace prefixes (e.g. `PREFIX-LIC-XXXX-YYYY`), thread-safe tenant registry, policy limits, and automatic HTTP request resolution via `X-Tenant-ID` headers and query parameters.
- Cloudflare Edge Gateway worker (`edge/cloudflare/worker.js`, `edge/cloudflare/wrangler.toml`, `edge/cloudflare/worker.test.mjs`) implementing sub-millisecond edge license verification, Web Crypto API HMAC-SHA256 signature verification, Cloudflare Workers KV caching with TTL, and sliding-window replay attack defense.
- Point-in-time automated backup and disaster recovery subsystem (`internal/backup/snapshot.go`, `internal/backup/snapshot_test.go`) capturing complete state across tenants, users, licenses, blacklist entries, audit logs, and KV documents with SHA-256 integrity checksums and AES-256-GCM authenticated encryption.
- Asynchronous webhook notification pipeline (`internal/webhook/dispatcher.go`, `internal/webhook/dispatcher_test.go`) delivering real-time lifecycle events (`license.created`, `license.verified`, `license.expired`, `license.revoked`, `device.banned`, `tamper.detected`) with HMAC-SHA256 signatures in `X-Broker-Signature`, exponential backoff retries, and tenant-level routing.
- Google Apps Script backend update (`gas/Code.gs`) adding `Tenants` sheet initialization and native support for `tenant_register`, `tenant_list`, `backup_export`, and `backup_restore` actions.
- Client SDK updates across Go, Python, TypeScript, and C# libraries adding `X-Tenant-ID` header injection for multi-tenant deployments.
- Embedded administration dashboard updates (`web/dist/index.html`) featuring dedicated Multi-Tenant Namespaces and Backup & Restore management tabs.
- New administrative REST API endpoints: `/api/tenants`, `/api/tenants/register`, `/api/backup/export`, `/api/backup/restore`, and `/api/webhooks/test`.

## [0.4.0] - 2026-10-14

### Added
- Multi-language client SDK suite supporting Python, C# / .NET, TypeScript / Node.js, and Go with automated hardware identifier (HWID) binding and cryptographic HMAC-SHA256 request signing.
- Standalone zero-dependency Python client library (`sdk/python/sheet_license_client.py`) with cross-platform hardware fingerprinting, full API coverage, CLI tooling, and unit tests (`sdk/python/test_client.py`).
- Single-file C# helper library (`sdk/csharp/SheetLicenseClient.cs`) tailored for Unity, WPF, and .NET desktop software protection with async/await and synchronous game-loop validation methods.
- Lightweight TypeScript / Node.js client package (`sdk/typescript/`) with strong type definitions, native ESM distribution build, and test suite.
- Native Go client package (`sdk/go/client.go`) with context-aware API methods and isolated unit tests.
- Production-grade application integration examples (`examples/`):
  - Python desktop application demonstrating startup licensing gate, offline grace period, and background heartbeat thread (`examples/python-desktop-app/main.py`).
  - C# console / Unity pattern demonstrating machine HWID device lock and startup validation (`examples/csharp-wpf-unity/Program.cs`).
  - Node.js SaaS API server with license verification middleware protecting premium endpoints (`examples/node-saas-backend/server.mjs`).

## [0.3.0] - 2026-10-14

### Added
- Cryptographic HMAC-SHA256 request signature verification engine to defeat MITM tampering and reverse-engineered proxy spoofing (`internal/security/guard.go`).
- Sliding-window nonce replay protection cache with configurable timestamp drift tolerance (default 5 minutes) and capacity bounds (`internal/security/nonce.go`).
- Remote revocation and device blacklisting subsystem in Google Apps Script and Go core (`internal/license/blacklist.go`, `gas/Code.gs`).
- Dedicated `Blacklist` and `Audit_Logs` tabs in Google Sheets backend for instant kill-switch propagation and administrative compliance logging.
- Blacklist synchronization and instant cache invalidation in the unified proxy layer (`internal/proxy/blacklist.go`, `internal/gas/blacklist.go`).
- New administrative endpoints: `POST /api/licenses/revoke`, `GET/POST /api/security/blacklist`, `POST /api/security/blacklist/remove`, and `GET /api/security/status`.
- Revocation controls, real-time blacklist management view, and HMAC security indicator in the embedded administration dashboard (`web/dist/index.html`).
- End-to-end integration test suite verifying health telemetry, signature enforcement, and replay attack rejection (`main_test.go`).

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
