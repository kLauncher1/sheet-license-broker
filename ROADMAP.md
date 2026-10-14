# Roadmap

This roadmap outlines the planned development trajectory for `sheet-license-broker`.

## Phase 1: Core Foundation & Gateway Engine (v0.1.0) - Completed
- [x] Full Google Apps Script (`Code.gs`) engine handling Users, Licenses, and KV_Database sheets
- [x] Salted SHA-256 cryptographic password hashing and authentication
- [x] Hardware ID (HWID) device locking and expiration validation
- [x] In-memory mock server & embedded dashboard web console
- [x] Zero-dependency Go HTTP multiplexer with `//go:embed`
- [x] 100% mechanical unit test verification

## Phase 2: Live Proxy & Production Integration (v0.2.0) - Completed
- [x] Direct HTTPS forwarder proxying local Go API calls to live Google Apps Script web app URLs (`internal/gas/client.go`)
- [x] Rate-limit resilient queueing with exponential backoff for Google Workspace quotas
- [x] Thread-safe local cache with offline fallback grace period for quota protection (`internal/gas/cache.go`)
- [x] Zero-click Google Apps Script Clasp CLI deployment configuration and automation script (`scripts/deploy_clasp.mjs`)
- [x] Interactive backend health telemetry and ping diagnostic controls in embedded dashboard

## Phase 3: Enterprise Anti-Tamper & Security (v0.3.0) - Completed
- [x] Request signing with shared HMAC-SHA256 secret keys to defeat proxy inspection and MITM
- [x] Replay attack mitigation with timestamp-based challenge-response sliding-window nonces
- [x] Instant remote kill switch and blacklist sheet synchronization (`internal/license/blacklist.go`, `gas/Code.gs`)
- [x] Dedicated `Blacklist` and `Audit_Logs` tabs in Google Sheets backend with audit trail logging
- [x] Embedded dashboard security status badge and interactive device banning controls

## Phase 4: Multi-Language Client SDKs (v0.4.0)
- [ ] Lightweight standalone Python client library (`sheet_license_client.py`)
- [ ] C# / .NET single-file helper for Unity and WPF desktop software protection
- [ ] Node.js / TypeScript lightweight client SDK
- [ ] Comprehensive code samples for SaaS applications

## Phase 5: Multi-Tenant Namespacing & Cloudflare Edge Gateway (v0.5.0)
- [ ] Multi-tenant isolation with namespace prefixes per application
- [ ] Edge proxy configuration for Cloudflare Workers with edge key caching
- [ ] Automated Google Sheets backup snapshot exporter
- [ ] Webhook notifications on license expiration or unauthorized device binding attempts

## Phase 6: Automated Reconciliation & High-Availability Sync (v0.6.0)
- [ ] Dual-sheet active-standby replication with collision-free merge
- [ ] Encrypted local disk fallback queue for zero-loss offline logging
- [ ] Prometheus-compatible metrics endpoint for enterprise monitoring
- [ ] Automated security incident webhooks for Slack and Discord alert channels
