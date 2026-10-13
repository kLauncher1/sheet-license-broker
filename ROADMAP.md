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

## Phase 3: Enterprise Anti-Tamper & Security (v0.3.0)
- [ ] Request signing with shared HMAC secret keys to defeat proxy inspection and MITM
- [ ] Replay attack mitigation with timestamp-based challenge-response nonces
- [ ] Instant remote kill switch and blacklist sheet synchronization
- [ ] Audit trail logging in dedicated Google Sheets tab (`Audit_Logs`)

## Phase 4: Multi-Language Client SDKs (v0.4.0)
- [ ] Python client SDK (`sheet_license_client.py`)
- [ ] C# / .NET SDK for Unity and WPF commercial desktop software
- [ ] Node.js / TypeScript client library
- [ ] Rust lightweight client crate

## Phase 5: Multi-Tenant Namespacing & Distributed Gateway (v0.5.0)
- [ ] Multi-tenant isolation with namespace prefixes per application
- [ ] Cloudflare Workers edge caching layer for sub-50ms worldwide latency
- [ ] Automated Google Sheets backup snapshot exporter
- [ ] Webhook notifications on license expiration or unauthorized device binding attempts
