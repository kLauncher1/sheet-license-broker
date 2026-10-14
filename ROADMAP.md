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

## Phase 4: Multi-Language Client SDKs (v0.4.0) - Completed
- [x] Lightweight standalone Python client library (`sheet_license_client.py`) with automatic HWID collection and HMAC signing
- [x] C# / .NET single-file helper for Unity and WPF desktop software protection (`SheetLicenseClient.cs`)
- [x] Node.js / TypeScript lightweight client SDK with ESM distribution build (`@sheet-license/client`)
- [x] Native Go client SDK package (`sdk/go/client.go`)
- [x] Comprehensive code samples for SaaS applications and protected desktop programs (`examples/`)

## Phase 5: Multi-Tenant Namespacing & Cloudflare Edge Gateway (v0.5.0) - Completed
- [x] Multi-tenant isolation with namespace prefixes per application (`internal/tenant/tenant.go`)
- [x] Edge proxy configuration for Cloudflare Workers with edge key caching (`edge/cloudflare/worker.js`)
- [x] Automated Google Sheets backup snapshot exporter with AES-256-GCM encryption (`internal/backup/snapshot.go`)
- [x] Real-time webhook notifications for license events and tamper attempts (`internal/webhook/dispatcher.go`)

## Phase 6: Automated Reconciliation & High-Availability Sync (v0.6.0) - Completed
- [x] Dual-sheet active-standby replication with collision-free merge (`internal/replication/replication.go`, `internal/replication/merge.go`)
- [x] Encrypted local disk fallback queue for zero-loss offline logging (`internal/queue/spool.go`)
- [x] Prometheus-compatible metrics endpoint for enterprise monitoring (`internal/metrics/metrics.go`, `/metrics`)
- [x] Automated security incident webhooks for Slack and Discord alert channels (`internal/webhook/alerts.go`)

## Phase 7: Dynamic Feature Flags & Usage-Based Tier Metering (v0.7.0)
- [ ] Dynamic feature entitlement tags attached to license records
- [ ] Daily API usage and seat-count metering stored in Google Sheets
- [ ] Client SDK helpers for conditional feature gating (`client.isFeatureEnabled("analytics")`)

## Phase 8: Cryptographic Hardware Attestation & Enclave Binding (v0.8.0)
- [ ] TPM 2.0 endorsement key signing and platform configuration register (PCR) binding
- [ ] Apple Secure Enclave / Windows Hello hardware key attestation
- [ ] Anti-debugging and memory-tamper heuristic telemetry detection

## Phase 9: Enterprise Security Incident Dispatchers & Rate Limiting (v0.9.0)
- [ ] IP and hardware ID brute-force rate-limiting with exponential backoff penalty
- [ ] In-memory sliding-window reputation cache with automatic temporary bans
- [ ] Encrypted token export pipeline for external SIEM integration

## Phase 10: Distributed Consensus & Multi-Region Quorum Sync (v1.0.0)
- [ ] Raft-inspired lightweight quorum consensus across distributed broker nodes
- [ ] Conflict-free Replicated Data Type (CRDT) document synchronization
- [ ] Multi-region active-active mesh with automated network partition healing
