# Changelog

All notable changes to this project will be documented in this file.

## [1.4.0] - 2026-10-16

### Added
- Module-Lattice-Based Digital Signature Algorithm (ML-DSA / NIST FIPS 204) engine (`internal/pqc/types.go`, `internal/pqc/poly.go`, `internal/pqc/mldsa.go`, `internal/pqc/hybrid.go`, `internal/pqc/rotation.go`, `internal/pqc/pqc_test.go`) implemented in pure Go standard library with zero external dependencies, providing long-term quantum resistance against Shor's algorithm.
- Complete ring arithmetic in quotient polynomial ring $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$ with $N=256$, modulus $q=8380417$, power-of-two decomposition, high/low bit extraction, hint bit generation/recovery, and rejection sampling algorithms for ML-DSA-44 and ML-DSA-65.
- Dual hybrid classical/post-quantum signature envelopes (`Hybrid-P256-MLDSA65` and `Hybrid-HMAC-MLDSA44`) requiring simultaneous verification of classical ECDSA (or HMAC) and lattice signatures over canonical SHA-256 payload digests.
- Thread-safe post-quantum key manager (`PQCKeyManager`) with atomic key rotation, configurable grace period validity windows (default 7 days), and immediate emergency key revocation kill-switch broadcasts.
- Dedicated modular PQC REST routing layer (`routes_pqc.go`, `routes_pqc_test.go`) exposing `GET /api/pqc/params`, `GET /api/pqc/keys`, `POST /api/pqc/sign`, `POST /api/pqc/verify`, `POST /api/pqc/rotate`, `POST /api/pqc/revoke`, and `GET /api/pqc/status`.
- Proxy layer PQC coordination (`internal/proxy/pqc.go`, `internal/proxy/pqc_test.go`) enforcing machine HWID binding on hybrid license signatures and broadcasting WebSocket kill-switch signals upon key revocation.
- Google Apps Script backend update (`gas/Code.gs`) adding automatic initialization and logging for the `PQC_Keys` sheet, with `pqc_key_save`, `pqc_key_revoke`, and `pqc_key_list` action handlers.
- Multi-language client SDK extensions across Go (`sdk/go/pqc.go`, `sdk/go/pqc_test.go`), TypeScript / Node.js (`sdk/typescript`), Python (`sdk/python`), and C# (`sdk/csharp`) adding PQC parameter querying, public key retrieval, hybrid signing, verification, rotation, and revocation methods with 100% test coverage.
- Embedded administration console update (`web/dist/index.html`) featuring an interactive "Post-Quantum Cryptography (PQC)" tab with live telemetry cards, active key ring table, hybrid signature generation/verification simulators, and emergency revocation controls.
- Version bump to 1.4.0 across core binary, manifests, documentation, and client libraries.

## [1.3.0] - 2026-10-15

### Added
- Enterprise Single Sign-On (SSO) federation and SCIM 2.0 directory user synchronization engine (`internal/sso/types.go`, `internal/sso/saml_oidc.go`, `internal/sso/scim.go`, `internal/sso/rbac_token.go`, `internal/sso/manager.go`, `internal/sso/sso_test.go`) implemented in pure Go standard library with zero external dependencies.
- Standard SAML 2.0 Service Provider metadata generator (`BuildSPMetadataXML`) and assertion parser (`ParseSAMLResponse`) extracting NameID, entity attributes, audience restriction checks, and expiry timestamps.
- OpenID Connect (OIDC) ID token and callback validator (`ValidateOIDCClaims`) with aud/iss verification and automated identity normalization.
- Multi-tenant Identity Provider registry (`internal/sso/saml_oidc.go`) supporting dynamic registration, resolution by entity ID / issuer URL, and tenant namespace isolation.
- RFC 7643 & RFC 7644 compliant SCIM 2.0 user directory management with full CRUD operations (`/scim/v2/Users`, `/scim/v2/ServiceProviderConfig`), pagination (`startIndex`, `count`), and lifecycle hooks (`OnProvision`, `OnDeprovision`).
- Automated enterprise license seat provisioning on user creation and instant seat revocation with real-time WebSocket kill-switch dispatch upon directory deprovisioning.
- Scoped Role-Based Access Control (RBAC) permissions matrix (`RoleScopeMatrix`) supporting `admin`, `operator`, `auditor`, and `user` roles with standard scopes (`license:read`, `license:write`, `license:revoke`, `audit:read`, `tenant:manage`, `sso:manage`, `scim:manage`).
- Ephemeral HMAC-SHA256 session token minter and constant-time validator issuing tamper-proof bearer tokens with sub-millisecond introspection.
- Dedicated modular SSO & SCIM REST routing layer (`routes_sso.go`, `routes_sso_test.go`) exposing `/api/sso/saml/metadata`, `/api/sso/saml/acs`, `/api/sso/oidc/callback`, `/api/sso/idp`, `/api/sso/token/mint`, `/api/sso/token/introspect`, `/api/sso/status`, and root `/scim/v2/*` endpoints.
- Proxy layer integration (`internal/proxy/sso.go`, `internal/proxy/sso_test.go`) connecting SCIM lifecycle hooks with audit event logging, automated tenant license issuance, and instant remote revocation.
- Google Apps Script backend update (`gas/Code.gs`) adding automatic initialization and logging for `SSO_Configs` and `Directory_Users` sheets, with `sso_idp_save`, `sso_idp_list`, `scim_user_sync`, `scim_user_deprovision`, and `scim_user_list` action handlers.
- Multi-language client SDK extensions across Go (`sdk/go/sso.go`, `sdk/go/zkp.go`, `sdk/go/client.go`), TypeScript / Node.js (`sdk/typescript`), Python (`sdk/python`), and C# (`sdk/csharp`) adding SSO IdP registration, SAML/OIDC callbacks, SCIM user provisioning/deprovisioning, and session token introspection with comprehensive unit tests.
- Embedded administration console update (`web/dist/index.html`) featuring an interactive "Enterprise SSO & SCIM" tab with registered IdP table, SCIM directory user roster, telemetry cards, and ephemeral session token inspection tools.
- Version bump to 1.3.0 across core binary, manifests, documentation, and client libraries.

## [1.2.0] - 2026-10-15

### Added
- Zero-Knowledge Proof (ZKP) license verification and anonymous credential engine (`internal/zkp/types.go`, `internal/zkp/commitment.go`, `internal/zkp/proof.go`, `internal/zkp/verifier.go`, `internal/zkp/zkp_test.go`) implemented in pure Go standard library with zero external dependencies, providing information-theoretic privacy for device hardware identifiers (HWID).
- Cryptographic Pedersen commitments $C = vG + rH$ over NIST P-256 elliptic curves with deterministic try-and-increment hash-to-curve independent generator $H$, ensuring computational binding against forgery while hiding underlying client identities.
- Non-interactive zero-knowledge presentation proofs (Sigma NIZK with Fiat-Shamir transformation) allowing air-gapped and privacy-sensitive client applications to prove entitlement, tier qualification, and HWID ownership without revealing private keys or device parameters.
- Constant-time proof verifier and spent nullifier replay protection registry (`internal/zkp/verifier.go`) preventing double-presentation replay attacks within active validity epochs while preserving cross-epoch unlinkability.
- Dedicated modular ZKP REST routing layer (`routes_zkp.go`, `routes_zkp_test.go`) exposing `GET /api/zkp/params`, `POST /api/zkp/credential/issue`, `POST /api/zkp/verify`, `GET /api/zkp/nullifiers/check`, and `GET /api/zkp/status`.
- Proxy layer ZKP coordination (`internal/proxy/zkp.go`, `internal/proxy/zkp_test.go`) binding the zero-knowledge verifier with automated audit event logging and Google Apps Script synchronization.
- Google Apps Script backend update (`gas/Code.gs`) adding automatic initialization and persistent logging for `ZKPCredentials` and `ZKPNullifiers` sheets, with `zkp_record_credential`, `zkp_record_nullifier`, and `zkp_list` action handlers.
- Multi-language client SDK extensions across Go (`sdk/go`), Python (`sdk/python`), TypeScript / Node.js (`sdk/typescript`), and C# (`sdk/csharp`) adding `GetZKPParams`, `IssueAnonymousCredential`, `VerifyZKPProof`, and `GetZKPStatus` methods with end-to-end unit test verification.
- Embedded administration console update (`web/dist/index.html`) featuring an interactive "Zero-Knowledge Proofs (ZKP)" tab with real-time public parameters, credential counters, spent nullifier monitors, anonymous credential issuance forms, proof simulators, and nullifier lookup utilities.
- Version bump to 1.2.0 across core binary, manifests, documentation, and client libraries.

## [1.1.0] - 2026-10-14

### Added
- Standard RFC 6455 WebSocket engine implemented in Go standard library (`internal/stream/websocket.go`, `internal/stream/client.go`, `internal/stream/types.go`) with zero external dependencies, supporting masked/unmasked frame parsing, payload length extension (126 uint16 / 127 uint64), connection hijacking, and concurrent write-safe framing.
- Bidirectional streaming hub (`internal/stream/hub.go`, `internal/stream/stream_test.go`) featuring O(1) multi-index client lookup (by license key, device HWID, and tenant ID), concurrent pub/sub broadcasting, in-memory stream event audit logging, and aggregate telemetry compilation.
- Sub-second remote kill-switch execution with targeted and broadcast directives (`routes_stream.go`, `internal/proxy/stream.go`), automatically pushing instantaneous revocation frames to active clients upon license invalidation or device blacklisting.
- Live client heartbeat telemetry stream with continuous round-trip ping/pong latency tracking, client metadata indexing, and status telemetry reporting.
- Dedicated modular streaming routes (`routes_stream.go`, `routes_stream_test.go`) exposing `GET /api/stream/ws` (WebSocket upgrade), `GET /api/stream/clients`, `POST /api/stream/kill`, `POST /api/stream/broadcast`, and `GET /api/stream/telemetry`.
- Proxy layer streaming coordination (`internal/proxy/stream.go`, `internal/proxy/stream_test.go`) binding the WebSocket streaming hub and automatically piping `RevokeLicense` and `BlacklistDevice` events into real-time client push streams.
- Google Apps Script backend update (`gas/Code.gs`) adding automatic initialization and persistent logging for the `StreamEvents` sheet, with `stream_event_record` and `stream_event_list` action handlers.
- Multi-language client SDK extensions across Go (`sdk/go`), Python (`sdk/python`), TypeScript / Node.js (`sdk/typescript`), and C# (`sdk/csharp`) adding `GetStreamClients`, `SendKillSwitch`, and `GetStreamTelemetry` methods with comprehensive unit test coverage.
- Embedded administration console update (`web/dist/index.html`) featuring an interactive "Real-Time Streams & Kill-Switch" tab with live connection counters, active socket session table, real-time stream audit feed, and targeted/broadcast remote kill-switch controls.
- Version bump to 1.1.0 across core binary, manifests, documentation, and client libraries.

## [1.0.0] - 2026-10-14

### Added
- Raft-like distributed quorum consensus engine (`internal/consensus/types.go`, `internal/consensus/raft.go`, `internal/consensus/election.go`, `internal/consensus/consensus_test.go`) supporting candidate, follower, and leader roles, term management, randomized election backoffs, majority quorum voting, and cryptographically chained append-entries log replication with SHA-256 integrity verification.
- Conflict-free Replicated Data Type (CRDT) document synchronization engine (`internal/consensus/crdt.go`) featuring Last-Write-Wins Element Sets (LWW-Element-Set) with a strict revocation-wins invariant on equal timestamps (`removeTime >= addTime`), Positive-Negative Counters (PN-Counters), and deterministic SHA-256 Merkle tree state digests for anti-entropy sync.
- Peer-to-peer gossip heartbeat mesh (`internal/consensus/mesh.go`) enabling dynamic peer discovery, node health probing, periodic gossip state exchange, automated partition healing, and HTTP RPC transport.
- Dedicated consensus HTTP routing layer (`routes_consensus.go`, `routes_consensus_test.go`) exposing `GET /api/consensus/status`, `GET /api/consensus/peers`, `POST /api/consensus/peers/join`, `POST /api/consensus/raft/vote`, `POST /api/consensus/raft/append`, `POST /api/consensus/crdt/sync`, and `POST /api/consensus/sync/trigger`.
- Proxy layer consensus coordination (`internal/proxy/consensus.go`, `internal/proxy/consensus_test.go`) binding the distributed consensus cluster, routing cluster state telemetry, and automating CRDT-driven cache invalidation across broker nodes.
- Google Apps Script backend update (`gas/Code.gs`) adding automatic initialization and heartbeat synchronization for the `ConsensusNodes` sheet, with `consensus_node_heartbeat` and `consensus_node_list` action handlers.
- Multi-language client SDK extensions across Go (`sdk/go`), Python (`sdk/python`), TypeScript / Node.js (`sdk/typescript`), and C# (`sdk/csharp`) adding `GetClusterStatus` and `GetClusterPeers` methods with end-to-end unit test verification.
- Embedded administration dashboard update (`web/dist/index.html`) featuring an interactive "Distributed Cluster" tab with real-time cluster quorum metrics, peer node topology table, SHA-256 Merkle tree state digest monitor, peer join dialog, and manual anti-entropy sync triggers.
- Version bump to 1.0.0 across core binary, manifests, documentation, and client libraries.

## [0.9.0] - 2026-10-14

### Added
- Enterprise rate-limiting and progressive penalty subsystem (`internal/ratelimit/limiter.go`, `internal/ratelimit/limiter_test.go`) featuring thread-safe sliding-window request tracking, per-IP and per-HWID throttling, sensitive endpoint thresholds (auth, validation, attestation), and progressive exponential backoff penalties with standard `X-RateLimit-*` and `Retry-After` HTTP headers.
- Sliding-window IP and HWID reputation tracker (`internal/ratelimit/reputation.go`) maintaining infraction score history across a configurable decay window, with automated security escalation: penalty point thresholds trigger instant temporary restrictions (HTTP 429), automated Discord/Slack incident alerts, and audit trail records.
- Cryptographically sealed audit token export engine (`internal/audit/export.go`, `internal/audit/export_test.go`) utilizing AES-256-GCM authenticated encryption and HMAC-SHA256 integrity signatures for compliant, tamper-proof external SIEM and SOC pipeline ingestion (Splunk, Datadog, Elastic, AWS CloudWatch).
- Dedicated modular security and rate limiting routes (`routes_security.go`, `routes_security_test.go`) exposing `GET /api/security/ratelimit/status`, `GET /api/security/reputation`, `GET/POST /api/security/bans`, `POST /api/security/bans/unban`, `GET /api/security/audit/records`, `POST /api/security/audit/export`, and `POST /api/security/audit/verify`.
- Global security rate-limiting and ban enforcement middleware (`securityRateLimitMiddleware`) intercepting all incoming `/api/` traffic with sub-millisecond overhead and constant-time ban lookups.
- Proxy layer integration (`internal/proxy/security.go`, `internal/proxy/security_test.go`) coordinating in-memory rate limiting, sliding-window reputation scoring, automated temporary restrictions, audit ring buffering, and incident dispatching across local memory and Google Sheets.
- Google Apps Script backend update (`gas/Code.gs`) adding `audit_log_record` and `audit_log_list` actions to record and retrieve compliance audit events from the `Audit_Logs` sheet.
- Multi-language client SDK extensions across Go (`sdk/go`), Python (`sdk/python`), TypeScript / Node.js (`sdk/typescript`), and C# (`sdk/csharp`) adding `ExportAuditToken` and dedicated `RateLimitError` exception handling with retry-after metadata.
- Embedded administration dashboard update (`web/dist/index.html`) featuring an interactive "Incidents & Rate Limiting" tab with real-time bucket counters, active temporary restrictions table, live security audit trail, and in-browser encrypted SIEM export and verification tools.
- Version bump to 0.9.0 across core binary, manifests, documentation, and client libraries.

## [0.8.0] - 2026-10-14

### Added
- Cryptographic hardware attestation and anti-tamper subsystem (`internal/attestation/types.go`, `internal/attestation/verify.go`, `internal/attestation/manager.go`, `internal/attestation/attestation_test.go`) supporting TPM 2.0 endorsement key signing and PCR binding, Apple Secure Enclave / Windows Hello hardware key attestation, and client anti-debugging / memory-tamper heuristic telemetry evaluation.
- Deterministic TPM 2.0 PCR composite calculation and ECDSA ASN.1/raw signature verification over platform configuration registers and single-use challenge nonces with 5-minute sliding-window replay defenses.
- Continuous client integrity telemetry ingest scoring (0-100 threshold) with automated defense mitigations: active debugger attachment or memory patch detection immediately triggers automatic license revocation, hardware device blacklisting, and security incident alerts.
- Dedicated modular attestation routes (`routes_attestation.go`, `routes_attestation_test.go`) wiring `POST /api/attestation/challenge`, `POST /api/attestation/verify`, `GET /api/attestation/status`, and `POST /api/attestation/telemetry`.
- Proxy layer coordination (`internal/proxy/attestation.go`, `internal/proxy/attestation_test.go`) linking hardware attestation state, automatic device blacklisting, audit logs, and security incident dispatches across local memory and Google Sheets.
- Google Apps Script backend update (`gas/Code.gs`) adding automatic initialization and logging for `Attestations` sheet, with actions `attestation_record` and `attestation_list`.
- Multi-language client SDK extensions across Go (`sdk/go`), Python (`sdk/python`), TypeScript / Node.js (`sdk/typescript`), and C# (`sdk/csharp`) adding `RequestAttestationChallenge`, `VerifyTPMAttestation`, and `ReportTelemetry` methods.
- Embedded administration dashboard update (`web/dist/index.html`) featuring an interactive "Hardware Attestation" tab with real-time trust tier status, live attestation registry, and challenge simulation tools.
- Version bump to 0.8.0 across core binary, manifests, documentation, and client libraries.

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
