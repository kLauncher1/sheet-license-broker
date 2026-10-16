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

## Phase 7: Dynamic Feature Flags & Usage-Based Tier Metering (v0.7.0) - Completed
- [x] Standard subscription tiers (`free`, `pro`, `enterprise`) and dynamic feature flags (`internal/feature/feature.go`)
- [x] Daily API usage and seat-count metering stored in Google Sheets (`Usage_Metering` sheet)
- [x] Multi-language client SDK helpers for conditional feature gating (`isFeatureEnabled`) and usage tracking
- [x] Cloudflare Edge Worker gateway edge KV caching for tier and feature lookups
- [x] Embedded admin console Features & Metering interactive management tab

## Phase 8: Cryptographic Hardware Attestation & Enclave Binding (v0.8.0) - Completed
- [x] TPM 2.0 endorsement key signing and platform configuration register (PCR) binding (`internal/attestation/verify.go`)
- [x] Apple Secure Enclave / Windows Hello hardware key attestation (`internal/attestation/manager.go`)
- [x] Anti-debugging and memory-tamper heuristic telemetry detection (`internal/attestation/types.go`)
- [x] Dedicated attestation router and test suite (`routes_attestation.go`, `routes_attestation_test.go`)
- [x] Apps Script backend attestation records and audit log synchronization (`gas/Code.gs`)
- [x] Multi-language client SDK methods for hardware attestation and telemetry reporting
- [x] Embedded admin console Hardware Attestation interactive management tab (`web/dist/index.html`)

## Phase 9: Enterprise Security Incident Dispatchers & Rate Limiting (v0.9.0) - Completed
- [x] IP and hardware ID brute-force rate-limiting with progressive backoff penalties (`internal/ratelimit/limiter.go`)
- [x] In-memory sliding-window IP/HWID reputation tracker with automatic temporary restrictions (`internal/ratelimit/reputation.go`)
- [x] AES-256-GCM encrypted audit token export pipeline for external SIEM/SOC integration (`internal/audit/export.go`)
- [x] Dedicated security router, rate-limiting middleware, and audit verification endpoints (`routes_security.go`)
- [x] Google Apps Script backend audit log synchronization (`gas/Code.gs`)
- [x] Multi-language client SDK extensions and interactive web console Incidents & Rate Limiting tab (`web/dist/index.html`)

## Phase 10: Distributed Consensus & Multi-Region Quorum Sync (v1.0.0) - Completed
- [x] Raft-inspired lightweight quorum consensus across distributed broker nodes (`internal/consensus/raft.go`, `internal/consensus/election.go`)
- [x] Conflict-free Replicated Data Type (CRDT) document synchronization with LWW-Element-Set and Merkle digests (`internal/consensus/crdt.go`)
- [x] Multi-region active-active mesh with automated network partition healing and anti-entropy sync (`internal/consensus/mesh.go`)
- [x] Dedicated consensus HTTP routes, proxy coordination, and multi-language client SDK extensions (`routes_consensus.go`, `internal/proxy/consensus.go`, `sdk/`)
- [x] Embedded admin console Distributed Cluster interactive management tab (`web/dist/index.html`)

## Phase 11: Real-Time WebSocket Streaming & Telemetry Push (v1.1.0) - Completed
- [x] Full RFC 6455 standard library WebSocket implementation with zero external dependencies
- [x] Bidirectional streaming hub with O(1) multi-index client lookup (by license key, device HWID, and tenant ID)
- [x] Sub-second remote kill-switch execution with targeted and broadcast actions (`/api/stream/kill`)
- [x] Real-time client heartbeat telemetry and round-trip ping/pong latency tracking
- [x] Multi-language client SDK extensions (Go, TypeScript, Python, C#) for stream monitoring and kill-switch control
- [x] Interactive web console Real-Time Streams tab with live connection counts, event feed, and kill-switch triggers

## Phase 12: Zero-Knowledge Proof (ZKP) License Verification & Privacy-Preserving Entitlements (v1.2.0) - Completed
- [x] NIST P-256 elliptic curve Pedersen commitments with deterministic hash-to-curve generators (`internal/zkp/commitment.go`)
- [x] Non-interactive zero-knowledge presentation proofs (Sigma protocol with Fiat-Shamir transformation) for HWID privacy (`internal/zkp/proof.go`)
- [x] Constant-time proof verifier and spent nullifier replay protection registry (`internal/zkp/verifier.go`)
- [x] Dedicated ZKP REST routing, proxy integration, and telemetry (`routes_zkp.go`, `internal/proxy/zkp.go`)
- [x] Apps Script backend support for anonymous credentials and nullifiers (`gas/Code.gs`)
- [x] Multi-language client SDK methods for ZKP workflows (Go, TypeScript, Python, C#)
- [x] Embedded admin console Zero-Knowledge Proofs (ZKP) interactive dashboard tab (`web/dist/index.html`)

## Phase 13: Enterprise Single Sign-On (SSO) & SCIM 2.0 Directory Provisioning (v1.3.0) - Completed
- [x] SAML 2.0 Service Provider metadata generator (`BuildSPMetadataXML`) and assertion parser (`ParseSAMLResponse`)
- [x] OpenID Connect (OIDC) ID token and callback validator (`ValidateOIDCClaims`) with claim normalization
- [x] Multi-tenant Identity Provider registry (`internal/sso/saml_oidc.go`) with tenant isolation
- [x] RFC 7643 & RFC 7644 compliant SCIM 2.0 user directory management (`internal/sso/scim.go`, `/scim/v2/*`)
- [x] Automated license seat allocation upon user provisioning and instant revocation on deprovisioning (`internal/proxy/sso.go`)
- [x] Scoped RBAC permissions matrix (`RoleScopeMatrix`) and ephemeral HMAC-SHA256 session token issuance (`internal/sso/rbac_token.go`)
- [x] Dedicated SSO & SCIM REST router and tests (`routes_sso.go`, `routes_sso_test.go`)
- [x] Google Apps Script backend sheets (`SSO_Configs`, `Directory_Users`) and action handlers (`gas/Code.gs`)
- [x] Multi-language client SDK methods for SSO and SCIM workflows across Go, TypeScript, Python, and C#
- [x] Embedded admin console Enterprise SSO & SCIM interactive dashboard tab (`web/dist/index.html`)

## Phase 14: Post-Quantum Cryptography & ML-DSA Signature Chains (v1.4.0) - Completed
- [x] Module-Lattice-Based Digital Signature Algorithm (NIST FIPS 204 ML-DSA-44 / ML-DSA-65) key generation, signing, and verification (`internal/pqc/mldsa.go`, `internal/pqc/poly.go`)
- [x] Quantum-resistant hybrid signature envelopes (`Hybrid-P256-MLDSA65` and `Hybrid-HMAC-MLDSA44`) combining classical ECDSA/HMAC with lattice chains (`internal/pqc/hybrid.go`)
- [x] Key rotation manager with zero-downtime grace period windows and emergency revocation kill-switch (`internal/pqc/rotation.go`)
- [x] Dedicated PQC REST routes (`routes_pqc.go`) and full proxy integration (`internal/proxy/pqc.go`)
- [x] Google Apps Script backend sheet (`PQC_Keys`) and action handlers (`gas/Code.gs`)
- [x] Multi-language client SDK methods across Go, TypeScript, Python, and C# (`sdk/`)
- [x] Embedded admin console Post-Quantum Cryptography (PQC) interactive tab (`web/dist/index.html`)

## Phase 15: Behavioral Anomaly Detection & Adaptive Risk Scoring (v1.5.0) - Completed
- [x] Statistical drift analysis on client heartbeat and geographic origin patterns (`internal/anomaly/drift.go`)
- [x] Sliding-window Z-Score calculation with &plusmn;15% network jitter margin and Haversine velocity impossible travel detection (&gt;950 km/h or concurrent /24 subnets)
- [x] Dynamic risk scoring engine with automated progressive nominal decay, challenge escalation at risk score &gt;= 50, and automatic zero-trust quarantine at risk score &gt;= 85 (`internal/anomaly/scoring.go`)
- [x] Real-time security incident graph exporter generating standardized topological nodes and edges for enterprise SIEM ingestion (`internal/anomaly/graph.go`)
- [x] Unified proxy integration with audit logging, alert webhooks, and automatic license verification rejection for quarantined entities (`internal/proxy/anomaly.go`)
- [x] Dedicated REST API routing layer (`routes_anomaly.go`) and integration test coverage (`routes_anomaly_test.go`)
- [x] Google Apps Script backend sheet (`Anomaly_Incidents`) and action handlers (`gas/Code.gs`)
- [x] Multi-language client SDK methods across Go, TypeScript, Python, and C# (`sdk/`)
- [x] Embedded admin console Behavioral Anomaly & Risk interactive dashboard tab (`web/dist/index.html`)

## Phase 16: Confidential Computing & Hardware Enclave Attestation Bridge (v1.6.0)
- [ ] Intel SGX / AMD SEV remote attestation quote validation
- [ ] End-to-end encrypted payload tunnels between client enclaves and broker
- [ ] Zero-plaintext memory guarantees during license key evaluation

## Phase 17: Multi-Cloud Object Storage Archive & Continuous Ledger Auditing (v1.7.0)
- [ ] Automated continuous cold-archive streaming to AWS S3, Cloudflare R2, and Google Cloud Storage
- [ ] Immutable append-only cryptographic Merkle audit ledger with verifiable integrity proofs
- [ ] Automated archival compaction and tamper-evident history verification

## Phase 18: Zero-Trust Ephemeral Peer Mesh & Mutual TLS Enclave Mesh (v1.8.0)
- [ ] Strict mutual TLS (mTLS) with automated X.509 certificate rotation for broker-to-broker RPC
- [ ] Ephemeral WireGuard/Noise protocol encrypted overlay mesh across cloud providers
- [ ] Hardware-enforced mTLS key storage in hardware security modules (HSM) and cloud KMS

## Phase 19: High-Throughput Batch Issuance & Bulk Entitlement Sharding (v1.9.0)
- [ ] High-throughput bulk license generation pipeline (>10,000 licenses/sec)
- [ ] Consistent hashing key-space partitioning across broker nodes
- [ ] Parallelized batch validation and aggregated HMAC verification endpoints

## Phase 20: Global Anycast Routing & Autonomous Edge Auto-Healing (v2.0.0)
- [ ] Global BGP Anycast and geo-distributed DNS routing integration
- [ ] Autonomous split-brain detection and automatic cluster reconciliation
- [ ] Self-healing multi-region mesh with zero-downtime rolling upgrades

## Phase 21: Autonomous License Healing & Dynamic Quota Rebalancing (v2.1.0)
- [ ] Real-time token bucket auto-scaling based on client stream telemetry load
- [ ] Automated self-healing retry tunnels on intermittent network disconnects
- [ ] Distributed quota borrowing between tenant namespaces and broker clusters

## Phase 22: Hardware Security Module (HSM) PKCS#11 Vault Integration (v2.2.0)
- [ ] Direct PKCS#11 hardware cryptoki engine binding
- [ ] HSM-backed master key derivation for audit token and snapshot encryption
- [ ] FIPS 140-3 Level 4 tamper-resistant storage certification bridge

## Phase 23: Quantum-Resistant ML-KEM Key Exchange & Lattice Cryptography (v2.3.0)
- [ ] NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber-768/1024)
- [ ] Post-quantum hybrid TLS key exchange wrappers and ephemeral forward secrecy
- [ ] Post-quantum client SDK handshakes with fallback resilience

## Phase 24: Confidential Computing SEV-SNP Remote Enclave Validation (v2.4.0)
- [ ] AMD SEV-SNP and Intel TDX remote attestation report cryptographic verification
- [ ] Hardware-isolated memory execution guarantees for sensitive license decryption
- [ ] End-to-end attestation token binding with hardware measurements and security version numbers (SVN)

## Phase 25: Real-Time Decentralized Audit Ledger & Verifiable Transparency Logs (v2.5.0)
- [ ] Cryptographic Merkle tree transparency log with RFC 6962 inclusion and consistency proofs
- [ ] Tamper-evident verifiable log server endpoints (`/api/transparency/inclusion-proof`)
- [ ] Continuous signed tree head (STH) publishing and multi-party witness co-signing

## Phase 26: Adaptive Zero-Trust Device Health Scoring & Continuous Posture Attestation (v2.6.0)
- [ ] Multi-vector client security posture analyzer (OS patch level, secure boot status, AV health)
- [ ] Dynamic confidence scoring engine triggering progressive step-up re-authentication
- [ ] Policy-driven auto-quarantine with graceful degradation mode and localized compliance webhooks

## Phase 27: Autonomous Multi-Cloud Edge Failover & Geo-DNS Health Routing (v2.7.0)
- [ ] Active-active multi-cloud edge routing across Cloudflare, AWS CloudFront, and Fastly
- [ ] Global latency health probes with sub-second failover orchestration
- [ ] Zero-packet-loss state synchronization across partitioned cloud providers

## Phase 28: Federated Differential Privacy & Blinded Entitlement Aggregation (v2.8.0)
- [ ] Local differential privacy noise injection for privacy-preserving telemetry analytics
- [ ] Secure multi-party computation (SMPC) seat usage aggregation without centralized cleartext exposure
- [ ] Verifiable zero-knowledge compliance attestations for high-assurance enterprise reporting

## Phase 29: Autonomous Self-Healing License Fabric & Fault-Tolerant Rebalancing (v2.9.0)
- [ ] Topology-aware dynamic workload distribution across resilient peer clusters
- [ ] Automatic gossip-based failure recovery and state reconciliation under network partitions
- [ ] Predictive lease extension and decentralized quota preservation during connectivity blackouts

## Phase 30: Cryptographic Zero-Trust Enclave Identity Attestation & Hardware Root of Trust (v3.0.0)
- [ ] Platform Security Processor (PSP) and ARM TrustZone cryptographically bound hardware credentials
- [ ] Measured boot log verification with PCR extension and remote attestation validation
- [ ] Tamper-proof ephemeral session generation anchored directly to hardware PUF (Physically Unclonable Function)



