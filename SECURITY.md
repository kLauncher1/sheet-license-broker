# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.7.x   | :white_check_mark: |
| 1.6.x   | :white_check_mark: |
| 1.5.x   | :white_check_mark: |
| 1.4.x   | :white_check_mark: |
| 1.3.x   | :white_check_mark: |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| 0.9.x   | :white_check_mark: |
| 0.8.x   | :white_check_mark: |
| 0.7.x   | :white_check_mark: |
| 0.6.x   | :white_check_mark: |
| 0.5.x   | :white_check_mark: |
| 0.4.x   | :white_check_mark: |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :white_check_mark: |

## Security Architecture & Best Practices

`sheet-license-broker` enables software developers to turn Google Sheets into an authenticated serverless database and license licensing gateway. While highly cost-effective, developers should adhere to the following security guidelines:

1. **HMAC-SHA256 Anti-Tamper Verification**:
   - For desktop and client applications, configure `HMAC_SECRET` and enable `HMAC_ENFORCE=true` in production environments.
   - All client requests must include valid `X-Signature`, `X-Timestamp`, and `X-Nonce` headers computed over the canonical request method, path, timestamp, nonce, and request body hash.
   - Signatures are compared using constant-time evaluation (`hmac.Equal` in Go / `timingSafeEqual` in Edge Worker) to mitigate timing side-channel attacks.

2. **Nonce Replay Attack Mitigation**:
   - The broker enforces a sliding 5-minute clock drift window. Requests older than 5 minutes or in the far future are discarded.
   - Used nonces are cached in-memory (or Cloudflare Edge KV) and rejected if submitted a second time within the active time window.

3. **Multi-Tenant Namespace Isolation**:
   - Applications and customers can be sandboxed into distinct namespaces (`PREFIX-LIC-XXXX-YYYY`).
   - Tenant boundaries prevent cross-tenant key enumeration and isolate webhook configurations and HMAC secrets.

4. **AES-256-GCM Encrypted Backup & Integrity Checksums**:
   - Point-in-time database snapshots are cryptographically sealed with authenticated AES-256-GCM encryption and unique 12-byte initialization vectors (IV).
   - Tamper-evident SHA-256 digests ensure snapshot integrity before restoration.

5. **Webhook Delivery Signatures**:
   - Asynchronous lifecycle event dispatches (e.g. `license.created`, `license.revoked`, `device.banned`) include cryptographically signed `X-Broker-Signature` headers (`sha256=<hex>`).
   - Receivers can verify signatures using constant-time evaluation (`VerifyPayloadSignature`).

6. **Remote Revocation & Device Blacklisting**:
   - The `Blacklist` tab in Google Sheets acts as an instant remote kill switch.
   - Banned machine hardware IDs (HWID) and revoked license keys are blocked immediately across local memory cache and remote queries.
   - All verification failures and administrative actions are logged in the `Audit_Logs` sheet for forensics.

7. **Google Apps Script Access Control**:
   - Always deploy your Google Apps Script Web App with execution set to `"Execute as: Me"` and access set to `"Who has access: Anyone"` if public client validation is required.
   - For administrative operations, configure an `ADMIN_TOKEN` secret in script properties.

8. **Password & Credential Security**:
   - Passwords are never stored in plaintext. They are salted with high-entropy unique salts and hashed using SHA-256 before being written to the `Users` tab.
   - Hash comparisons use constant-time comparison to prevent side-channel timing leaks.

9. **Secrets & Environment Variables**:
   - Never commit Google Sheet IDs, Apps Script deployment IDs, HMAC secrets, or GitHub tokens to public repositories.

10. **Encrypted Local Fallback Spool Queue**:
    - On-disk journal files (`spool.bin`) buffering events during network or upstream outages are encrypted using AES-256-GCM.
    - Spool entries cannot be inspected or altered on disk without knowledge of the cryptographic secret key.

11. **Dual-Sheet High Availability & Reconciliation Invariants**:
    - During active-standby dataset reconciliation, revocations strictly supersede active states. Once revoked, a license key or banned hardware ID cannot be re-activated through dataset merges.

12. **Dynamic Feature Flags & Usage Metering Isolation**:
    - Usage quotas are incremented using thread-safe atomic counters with strict upper bound and negative value rejection.
    - Feature check evaluation strictly enforces tier entitlements and custom overrides, preventing privilege escalation or entitlement spoofing.

13. **Cryptographic Hardware Attestation & Anti-Tamper Telemetry**:
    - TPM 2.0 PCR quote verification validates that hardware platform configuration registers match expected baseline measurements, signed by the endpoint's Attestation Key (AK).
    - Single-use challenge nonces expire after 5 minutes, preventing replay of valid hardware attestation statements.
    - Apple Secure Enclave and Windows Hello statements are verified against hardware public key fingerprints and monotonic counter monotonicity.
    - Anti-debugging and code section integrity telemetry reports are continuously analyzed; client instances triggering memory patch detection or active debugger attachment automatically result in immediate license revocation and hardware device blacklisting.

14. **Sliding-Window IP Reputation & Progressive Rate Limiting**:
    - Rate limits are enforced on a per-IP and per-HWID basis with separate conservative thresholds for sensitive operations (authentication, license verification, hardware attestation).
    - Rate limit violations trigger progressive backoff penalties with standard `X-RateLimit-*` and `Retry-After` headers.
    - Security infractions (replay attempts, HMAC signature mismatches, brute-force attempts) accrue violation points in a 15-minute sliding window; exceeding threshold values triggers automatic temporary bans and high-priority incident webhook alerts.

15. **Encrypted Audit Token Export for Enterprise SIEM Compliance**:
    - Compliance audit trails can be exported in an AES-256-GCM authenticated encrypted container with HMAC-SHA256 integrity validation.
    - Export bundles protect audit records from transit inspection or tampering during ingestion into enterprise SIEM pipelines (Splunk, Datadog, Elastic, AWS CloudWatch).

16. **Distributed Quorum Consensus & CRDT Revocation Invariants**:
    - Raft-like cluster communication mandates majority quorum confirmation across nodes before mutating cluster state or committing entries.
    - In CRDT LWW-Element-Sets, removals strictly take precedence over additions on equal timestamps (`removeTime >= addTime`). This mathematical invariant guarantees that a compromised or revoked license cannot be re-activated or un-revoked during concurrent network partitions or split-brain resolutions.
    - Anti-entropy state synchronizations exchange SHA-256 Merkle tree state digests to identify out-of-sync partitions without transmitting full datasets unless discrepancies are detected.

17. **Real-Time WebSocket Streaming & Sub-Second Remote Kill-Switch Invariants**:
    - RFC 6455 connections require standard HTTP upgrade handshake validation (`Sec-WebSocket-Key` / `Sec-WebSocket-Accept`).
    - Incoming client frames must be properly masked; unmasked client frames or payloads exceeding the 1MB buffer ceiling are rejected immediately to eliminate denial-of-service and memory exhaustion vectors.
    - Revocation and kill-switch directives (`EventRevocation` & `EventKillSwitch`) are pushed with sub-second latency across active connections indexed by license key, device HWID, or client ID.
    - Kill-switch payloads instruct connected applications to terminate execution or lock functionality immediately upon trigger.

18. **Zero-Knowledge Proof (ZKP) Anonymous Verification & Nullifier Privacy Invariants**:
    - **Pedersen Commitment Information-Theoretic Hiding**: Device hardware fingerprints (HWID) are converted to scalar representations and blinded using Pedersen commitments $C = vG + rH$ over NIST P-256 elliptic curves. Independent generator $H$ is computed deterministically via try-and-increment hash-to-curve without a known discrete logarithm relative to $G$, guaranteeing both information-theoretic privacy for client identifiers and computational binding against forgery.
    - **Sigma NIZK Proofs via Fiat-Shamir Transformation**: Client entitlement verification proves possession of a valid blinded credential and knowledge of underlying opening scalars $(v, r)$ without revealing the values to the broker or network observers. Challenge hashes are bound to credential identifiers, epoch numbers, and presentation statements.
    - **Spent Nullifier Replay Defense**: Proof evaluations require an HMAC-SHA256 derived nullifier $\eta$. The broker maintains a thread-safe nullifier registry that enforces single-use verification within the current validity epoch. Replay attacks submitting identical nullifiers are rejected in constant time, preventing entitlement replay while preserving cross-epoch unlinkability.
    - **ECDSA Issuer Signatures & Tier Integrity**: Issued anonymous credentials include an ECDSA P-256 signature calculated over the credential digest $(C, \text{tier}, \text{max\_seats}, \text{expires\_at})$. Proof verifications validate the signature against the broker's public key before accepting the zero-knowledge presentation proof, ensuring unforgeable entitlement assertions.

19. **Enterprise Single Sign-On (SSO) & SCIM 2.0 Directory Invariants**:
    - **Federation Assertion Validation**: Inbound SAML 2.0 assertions and OIDC claims are parsed and strictly validated against configured IdP certificates, expected audience identifiers (`urn:sheet-license-broker:sp`), and expiry timestamps. Expired assertions or invalid audiences are rejected immediately.
    - **RFC 7643 & RFC 7644 SCIM 2.0 Standards Compliance**: Directory synchronizations adhere to standard SCIM schemas (`urn:ietf:params:scim:schemas:core:2.0:User`). User attributes and emails are normalized, and unknown schemas or malformed JSON payloads return standard RFC 7644 error responses.
    - **Automated Revocation Invariant on Deprovisioning**: When a user is deprovisioned via SCIM (either through `DELETE /scim/v2/Users/{id}` or `active: false` update), their assigned license key is immediately revoked, local and remote caches are invalidated, and an instantaneous WebSocket kill-switch signal is dispatched to terminate active software sessions.
    - **Scoped RBAC & Constant-Time Ephemeral Token Introspection**: Session tokens minted via `/api/sso/token/mint` are HMAC-SHA256 authenticated. Verifications execute in constant time using `hmac.Equal` to eliminate timing side-channels, and actions are gated by the Role-Scope matrix to prevent privilege escalation.

20. **Post-Quantum Cryptography (PQC) & ML-DSA Signature Chains (NIST FIPS 204)**:
    - **Quantum-Resistant Module-Lattice Foundation**: Core digital signature schemes implement ML-DSA-44 and ML-DSA-65 over the quotient ring $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$ with $q=8380417$, providing long-term forward resistance against Shor's algorithm and cryptanalytically relevant quantum computers (CRQC).
    - **Hybrid Classical/Quantum Dual Signatures**: Hybrid signature envelopes (`Hybrid-P256-MLDSA65` and `Hybrid-HMAC-MLDSA44`) require simultaneous validity of both classical ECDSA P-256 (or HMAC-SHA256) and post-quantum lattice signatures over canonical SHA-256 payload digests, preventing security compromises even if one cryptographic primitive suffers future algebraic breakthroughs.
    - **Constant-Time Operations & Rejection-Sampling Bounds**: Polynomial operations, hint vector calculations, and signature verification evaluations maintain strict coefficient bounds ($||z||_\infty < \gamma_1 - \beta$, $||w - c s_2 + c t_0||_\infty < \gamma_2 - \beta$) and use `subtle.ConstantTimeCompare` where appropriate to mitigate timing and side-channel leakage.
    - **Zero-Downtime Key Rotation & Instant Revocation**: Key rollover supports configurable grace period validity windows (default 7 days) during which older keys remain verifiable for signed payloads, while compromised keys can be revoked instantly via emergency administrative endpoints, triggering immediate WebSocket kill-switch broadcasts to all connected clients.

21. **Behavioral Anomaly Detection & Adaptive Risk Scoring Governance**:
    - **Statistical Drift Analysis with Jitter Margins**: The heartbeat drift analyzer applies sliding-window online mean, variance, and Z-Score statistics over inter-arrival times. To prevent false-positive alarms on tightly clustered baselines ($\sigma \approx 0$), the engine enforces a &plusmn;15% network jitter margin ($|\Delta t - \mu| \le 0.15\mu$) before computing Z-Scores.
    - **Impossible Travel & Concurrent Subnet Detection**: Geographical velocity is computed using spherical Haversine formulas. Travel between consecutive observations exceeding 950 km/h or concurrent activity originating from multiple distinct /24 IPv4 CIDR subnets within a 1-hour window immediately flags an anomaly incident.
    - **Adaptive Risk Scoring & Nominal Decay**: Accumulated risk points progressively decay during sustained nominal activity, preventing permanent penalization of transient anomalies.
    - **Challenge Escalation & Zero-Trust Quarantine Invariants**:
      - Risk score $\ge 50$ (Suspicious): Enforces single-use 5-minute cryptographic re-attestation challenge tokens. Unchallenged or expired tokens block privilege escalation.
      - Risk score $\ge 85$ (High Risk / Compromised): Automatically triggers zero-trust quarantine isolation. The unified proxy layer strictly rejects `VerifyLicense` requests for quarantined entities with HTTP 403 Forbidden, and alerts are dispatched to security webhooks.
    - **SIEM Topology Graph Export (`siem-topology-v1`)**: Exports standardized topological nodes (`CLIENT`, `SUBNET`, `GEO_LOCATION`, `CHALLENGE`) and weighted relationship edges for ingestion into enterprise SIEM platforms (Splunk, Datadog, Elastic, Sentinel).

22. **Confidential Computing Enclave Attestation & Zero-Plaintext Tunnels**:
    - **Hardware-Rooted Trust**: Intel SGX Quote v3/v4 ECDSA P-256 signatures and AMD SEV-SNP 1184-byte cryptographically signed attestation reports are verified against expected MREnclave, MRSigner, and ISVSVN security version policies.
    - **Enclave Debug Mode Enforcement**: Enclave policies reject quotes running in Debug mode (such as AMD SEV-SNP policy bit 17 or SGX attributes flag) unless explicitly whitelisted in development testing profiles.
    - **Memory-Barrier Zeroization**: Sensitive cryptographic credentials, ephemeral private keys, and intermediate plaintexts are managed inside `SecureBuffer` wrappers with deterministic zeroing on disposal (`Destroy()`). Memory buffers are compared using constant-time equality checks (`subtle.ConstantTimeCompare`) to mitigate side-channel timing leaks.
    - **Ephemeral Forward Secrecy**: Tunnels negotiate single-use NIST P-256 elliptic curve keys combined via RFC 5869 HKDF Extract-and-Expand with SHA-256. All communications are sealed with authenticated AES-256-GCM encryption.
    - **Monotonic Replay Sequence Guards**: 64-bit strictly monotonic sequence counters reject duplicate or out-of-order encrypted payloads within each active tunnel session.

23. **Geo-Distributed Anycast Edge Routing & Partition Mitigation Security**:
    - **Signed Routing Tokens**: Anycast routing decisions generate HMAC-SHA256 tokens encoding selected POP, client IP, coordinates, and expiration timestamps. In-memory and edge verifiers validate tokens with constant-time comparison (`subtle.ConstantTimeCompare`) to prevent forged edge affinity claims.
    - **Sub-Millisecond L1 Cache Invariants**: Cached license entitlements enforce atomic thread-safe access with monotonic TTL clocks. Asynchronous Stale-While-Revalidate (SWR) background refreshes ensure clients never experience cache stampedes while ensuring evicted or revoked licenses are cleared within seconds.
    - **Partition Tolerance & Offline Emergency Leases**: During cloud network partitions or upstream outages, the partition mitigator issues cryptographically signed emergency lease tokens (`EmergencyLeaseToken`) with bounded validity, preventing client lockouts while recording all emergency events for automatic reconciliation when connectivity is restored.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it privately:

- **Security Contact**: Open a private advisory on GitHub or email the maintainer.
- **Response SLA**: Security issues will be reviewed and acknowledged within 48 hours.
- **Fix Policy**: Patches will be developed and released in a patch release prior to public disclosure.
