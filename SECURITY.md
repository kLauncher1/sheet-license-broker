# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
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

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it privately:

- **Security Contact**: Open a private advisory on GitHub or email the maintainer.
- **Response SLA**: Security issues will be reviewed and acknowledged within 48 hours.
- **Fix Policy**: Patches will be developed and released in a patch release prior to public disclosure.
