import { createHash, createHmac, randomBytes } from 'node:crypto';
import { getMachineHwid } from './hwid.js';
export { BrokerError, AuthenticationError, LicenseValidationError, RateLimitError } from './errors.js';
import { BrokerError, AuthenticationError, LicenseValidationError, RateLimitError } from './errors.js';
export class SheetLicenseClient {
    baseUrl;
    secretKey;
    tenantId;
    timeoutMs;
    constructor(options = {}) {
        this.baseUrl = (options.baseUrl || 'http://127.0.0.1:9082').replace(/\/+$/, '');
        this.secretKey = options.secretKey;
        this.tenantId = options.tenantId;
        this.timeoutMs = options.timeoutMs || 10000;
    }
    computeBodyHash(body) {
        return createHash('sha256').update(body, 'utf8').digest('hex');
    }
    buildCanonicalString(method, path, timestamp, nonce, body) {
        const bHash = this.computeBodyHash(body);
        return `${method.toUpperCase().trim()}\n${path.trim()}\n${timestamp}\n${nonce}\n${bHash}`;
    }
    sign(method, path, timestamp, nonce, body) {
        if (!this.secretKey)
            return '';
        const canonical = this.buildCanonicalString(method, path, timestamp, nonce, body);
        return createHmac('sha256', this.secretKey).update(canonical, 'utf8').digest('hex');
    }
    async request(method, path, payload) {
        const url = `${this.baseUrl}${path}`;
        const bodyStr = payload !== undefined ? JSON.stringify(payload) : '';
        const headers = {
            Accept: 'application/json',
            'User-Agent': 'SheetLicenseClient-TS/0.5.0',
        };
        if (this.tenantId) {
            headers['X-Tenant-ID'] = this.tenantId;
        }
        if (payload !== undefined) {
            headers['Content-Type'] = 'application/json';
        }
        if (this.secretKey) {
            const ts = Math.floor(Date.now() / 1000);
            const nonce = randomBytes(16).toString('hex');
            const sig = this.sign(method, path, ts, nonce, bodyStr);
            headers['X-Signature'] = sig;
            headers['X-Timestamp'] = String(ts);
            headers['X-Nonce'] = nonce;
        }
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const res = await fetch(url, {
                method,
                headers,
                body: method !== 'GET' && bodyStr ? bodyStr : undefined,
                signal: controller.signal,
            });
            const text = await res.text();
            let data = {};
            try {
                if (text)
                    data = JSON.parse(text);
            }
            catch { }
            if (!res.ok) {
                const errMsg = data.error || data.message || `HTTP ${res.status}`;
                if (res.status === 429) {
                    const retryHeader = res.headers.get('retry-after');
                    const retryVal = retryHeader ? parseInt(retryHeader, 10) : (Number(data.retry_after) || 0);
                    throw new RateLimitError(`Rate limit exceeded: ${errMsg}`, res.status, data, retryVal);
                }
                if (res.status === 401) {
                    if (String(errMsg).toLowerCase().includes('signature')) {
                        throw new AuthenticationError(`Security signature failed: ${errMsg}`, res.status, data);
                    }
                    throw new LicenseValidationError(`License authorization failed: ${errMsg}`, res.status, data);
                }
                throw new BrokerError(`Broker error (${res.status}): ${errMsg}`, res.status, data);
            }
            return data;
        }
        catch (err) {
            if (err instanceof BrokerError)
                throw err;
            if (err.name === 'AbortError') {
                throw new BrokerError(`Request timed out after ${this.timeoutMs}ms`);
            }
            throw new BrokerError(`Network failure contacting broker: ${err.message}`);
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    /**
     * Queries broker health status.
     */
    async health() {
        return this.request('GET', '/health');
    }
    /**
     * Performs an end-to-end ping check with the underlying Google Apps Script backend.
     */
    async ping() {
        return this.request('GET', '/api/proxy/ping');
    }
    /**
     * Validates a license key for the machine hardware ID.
     * If hwid is omitted, it is automatically resolved from the local system.
     */
    async verifyLicense(licenseKey, hwid) {
        const targetHwid = hwid || getMachineHwid();
        return this.request('POST', '/api/licenses/validate', {
            license_key: licenseKey.trim(),
            hwid: targetHwid,
        });
    }
    /**
     * Issues a new license key with the requested duration in days.
     */
    async createLicense(days = 30, maxDevices = 1) {
        return this.request('POST', '/api/licenses', {
            days,
            max_devices: maxDevices,
        });
    }
    /**
     * Instantly revokes an active license key.
     */
    async revokeLicense(licenseKey, reason = '') {
        return this.request('POST', '/api/licenses/revoke', {
            license_key: licenseKey.trim(),
            reason,
        });
    }
    /**
     * Adds a device HWID or license key to the blacklist.
     */
    async addBlacklist(type, target, reason = '') {
        return this.request('POST', '/api/security/blacklist', {
            type,
            target,
            reason,
        });
    }
    /**
     * Removes a device HWID or license key from the blacklist.
     */
    async removeBlacklist(type, target) {
        return this.request('POST', '/api/security/blacklist/remove', {
            type,
            target,
        });
    }
    /**
     * Registers a user account with salted password hashing.
     */
    async registerUser(username, password, role = 'user') {
        return this.request('POST', '/api/users/register', {
            username,
            password,
            role,
        });
    }
    /**
     * Authenticates user credentials.
     */
    async loginUser(username, password) {
        return this.request('POST', '/api/users/login', {
            username,
            password,
        });
    }
    /**
     * Writes a JSON document into the NoSQL KV store.
     */
    async putDoc(collection, id, payload) {
        return this.request('POST', '/api/docs', {
            action: 'put',
            collection,
            id,
            payload,
        });
    }
    /**
     * Retrieves a JSON document by ID from the NoSQL KV store.
     */
    async getDoc(collection, id) {
        return this.request('POST', '/api/docs', {
            action: 'get',
            collection,
            id,
        });
    }
    /**
     * Checks whether a feature entitlement is enabled for a license key.
     */
    async isFeatureEnabled(licenseKey, feature) {
        const res = await this.request('POST', '/api/features/check', {
            license_key: licenseKey.trim(),
            feature: feature.trim(),
        });
        return Boolean(res.enabled);
    }
    /**
     * Reports resource consumption units for a license key with quota check.
     */
    async recordUsage(licenseKey, metric, units = 1, limit = 0, period = '') {
        const payload = {
            license_key: licenseKey.trim(),
            metric: metric.trim(),
            units,
            limit,
        };
        if (period) {
            payload.period = period.trim();
        }
        return this.request('POST', '/api/usage/record', payload);
    }
    /**
     * Retrieves consumption records for all metered resources of a license key.
     */
    async getUsage(licenseKey) {
        const quoted = encodeURIComponent(licenseKey.trim());
        const res = await this.request('GET', `/api/usage/stats?license_key=${quoted}`);
        return res.records || [];
    }
    /**
     * Obtains a fresh single-use random nonce challenge for TPM/enclave binding.
     */
    async requestAttestationChallenge(licenseKey, hwid) {
        const targetHwid = hwid || getMachineHwid();
        return this.request('POST', '/api/attestation/challenge', {
            license_key: licenseKey.trim(),
            hwid: targetHwid.trim(),
        });
    }
    /**
     * Submits a signed TPM 2.0 PCR quote to attest hardware platform integrity.
     */
    async verifyTPMAttestation(licenseKey, challengeId, quoteData, hwid) {
        const targetHwid = hwid || getMachineHwid();
        return this.request('POST', '/api/attestation/verify', {
            license_key: licenseKey.trim(),
            hwid: targetHwid.trim(),
            challenge_id: challengeId.trim(),
            attestation_type: 'tpm2',
            tpm_quote: quoteData,
        });
    }
    /**
     * Transmits anti-debugging and memory integrity telemetry to broker.
     */
    async reportTelemetry(licenseKey, report, hwid) {
        const targetHwid = hwid || getMachineHwid();
        return this.request('POST', '/api/attestation/telemetry', {
            license_key: licenseKey.trim(),
            hwid: targetHwid.trim(),
            report,
        });
    }
    /**
     * Requests an encrypted audit bundle for enterprise compliance auditing pipelines.
     */
    async exportAuditToken(secretKey, limit = 500) {
        const payload = { limit };
        if (secretKey) {
            payload.secret_key = secretKey;
        }
        const res = await this.request('POST', '/api/security/audit/export', payload);
        return res.bundle;
    }
    /**
     * Queries the broker's distributed Raft role, quorum health, and cluster topology.
     */
    async getClusterStatus() {
        return this.request('GET', '/api/consensus/status');
    }
    /**
     * Retrieves active peer nodes in the consensus mesh.
     */
    async getClusterPeers() {
        const res = await this.request('GET', '/api/consensus/peers');
        return res.peers || [];
    }
    /**
     * Queries active WebSocket telemetry client sessions.
     */
    async getStreamClients() {
        const res = await this.request('GET', '/api/stream/clients');
        return res.clients || [];
    }
    /**
     * Dispatches an instantaneous remote kill-switch directive to targeted clients.
     */
    async sendKillSwitch(target, reason = 'Administrative remote termination directive', immediate = true) {
        return this.request('POST', '/api/stream/kill', {
            target,
            reason,
            immediate,
        });
    }
    /**
     * Queries aggregate streaming telemetry and active client metrics.
     */
    async getStreamTelemetry() {
        const res = await this.request('GET', '/api/stream/telemetry');
        return res.telemetry;
    }
    /**
     * Fetches the public elliptic curve parameters and issuer public key.
     */
    async getZKPParams() {
        return this.request('GET', '/api/zkp/params');
    }
    /**
     * Issues an issuer-signed anonymous credential for an authenticated license.
     */
    async issueAnonymousCredential(params) {
        const hwid = params.hwid || getMachineHwid();
        return this.request('POST', '/api/zkp/credential/issue', {
            license_key: params.licenseKey,
            hwid,
            hwid_commitment: params.hwidCommitment,
            tier: params.tier || 'pro',
            valid_days: params.validDays || 30,
            scope: params.scope || 'production',
            tenant_id: this.tenantId || 'default',
        });
    }
    /**
     * Submits a zero-knowledge presentation proof for privacy-preserving entitlement access.
     */
    async verifyZKPProof(proof, requiredTier = 'free', epoch) {
        return this.request('POST', '/api/zkp/verify', {
            proof,
            required_tier: requiredTier,
            epoch: epoch || Math.floor(Date.now() / 3600000),
        });
    }
    async getZKPStatus() {
        return (await this.request('GET', '/api/zkp/status')).zkp;
    }
    async getSSOStatus() {
        return this.request('GET', '/api/sso/status');
    }
    /**
     * Validates an ephemeral session token and checks permissions.
     */
    async introspectSessionToken(token, requiredScope) {
        return this.request('POST', '/api/sso/token/introspect', {
            token,
            required_scope: requiredScope,
        });
    }
    /**
     * Queries SCIM 2.0 directory users list with pagination.
     */
    async listSCIMUsers(startIndex = 1, count = 50) {
        return this.request('GET', `/scim/v2/Users?startIndex=${startIndex}&count=${count}`);
    }
    /**
     * Retrieves post-quantum cryptography parameters and active key info.
     */
    async getPQCParams() {
        return this.request('GET', '/api/pqc/params');
    }
    /**
     * Retrieves public keys for client-side lattice signature verification.
     */
    async getPQCPublicKeys() {
        const res = await this.request('GET', '/api/pqc/keys');
        return res.keys || [];
    }
    /**
     * Issues a quantum-resistant hybrid signature over a payload for an authenticated license.
     */
    async signPQCLicense(licenseKey, payload, hwid) {
        const machineHwid = hwid || (await getMachineHwid());
        const res = await this.request('POST', '/api/pqc/sign', {
            license_key: licenseKey,
            hwid: machineHwid,
            payload,
        });
        return res.signature;
    }
    /**
     * Verifies a dual classical and post-quantum lattice signature.
     */
    async verifyPQCSignature(payload, signature) {
        const res = await this.request('POST', '/api/pqc/verify', {
            payload,
            signature,
        });
        return res.result;
    }
    /**
     * Requests an administrative PQC key rotation with grace window.
     */
    async rotatePQCKey(algo, graceDays = 7, reason = 'Routine rotation') {
        return this.request('POST', '/api/pqc/rotate', {
            algorithm: algo,
            grace_days: graceDays,
            reason,
        });
    }
    /**
     * Revokes a compromised PQC key by ID.
     */
    async revokePQCKey(keyId, reason = 'Administrative revocation') {
        return this.request('POST', '/api/pqc/revoke', {
            key_id: keyId,
            reason,
        });
    }
    /**
     * Retrieves operational telemetry for the PQC engine.
     */
    async getPQCStatus() {
        const res = await this.request('GET', '/api/pqc/status');
        return res.pqc;
    }
    /**
     * Submits heartbeat or telemetry observation to behavioral anomaly detection engine.
     */
    async recordAnomalyObservation(observation) {
        const hwid = observation.hwid || (await getMachineHwid());
        const res = await this.request('POST', '/api/anomaly/record', {
            ...observation,
            hwid,
        });
        return res.risk_score;
    }
    /**
     * Retrieves current adaptive risk score and factors for an entity.
     */
    async getAnomalyRiskScore(licenseKey, hwid) {
        const machineHwid = hwid || (!licenseKey ? await getMachineHwid() : '');
        const query = new URLSearchParams();
        if (licenseKey)
            query.set('license_key', licenseKey);
        if (machineHwid)
            query.set('hwid', machineHwid);
        return this.request('GET', `/api/anomaly/score?${query.toString()}`);
    }
    /**
     * Requests an escalation challenge token for an entity.
     */
    async issueAnomalyChallenge(licenseKey, hwid) {
        const machineHwid = hwid || (await getMachineHwid());
        const res = await this.request('POST', '/api/anomaly/challenge/issue', {
            license_key: licenseKey,
            hwid: machineHwid,
        });
        return { token: res.challenge_token, riskScore: res.risk_score };
    }
    /**
     * Submits challenge response token to clear escalation penalties.
     */
    async verifyAnomalyChallenge(challengeToken) {
        const res = await this.request('POST', '/api/anomaly/challenge/verify', {
            challenge_token: challengeToken,
        });
        return { valid: res.valid, riskScore: res.risk_score };
    }
    /**
     * Exports real-time topological incident graph for enterprise SIEM ingestion.
     */
    async exportIncidentGraph(minScore, limit) {
        const query = new URLSearchParams();
        if (minScore !== undefined)
            query.set('min_score', minScore.toString());
        if (limit !== undefined)
            query.set('limit', limit.toString());
        return this.request('GET', `/api/anomaly/graph?${query.toString()}`);
    }
    /**
     * Queries behavioral anomaly operational telemetry metrics.
     */
    async getAnomalyStatus() {
        return this.request('GET', '/api/anomaly/status');
    }
    /**
     * Requests a single-use cryptographic challenge nonce for enclave attestation.
     */
    async requestEnclaveChallenge() {
        const res = await this.request('POST', '/api/enclave/challenge');
        return res.challenge;
    }
    /**
     * Attests an Intel SGX or AMD SEV-SNP attestation quote against security policies.
     */
    async attestEnclaveQuote(params) {
        const res = await this.request('POST', '/api/enclave/attest', {
            platform: params.platform,
            quote: params.quoteHex,
            nonce: params.nonce,
            policy_id: params.policyId,
        });
        return res.attestation;
    }
    /**
     * Performs an enclave ECDH handshake and establishes an end-to-end encrypted session tunnel.
     */
    async establishEnclaveTunnel(params) {
        return this.request('POST', '/api/enclave/tunnel/handshake', {
            platform: params.platform,
            quote: params.quoteHex,
            nonce: params.nonce,
            policy_id: params.policyId,
            client_public_key: params.clientPublicKey,
        });
    }
    /**
     * Evaluates an encrypted license query inside the zero-plaintext confidential computing enclave tunnel.
     */
    async evaluateEnclaveLicense(msg) {
        return this.request('POST', '/api/enclave/tunnel/evaluate', {
            session_id: msg.session_id,
            sequence: msg.sequence,
            nonce: msg.nonce,
            payload: msg.payload,
        });
    }
    /**
     * Queries confidential computing operational telemetry and active policies.
     */
    async getEnclaveStatus() {
        return this.request('GET', '/api/enclave/status');
    }
    /**
     * Submits an Intel TDX Quote v4 for cryptographic and policy verification.
     */
    async verifyTDXQuote(params) {
        const res = await this.request('POST', '/api/enclave/tdx/verify', {
            quote: params.quoteHex,
            nonce: params.nonce,
            policy_id: params.policyId,
        });
        return res.attestation;
    }
    /**
     * Requests an immutable signed attestation token binding hardware measurements and SVN.
     */
    async issueAttestationToken(params) {
        const res = await this.request('POST', '/api/enclave/token/issue', {
            platform: params.platform || 'intel_tdx',
            measurement: params.measurement,
            rtmr0: params.rtmr0,
            svn: params.svn,
            debug: params.debug ?? false,
            nonce: params.nonce,
            enclave_pub_key: params.enclavePubKey,
            ttl_seconds: params.ttlSeconds ?? 1800,
        });
        return res.token;
    }
    /**
     * Validates an attestation token against minimum SVN and debug posture requirements.
     */
    async verifyAttestationToken(params) {
        const res = await this.request('POST', '/api/enclave/token/verify', {
            token_id: params.tokenId,
            token: params.token,
            min_svn: params.minSVN,
            allow_debug: params.allowDebug ?? false,
        });
        return res.result;
    }
    /**
     * Requests hardware-isolated memory execution and sensitive license evaluation.
     */
    async executeIsolatedDecryption(params) {
        const res = await this.request('POST', '/api/enclave/isolated/decrypt', params);
        return res.result;
    }
    /**
     * Queries the nearest edge Anycast Point of Presence based on coordinates, country, or region.
     */
    async getAnycastRoute(options) {
        const params = new URLSearchParams();
        if (options?.lat !== undefined)
            params.set('lat', String(options.lat));
        if (options?.lon !== undefined)
            params.set('lon', String(options.lon));
        if (options?.country)
            params.set('country', options.country);
        if (options?.region)
            params.set('region', options.region);
        const query = params.toString() ? `?${params.toString()}` : '';
        return this.request('GET', `/api/anycast/route${query}`);
    }
    /**
     * Reports an edge latency and packet loss probe to the Anycast routing engine.
     */
    async reportAnycastProbe(probe) {
        return this.request('POST', '/api/anycast/probe', {
            target_pop_id: probe.targetPopId,
            rtt_latency_ms: probe.rttLatencyMs,
            source_region: probe.sourceRegion || 'global',
            source_ip: probe.sourceIp || '',
            packet_loss: probe.packetLoss || 0,
            jitter_ms: probe.jitterMs || 0,
        });
    }
    /**
     * Retrieves overall Anycast status including POP health, partition isolation, and cache metrics.
     */
    async getAnycastStatus() {
        return this.request('GET', '/api/anycast/status');
    }
    /**
     * Retrieves microsecond-level L1 edge cache performance telemetry.
     */
    async getEdgeCacheStats() {
        return this.request('GET', '/api/anycast/cache/stats');
    }
    /**
     * Executes a fast sub-millisecond license check against the edge L1 cache.
     */
    async fastVerifyLicense(licenseKey, hwid) {
        const machineHwid = hwid || (await getMachineHwid());
        return this.request('POST', '/api/anycast/verify', {
            license_key: licenseKey,
            hwid: machineHwid,
        });
    }
    /**
     * Retrieves diagnostic telemetry from the automated marketplace webhooks bridge.
     */
    async getMarketplaceStatus() {
        return this.request('GET', '/api/marketplace/status');
    }
    /**
     * Sends a synthetic purchase or cancellation webhook to test automated provisioning and revocation.
     */
    async simulateMarketplaceWebhook(req) {
        return this.request('POST', '/api/marketplace/simulate', req);
    }
    /**
     * Retrieves the transaction audit ledger of processed marketplace webhook events.
     */
    async listMarketplaceTransactions(filter) {
        let path = '/api/marketplace/transactions';
        if (filter) {
            const params = new URLSearchParams();
            if (filter.provider) params.set('provider', filter.provider);
            const email = filter.customer_email || filter.email;
            if (email) params.set('customer_email', email);
            if (filter.status) params.set('status', filter.status);
            if (filter.limit && filter.limit > 0) params.set('limit', String(filter.limit));
            const qs = params.toString();
            if (qs) path += `?${qs}`;
        }
        return this.request('GET', path);
    }
    /**
     * Retrieves operational telemetry for the air-gapped license vault.
     */
    async getAirgapStatus() {
        return this.request('GET', '/api/airgap/status');
    }
    /**
     * Issues a cryptographically signed offline dongle token.
     */
    async issueAirgapDongleToken(req) {
        const hwid = req.hwid || (await getMachineHwid());
        return this.request('POST', '/api/airgap/token/issue', {
            ...req,
            hwid,
        });
    }
    /**
     * Verifies an offline dongle token against the broker's master key and monotonic clock.
     */
    async verifyAirgapDongleToken(token, hwid, timestamp) {
        const machineHwid = hwid || (await getMachineHwid());
        return this.request('POST', '/api/airgap/token/verify', {
            token,
            hwid: machineHwid,
            timestamp: timestamp || Math.floor(Date.now() / 1000),
        });
    }
    /**
     * Submits an offline machine challenge and returns an activation response with QR payload.
     */
    async requestAirgapActivation(req) {
        const hwid = req.hwid || (await getMachineHwid());
        const res = await this.request('POST', '/api/airgap/activate/request', {
            ...req,
            hwid,
        });
        return res.activation;
    }
    /**
     * Consumes an air-gap QR payload and returns the fulfilled offline DongleToken.
     */
    async fulfillAirgapActivation(qrPayload) {
        const res = await this.request('POST', '/api/airgap/activate/fulfill', {
            qr_payload: qrPayload,
        });
        return res.token;
    }
    /**
     * Queries the monotonic clock and rollback tamper state for an HWID.
     */
    async getAirgapRollbackState(hwid) {
        const machineHwid = hwid || (await getMachineHwid());
        const res = await this.request('GET', `/api/airgap/rollback/state?hwid=${encodeURIComponent(machineHwid)}`);
        return res.state;
    }
    /**
     * Unlocks a tripped airgap vault using an administrative recovery token.
     */
    async unlockAirgapRollback(req) {
        const res = await this.request('POST', '/api/airgap/rollback/unlock', req);
        return res.state;
    }
    /**
     * Retrieves high-level operational status of the Zero-Trust mesh and internal CA.
     */
    async getZeroTrustStatus() {
        return this.request('GET', '/api/zerotrust/status');
    }
    /**
     * Lists all known enrolled Zero-Trust mesh peer nodes.
     */
    async listZeroTrustPeers() {
        const res = await this.request('GET', '/api/zerotrust/peers');
        return res.peers;
    }
    /**
     * Enrolls a new peer node and issues an mTLS certificate signed by the internal CA.
     */
    async enrollZeroTrustPeer(req) {
        const res = await this.request('POST', '/api/zerotrust/peers/enroll', req);
        return res.enrollment;
    }
    /**
     * Revokes a peer node certificate and marks its status as REVOKED in the internal CRL.
     */
    async revokeZeroTrustPeer(nodeId, reason) {
        return this.request('POST', '/api/zerotrust/peers/revoke', {
            node_id: nodeId,
            reason: reason || 'Administrative revocation',
        });
    }
    /**
     * Rotates the internal Root CA while maintaining dual-trust continuity.
     */
    async rotateZeroTrustCA(validityDays) {
        return this.request('POST', '/api/zerotrust/ca/rotate', {
            validity_days: validityDays || 365,
        });
    }
    /**
     * Queries hardware-backed key slot capabilities and operation counters.
     */
    async getZeroTrustHSMStatus() {
        return this.request('GET', '/api/zerotrust/hsm/status');
    }
    /**
     * Cryptographically verifies whether a given peer identity is actively authorized.
     */
    async verifyZeroTrustPeer(peer) {
        return this.request('POST', '/api/zerotrust/verify', peer);
    }
    async getHealingStatus() {
        return this.request('GET', '/api/healing/status');
    }
    async consumeHealingBucket(tokens = 1.0) {
        return this.request('POST', '/api/healing/bucket/consume', { tokens });
    }
    async issueHealingTicket(params) {
        return this.request('POST', '/api/healing/tunnel/ticket', {
            session_id: params.sessionId || '',
            client_id: params.clientId,
            hwid: params.hwid,
            tenant_id: params.tenantId || 'default',
            last_ack_seq: params.lastAckSeq || 0,
            ttl_seconds: params.ttlSeconds || 180,
        });
    }
    async resumeHealingTunnel(ticket) {
        return this.request('POST', '/api/healing/tunnel/resume', ticket);
    }
    async borrowHealingQuota(params) {
        return this.request('POST', '/api/healing/quota/borrow', {
            borrower_tenant: params.borrowerTenant,
            lender_tenant: params.lenderTenant,
            amount: params.amount,
            duration_minutes: params.durationMinutes || 15,
        });
    }
    async returnHealingQuota(leaseId) {
        return this.request('POST', '/api/healing/quota/return', {
            lease_id: leaseId,
        });
    }
    async recallHealingQuota(leaseId, reason) {
        return this.request('POST', '/api/healing/quota/recall', {
            lease_id: leaseId,
            reason: reason || 'Lender utilization surge',
        });
    }
    async rebalanceHealingQuotas() {
        return this.request('POST', '/api/healing/quota/rebalance', {});
    }
    async getHsmStatus() {
        return this.request('GET', '/api/hsm/status');
    }
    async listHsmSlots() {
        return this.request('GET', '/api/hsm/slots');
    }
    async hsmLogin(slotId, pin, userType = 'USER') {
        return this.request('POST', '/api/hsm/login', {
            slot_id: slotId,
            user_type: userType,
            pin,
        });
    }
    async hsmLogout(slotId = 0) {
        return this.request('POST', '/api/hsm/logout', { slot_id: slotId });
    }
    async deriveHsmKey(params) {
        return this.request('POST', '/api/hsm/derive', params);
    }
    async encryptHsmEnvelope(params) {
        return this.request('POST', '/api/hsm/encrypt', params);
    }
    async decryptHsmEnvelope(params) {
        return this.request('POST', '/api/hsm/decrypt', params);
    }
    async runHsmSelfTest() {
        return this.request('POST', '/api/hsm/fips/selftest', {});
    }
    async getHsmFipsReport() {
        return this.request('GET', '/api/hsm/fips/report');
    }
    async simulateHsmTamper(sensorId = 'DEFAULT_BREACH') {
        return this.request('POST', '/api/hsm/tamper/simulate', { sensor_id: sensorId });
    }
    async zeroizeHsm() {
        return this.request('POST', '/api/hsm/zeroize', {});
    }
    async getMLKEMStatus() {
        return this.request('GET', '/api/pqc/kem/status');
    }
    async listMLKEMKeys() {
        const res = await this.request('GET', '/api/pqc/kem/keys');
        return res.keys || [];
    }
    async generateMLKEMKey(algorithm = 'ML-KEM-768') {
        return this.request('POST', '/api/pqc/kem/keys/generate', { algorithm });
    }
    async encapsulateMLKEM(keyId) {
        return this.request('POST', '/api/pqc/kem/encapsulate', { key_id: keyId || '' });
    }
    async decapsulateMLKEM(keyId, ciphertextHex) {
        const res = await this.request('POST', '/api/pqc/kem/decapsulate', {
            key_id: keyId,
            ciphertext_hex: ciphertextHex,
        });
        return res.shared_secret_hex;
    }
    async hybridKEMHandshake(req) {
        return this.request('POST', '/api/pqc/kem/handshake', req);
    }
    async verifyHybridKEMSession(sessionId) {
        return this.request('GET', `/api/pqc/kem/sessions/verify?session_id=${encodeURIComponent(sessionId)}`);
    }
    async getTransparencyStatus() {
        return this.request('GET', '/api/transparency/status');
    }
    async appendTransparencyEntry(action, tenantId = 'default', payload = {}) {
        return this.request('POST', '/api/transparency/append', { action, tenant_id: tenantId, payload });
    }
    async getTransparencySTH() {
        return this.request('GET', '/api/transparency/sth');
    }
    async getTransparencyEntries(start = 0, count = 20) {
        return this.request('GET', `/api/transparency/entries?start=${start}&count=${count}`);
    }
    async getTransparencyInclusionProof(index, treeSize) {
        return this.request('GET', `/api/transparency/inclusion-proof?index=${index}&tree_size=${treeSize}`);
    }
    async verifyTransparencyInclusionProof(proof) {
        return this.request('POST', '/api/transparency/inclusion-proof/verify', proof);
    }
    async getTransparencyConsistencyProof(first, second) {
        return this.request('GET', `/api/transparency/consistency-proof?first=${first}&second=${second}`);
    }
    async verifyTransparencyConsistencyProof(proof) {
        return this.request('POST', '/api/transparency/consistency-proof/verify', proof);
    }
    async cosignTransparencySTH(witnessId) {
        return this.request('POST', '/api/transparency/witness/cosign', { witness_id: witnessId });
    }
    async listTransparencyWitnesses() {
        const res = await this.request('GET', '/api/transparency/witnesses');
        return res.witnesses || [];
    }
}
//# sourceMappingURL=client.js.map