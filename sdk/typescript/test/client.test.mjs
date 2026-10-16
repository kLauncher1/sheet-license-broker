import assert from 'node:assert';
import { createHash, createHmac } from 'node:crypto';
import http from 'node:http';
import { describe, it, before, after } from 'node:test';
import {
  getMachineHwid,
  SheetLicenseClient,
  AuthenticationError,
  LicenseValidationError,
  RateLimitError,
} from '../dist/index.js';

describe('Sheet License Broker TypeScript Client Tests', () => {
  let server;
  let baseUrl;
  const SECRET_KEY = 'test-secret-key-ts';

  before(async () => {
    server = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        const bodyStr = Buffer.concat(chunks).toString('utf8');
        const sig = req.headers['x-signature'];
        const ts = req.headers['x-timestamp'];
        const nonce = req.headers['x-nonce'];

        if (sig && ts && nonce) {
          const bHash = createHash('sha256').update(bodyStr).digest('hex');
          const canonical = `${req.method.toUpperCase()}\n${req.url}\n${ts}\n${nonce}\n${bHash}`;
          const expectedSig = createHmac('sha256', SECRET_KEY).update(canonical).digest('hex');
          if (sig !== expectedSig) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'invalid_signature', message: 'Signature mismatch' }));
            return;
          }
        }

        if (req.url === '/health' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'healthy', version: '0.8.0' }));
          return;
        }

        if (req.url === '/api/licenses/validate' && req.method === 'POST') {
          const payload = JSON.parse(bodyStr || '{}');
          if (payload.license_key === 'VALID-KEY-TS') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              valid: true,
              message: 'License active',
              source: 'memory',
              license: { key: payload.license_key, hwid: payload.hwid, status: 'active' },
              tenant_id: req.headers['x-tenant-id']
            }));
          } else {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ valid: false, error: 'License invalid or expired' }));
          }
          return;
        }

        if (req.url === '/api/features/check' && req.method === 'POST') {
          const payload = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            license_key: payload.license_key,
            feature: payload.feature,
            enabled: payload.feature === 'analytics',
            tier: 'pro'
          }));
          return;
        }

        if (req.url === '/api/usage/record' && req.method === 'POST') {
          const payload = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            record: {
              key: payload.license_key,
              metric: payload.metric,
              period: payload.period || '2026-10-14',
              count: payload.units || 1,
              limit: payload.limit || 0
            },
            exceeded: false
          }));
          return;
        }

        if (req.url?.startsWith('/api/usage/stats') && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            records: [
              { metric: 'api_calls', count: 120, limit: 1000 }
            ]
          }));
          return;
        }

        if (req.url === '/api/users/login' && req.method === 'POST') {
          const payload = JSON.parse(bodyStr || '{}');
          if (payload.username === 'admin' && payload.password === 'pass') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ authenticated: true, username: 'admin' }));
          } else {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Bad credentials' }));
          }
          return;
        }

        if (req.url === '/api/attestation/challenge' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            challenge_id: 'ts-ch-1234',
            nonce: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            expires_at: '2026-10-14T12:00:00Z'
          }));
          return;
        }

        if (req.url === '/api/attestation/verify' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            record: {
              license_key: 'VALID-KEY-TS',
              trust_level: 'attested_hardware',
              tamper_score: 0
            }
          }));
          return;
        }

        if (req.url === '/api/attestation/telemetry' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            tamper_score: 0,
            tampered: false,
            trust_level: 'software_grace'
          }));
          return;
        }

        if (req.url === '/api/security/audit/export' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            bundle: {
              bundle_id: 'bundle_ts_123',
              record_count: 8,
              ciphertext_hex: 'aabbccdd'
            }
          }));
          return;
        }

        if (req.url === '/api/test/ratelimit' && req.method === 'POST') {
          res.writeHead(429, {
            'Content-Type': 'application/json',
            'Retry-After': '30'
          });
          res.end(JSON.stringify({
            error: 'rate_limit_exceeded',
            retry_after: 30
          }));
          return;
        }

        if (req.url === '/api/consensus/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            node_id: 'ts-node-1',
            role: 'leader',
            current_term: 2,
            has_quorum: true
          }));
          return;
        }

        if (req.url === '/api/consensus/peers' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            peers: [{ id: 'peer-ts-2', active: true }]
          }));
          return;
        }

        if (req.url === '/api/stream/clients' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            count: 1,
            clients: [{ id: 'cl-ts-1', license_key: 'LIC-STREAM-TS', latency_ms: 12 }]
          }));
          return;
        }

        if (req.url === '/api/stream/kill' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            target: 'LIC-STREAM-TS',
            signaled_clients: 1,
            message: 'Kill switch dispatched to 1 client(s)'
          }));
          return;
        }

        if (req.url === '/api/stream/telemetry' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            telemetry: {
              active_connections: 1,
              unique_licenses: 1,
              unique_devices: 1,
              total_heartbeats: 15,
              total_revocations: 1,
              uptime_seconds: 3600
            }
          }));
          return;
        }

        if (req.url === '/api/zkp/params' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            curve: 'P-256',
            order_n: 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'
          }));
          return;
        }

        if (req.url === '/api/zkp/credential/issue' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            credential: {
              id: 'cred-ts-test-01',
              tier: 2,
              max_seats: 1,
              expires_at: 1800000000,
              scope: 'production',
              tenant_id: 'default'
            },
            blinding_factor: 'fedcba9876543210'
          }));
          return;
        }

        if (req.url === '/api/zkp/verify' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            valid: true,
            details: {
              valid: true,
              claimed_tier: 2,
              tier_name: 'pro',
              tenant_id: 'default',
              nullifier: 'null-ts-01'
            }
          }));
          return;
        }

        if (req.url === '/api/zkp/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            zkp: {
              total_credentials_issued: 3,
              total_proofs_verified: 5,
              spent_nullifiers_count: 2
            }
          }));
          return;
        }

        if (req.url === '/api/sso/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            total_idps: 2,
            active_directory_users: 12,
            deprovisioned_users: 1,
            allocated_license_seats: 12,
            supported_protocols: ['SAML 2.0', 'OIDC 1.0', 'SCIM 2.0']
          }));
          return;
        }

        if (req.url === '/api/sso/token/introspect' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            active: true,
            authorized: true,
            claims: {
              session_id: 'sess-ts-1',
              user_id: 'usr-ts-1',
              email: 'ts-user@corp.com',
              tenant_id: 'default',
              role: 'admin',
              scopes: ['license:read', 'license:write']
            }
          }));
          return;
        }

        if (req.url.startsWith('/scim/v2/Users') && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/scim+json' });
          res.end(JSON.stringify({
            schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            totalResults: 1,
            startIndex: 1,
            itemsPerPage: 1,
            Resources: [
              {
                schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
                id: 'scim-ts-1',
                userName: 'ts-user@corp.com',
                active: true
              }
            ]
          }));
          return;
        }

        if (req.url === '/api/pqc/params' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            default_algorithm: 'Hybrid-P256-MLDSA65',
            prime_modulus_q: 8380417,
            lattice_degree: 256
          }));
          return;
        }

        if (req.url === '/api/pqc/keys' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            count: 1,
            keys: [{ key_id: 'PQC-TS-01', algorithm: 'Hybrid-P256-MLDSA65', public_hex: 'ts-pub-hex-01' }]
          }));
          return;
        }

        if (req.url === '/api/pqc/sign' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            signature: {
              algorithm: 'Hybrid-P256-MLDSA65',
              key_id: 'PQC-TS-01',
              classical_sig: 'sig-classical-ts',
              quantum_sig: 'sig-quantum-ts',
              timestamp: '2026-10-16T10:00:00Z'
            }
          }));
          return;
        }

        if (req.url === '/api/pqc/verify' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            result: {
              valid: true,
              algorithm: 'Hybrid-P256-MLDSA65',
              key_id: 'PQC-TS-01',
              classical_valid: true,
              quantum_valid: true
            }
          }));
          return;
        }

        if (req.url === '/api/pqc/rotate' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            rotation: {
              new_key_id: 'PQC-TS-02',
              old_key_id: 'PQC-TS-01'
            }
          }));
          return;
        }

        if (req.url === '/api/pqc/revoke' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            key_id: 'PQC-TS-01'
          }));
          return;
        }

        if (req.url === '/api/pqc/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            pqc: {
              active_key_id: 'PQC-TS-02',
              default_algorithm: 'Hybrid-P256-MLDSA65',
              verified_signatures: 99
            }
          }));
          return;
        }

        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'not_found' }));
      });
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    await new Promise(resolve => server.close(resolve));
  });

  it('generates consistent and valid HWID string', () => {
    const hwid1 = getMachineHwid();
    const hwid2 = getMachineHwid();
    assert.ok(hwid1.startsWith('HWID-'), 'Should start with HWID- prefix');
    assert.strictEqual(hwid1.split('-').length, 5, 'Should have 5 dash-separated sections');
    assert.strictEqual(hwid1, hwid2, 'HWID must be deterministic on the same host');
  });

  it('queries health status successfully', async () => {
    const client = new SheetLicenseClient({ baseUrl });
    const health = await client.health();
    assert.strictEqual(health.status, 'healthy');
    assert.strictEqual(health.version, '0.8.0');
  });

  it('validates active license with HMAC request signing', async () => {
    const client = new SheetLicenseClient({ baseUrl, secretKey: SECRET_KEY });
    const res = await client.verifyLicense('VALID-KEY-TS');
    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.license?.key, 'VALID-KEY-TS');
  });

  it('rejects invalid license with LicenseValidationError', async () => {
    const client = new SheetLicenseClient({ baseUrl, secretKey: SECRET_KEY });
    await assert.rejects(
      async () => client.verifyLicense('INVALID-KEY-TS'),
      (err) => err instanceof LicenseValidationError
    );
  });

  it('rejects tampered secret key with AuthenticationError', async () => {
    const client = new SheetLicenseClient({ baseUrl, secretKey: 'wrong-secret' });
    await assert.rejects(
      async () => client.verifyLicense('VALID-KEY-TS'),
      (err) => err instanceof AuthenticationError
    );
  });

  it('authenticates user login credentials', async () => {
    const client = new SheetLicenseClient({ baseUrl });
    const res = await client.loginUser('admin', 'pass');
    assert.strictEqual(res.authenticated, true);
    assert.strictEqual(res.username, 'admin');
  });

  it('sends X-Tenant-ID header when tenantId option is configured', async () => {
    const client = new SheetLicenseClient({ baseUrl, tenantId: 'tenant-ts-99' });
    const res = await client.verifyLicense('VALID-KEY-TS');
    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.tenant_id, 'tenant-ts-99');
  });

  it('checks feature flags and tracks usage consumption', async () => {
    const client = new SheetLicenseClient({ baseUrl });
    const isAnalytics = await client.isFeatureEnabled('VALID-KEY-TS', 'analytics');
    assert.strictEqual(isAnalytics, true);

    const isSSO = await client.isFeatureEnabled('VALID-KEY-TS', 'sso');
    assert.strictEqual(isSSO, false);

    const usageRes = await client.recordUsage('VALID-KEY-TS', 'api_calls', 50, 500);
    assert.strictEqual(usageRes.status, 'success');
    assert.strictEqual(usageRes.exceeded, false);

    const records = await client.getUsage('VALID-KEY-TS');
    assert.strictEqual(records.length, 1);
    assert.strictEqual(records[0].metric, 'api_calls');
  });

  it('requests attestation challenge, verifies TPM quote, and reports telemetry', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    // 1. Challenge
    const ch = await client.requestAttestationChallenge('VALID-KEY-TS');
    assert.strictEqual(ch.status, 'success');
    assert.strictEqual(ch.challenge_id, 'ts-ch-1234');
    assert.strictEqual(ch.nonce.length, 64);

    // 2. TPM quote verify
    const verifyRes = await client.verifyTPMAttestation('VALID-KEY-TS', ch.challenge_id, { mock: true });
    assert.strictEqual(verifyRes.status, 'success');
    assert.strictEqual(verifyRes.record.trust_level, 'attested_hardware');

    // 3. Telemetry
    const telemRes = await client.reportTelemetry('VALID-KEY-TS', {
      debugger_present: false,
      memory_integrity: true,
    });
    assert.strictEqual(telemRes.status, 'success');
    assert.strictEqual(telemRes.tamper_score, 0);
    assert.strictEqual(telemRes.tampered, false);
    assert.strictEqual(telemRes.trust_level, 'software_grace');
  });

  it('exports encrypted audit token and handles RateLimitError on 429', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    // 1. Audit export
    const bundle = await client.exportAuditToken('secret-ts-key', 20);
    assert.strictEqual(bundle.bundle_id, 'bundle_ts_123');
    assert.strictEqual(bundle.record_count, 8);

    // 2. RateLimitError on 429
    await assert.rejects(
      async () => {
        await client.request('POST', '/api/test/ratelimit');
      },
      (err) => {
        assert.ok(err instanceof RateLimitError);
        assert.strictEqual(err.statusCode, 429);
        assert.strictEqual(err.retryAfter, 30);
        return true;
      }
    );
  });

  it('queries cluster consensus status and active peers', async () => {
    const client = new SheetLicenseClient({ baseUrl });
    const status = await client.getClusterStatus();
    assert.strictEqual(status.node_id, 'ts-node-1');
    assert.strictEqual(status.role, 'leader');
    assert.strictEqual(status.has_quorum, true);

    const peers = await client.getClusterPeers();
    assert.strictEqual(peers.length, 1);
    assert.strictEqual(peers[0].id, 'peer-ts-2');
  });

  it('queries stream clients, executes kill switch, and retrieves telemetry', async () => {
    const client = new SheetLicenseClient({ baseUrl });
    const clients = await client.getStreamClients();
    assert.strictEqual(clients.length, 1);
    assert.strictEqual(clients[0].id, 'cl-ts-1');
    assert.strictEqual(clients[0].license_key, 'LIC-STREAM-TS');

    const killRes = await client.sendKillSwitch('LIC-STREAM-TS', 'Violation detected', true);
    assert.strictEqual(killRes.status, 'success');
    assert.strictEqual(killRes.signaled_clients, 1);

    const telem = await client.getStreamTelemetry();
    assert.strictEqual(telem.active_connections, 1);
    assert.strictEqual(telem.total_heartbeats, 15);
  });

  it('queries zkp params, issues anonymous credential, verifies proof, and checks status', async () => {
    const client = new SheetLicenseClient({ baseUrl });
    const params = await client.getZKPParams();
    assert.strictEqual(params.curve, 'P-256');

    const issueRes = await client.issueAnonymousCredential({
      licenseKey: 'LIC-ZKP-TS-01',
      tier: 'pro',
      validDays: 30,
    });
    assert.strictEqual(issueRes.status, 'success');
    assert.strictEqual(issueRes.credential.id, 'cred-ts-test-01');
    assert.strictEqual(issueRes.blinding_factor, 'fedcba9876543210');

    const verifyRes = await client.verifyZKPProof({
      ax: '11',
      ay: '22',
      sv: '33',
      sr: '44',
      hwid_commitment: { x: '55', y: '66' },
      credential_id: 'cred-ts-test-01',
      claimed_tier: 2,
      max_seats: 1,
      expires_at: 1800000000,
      scope: 'production',
      tenant_id: 'default',
      nullifier: 'null-ts-01',
      epoch: 1234,
      challenge: '77',
    }, 'pro');
    assert.strictEqual(verifyRes.valid, true);
    assert.strictEqual(verifyRes.details.tier_name, 'pro');

    const status = await client.getZKPStatus();
    assert.strictEqual(status.total_credentials_issued, 3);
    assert.strictEqual(status.total_proofs_verified, 5);
  });

  it('queries sso status, introspects session token, and lists scim users', async () => {
    const client = new SheetLicenseClient({ baseUrl });
    const status = await client.getSSOStatus();
    assert.strictEqual(status.active_directory_users, 12);
    assert.strictEqual(status.total_idps, 2);

    const intro = await client.introspectSessionToken('sso.mock.token', 'license:read');
    assert.strictEqual(intro.active, true);
    assert.strictEqual(intro.authorized, true);
    assert.strictEqual(intro.claims.email, 'ts-user@corp.com');

    const scim = await client.listSCIMUsers(1, 10);
    assert.strictEqual(scim.totalResults, 1);
    assert.strictEqual(scim.Resources[0].userName, 'ts-user@corp.com');
  });

  it('queries pqc params, signs license, verifies signature, rotates key, and checks status', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    const params = await client.getPQCParams();
    assert.strictEqual(params.default_algorithm, 'Hybrid-P256-MLDSA65');
    assert.strictEqual(params.prime_modulus_q, 8380417);

    const keys = await client.getPQCPublicKeys();
    assert.strictEqual(keys.length, 1);
    assert.strictEqual(keys[0].key_id, 'PQC-TS-01');

    const sig = await client.signPQCLicense('LIC-TS-01', 'sample-pqc-payload', 'HWID-TS-01');
    assert.strictEqual(sig.algorithm, 'Hybrid-P256-MLDSA65');
    assert.strictEqual(sig.key_id, 'PQC-TS-01');

    const verify = await client.verifyPQCSignature('sample-pqc-payload', sig);
    assert.strictEqual(verify.valid, true);
    assert.strictEqual(verify.quantum_valid, true);

    const rot = await client.rotatePQCKey('Hybrid-HMAC-MLDSA44', 5, 'testing rotation');
    assert.strictEqual(rot.status, 'success');

    const revoke = await client.revokePQCKey('PQC-TS-01', 'testing revocation');
    assert.strictEqual(revoke.status, 'success');

    const status = await client.getPQCStatus();
    assert.strictEqual(status.active_key_id, 'PQC-TS-02');
    assert.strictEqual(status.verified_signatures, 99);
  });
});


