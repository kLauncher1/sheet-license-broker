import assert from 'node:assert';
import { createHash, createHmac } from 'node:crypto';
import http from 'node:http';
import { describe, it, before, after } from 'node:test';
import {
  getMachineHwid,
  SheetLicenseClient,
  AuthenticationError,
  LicenseValidationError,
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
});
