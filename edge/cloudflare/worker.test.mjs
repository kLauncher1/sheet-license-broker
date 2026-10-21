import test, { describe } from 'node:test';
import assert from 'node:assert/strict';
import worker, { verifyHMAC, timingSafeEqual } from './worker.js';

class MockKV {
  constructor() {
    this.store = new Map();
  }

  async get(key) {
    return this.store.get(key) || null;
  }

  async put(key, val, options) {
    this.store.set(key, val);
  }
}

async function computeSignature(secret, timestamp, nonce, body) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const payload = `${timestamp}:${nonce}:${body}`;
  const sigBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  return Array.from(new Uint8Array(sigBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('Cloudflare Edge Worker Gateway Tests', () => {
  test('returns health status on /edge/health', async () => {
    const req = new Request('https://edge.example.com/edge/health');
    const resp = await worker.fetch(req, {});
    assert.equal(resp.status, 200);
    const data = await resp.json();
    assert.equal(data.status, 'healthy');
    assert.equal(resp.headers.get('X-Broker-Edge'), 'cloudflare-worker');
  });

  test('validates HMAC signatures correctly and rejects tampered ones', async () => {
    const secret = 'test-edge-secret';
    const timestamp = new Date().toISOString();
    const nonce = 'nonce-12345';
    const body = JSON.stringify({ license_key: 'KEY-TEST-001', hwid: 'HWID-001' });

    const sig = await computeSignature(secret, timestamp, nonce, body);
    const valid = await verifyHMAC(secret, timestamp, nonce, body, sig);
    assert.equal(valid, true, 'valid signature should pass');

    const tampered = await verifyHMAC(secret, timestamp, nonce, body, 'bad-signature');
    assert.equal(tampered, false, 'tampered signature should fail');

    const expiredTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const expiredSig = await computeSignature(secret, expiredTimestamp, nonce, body);
    const timeDriftValid = await verifyHMAC(secret, expiredTimestamp, nonce, body, expiredSig);
    assert.equal(timeDriftValid, false, 'timestamp outside drift window should fail');

    // Test timingSafeEqual constant-time helper directly
    assert.equal(timingSafeEqual('abcdef', 'abcdef'), true);
    assert.equal(timingSafeEqual('abcdef', 'abcdeg'), false);
    assert.equal(timingSafeEqual('short', 'longer-string'), false);
    assert.equal(timingSafeEqual(123, '123'), false);
  });

  test('enforces HMAC and detects nonce replay attack', async () => {
    const kv = new MockKV();
    const env = {
      HMAC_SECRET: 'test-secret',
      HMAC_ENFORCE: 'true',
      LICENSE_KV: kv
    };

    const timestamp = new Date().toISOString();
    const nonce = 'replay-nonce-99';
    const body = JSON.stringify({ license_key: 'KEY-TEST-001', hwid: 'HWID-001' });
    const sig = await computeSignature(env.HMAC_SECRET, timestamp, nonce, body);

    // First request passes nonce check
    const req1 = new Request('https://edge.example.com/api/licenses/validate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Broker-Signature': sig,
        'X-Broker-Timestamp': timestamp,
        'X-Broker-Nonce': nonce
      },
      body
    });

    // Populate KV with active license to verify happy path
    await kv.put('license:KEY-TEST-001', JSON.stringify({
      valid: true,
      license_key: 'KEY-TEST-001',
      hwid_bound: 'HWID-001',
      expires_at: new Date(Date.now() + 86400000).toISOString()
    }));

    const resp1 = await worker.fetch(req1, env);
    assert.equal(resp1.status, 200);

    // Second request with same nonce must be rejected
    const req2 = new Request('https://edge.example.com/api/licenses/validate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Broker-Signature': sig,
        'X-Broker-Timestamp': timestamp,
        'X-Broker-Nonce': nonce
      },
      body
    });

    const resp2 = await worker.fetch(req2, env);
    assert.equal(resp2.status, 401);
    const errData = await resp2.json();
    assert.match(errData.error, /Replay attack/);
  });

  test('serves cache HIT directly from Edge KV', async () => {
    const kv = new MockKV();
    const env = { LICENSE_KV: kv };

    const activeLic = {
      valid: true,
      license_key: 'KEY-KV-HIT',
      hwid_bound: 'HWID-DEVICE-1',
      expires_at: new Date(Date.now() + 30 * 86400000).toISOString()
    };
    await kv.put('license:KEY-KV-HIT', JSON.stringify(activeLic));

    const req = new Request('https://edge.example.com/api/licenses/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'KEY-KV-HIT', hwid: 'HWID-DEVICE-1' })
    });

    const resp = await worker.fetch(req, env);
    assert.equal(resp.status, 200);
    assert.equal(resp.headers.get('X-Broker-Cache'), 'HIT');
    const data = await resp.json();
    assert.equal(data.valid, true);
    assert.equal(data.source, 'edge_kv_cache');
  });

  test('handles cache MISS by forwarding to origin and caching result', async () => {
    const kv = new MockKV();
    const env = {
      LICENSE_KV: kv,
      ORIGIN_URL: 'https://mock-origin.internal'
    };

    // Mock global fetch for origin call
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      if (url.toString().startsWith('https://mock-origin.internal/api/licenses/validate')) {
        return new Response(JSON.stringify({
          valid: true,
          license_key: 'KEY-ORIGIN-001',
          hwid_bound: 'HWID-001',
          expires_at: new Date(Date.now() + 86400000).toISOString(),
          source: 'remote_gas'
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      return originalFetch(url, init);
    };

    try {
      const req = new Request('https://edge.example.com/api/licenses/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ license_key: 'KEY-ORIGIN-001', hwid: 'HWID-001' })
      });

      const resp = await worker.fetch(req, env);
      assert.equal(resp.status, 200);
      assert.equal(resp.headers.get('X-Broker-Cache'), 'MISS');
      const data = await resp.json();
      assert.equal(data.valid, true);

      // Verify populated into KV
      const cached = await kv.get('license:KEY-ORIGIN-001');
      assert.ok(cached, 'license should be cached in KV after origin success');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('resolves nearest Anycast edge POP from coordinates or country header', async () => {
    // 1. Query with Tokyo coordinates
    const reqTokyo = new Request('https://edge.example.com/edge/anycast/route?lat=35.6762&lon=139.6503');
    const respTokyo = await worker.fetch(reqTokyo, {});
    assert.equal(respTokyo.status, 200);
    const dataTokyo = await respTokyo.json();
    assert.equal(dataTokyo.selected_pop.id, 'nrt');
    assert.equal(respTokyo.headers.get('X-Edge-POP'), 'nrt');

    // 2. Query with Germany country fallback
    const reqDE = new Request('https://edge.example.com/edge/anycast/route?country=DE');
    const respDE = await worker.fetch(reqDE, {});
    assert.equal(respDE.status, 200);
    const dataDE = await respDE.json();
    assert.equal(dataDE.selected_pop.id, 'fra');
    assert.equal(respDE.headers.get('X-Edge-POP'), 'fra');
  });

  test('verifies Ed25519 air-gap dongle token at edge and rejects tampered ones', async () => {
    // 1. Generate Ed25519 keypair using Web Crypto
    const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const rawPubKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const pubKeyHex = Array.from(new Uint8Array(rawPubKey)).map(b => b.toString(16).padStart(2, '0')).join('');

    const token = {
      token_id: 'DONGLE-EDGE-TEST-001',
      license_key: 'LIC-AIRGAP-EDGE-99',
      hwid: 'HWID-EDGE-AIRGAP',
      tier: 'defense-airgap',
      features: ['offline_radar', 'edge_mesh'],
      max_devices: 1,
      issued_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 86400 * 30,
      counter: 12,
      public_key: pubKeyHex
    };

    const canonicalMsg = `DONGLE-v1:${token.token_id}:${token.license_key}:${token.hwid}:${token.tier}:${token.features.join(',')}:${token.max_devices}:${token.issued_at}:${token.expires_at}:${token.counter}`;
    const sigBuffer = await crypto.subtle.sign('Ed25519', keyPair.privateKey, new TextEncoder().encode(canonicalMsg));
    token.signature = Array.from(new Uint8Array(sigBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

    // Happy path: valid token verification
    const reqValid = new Request('https://edge.example.com/edge/airgap/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, hwid: 'HWID-EDGE-AIRGAP' })
    });
    const respValid = await worker.fetch(reqValid, {});
    assert.equal(respValid.status, 200);
    const dataValid = await respValid.json();
    assert.equal(dataValid.valid, true);
    assert.equal(dataValid.edge_verified, true);
    assert.equal(dataValid.token.license_key, 'LIC-AIRGAP-EDGE-99');

    // Tampered signature rejection
    const tamperedToken = { ...token, signature: '00'.repeat(64) };
    const reqTampered = new Request('https://edge.example.com/edge/airgap/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: tamperedToken, hwid: 'HWID-EDGE-AIRGAP' })
    });
    const respTampered = await worker.fetch(reqTampered, {});
    assert.equal(respTampered.status, 401);
    const dataTampered = await respTampered.json();
    assert.equal(dataTampered.valid, false);

    // Mismatched HWID rejection
    const reqHwidMismatch = new Request('https://edge.example.com/edge/airgap/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, hwid: 'HWID-DIFFERENT' })
    });
    const respHwidMismatch = await worker.fetch(reqHwidMismatch, {});
    assert.equal(respHwidMismatch.status, 401);
    const dataHwidMismatch = await respHwidMismatch.json();
    assert.equal(dataHwidMismatch.valid, false);
  });

  test('reports Zero-Trust edge telemetry and forwards client cert fingerprint', async () => {
    const req = new Request('https://edge.example.com/edge/zerotrust/status', {
      headers: { 'cf-client-cert-sha256': 'aabbccddeeff112233445566' }
    });
    const resp = await worker.fetch(req, { MTLS_ENFORCED: 'true' });
    assert.equal(resp.status, 200);
    const data = await resp.json();
    assert.equal(data.edge_zerotrust_enabled, true);
    assert.equal(data.mtls_enforced, true);
    assert.equal(data.client_cert_present, true);
    assert.equal(data.client_cert_sha256, 'aabbccddeeff112233445566');
  });
});

