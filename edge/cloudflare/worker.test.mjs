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
});
