/**
 * Cloudflare Edge Gateway for Sheet-License-Broker
 * 
 * Provides sub-millisecond license verification at edge POPs,
 * Web Crypto API HMAC-SHA256 validation, Cloudflare KV caching,
 * nonce replay detection, and origin fallback.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Edge health check
    if (url.pathname === '/edge/health') {
      return new Response(JSON.stringify({
        status: 'healthy',
        service: 'sheet-license-broker-edge',
        timestamp: new Date().toISOString()
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'X-Broker-Edge': 'cloudflare-worker'
        }
      });
    }

    // 2. Intercept and accelerate license validation
    if (url.pathname === '/api/licenses/validate' && request.method === 'POST') {
      return handleEdgeLicenseValidation(request, env);
    }

    // 3. Forward all other routes to origin
    return forwardToOrigin(request, env);
  }
};

export async function verifyHMAC(secret, timestamp, nonce, bodyText, signatureHeader) {
  if (!secret) return true; // Bypass if secret is not configured
  if (!signatureHeader || !timestamp || !nonce) return false;

  // Window drift check: 5 minutes (300 seconds)
  const reqTime = Date.parse(timestamp);
  if (isNaN(reqTime) || Math.abs(Date.now() - reqTime) > 300 * 1000) {
    return false;
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const payload = `${timestamp}:${nonce}:${bodyText}`;
  const sigBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
  const hexSig = Array.from(new Uint8Array(sigBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return timingSafeEqual(hexSig.toLowerCase(), signatureHeader.trim().toLowerCase());
}

/**
 * Constant-time comparison between two strings to prevent timing side-channel attacks.
 */
export function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function handleEdgeLicenseValidation(request, env) {
  const bodyText = await request.text();
  const signature = request.headers.get('X-Broker-Signature');
  const timestamp = request.headers.get('X-Broker-Timestamp');
  const nonce = request.headers.get('X-Broker-Nonce');

  // Enforce HMAC signature check if configured
  const enforceHMAC = env.HMAC_ENFORCE === 'true' || env.HMAC_ENFORCE === '1';
  if (enforceHMAC || signature) {
    const validSig = await verifyHMAC(env.HMAC_SECRET, timestamp, nonce, bodyText, signature);
    if (!validSig) {
      return new Response(JSON.stringify({
        valid: false,
        error: 'Invalid or expired HMAC signature',
        source: 'edge_guard'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json', 'X-Broker-Edge': 'cloudflare-worker' }
      });
    }

    // Replay attack prevention via KV nonce cache
    if (env.LICENSE_KV && nonce) {
      const nonceKey = `nonce:${nonce}`;
      const seen = await env.LICENSE_KV.get(nonceKey);
      if (seen) {
        return new Response(JSON.stringify({
          valid: false,
          error: 'Replay attack detected: duplicate nonce',
          source: 'edge_guard'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', 'X-Broker-Edge': 'cloudflare-worker' }
        });
      }
      // Record nonce for 5 minutes (300 seconds)
      await env.LICENSE_KV.put(nonceKey, '1', { expirationTtl: 300 });
    }
  }

  let reqData;
  try {
    reqData = JSON.parse(bodyText);
  } catch (err) {
    return new Response(JSON.stringify({ error: 'Invalid JSON payload' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const licenseKey = (reqData.license_key || '').trim().toUpperCase();
  const hwid = (reqData.hwid || '').trim();

  // Edge KV Cache Evaluation
  if (env.LICENSE_KV && licenseKey) {
    const cacheKey = `license:${licenseKey}`;
    const cachedStr = await env.LICENSE_KV.get(cacheKey);

    if (cachedStr) {
      try {
        const cached = JSON.parse(cachedStr);

        // Check revocation
        if (cached.revoked || cached.status === 'revoked') {
          return new Response(JSON.stringify({
            valid: false,
            license_key: licenseKey,
            source: 'edge_kv_revoked',
            message: 'License key has been revoked'
          }), {
            status: 401,
            headers: {
              'Content-Type': 'application/json',
              'X-Broker-Cache': 'HIT',
              'X-Broker-Edge': 'cloudflare-worker'
            }
          });
        }

        // Check expiration
        if (cached.expires_at && new Date(cached.expires_at) < new Date()) {
          return new Response(JSON.stringify({
            valid: false,
            license_key: licenseKey,
            source: 'edge_kv_expired',
            message: 'License key has expired'
          }), {
            status: 401,
            headers: {
              'Content-Type': 'application/json',
              'X-Broker-Cache': 'HIT',
              'X-Broker-Edge': 'cloudflare-worker'
            }
          });
        }

        // Check HWID binding
        if (cached.hwid_bound && cached.hwid_bound !== '' && cached.hwid_bound !== hwid) {
          return new Response(JSON.stringify({
            valid: false,
            license_key: licenseKey,
            source: 'edge_kv_mismatch',
            message: 'Hardware ID mismatch'
          }), {
            status: 401,
            headers: {
              'Content-Type': 'application/json',
              'X-Broker-Cache': 'HIT',
              'X-Broker-Edge': 'cloudflare-worker'
            }
          });
        }

        // Cache HIT - Valid License
        return new Response(JSON.stringify({
          valid: true,
          license_key: licenseKey,
          hwid_bound: cached.hwid_bound || hwid,
          expires_at: cached.expires_at,
          source: 'edge_kv_cache',
          message: 'Verified instantly via Cloudflare Edge KV'
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'X-Broker-Cache': 'HIT',
            'X-Broker-Edge': 'cloudflare-worker'
          }
        });
      } catch (e) {
        // Fall through to origin on parse failure
      }
    }
  }

  // Cache MISS: Fallback to origin
  const originResponse = await forwardToOrigin(request, env, bodyText);

  // If origin returns a verified license, asynchronously populate Edge KV
  if (originResponse.status === 200 && env.LICENSE_KV && licenseKey) {
    try {
      const respClone = originResponse.clone();
      const resData = await respClone.json();
      if (resData.valid) {
        const ttl = parseInt(env.CACHE_TTL_SECONDS || '600', 10);
        await env.LICENSE_KV.put(`license:${licenseKey}`, JSON.stringify(resData), {
          expirationTtl: ttl > 60 ? ttl : 60
        });
      }
    } catch (e) {
      // Non-fatal cache population error
    }
  }

  const modifiedHeaders = new Headers(originResponse.headers);
  modifiedHeaders.set('X-Broker-Cache', 'MISS');
  modifiedHeaders.set('X-Broker-Edge', 'cloudflare-worker');

  return new Response(originResponse.body, {
    status: originResponse.status,
    statusText: originResponse.statusText,
    headers: modifiedHeaders
  });
}

async function forwardToOrigin(request, env, preloadedBody = null) {
  const originBase = (env.ORIGIN_URL || '').replace(/\/+$/, '');
  if (!originBase) {
    return new Response(JSON.stringify({
      error: 'ORIGIN_URL environment variable is not configured on Cloudflare Worker'
    }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', 'X-Broker-Edge': 'cloudflare-worker' }
    });
  }

  const url = new URL(request.url);
  const targetURL = `${originBase}${url.pathname}${url.search}`;

  const forwardHeaders = new Headers(request.headers);
  forwardHeaders.set('X-Forwarded-Host', url.host);

  const init = {
    method: request.method,
    headers: forwardHeaders
  };

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = preloadedBody !== null ? preloadedBody : await request.text();
  }

  try {
    return await fetch(targetURL, init);
  } catch (err) {
    return new Response(JSON.stringify({
      error: 'Origin gateway unreachable',
      details: err.message
    }), {
      status: 504,
      headers: { 'Content-Type': 'application/json', 'X-Broker-Edge': 'cloudflare-worker' }
    });
  }
}
