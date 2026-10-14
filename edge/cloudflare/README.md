# Cloudflare Edge Gateway

The Cloudflare Edge Gateway provides low-latency edge verification for `sheet-license-broker` using Cloudflare Workers and Cloudflare Workers KV.

## Architecture

```
[ Client Applications ]
          │
          ▼ HTTPS REST + HMAC-SHA256
[ Cloudflare Global Anycast Edge ]
  ├── Web Crypto API HMAC Verification
  ├── Workers KV Cache (Sub-millisecond HIT)
  └── Nonce Sliding Window Replay Defense
          │ (Cache MISS / Mutations)
          ▼
[ sheet-license-broker Origin Server ]
          │
          ▼
[ Google Sheets Database Backend ]
```

## Features

- **Sub-Millisecond Verification**: Cached active licenses resolve in under 10ms directly at the nearest Cloudflare POP.
- **Native Web Crypto API**: High-speed cryptographic HMAC-SHA256 signature verification directly at the edge before hitting the origin.
- **Workers KV Caching**: Stores verified license entitlements with automated TTL expiration.
- **Replay Protection**: Caches request nonces within a 5-minute sliding window.
- **Zero-Downtime Origin Fallback**: Seamlessly proxies mutations, invalidations, and uncached queries to the origin gateway.

## Configuration

Edit `wrangler.toml` or set environment variables in Cloudflare Dashboard:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `ORIGIN_URL` | Base HTTPS URL of your upstream `sheet-license-broker` instance | Required |
| `HMAC_SECRET` | Shared secret key for HMAC-SHA256 signature verification | Optional |
| `HMAC_ENFORCE` | Set to `true` or `1` to reject requests lacking valid signatures | `false` |
| `CACHE_TTL_SECONDS`| Edge KV cache lifetime for valid licenses | `600` (10 minutes) |

## Deployment

1. Install Wrangler CLI:
   ```bash
   npm install -g wrangler
   ```

2. Authenticate with your Cloudflare account:
   ```bash
   wrangler login
   ```

3. Create the KV namespace:
   ```bash
   wrangler kv:namespace create "LICENSE_KV"
   ```
   Copy the generated namespace ID into `wrangler.toml`.

4. Deploy the worker:
   ```bash
   wrangler deploy
   ```

## Local Testing

Run the edge gateway test suite:
```bash
node --test edge/cloudflare/worker.test.mjs
```
