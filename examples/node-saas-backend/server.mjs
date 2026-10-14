/**
 * Real-world Node.js SaaS backend API sample.
 * Demonstrates how a SaaS service protects its premium/enterprise endpoints
 * using @sheet-license/client with HMAC-SHA256 request signing and device HWID validation.
 */

import http from 'node:http';
import { SheetLicenseClient, LicenseValidationError } from '../../sdk/typescript/dist/index.js';

const BROKER_URL = process.env.BROKER_URL || 'http://127.0.0.1:9082';
const BROKER_SECRET = process.env.BROKER_SECRET || '';
const PORT = process.env.PORT || 4000;

const licenseClient = new SheetLicenseClient({
  baseUrl: BROKER_URL,
  secretKey: BROKER_SECRET,
  timeoutMs: 5000,
});

/**
 * Middleware validating license key provided in request headers.
 */
async function requireLicense(req, res, next) {
  const licenseKey = req.headers['x-license-key'];
  const hwid = req.headers['x-hwid']; // Optional client hardware identifier

  if (!licenseKey) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: 'license_required',
      message: 'Header X-License-Key is required to access premium SaaS APIs',
    }));
    return;
  }

  try {
    const result = await licenseClient.verifyLicense(licenseKey, hwid);
    if (!result.valid) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'license_invalid',
        message: result.message || 'License key is expired, revoked, or device-mismatched',
      }));
      return;
    }

    // Attach verified license entitlement to request context
    req.license = result.license;
    next();
  } catch (err) {
    if (err instanceof LicenseValidationError) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'license_denied', message: err.message }));
      return;
    }

    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'broker_unavailable', message: err.message }));
  }
}

const server = http.createServer((req, res) => {
  // Public Route
  if (req.url === '/api/public/ping' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'saas-backend-demo' }));
    return;
  }

  // Protected SaaS Premium Route
  if (req.url === '/api/premium/data-export' && req.method === 'POST') {
    requireLicense(req, res, () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'success',
        data: {
          export_id: 'exp_' + Date.now(),
          records: 1500,
          entitlement: req.license,
        },
      }));
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not_found' }));
});

if (process.env.NODE_ENV !== 'test') {
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`[+] SaaS Backend Demo running on http://127.0.0.1:${PORT}`);
    console.log(`[*] Protected Endpoint: POST /api/premium/data-export (Requires X-License-Key header)`);
    // Close immediately in CI dry-run test
    if (process.argv.includes('--dry-run')) {
      server.close();
    }
  });
}

export default server;
