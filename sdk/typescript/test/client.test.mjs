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

        if (req.url === '/api/anomaly/record' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'recorded',
            risk_score: {
              entity_id: 'LIC-TS-ANOMALY',
              score: 0,
              level: 'low',
              factors: [],
              challenge_escalation: false,
              quarantine_triggered: false,
              evaluated_at: new Date().toISOString()
            }
          }));
          return;
        }

        if (req.url.startsWith('/api/anomaly/score') && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            entity_id: 'LIC-TS-ANOMALY',
            score: 15,
            level: 'low',
            factors: [{ code: 'HEARTBEAT_DRIFT', description: 'Mild drift', severity: 15, detected_at: new Date().toISOString() }],
            challenge_escalation: false,
            quarantine_triggered: false,
            evaluated_at: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/anomaly/challenge/issue' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'challenge_issued',
            challenge_token: 'ts-token-999',
            risk_score: {
              entity_id: 'LIC-TS-ANOMALY',
              score: 55,
              level: 'high',
              challenge_escalation: true
            }
          }));
          return;
        }

        if (req.url === '/api/anomaly/challenge/verify' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'challenge_cleared',
            valid: true,
            risk_score: {
              entity_id: 'LIC-TS-ANOMALY',
              score: 10,
              level: 'low',
              challenge_escalation: false
            }
          }));
          return;
        }

        if (req.url.startsWith('/api/anomaly/graph') && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            format: 'siem-topology-v1',
            generated_at: new Date().toISOString(),
            total_nodes: 3,
            total_edges: 2,
            nodes: [
              { id: 'license:LIC-TS', type: 'license', label: 'LIC-TS', risk_score: 50 }
            ],
            edges: []
          }));
          return;
        }

        if (req.url === '/api/anomaly/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            total_observations: 50,
            active_monitored_entities: 10,
            anomalies_detected: 2,
            challenges_issued: 1,
            challenges_cleared: 1,
            active_quarantines: 0
          }));
          return;
        }

        if (req.url === '/api/enclave/challenge' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            challenge: '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
            expires_in: 300
          }));
          return;
        }

        if (req.url === '/api/enclave/attest' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            valid: true,
            attestation: {
              valid: true,
              platform: 'intel_sgx',
              mr_enclave: 'aabbccddeeff',
              mr_signer: '112233445566',
              svn: 2,
              debug: false,
              report_data_hex: '00112233',
              verified_at: new Date().toISOString()
            }
          }));
          return;
        }

        if (req.url === '/api/enclave/tunnel/handshake' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            established: true,
            session_id: 'enclave-sess-ts-001',
            broker_public_key: 'abcdef0123456789abcdef0123456789',
            expires_at: '2030-01-01T00:00:00Z'
          }));
          return;
        }

        if (req.url === '/api/enclave/tunnel/evaluate' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            session_id: 'enclave-sess-ts-001',
            sequence: 1,
            nonce: '0102030405060708090a0b0c',
            payload: 'deadbeefcafebabe'
          }));
          return;
        }

        if (req.url === '/api/enclave/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            telemetry: {
              verified_quotes: 12,
              active_tunnels: 3,
              total_evaluations: 25,
              failed_attestations: 1,
              quotes_by_platform: { intel_sgx: 10, amd_sev_snp: 2 },
              active_policies_count: 2
            },
            policies: []
          }));
          return;
        }

        if (req.url === '/api/enclave/tdx/verify' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            valid: true,
            attestation: {
              valid: true,
              platform: 'intel_tdx',
              measurement: 'mrtd_ts_hex_digest',
              rtmr0: 'rtmr0_ts_hex_digest',
              svn: 2,
              debug: false,
              report_data_hex: '00112233',
              verified_at: new Date().toISOString()
            }
          }));
          return;
        }

        if (req.url === '/api/enclave/token/issue' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            token: {
              token_id: 'tok_ts_test_123',
              platform: 'intel_tdx',
              measurement: 'mrtd_ts_hex_digest',
              rtmr0: 'rtmr0_ts_hex_digest',
              svn: 2,
              debug_allowed: false,
              challenge_nonce: 'nonce_ts_123',
              enclave_pub_key: '04pubkey',
              issued_at: new Date().toISOString(),
              expires_at: new Date(Date.now() + 1800000).toISOString(),
              signature: 'sig_ts_hex_123'
            }
          }));
          return;
        }

        if (req.url === '/api/enclave/token/verify' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            valid: true,
            result: {
              valid: true,
              platform: 'intel_tdx',
              svn: 2,
              measurement: 'mrtd_ts_hex_digest'
            }
          }));
          return;
        }

        if (req.url === '/api/enclave/isolated/decrypt' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            result: {
              success: true,
              license_key_masked: 'SLB-****-****-9999',
              tier: 'enterprise',
              features: ['hardware_enclave', 'post_quantum'],
              expires_at: '2028-01-01T00:00:00Z',
              platform: 'intel_tdx',
              svn: 2,
              hardware_isolated: true,
              memory_zeroized: true,
              execution_time_us: 42,
              evaluation_digest: 'digest_sha256_mock',
              evaluated_at: new Date().toISOString()
            }
          }));
          return;
        }

        if (req.url.startsWith('/api/anycast/route') && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            selected_pop: {
              id: 'iad',
              name: 'Ashburn IAD',
              region: 'us-east',
              country: 'US',
              status: 'healthy'
            },
            estimated_latency_ms: 8.5,
            signed_routing_token: 'ts-signed-token-123',
            timestamp: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/anycast/probe' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'recorded' }));
          return;
        }

        if (req.url === '/api/anycast/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            pop_count: 6,
            edge_routing_enabled: true,
            is_partitioned: false,
            pops: [],
            cache_stats: { hits: 10, misses: 1, revalidations: 0, lookup_latency_us: 120, cached_tier_entries: 5, hit_ratio: 0.909 },
            partition_states: []
          }));
          return;
        }

        if (req.url === '/api/anycast/cache/stats' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            hits: 10,
            misses: 1,
            revalidations: 0,
            lookup_latency_us: 120,
            cached_tier_entries: 5,
            hit_ratio: 0.909
          }));
          return;
        }

        if (req.url === '/api/anycast/verify' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            valid: true,
            license_key: 'LIC-ANYCAST-TS',
            hwid_bound: 'HWID-TS-01',
            tier: 'enterprise',
            message: 'Fast verify L1 cache hit'
          }));
          return;
        }

        if (req.url === '/api/marketplace/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            enabled: true,
            supported_providers: ['stripe', 'lemonsqueezy', 'paddle'],
            total_processed_events: 5,
            total_provisioned: 3,
            total_revoked: 1,
            total_duplicates: 1,
            total_failed: 0,
            recent_transactions: 3,
            stripe_configured: true,
            lemon_squeezy_configured: true,
            paddle_configured: true,
            timestamp: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/marketplace/simulate' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            event: { provider: 'stripe', action: 'provision' },
            transaction: {
              id: 'tx_ts_123',
              event_id: 'sim_ts_1',
              provider: 'stripe',
              action: 'provision',
              customer_email: 'ts_buyer@example.com',
              license_key: 'KEY-TS-MKT-01',
              tier: 'enterprise',
              seats: 4,
              status: 'PROVISIONED',
              processed_at: new Date().toISOString()
            }
          }));
          return;
        }

        if (req.url === '/api/marketplace/transactions' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify([
            {
              id: 'tx_ts_123',
              event_id: 'sim_ts_1',
              provider: 'stripe',
              action: 'provision',
              customer_email: 'ts_buyer@example.com',
              license_key: 'KEY-TS-MKT-01',
              tier: 'enterprise',
              seats: 4,
              status: 'PROVISIONED',
              processed_at: new Date().toISOString()
            }
          ]));
          return;
        }

        if (req.url === '/api/airgap/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            vault_active: true,
            master_public_key: 'pub_key_mock_hex',
            admin_public_key: 'admin_key_mock_hex',
            total_issued_tokens: 10,
            total_verified_tokens: 25,
            total_activations: 5,
            rollback_tripped_count: 0,
            last_high_water_mark: Math.floor(Date.now() / 1000),
            tracked_vaults: 3,
            timestamp: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/airgap/token/issue' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            token: {
              token_id: 'DONGLE-TS-001',
              license_key: body.license_key,
              hwid: body.hwid || 'HWID-TS-DEFAULT',
              tier: body.tier || 'enterprise',
              max_devices: 1,
              issued_at: Math.floor(Date.now() / 1000),
              expires_at: Math.floor(Date.now() / 1000) + 86400 * 30,
              counter: 7,
              signature: 'sig_ts_mock_hex'
            },
            dongle_token: 'compact_ts_token_base64',
            qr_payload: 'AIRGAP:B45:12345678:QRTSPAYLOAD'
          }));
          return;
        }

        if (req.url === '/api/airgap/token/verify' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            valid: true,
            token: {
              token_id: 'DONGLE-TS-001',
              license_key: 'LIC-AIRGAP-TS-1',
              hwid: body.hwid || 'HWID-TS-DEFAULT',
              tier: 'enterprise',
              max_devices: 1,
              issued_at: Math.floor(Date.now() / 1000),
              expires_at: Math.floor(Date.now() / 1000) + 86400 * 30,
              counter: 8,
              signature: 'sig_ts_mock_hex'
            }
          }));
          return;
        }

        if (req.url === '/api/airgap/activate/request' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            activation: {
              request_id: 'ACT-TS-001',
              license_key: body.license_key,
              hwid: body.hwid,
              dongle_token: 'compact_act_token_base64',
              qr_payload: 'AIRGAP:B45:AABBCCDD:ACTQRPAYLOAD',
              valid_until: Math.floor(Date.now() / 1000) + 86400 * 90,
              counter: 1,
              status: 'ACTIVATED',
              signature: 'act_sig_hex'
            }
          }));
          return;
        }

        if (req.url === '/api/airgap/activate/fulfill' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            token: {
              token_id: 'DONGLE-FULFILLED-TS',
              license_key: 'LIC-AIRGAP-TS-ACT',
              hwid: 'HWID-TS-DEFAULT',
              tier: 'enterprise-airgap',
              max_devices: 1,
              issued_at: Math.floor(Date.now() / 1000),
              expires_at: Math.floor(Date.now() / 1000) + 86400 * 90,
              counter: 1,
              signature: 'act_sig_hex'
            }
          }));
          return;
        }

        if (req.url.startsWith('/api/airgap/rollback/state') && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            state: {
              vault_id: 'VAULT-HWID-TS-01',
              hwid: 'HWID-TS-01',
              high_water_mark: Math.floor(Date.now() / 1000),
              monotonic_counter: 99,
              tampered: false
            }
          }));
          return;
        }

        if (req.url === '/api/airgap/rollback/unlock' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            state: {
              vault_id: 'VAULT-HWID-TS-01',
              hwid: 'HWID-TS-01',
              high_water_mark: Math.floor(Date.now() / 1000),
              monotonic_counter: 100,
              tampered: false,
              unlocked_at: Math.floor(Date.now() / 1000)
            }
          }));
          return;
        }

        if (req.url === '/api/zerotrust/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            ca_initialized: true,
            ca_root_fingerprint: 'zt_ca_fingerprint_hex',
            ca_expires_at: new Date(Date.now() + 86400000 * 365).toISOString(),
            active_peers_count: 3,
            revoked_peers_count: 0,
            mtls_enforced: true,
            hsm_enabled: true,
            hsm_slots_count: 3,
            timestamp: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/zerotrust/peers' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            peers: [
              {
                node_id: 'peer-ts-01',
                role: 'cluster_peer',
                common_name: 'peer-ts-01',
                serial_number: 'serial_01_hex',
                fingerprint_sha256: 'fp_01_hex',
                expires_at: new Date(Date.now() + 86400000 * 90).toISOString(),
                status: 'ACTIVE'
              }
            ]
          }));
          return;
        }

        if (req.url === '/api/zerotrust/peers/enroll' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            enrollment: {
              node_id: body.node_id,
              role: body.role || 'cluster_peer',
              certificate_pem: '-----BEGIN CERTIFICATE-----\nTS_CERT\n-----END CERTIFICATE-----',
              private_key_pem: '-----BEGIN EC PRIVATE KEY-----\nTS_KEY\n-----END EC PRIVATE KEY-----',
              root_ca_pem: '-----BEGIN CERTIFICATE-----\nTS_ROOT\n-----END CERTIFICATE-----',
              serial_number: 'serial_enrolled_hex',
              fingerprint_sha256: 'fp_enrolled_hex',
              expires_at: new Date(Date.now() + 86400000 * 90).toISOString()
            }
          }));
          return;
        }

        if (req.url === '/api/zerotrust/peers/revoke' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            node_id: body.node_id,
            revoked: true,
            reason: body.reason || 'Revocation test'
          }));
          return;
        }

        if (req.url === '/api/zerotrust/ca/rotate' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            message: 'Internal CA successfully rotated',
            root_fingerprint: 'rotated_ca_fp_hex',
            ca_expires_at: new Date(Date.now() + 86400000 * 365).toISOString()
          }));
          return;
        }

        if (req.url === '/api/zerotrust/hsm/status' && (req.method === 'GET' || req.method === 'POST')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            hsm_enabled: true,
            slots_count: 3,
            slots: [
              {
                slot_id: 0,
                label: 'Root CA Master Key Slot',
                algorithm: 'ECDSA_P256_SHA256',
                key_present: true,
                public_key_pem: 'pub_key_0',
                operations_count: 5,
                zeroized: false
              }
            ]
          }));
          return;
        }

        if (req.url === '/api/zerotrust/verify' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            valid: true,
            reason: 'valid',
            node_id: body.node_id
          }));
          return;
        }

        if (req.url === '/api/healing/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            bucket: {
              current_tokens: 95.0,
              capacity: 100.0,
              base_capacity: 100.0,
              refill_rate: 20.0,
              load_score: 1.0,
              scale_multiplier: 1.0,
              mode: 'normal',
              last_refill: new Date().toISOString()
            },
            active_tunnels: 2,
            suspended_tunnels: 0,
            total_missed_events: 1,
            quota_pools: [
              {
                tenant_id: 'tenant-ts-alpha',
                total_quota: 5000,
                used_quota: 1000,
                borrowed_in: 0,
                lent_out: 0,
                available_quota: 4000,
                utilization: 0.2
              }
            ],
            active_leases: [],
            recent_rebalances: []
          }));
          return;
        }

        if (req.url === '/api/healing/bucket/consume' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            allowed: true,
            stats: {
              current_tokens: 94.0,
              capacity: 100.0,
              base_capacity: 100.0,
              refill_rate: 20.0,
              load_score: 1.0,
              scale_multiplier: 1.0,
              mode: 'normal',
              last_refill: new Date().toISOString()
            }
          }));
          return;
        }

        if (req.url === '/api/healing/tunnel/ticket' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            session_id: body.session_id || 'sess-ts-heal',
            client_id: body.client_id,
            hwid: body.hwid,
            tenant_id: body.tenant_id || 'default',
            issued_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 180000).toISOString(),
            last_ack_seq: body.last_ack_seq || 0,
            signature: 'heal_sig_ts_hex'
          }));
          return;
        }

        if (req.url === '/api/healing/tunnel/resume' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'resumed',
            session: {
              session_id: body.session_id,
              client_id: body.client_id,
              hwid: body.hwid,
              tenant_id: body.tenant_id,
              state: 'resumed',
              connected_at: new Date().toISOString(),
              last_heartbeat: new Date().toISOString(),
              missed_events_count: 1
            },
            missed_events: [
              {
                sequence: 1,
                tenant_id: body.tenant_id,
                client_id: body.client_id,
                event_type: 'license_refresh',
                payload: '{"status":"active"}',
                timestamp: new Date().toISOString()
              }
            ],
            missed_count: 1
          }));
          return;
        }

        if (req.url === '/api/healing/quota/borrow' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'success',
            lease: {
              lease_id: 'lease-ts-01',
              borrower_tenant: body.borrower_tenant,
              lender_tenant: body.lender_tenant,
              amount: body.amount,
              borrowed_at: new Date().toISOString(),
              expires_at: new Date(Date.now() + 900000).toISOString(),
              status: 'active'
            }
          }));
          return;
        }

        if (req.url === '/api/healing/quota/return' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'returned',
            lease_id: body.lease_id
          }));
          return;
        }

        if (req.url === '/api/healing/quota/rebalance' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            status: 'rebalanced',
            events: []
          }));
          return;
        }

        if (req.url === '/api/hsm/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            initialized: true,
            hardware_available: true,
            fips_level: 'FIPS_140_3_LEVEL_4',
            slots_total: 3,
            active_sessions: 1,
            tamper_detected: false,
            locked_out: false,
            master_key_present: true,
            operations_count: 42,
            last_self_test: new Date().toISOString(),
            uptime_seconds: 1200
          }));
          return;
        }

        if (req.url === '/api/hsm/slots' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            slots: [
              {
                slot_id: 0,
                description: 'Hardware HSM Cryptoki Slot 0',
                manufacturer_id: 'CloudHSM Cryptoki Enterprise Inc.',
                hardware_version: '4.2.0',
                firmware_version: '4.2.0-FIPS',
                mechanisms: ['CKM_AES_GCM', 'CKM_HKDF_DERIVE'],
                token_present: true,
                removable: false,
                hardware_slot: true
              }
            ]
          }));
          return;
        }

        if (req.url === '/api/hsm/login' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            authenticated: true,
            slot_id: body.slot_id,
            user_type: body.user_type || 'USER'
          }));
          return;
        }

        if (req.url === '/api/hsm/logout' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            logged_out: true,
            slot_id: body.slot_id || 0
          }));
          return;
        }

        if (req.url === '/api/hsm/derive' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            slot_id: body.slot_id || 0,
            purpose: body.purpose,
            derived_key_handle: 123456789,
            fingerprint: 'HSM-KEY-TS-FPR-01',
            key_length_bits: 256,
            algorithm: 'AES_256_GCM_HKDF_SHA256',
            derived_at: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/hsm/encrypt' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            slot_id: body.slot_id,
            ciphertext_hex: 'a1b2c3d4e5f6',
            nonce_hex: '00112233445566778899aabb',
            key_fingerprint: 'HSM-KEY-TS-FPR-01',
            algorithm: 'AES_256_GCM_FIPS_140_3',
            encrypted_at: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/hsm/decrypt' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            slot_id: 1,
            plaintext: 'CONFIDENTIAL-TS-ENVELOPE',
            authenticated: true,
            decrypted_at: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/hsm/fips/selftest' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            self_tests: [
              { test_name: 'KAT-SHA-256', passed: true, execution_time_us: 15, algorithm_tested: 'SHA-256', details: 'Passed' },
              { test_name: 'KAT-AES-256-GCM', passed: true, execution_time_us: 25, algorithm_tested: 'AES-256-GCM', details: 'Passed' }
            ],
            count: 2
          }));
          return;
        }

        if (req.url === '/api/hsm/fips/report' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            certification_level: 'FIPS_140_3_LEVEL_4',
            hardware_model: 'FIPS-140-3-L4-VAULT',
            serial_number: 'HSM4-ROOT-9842',
            firmware_revision: '4.2.0-FIPS',
            tamper_state: 'SECURE_NORMAL',
            active_slots: 3,
            kat_passed: true,
            self_tests: [],
            zeroize_on_tamper: true,
            generated_at: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/hsm/tamper/simulate' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            tamper_latched: true,
            sensor_id: body.sensor_id,
            zeroized: true
          }));
          return;
        }

        if (req.url === '/api/hsm/zeroize' && req.method === 'POST') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            zeroized: true
          }));
          return;
        }

        if (req.url === '/api/pqc/kem/status' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            initialized: true,
            active_keys_count: 2,
            default_algorithm: 'ML-KEM-768',
            active_sessions_count: 1,
            quantum_enforced: false,
            total_encapsulations: 10,
            total_decapsulations: 10,
            total_handshakes: 5,
            fallback_attempts: 1,
            fallback_rejected: 0,
            uptime_seconds: 120
          }));
          return;
        }

        if (req.url === '/api/pqc/kem/keys' && req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            keys: [
              {
                key_id: 'mlkem-768-mock-01',
                algorithm: 'ML-KEM-768',
                fingerprint: 'fp-mock-768-01',
                raw_hex: '0102030405',
                created_at: new Date().toISOString()
              }
            ]
          }));
          return;
        }

        if (req.url === '/api/pqc/kem/keys/generate' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            key_id: 'mlkem-1024-mock-02',
            algorithm: body.algorithm || 'ML-KEM-1024',
            fingerprint: 'fp-mock-1024-02',
            raw_hex: '0908070605',
            created_at: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/pqc/kem/encapsulate' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            key_id: body.key_id || 'mlkem-768-mock-01',
            algorithm: 'ML-KEM-768',
            ciphertext_hex: 'c0ffeec0ffee',
            shared_secret_hex: 'feedfacefeedfacefeedfacefeedface',
            encapsulated_at: new Date().toISOString()
          }));
          return;
        }

        if (req.url === '/api/pqc/kem/decapsulate' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            key_id: body.key_id,
            shared_secret_hex: 'feedfacefeedfacefeedfacefeedface'
          }));
          return;
        }

        if (req.url === '/api/pqc/kem/handshake' && req.method === 'POST') {
          const body = JSON.parse(bodyStr || '{}');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            session_id: 'sess-pqc-mock-777',
            server_ecdh_pub_hex: '04aabbccddeeff00112233445566778899',
            ciphertext_hex: 'c0ffeec0ffee',
            auth_tag_hex: 'aabbcc112233',
            agreed_mode: body.requested_mode || 'hybrid',
            algorithm: body.algorithm || 'ML-KEM-768',
            quantum_resistant: true,
            expires_at: new Date(Date.now() + 900000).toISOString()
          }));
          return;
        }

        if (req.url.startsWith('/api/pqc/kem/sessions/verify') && req.method === 'GET') {
          const urlObj = new URL(req.url, 'http://127.0.0.1');
          const sid = urlObj.searchParams.get('session_id');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            valid: true,
            session_id: sid || 'sess-pqc-mock-777',
            agreed_mode: 'hybrid',
            algorithm: 'ML-KEM-768',
            quantum_resistant: true,
            created_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 900000).toISOString()
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

  it('records anomaly observation, queries risk score, verifies challenge, and exports incident graph', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    const obs = await client.recordAnomalyObservation({
      license_key: 'LIC-TS-ANOMALY',
      ip: '198.51.100.5',
      action: 'heartbeat',
    });
    assert.strictEqual(obs.entity_id, 'LIC-TS-ANOMALY');
    assert.strictEqual(obs.score, 0);

    const score = await client.getAnomalyRiskScore('LIC-TS-ANOMALY');
    assert.strictEqual(score.score, 15);
    assert.strictEqual(score.factors.length, 1);

    const challenge = await client.issueAnomalyChallenge('LIC-TS-ANOMALY');
    assert.strictEqual(challenge.token, 'ts-token-999');
    assert.strictEqual(challenge.riskScore.score, 55);

    const verified = await client.verifyAnomalyChallenge(challenge.token);
    assert.strictEqual(verified.valid, true);
    assert.strictEqual(verified.riskScore.score, 10);

    const graph = await client.exportIncidentGraph(0, 10);
    assert.strictEqual(graph.format, 'siem-topology-v1');
    assert.strictEqual(graph.total_nodes, 3);

    const status = await client.getAnomalyStatus();
    assert.strictEqual(status.total_observations, 50);
    assert.strictEqual(status.active_monitored_entities, 10);
  });

  it('requests enclave challenge, attests quote, establishes tunnel, evaluates zero-plaintext license, and queries status', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    const challenge = await client.requestEnclaveChallenge();
    assert.strictEqual(challenge.length, 64);

    const attest = await client.attestEnclaveQuote({
      platform: 'intel_sgx',
      quoteHex: 'deadbeef',
      nonce: challenge,
    });
    assert.strictEqual(attest.valid, true);
    assert.strictEqual(attest.platform, 'intel_sgx');

    const handshake = await client.establishEnclaveTunnel({
      platform: 'intel_sgx',
      quoteHex: 'deadbeef',
      nonce: challenge,
      clientPublicKey: 'abcdef0123456789',
    });
    assert.strictEqual(handshake.established, true);
    assert.strictEqual(handshake.session_id, 'enclave-sess-ts-001');

    const evalResult = await client.evaluateEnclaveLicense({
      session_id: handshake.session_id,
      sequence: 1,
      nonce: '0102030405060708090a0b0c',
      payload: 'aabbccdd',
    });
    assert.strictEqual(evalResult.payload, 'deadbeefcafebabe');

    const status = await client.getEnclaveStatus();
    assert.strictEqual(status.telemetry.verified_quotes, 12);
    assert.strictEqual(status.telemetry.active_tunnels, 3);
  });

  it('verifies TDX quote, issues attestation token, validates token, and executes isolated license decryption', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    // 1. Verify TDX Quote
    const tdxRes = await client.verifyTDXQuote({
      quoteHex: 'deadbeef_tdx_quote_hex',
      nonce: 'nonce_ts_123',
      policyId: 'default-tdx',
    });
    assert.strictEqual(tdxRes.valid, true);
    assert.strictEqual(tdxRes.platform, 'intel_tdx');
    assert.strictEqual(tdxRes.measurement, 'mrtd_ts_hex_digest');
    assert.strictEqual(tdxRes.svn, 2);

    // 2. Issue Attestation Token
    const token = await client.issueAttestationToken({
      platform: 'intel_tdx',
      measurement: tdxRes.measurement || 'mrtd_ts_hex_digest',
      rtmr0: tdxRes.rtmr0,
      svn: tdxRes.svn,
      debug: false,
      nonce: 'nonce_ts_123',
      enclavePubKey: '04pubkey',
      ttlSeconds: 1800,
    });
    assert.strictEqual(token.token_id, 'tok_ts_test_123');
    assert.strictEqual(token.platform, 'intel_tdx');
    assert.strictEqual(token.signature, 'sig_ts_hex_123');

    // 3. Verify Attestation Token
    const verifyRes = await client.verifyAttestationToken({
      tokenId: token.token_id,
      token,
      minSVN: 1,
      allowDebug: false,
    });
    assert.strictEqual(verifyRes.valid, true);
    assert.strictEqual(verifyRes.svn, 2);

    // 4. Execute Isolated License Decryption
    const decRes = await client.executeIsolatedDecryption({
      platform: 'intel_tdx',
      attestation_token: token.token_id,
      token,
      encrypted_payload_hex: 'enc_payload_hex',
      nonce_hex: '0102030405060708090a0b0c',
      session_key_hex: '32_byte_session_key_hex_12345678',
    });
    assert.strictEqual(decRes.success, true);
    assert.strictEqual(decRes.hardware_isolated, true);
    assert.strictEqual(decRes.memory_zeroized, true);
    assert.strictEqual(decRes.tier, 'enterprise');
    assert.strictEqual(decRes.license_key_masked, 'SLB-****-****-9999');
  });

  it('queries anycast route, reports probe, queries status, edge cache stats, and fast verifies license', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    const route = await client.getAnycastRoute({ lat: 39.0438, lon: -77.4874, country: 'US' });
    assert.strictEqual(route.selected_pop.id, 'iad');
    assert.strictEqual(route.signed_routing_token, 'ts-signed-token-123');

    const probeRes = await client.reportAnycastProbe({ targetPopId: 'iad', rttLatencyMs: 12.5 });
    assert.strictEqual(probeRes.status, 'recorded');

    const status = await client.getAnycastStatus();
    assert.strictEqual(status.pop_count, 6);
    assert.strictEqual(status.edge_routing_enabled, true);

    const cacheStats = await client.getEdgeCacheStats();
    assert.strictEqual(cacheStats.hits, 10);
    assert.strictEqual(cacheStats.hit_ratio, 0.909);

    const fastVerify = await client.fastVerifyLicense('LIC-ANYCAST-TS', 'HWID-TS-01');
    assert.strictEqual(fastVerify.valid, true);
    assert.strictEqual(fastVerify.tier, 'enterprise');
  });

  it('queries marketplace status, simulates webhook, and lists transactions', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    const status = await client.getMarketplaceStatus();
    assert.strictEqual(status.enabled, true);
    assert.strictEqual(status.total_provisioned, 3);
    assert.strictEqual(status.stripe_configured, true);

    const simRes = await client.simulateMarketplaceWebhook({
      provider: 'stripe',
      action: 'provision',
      customer_email: 'ts_buyer@example.com',
      tier: 'enterprise',
      seats: 4,
    });
    assert.strictEqual(simRes.status, 'success');
    assert.strictEqual(simRes.transaction.license_key, 'KEY-TS-MKT-01');
    assert.strictEqual(simRes.transaction.status, 'PROVISIONED');

    const txList = await client.listMarketplaceTransactions();
    assert.strictEqual(txList.length, 1);
    assert.strictEqual(txList[0].customer_email, 'ts_buyer@example.com');
  });

  it('issues airgap token, verifies dongle, requests activation, fulfills QR payload, and handles rollback', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    const status = await client.getAirgapStatus();
    assert.strictEqual(status.vault_active, true);
    assert.strictEqual(status.master_public_key, 'pub_key_mock_hex');
    assert.strictEqual(status.total_issued_tokens, 10);

    const issueRes = await client.issueAirgapDongleToken({
      license_key: 'LIC-AIRGAP-TS-1',
      hwid: 'HWID-TS-TEST',
      tier: 'enterprise',
      days_valid: 30,
    });
    assert.strictEqual(issueRes.status, 'success');
    assert.strictEqual(issueRes.token.license_key, 'LIC-AIRGAP-TS-1');
    assert.strictEqual(issueRes.dongle_token, 'compact_ts_token_base64');
    assert.strictEqual(issueRes.qr_payload, 'AIRGAP:B45:12345678:QRTSPAYLOAD');

    const verifyRes = await client.verifyAirgapDongleToken(issueRes.dongle_token, 'HWID-TS-TEST');
    assert.strictEqual(verifyRes.valid, true);
    assert.strictEqual(verifyRes.token.license_key, 'LIC-AIRGAP-TS-1');

    const actRes = await client.requestAirgapActivation({
      license_key: 'LIC-AIRGAP-TS-ACT',
      hwid: 'HWID-TS-TEST',
    });
    assert.strictEqual(actRes.status, 'ACTIVATED');
    assert.strictEqual(actRes.qr_payload, 'AIRGAP:B45:AABBCCDD:ACTQRPAYLOAD');

    const fulfilledTok = await client.fulfillAirgapActivation(actRes.qr_payload);
    assert.strictEqual(fulfilledTok.license_key, 'LIC-AIRGAP-TS-ACT');

    const rbState = await client.getAirgapRollbackState('HWID-TS-01');
    assert.strictEqual(rbState.monotonic_counter, 99);
    assert.strictEqual(rbState.tampered, false);

    const unlockedState = await client.unlockAirgapRollback({
      vault_id: 'VAULT-HWID-TS-01',
      hwid: 'HWID-TS-01',
      nonce: 'NONCE-123',
      timestamp: Math.floor(Date.now() / 1000),
      admin_signature: 'sig_admin_hex',
    });
    assert.strictEqual(unlockedState.monotonic_counter, 100);
    assert.strictEqual(unlockedState.tampered, false);
  });

  it('queries zerotrust status, peers, enrolls/revokes peer, rotates CA, and tests HSM', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    const status = await client.getZeroTrustStatus();
    assert.strictEqual(status.ca_initialized, true);
    assert.strictEqual(status.ca_root_fingerprint, 'zt_ca_fingerprint_hex');
    assert.strictEqual(status.mtls_enforced, true);

    const peers = await client.listZeroTrustPeers();
    assert.strictEqual(peers.length, 1);
    assert.strictEqual(peers[0].node_id, 'peer-ts-01');

    const enrolled = await client.enrollZeroTrustPeer({
      node_id: 'peer-ts-new',
      role: 'worker_node',
      dns_names: ['new.mesh.internal'],
      ip_addresses: ['10.0.0.99'],
      validity_days: 90
    });
    assert.strictEqual(enrolled.node_id, 'peer-ts-new');
    assert.strictEqual(enrolled.role, 'worker_node');

    const verifyRes = await client.verifyZeroTrustPeer({
      node_id: 'peer-ts-new',
      serial_number: enrolled.serial_number
    });
    assert.strictEqual(verifyRes.valid, true);

    const revokeRes = await client.revokeZeroTrustPeer('peer-ts-new', 'Test decomm');
    assert.strictEqual(revokeRes.status, 'success');
    assert.strictEqual(revokeRes.revoked, true);

    const rotateRes = await client.rotateZeroTrustCA(180);
    assert.strictEqual(rotateRes.status, 'success');
    assert.strictEqual(rotateRes.root_fingerprint, 'rotated_ca_fp_hex');

    const hsmStatus = await client.getZeroTrustHSMStatus();
    assert.strictEqual(hsmStatus.hsm_enabled, true);
    assert.strictEqual(hsmStatus.slots.length, 1);
    assert.strictEqual(hsmStatus.slots[0].slot_id, 0);
  });

  it('queries healing status, consumes bucket, issues/resumes tunnel, borrows/returns quota, and rebalances', async () => {
    const client = new SheetLicenseClient({ baseUrl });

    const status = await client.getHealingStatus();
    assert.strictEqual(status.bucket.capacity, 100.0);
    assert.strictEqual(status.active_tunnels, 2);

    const consume = await client.consumeHealingBucket(2.0);
    assert.strictEqual(consume.allowed, true);
    assert.strictEqual(consume.stats.current_tokens, 94.0);

    const ticket = await client.issueHealingTicket({
      sessionId: 'sess-ts-heal',
      clientId: 'client-ts-01',
      hwid: 'HWID-TS-01',
      tenantId: 'tenant-ts-alpha',
      lastAckSeq: 0,
      ttlSeconds: 180,
    });
    assert.strictEqual(ticket.session_id, 'sess-ts-heal');
    assert.strictEqual(ticket.signature, 'heal_sig_ts_hex');

    const resume = await client.resumeHealingTunnel(ticket);
    assert.strictEqual(resume.status, 'resumed');
    assert.strictEqual(resume.session.state, 'resumed');
    assert.strictEqual(resume.missed_count, 1);
    assert.strictEqual(resume.missed_events[0].sequence, 1);

    const borrow = await client.borrowHealingQuota({
      borrowerTenant: 'tenant-ts-beta',
      lenderTenant: 'tenant-ts-alpha',
      amount: 500,
      durationMinutes: 15,
    });
    assert.strictEqual(borrow.status, 'success');
    assert.strictEqual(borrow.lease.lease_id, 'lease-ts-01');
    assert.strictEqual(borrow.lease.amount, 500);

    const ret = await client.returnHealingQuota('lease-ts-01');
    assert.strictEqual(ret.status, 'returned');
    assert.strictEqual(ret.lease_id, 'lease-ts-01');

    const rebal = await client.rebalanceHealingQuotas();
    assert.strictEqual(rebal.status, 'rebalanced');
  });

  it('queries HSM status, lists slots, logs in/out, derives key, encrypts/decrypts envelope, runs FIPS self-test, gets report, simulates tamper, and zeroizes', async () => {
    const client = new SheetLicenseClient({ baseUrl });
    const status = await client.getHsmStatus();
    assert.strictEqual(status.initialized, true);
    assert.strictEqual(status.fips_level, 'FIPS_140_3_LEVEL_4');
    assert.strictEqual(status.slots_total, 3);

    const slotsResp = await client.listHsmSlots();
    assert.strictEqual(slotsResp.slots.length, 1);
    assert.strictEqual(slotsResp.slots[0].token_present, true);

    const login = await client.hsmLogin(0, 'FIPS-ROOT-PIN-9842', 'USER');
    assert.strictEqual(login.authenticated, true);
    assert.strictEqual(login.slot_id, 0);

    const logout = await client.hsmLogout(0);
    assert.strictEqual(logout.logged_out, true);

    const derive = await client.deriveHsmKey({
      slot_id: 0,
      purpose: 'audit_token_encryption',
      context: 'TEST-CTX',
    });
    assert.strictEqual(derive.fingerprint, 'HSM-KEY-TS-FPR-01');

    const enc = await client.encryptHsmEnvelope({
      slot_id: 1,
      plaintext: 'CONFIDENTIAL-TS-ENVELOPE',
      associated_data: 'AAD-TS',
    });
    assert.strictEqual(enc.ciphertext_hex, 'a1b2c3d4e5f6');

    const dec = await client.decryptHsmEnvelope({
      slot_id: 1,
      ciphertext_hex: enc.ciphertext_hex,
      nonce_hex: enc.nonce_hex,
      associated_data: 'AAD-TS',
    });
    assert.strictEqual(dec.plaintext, 'CONFIDENTIAL-TS-ENVELOPE');
    assert.strictEqual(dec.authenticated, true);

    const selfTests = await client.runHsmSelfTest();
    assert.strictEqual(selfTests.count, 2);
    assert.strictEqual(selfTests.self_tests[0].passed, true);

    const report = await client.getHsmFipsReport();
    assert.strictEqual(report.certification_level, 'FIPS_140_3_LEVEL_4');
    assert.strictEqual(report.tamper_state, 'SECURE_NORMAL');

    const tamper = await client.simulateHsmTamper('SENSOR_DRILL_BREACH');
    assert.strictEqual(tamper.tamper_latched, true);
    assert.strictEqual(tamper.zeroized, true);

    const zeroize = await client.zeroizeHsm();
    assert.strictEqual(zeroize.zeroized, true);
  });

  it('queries ML-KEM status, lists keys, generates key, encapsulates/decapsulates, performs hybrid handshake, and verifies session', async () => {
    const client = new SheetLicenseClient({ baseUrl });
    const status = await client.getMLKEMStatus();
    assert.strictEqual(status.initialized, true);
    assert.strictEqual(status.default_algorithm, 'ML-KEM-768');
    assert.strictEqual(status.active_keys_count, 2);

    const keys = await client.listMLKEMKeys();
    assert.strictEqual(keys.length, 1);
    assert.strictEqual(keys[0].algorithm, 'ML-KEM-768');

    const generated = await client.generateMLKEMKey('ML-KEM-1024');
    assert.strictEqual(generated.key_id, 'mlkem-1024-mock-02');
    assert.strictEqual(generated.algorithm, 'ML-KEM-1024');

    const encap = await client.encapsulateMLKEM(generated.key_id);
    assert.strictEqual(encap.key_id, generated.key_id);
    assert.strictEqual(encap.ciphertext_hex, 'c0ffeec0ffee');

    const decapSS = await client.decapsulateMLKEM(generated.key_id, encap.ciphertext_hex);
    assert.strictEqual(decapSS, encap.shared_secret_hex);

    const hs = await client.hybridKEMHandshake({
      client_ecdh_pub_hex: '0411223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff',
      requested_mode: 'hybrid',
      algorithm: 'ML-KEM-768',
      client_nonce: 'ts-nonce-456',
    });
    assert.strictEqual(hs.session_id, 'sess-pqc-mock-777');
    assert.strictEqual(hs.quantum_resistant, true);
    assert.strictEqual(hs.agreed_mode, 'hybrid');

    const sessVerify = await client.verifyHybridKEMSession(hs.session_id);
    assert.strictEqual(sessVerify.valid, true);
    assert.strictEqual(sessVerify.session_id, hs.session_id);
    assert.strictEqual(sessVerify.quantum_resistant, true);
  });
});



