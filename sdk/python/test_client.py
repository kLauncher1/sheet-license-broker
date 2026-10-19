"""
Unit tests for Sheet License Broker Python Client SDK.
Verifies HWID generation, HMAC canonical signing, and client operations.
"""

import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import unittest

from sheet_license_client import (
    AuthenticationError,
    BrokerError,
    LicenseValidationError,
    SheetLicenseClient,
    get_machine_hwid,
)


class MockBrokerHandler(BaseHTTPRequestHandler):
    secret_key = b"test-secret-key-12345"

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP server logging during test runs
        pass

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "version": "0.7.0"}).encode())
            return
        if self.path.startswith("/api/usage/stats"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "records": [
                    {"metric": "api_calls", "count": 100, "limit": 1000}
                ]
            }).encode())
            return
        if self.path == "/api/consensus/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "node_id": "py-node-1",
                "role": "leader",
                "current_term": 1,
                "has_quorum": True
            }).encode())
            return
        if self.path == "/api/consensus/peers":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "peers": [{"id": "peer-py-2", "active": True}]
            }).encode())
            return
        if self.path == "/api/stream/clients":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "count": 1,
                "clients": [{"id": "cl-py-1", "license_key": "LIC-STREAM-PY"}]
            }).encode())
            return
        if self.path == "/api/stream/telemetry":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "telemetry": {
                    "active_connections": 1,
                    "total_heartbeats": 25
                }
            }).encode())
            return
        if self.path == "/api/zkp/params":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "curve": "P-256"
            }).encode())
            return
        if self.path == "/api/zkp/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "zkp": {
                    "total_credentials_issued": 2,
                    "total_proofs_verified": 4
                }
            }).encode())
            return
        if self.path == "/api/sso/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "total_idps": 3,
                "active_directory_users": 18,
                "deprovisioned_users": 2,
                "allocated_license_seats": 18
            }).encode())
            return
        if self.path.startswith("/scim/v2/Users"):
            self.send_response(200)
            self.send_header("Content-Type", "application/scim+json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 1,
                "startIndex": 1,
                "itemsPerPage": 1,
                "Resources": [
                    {"id": "scim-py-1", "userName": "py-user@corp.com", "active": True}
                ]
            }).encode())
            return
        if self.path == "/api/pqc/params":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "lattice": {"dimension": 256, "modulus": 8380417, "d": 13},
                "primary_algorithm": "ML-DSA-65",
                "active_key_id": "pqc-key-py-1"
            }).encode())
            return
        if self.path == "/api/pqc/keys":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "count": 1,
                "keys": [{"key_id": "pqc-key-py-1", "algorithm": "ML-DSA-65", "public_key_hex": "aabbcc", "status": "active"}]
            }).encode())
            return
        if self.path == "/api/pqc/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "pqc": {
                    "primary_algorithm": "ML-DSA-65",
                    "active_keys": 1,
                    "total_signatures": 10,
                    "total_verifications": 8,
                    "rotation_count": 1
                }
            }).encode())
            return

        if self.path.startswith("/api/anomaly/score"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "entity_id": "LIC-PY-01",
                "score": 25,
                "level": "low",
                "factors": [{"code": "HEARTBEAT_DRIFT", "severity": 25}]
            }).encode())
            return

        if self.path.startswith("/api/anomaly/graph"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "format": "siem-topology-v1",
                "total_nodes": 4,
                "total_edges": 3
            }).encode())
            return

        if self.path == "/api/anomaly/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "total_observations": 120,
                "active_monitored_entities": 15,
                "anomalies_detected": 3,
                "active_quarantines": 0
            }).encode())
            return

        if self.path == "/api/enclave/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "telemetry": {
                    "verified_quotes": 8,
                    "active_tunnels": 2,
                    "total_evaluations": 14,
                    "failed_attestations": 0,
                    "quotes_by_platform": {"intel_sgx": 6, "amd_sev_snp": 2},
                    "active_policies_count": 2
                },
                "policies": []
            }).encode())
            return

        if self.path.startswith("/api/anycast/route"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "selected_pop": {
                    "id": "iad",
                    "name": "Ashburn IAD",
                    "region": "us-east",
                    "status": "healthy"
                },
                "estimated_latency_ms": 7.2,
                "signed_routing_token": "py-anycast-token-123",
                "timestamp": "2026-10-18T12:00:00Z"
            }).encode())
            return

        if self.path == "/api/anycast/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "pop_count": 6,
                "edge_routing_enabled": True,
                "is_partitioned": False
            }).encode())
            return

        if self.path == "/api/anycast/cache/stats":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "hits": 25,
                "misses": 2,
                "lookup_latency_us": 95.5,
                "hit_ratio": 0.926
            }).encode())
            return

        if self.path == "/api/marketplace/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "enabled": True,
                "supported_providers": ["stripe", "lemonsqueezy", "paddle"],
                "total_processed_events": 8,
                "total_provisioned": 5,
                "stripe_configured": True,
            }).encode())
            return

        if self.path == "/api/marketplace/transactions":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([
                {
                    "id": "tx_py_101",
                    "event_id": "sim_py_1",
                    "provider": "stripe",
                    "action": "provision",
                    "customer_email": "py_buyer@test.com",
                    "license_key": "KEY-PY-MKT-1",
                    "tier": "enterprise",
                    "seats": 3,
                    "status": "PROVISIONED",
                }
            ]).encode())
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""

        # Verify HMAC if signature header is provided
        sig = self.headers.get("X-Signature")
        ts = self.headers.get("X-Timestamp")
        nonce = self.headers.get("X-Nonce")

        if sig and ts and nonce:
            b_hash = hashlib.sha256(body).hexdigest()
            canonical = f"POST\n{self.path}\n{ts}\n{nonce}\n{b_hash}"
            expected_sig = hmac.new(self.secret_key, canonical.encode(), hashlib.sha256).hexdigest()
            if sig != expected_sig:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "invalid_signature", "message": "Signature mismatch"}).encode())
                return

        if self.path == "/api/licenses/validate":
            data = json.loads(body.decode()) if body else {}
            key = data.get("license_key", "")
            hwid = data.get("hwid", "")

            if key == "VALID-KEY-123":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "valid": True,
                    "message": "License active and valid",
                    "license": {"key": key, "hwid": hwid, "status": "active"},
                    "tenant_id": self.headers.get("X-Tenant-ID", "")
                }).encode())
            elif key == "EXPIRED-KEY-999":
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"valid": False, "error": "License expired"}).encode())
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"valid": False, "error": "License not found"}).encode())
            return

        if self.path == "/api/users/login":
            data = json.loads(body.decode()) if body else {}
            if data.get("username") == "admin" and data.get("password") == "correct":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"authenticated": True, "username": "admin"}).encode())
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid credentials"}).encode())
            return

        if self.path == "/api/docs":
            data = json.loads(body.decode()) if body else {}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "action": data.get("action")}).encode())
            return

        if self.path == "/api/features/check":
            data = json.loads(body.decode()) if body else {}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "license_key": data.get("license_key"),
                "feature": data.get("feature"),
                "enabled": data.get("feature") == "analytics",
                "tier": "pro"
            }).encode())
            return

        if self.path == "/api/usage/record":
            data = json.loads(body.decode()) if body else {}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "exceeded": False,
                "record": {
                    "key": data.get("license_key"),
                    "metric": data.get("metric"),
                    "count": data.get("units", 1),
                    "limit": data.get("limit", 0)
                }
            }).encode())
            return

        if self.path == "/api/attestation/challenge":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "challenge_id": "py-ch-1234",
                "nonce": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "expires_at": "2026-10-14T12:00:00Z"
            }).encode())
            return

        if self.path == "/api/attestation/verify":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "record": {"trust_level": "attested_hardware"}
            }).encode())
            return

        if self.path == "/api/attestation/telemetry":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "tamper_score": 0,
                "tampered": False,
                "trust_level": "software_grace"
            }).encode())
            return

        if self.path == "/api/security/audit/export":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "bundle": {
                    "bundle_id": "bundle_py_123",
                    "record_count": 5,
                    "ciphertext_hex": "11223344"
                }
            }).encode())
            return

        if self.path == "/api/test/ratelimit":
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "15")
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "rate_limit_exceeded",
                "retry_after": 15
            }).encode())
            return

        if self.path == "/api/stream/kill":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "target": "LIC-STREAM-PY",
                "signaled_clients": 1,
                "message": "Kill switch dispatched to 1 client(s)"
            }).encode())
            return

        if self.path == "/api/zkp/credential/issue":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "credential": {"id": "cred-py-01", "tier": 2},
                "blinding_factor": "aabbcc"
            }).encode())
            return

        if self.path == "/api/zkp/verify":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "valid": True,
                "details": {"valid": True, "claimed_tier": 2, "tier_name": "pro"}
            }).encode())
            return

        if self.path == "/api/sso/token/introspect":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "active": True,
                "authorized": True,
                "claims": {
                    "user_id": "usr-py-1",
                    "email": "py-user@corp.com",
                    "role": "admin"
                }
            }).encode())
            return

        if self.path == "/api/pqc/sign":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "signature": {
                    "algorithm": "Hybrid-P256-MLDSA65",
                    "key_id": "pqc-key-py-1",
                    "classical_sig_b64": "class_sig",
                    "pqc_sig_hex": "pqc_sig",
                    "payload_hash_hex": "hash_val"
                }
            }).encode())
            return

        if self.path == "/api/pqc/verify":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "result": {
                    "valid": True,
                    "algorithm": "Hybrid-P256-MLDSA65",
                    "classical_valid": True,
                    "pqc_valid": True
                }
            }).encode())
            return

        if self.path == "/api/pqc/rotate":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "active_key": {"key_id": "pqc-key-py-2", "algorithm": "ML-DSA-65", "status": "active"},
                "grace_period_days": 7
            }).encode())
            return

        if self.path == "/api/pqc/revoke":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "revoked_key_id": "pqc-key-py-1",
                "reason": "Administrative revocation"
            }).encode())
            return

        if self.path == "/api/anomaly/record":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "recorded",
                "risk_score": {
                    "entity_id": "LIC-PY-01",
                    "score": 0,
                    "level": "low"
                }
            }).encode())
            return

        if self.path == "/api/anomaly/challenge/issue":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "challenge_issued",
                "challenge_token": "py-challenge-token-123",
                "risk_score": {"entity_id": "LIC-PY-01", "score": 55, "challenge_escalation": True}
            }).encode())
            return

        if self.path == "/api/anomaly/challenge/verify":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "challenge_cleared",
                "valid": True,
                "risk_score": {"entity_id": "LIC-PY-01", "score": 10, "challenge_escalation": False}
            }).encode())
            return

        if self.path == "/api/enclave/challenge":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "challenge": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
                "expires_in": 300
            }).encode())
            return

        if self.path == "/api/enclave/attest":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "valid": True,
                "attestation": {
                    "valid": True,
                    "platform": "intel_sgx",
                    "mr_enclave": "aabbccddeeff",
                    "mr_signer": "112233445566",
                    "svn": 2,
                    "debug": False,
                    "report_data_hex": "00112233"
                }
            }).encode())
            return

        if self.path == "/api/enclave/tunnel/handshake":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "established": True,
                "session_id": "enclave-sess-py-01",
                "broker_public_key": "abcdef0123456789abcdef0123456789",
                "expires_at": "2030-01-01T00:00:00Z"
            }).encode())
            return

        if self.path == "/api/enclave/tunnel/evaluate":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "session_id": "enclave-sess-py-01",
                "sequence": 1,
                "nonce": "0102030405060708090a0b0c",
                "payload": "cafebabedeadbeef"
            }).encode())
            return

        if self.path == "/api/anycast/probe":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "recorded"}).encode())
            return

        if self.path == "/api/anycast/verify":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "valid": True,
                "license_key": "LIC-PY-ANYCAST",
                "hwid_bound": "HWID-PY-01",
                "tier": "enterprise",
                "message": "Fast verify L1 cache hit"
            }).encode())
            return

        if self.path == "/api/marketplace/simulate":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "transaction": {
                    "id": "tx_py_101",
                    "event_id": "sim_py_1",
                    "provider": "stripe",
                    "action": "provision",
                    "customer_email": "py_buyer@test.com",
                    "license_key": "KEY-PY-MKT-1",
                    "tier": "enterprise",
                    "seats": 3,
                    "status": "PROVISIONED",
                }
            }).encode())
            return

        self.send_error(404, "Not Found")



class TestSheetLicenseClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockBrokerHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_hwid_format(self):
        hwid1 = get_machine_hwid()
        hwid2 = get_machine_hwid()
        self.assertTrue(hwid1.startswith("HWID-"))
        parts = hwid1.split("-")
        self.assertEqual(len(parts), 5)  # HWID, 4 hex chunks
        self.assertEqual(hwid1, hwid2, "HWID should be deterministic within machine")

    def test_health(self):
        client = SheetLicenseClient(self.base_url)
        res = client.health()
        self.assertEqual(res.get("status"), "healthy")
        self.assertEqual(res.get("version"), "0.7.0")

    def test_validate_license_success_with_hmac(self):
        client = SheetLicenseClient(self.base_url, secret_key="test-secret-key-12345")
        res = client.verify_license("VALID-KEY-123")
        self.assertTrue(res.get("valid"))
        self.assertEqual(res["license"]["key"], "VALID-KEY-123")

    def test_validate_license_invalid_key(self):
        client = SheetLicenseClient(self.base_url, secret_key="test-secret-key-12345")
        with self.assertRaises(LicenseValidationError):
            client.verify_license("INVALID-KEY-000")

    def test_hmac_signature_mismatch(self):
        client = SheetLicenseClient(self.base_url, secret_key="wrong-secret-key")
        with self.assertRaises(AuthenticationError):
            client.verify_license("VALID-KEY-123")

    def test_user_login(self):
        client = SheetLicenseClient(self.base_url)
        res = client.login_user("admin", "correct")
        self.assertTrue(res.get("authenticated"))

        with self.assertRaises(BrokerError):
            client.login_user("admin", "wrong")

    def test_doc_operations(self):
        client = SheetLicenseClient(self.base_url)
        res = client.put_doc("configs", "app_conf", {"theme": "dark"})
        self.assertTrue(res.get("success"))

    def test_tenant_header(self):
        client = SheetLicenseClient(self.base_url, tenant_id="tenant-acme")
        res = client.verify_license("VALID-KEY-123")
        self.assertTrue(res.get("valid"))
        self.assertEqual(res.get("tenant_id"), "tenant-acme")

    def test_features_and_usage(self):
        client = SheetLicenseClient(self.base_url)
        # 1. Feature check
        self.assertTrue(client.is_feature_enabled("VALID-KEY-123", "analytics"))
        self.assertFalse(client.is_feature_enabled("VALID-KEY-123", "sso"))

        # 2. Record usage
        rec = client.record_usage("VALID-KEY-123", "api_calls", units=25, limit=500)
        self.assertEqual(rec.get("status"), "success")
        self.assertFalse(rec.get("exceeded"))

        # 3. Get usage
        stats = client.get_usage("VALID-KEY-123")
        self.assertEqual(len(stats), 1)
        self.assertEqual(stats[0]["metric"], "api_calls")

    def test_attestation_and_telemetry(self):
        client = SheetLicenseClient(self.base_url)

        # 1. Challenge
        ch = client.request_attestation_challenge("VALID-KEY-123")
        self.assertEqual(ch.get("challenge_id"), "py-ch-1234")
        self.assertEqual(len(ch.get("nonce", "")), 64)

        # 2. Verify TPM
        res = client.verify_tpm_attestation("VALID-KEY-123", "py-ch-1234", {"mock": True})
        self.assertEqual(res.get("record", {}).get("trust_level"), "attested_hardware")

        # 3. Telemetry
        telem = client.report_telemetry("VALID-KEY-123", {"debugger_present": False})
        self.assertEqual(telem.get("tamper_score"), 0)
        self.assertFalse(telem.get("tampered"))
        self.assertEqual(telem.get("trust_level"), "software_grace")

    def test_audit_export_and_rate_limit(self):
        client = SheetLicenseClient(self.base_url)

        # 1. Audit export
        bundle = client.export_audit_token("secret", limit=10)
        self.assertEqual(bundle.get("bundle_id"), "bundle_py_123")
        self.assertEqual(bundle.get("record_count"), 5)

        # 2. RateLimitError on 429
        from sheet_license_client import RateLimitError
        with self.assertRaises(RateLimitError) as cm:
            client._request("POST", "/api/test/ratelimit")
        self.assertEqual(cm.exception.status_code, 429)
        self.assertEqual(cm.exception.retry_after, 15)

    def test_cluster_consensus(self):
        client = SheetLicenseClient(self.base_url)
        status = client.get_cluster_status()
        self.assertEqual(status.get("node_id"), "py-node-1")
        self.assertEqual(status.get("role"), "leader")
        self.assertTrue(status.get("has_quorum"))

        peers = client.get_cluster_peers()
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0].get("id"), "peer-py-2")

    def test_stream_clients_and_kill_switch(self):
        client = SheetLicenseClient(self.base_url)
        clients = client.get_stream_clients()
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].get("id"), "cl-py-1")
        self.assertEqual(clients[0].get("license_key"), "LIC-STREAM-PY")

        kill_res = client.send_kill_switch("LIC-STREAM-PY", "Test kill reason", True)
        self.assertEqual(kill_res.get("status"), "success")
        self.assertEqual(kill_res.get("signaled_clients"), 1)

        telem = client.get_stream_telemetry()
        self.assertEqual(telem.get("active_connections"), 1)
        self.assertEqual(telem.get("total_heartbeats"), 25)

    def test_zkp_workflow(self):
        client = SheetLicenseClient(self.base_url)
        params = client.get_zkp_params()
        self.assertEqual(params.get("curve"), "P-256")

        issue_res = client.issue_anonymous_credential("LIC-PY-01", tier="pro", valid_days=30)
        self.assertEqual(issue_res.get("status"), "success")
        self.assertEqual(issue_res.get("credential", {}).get("id"), "cred-py-01")

        verify_res = client.verify_zkp_proof({"ax": "1", "ay": "2"}, required_tier="pro")
        self.assertEqual(verify_res.get("status"), "success")
        self.assertTrue(verify_res.get("valid"))

        status = client.get_zkp_status()
        self.assertEqual(status.get("total_proofs_verified"), 4)

    def test_sso_and_scim_workflow(self):
        client = SheetLicenseClient(self.base_url)
        status = client.get_sso_status()
        self.assertEqual(status.get("active_directory_users"), 18)
        self.assertEqual(status.get("total_idps"), 3)

        intro = client.introspect_session_token("sso.test.token", "license:read")
        self.assertTrue(intro.get("active"))
        self.assertTrue(intro.get("authorized"))
        self.assertEqual(intro.get("claims", {}).get("email"), "py-user@corp.com")

        scim = client.list_scim_users(1, 10)
        self.assertEqual(scim.get("totalResults"), 1)
        self.assertEqual(scim.get("Resources")[0].get("userName"), "py-user@corp.com")

    def test_pqc_workflow(self):
        client = SheetLicenseClient(self.base_url)
        params = client.get_pqc_params()
        self.assertEqual(params.get("primary_algorithm"), "ML-DSA-65")
        self.assertEqual(params.get("lattice", {}).get("dimension"), 256)

        keys = client.get_pqc_public_keys()
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0].get("key_id"), "pqc-key-py-1")

        sig = client.sign_pqc_license("VALID-KEY-123", "payload-data")
        self.assertEqual(sig.get("algorithm"), "Hybrid-P256-MLDSA65")
        self.assertEqual(sig.get("key_id"), "pqc-key-py-1")

        res = client.verify_pqc_signature("payload-data", sig)
        self.assertTrue(res.get("valid"))
        self.assertTrue(res.get("classical_valid"))
        self.assertTrue(res.get("pqc_valid"))

        rotate_res = client.rotate_pqc_key("ML-DSA-65", grace_days=7)
        self.assertEqual(rotate_res.get("status"), "success")
        self.assertEqual(rotate_res.get("active_key", {}).get("key_id"), "pqc-key-py-2")

        revoke_res = client.revoke_pqc_key("pqc-key-py-1")
        self.assertEqual(revoke_res.get("status"), "success")
        self.assertEqual(revoke_res.get("revoked_key_id"), "pqc-key-py-1")

        status = client.get_pqc_status()
        self.assertEqual(status.get("primary_algorithm"), "ML-DSA-65")
        self.assertEqual(status.get("total_signatures"), 10)

    def test_anomaly_workflow(self):
        client = SheetLicenseClient(self.base_url)

        obs = client.record_anomaly_observation({
            "license_key": "LIC-PY-01",
            "ip": "198.51.100.5",
            "action": "heartbeat"
        })
        self.assertEqual(obs.get("entity_id"), "LIC-PY-01")
        self.assertEqual(obs.get("score"), 0)

        score = client.get_anomaly_risk_score("LIC-PY-01")
        self.assertEqual(score.get("score"), 25)
        self.assertEqual(len(score.get("factors", [])), 1)

        challenge = client.issue_anomaly_challenge("LIC-PY-01")
        token = challenge.get("challenge_token")
        self.assertEqual(token, "py-challenge-token-123")
        self.assertTrue(challenge.get("risk_score", {}).get("challenge_escalation"))

        verify = client.verify_anomaly_challenge(token)
        self.assertTrue(verify.get("valid"))
        self.assertEqual(verify.get("risk_score", {}).get("score"), 10)

        graph = client.export_incident_graph(min_score=0, limit=10)
        self.assertEqual(graph.get("format"), "siem-topology-v1")
        self.assertEqual(graph.get("total_nodes"), 4)

        status = client.get_anomaly_status()
        self.assertEqual(status.get("total_observations"), 120)
        self.assertEqual(status.get("active_monitored_entities"), 15)

    def test_enclave_workflow(self):
        client = SheetLicenseClient(self.base_url)

        # 1. Challenge
        ch = client.request_enclave_challenge()
        self.assertEqual(len(ch), 64)

        # 2. Attest Quote
        attest = client.attest_enclave_quote("intel_sgx", "aabbccddeeff", ch)
        self.assertTrue(attest.get("valid"))
        self.assertEqual(attest.get("platform"), "intel_sgx")
        self.assertEqual(attest.get("mr_enclave"), "aabbccddeeff")

        # 3. Tunnel Handshake
        handshake = client.establish_enclave_tunnel("intel_sgx", "aabbccddeeff", ch, "client_pub_hex")
        self.assertTrue(handshake.get("established"))
        self.assertEqual(handshake.get("session_id"), "enclave-sess-py-01")

        # 4. Evaluate License inside Enclave
        eval_res = client.evaluate_enclave_license("enclave-sess-py-01", 1, "0102030405060708090a0b0c", "cafebabedeadbeef")
        self.assertEqual(eval_res.get("session_id"), "enclave-sess-py-01")
        self.assertEqual(eval_res.get("sequence"), 1)
        self.assertEqual(eval_res.get("payload"), "cafebabedeadbeef")

        # 5. Enclave Status
        status = client.get_enclave_status()
        self.assertEqual(status.get("telemetry", {}).get("verified_quotes"), 8)
        self.assertEqual(status.get("telemetry", {}).get("active_tunnels"), 2)

    def test_anycast_workflow(self):
        client = SheetLicenseClient(self.base_url)

        # 1. Anycast Route
        route = client.get_anycast_route(lat=39.0438, lon=-77.4874, country="US")
        self.assertEqual(route.get("selected_pop", {}).get("id"), "iad")
        self.assertEqual(route.get("signed_routing_token"), "py-anycast-token-123")

        # 2. Anycast Probe
        probe_res = client.report_anycast_probe("iad", 7.2)
        self.assertEqual(probe_res.get("status"), "recorded")

        # 3. Anycast Status
        status = client.get_anycast_status()
        self.assertEqual(status.get("pop_count"), 6)
        self.assertTrue(status.get("edge_routing_enabled"))

        # 4. Edge Cache Stats
        cache_stats = client.get_edge_cache_stats()
        self.assertEqual(cache_stats.get("hits"), 25)
        self.assertEqual(cache_stats.get("hit_ratio"), 0.926)

        # 5. Fast Verify
        fast_verify = client.fast_verify_license("LIC-PY-ANYCAST", "HWID-PY-01")
        self.assertTrue(fast_verify.get("valid"))
        self.assertEqual(fast_verify.get("tier"), "enterprise")

    def test_marketplace_workflow(self):
        client = SheetLicenseClient(self.base_url)

        # 1. Marketplace Status
        status = client.get_marketplace_status()
        self.assertTrue(status.get("enabled"))
        self.assertEqual(status.get("total_provisioned"), 5)
        self.assertTrue(status.get("stripe_configured"))

        # 2. Simulate Webhook
        sim_res = client.simulate_marketplace_webhook(
            customer_email="py_buyer@test.com",
            provider="stripe",
            tier="enterprise",
            seats=3,
        )
        self.assertEqual(sim_res.get("status"), "success")
        tx = sim_res.get("transaction", {})
        self.assertEqual(tx.get("license_key"), "KEY-PY-MKT-1")
        self.assertEqual(tx.get("status"), "PROVISIONED")

        # 3. List Transactions
        tx_list = client.list_marketplace_transactions()
        self.assertEqual(len(tx_list), 1)
        self.assertEqual(tx_list[0].get("customer_email"), "py_buyer@test.com")


if __name__ == "__main__":
    unittest.main()


