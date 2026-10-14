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


if __name__ == "__main__":
    unittest.main()
