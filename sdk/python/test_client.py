"""
Unit test suite for Sheet License Broker Python Client SDK.
Covers authentication, HMAC signatures, hardware attestation, consensus,
streaming kill-switches, ZKP, SSO, PQC, behavioral anomaly detection,
confidential enclaves, Anycast edge routing, marketplace webhooks,
and air-gapped license vault & offline dongles.
"""

import hashlib
import hmac
import json
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

from sheet_license_client import (
    AuthenticationError,
    LicenseValidationError,
    RateLimitError,
    SheetLicenseClient,
    get_machine_hwid,
)

SECRET_KEY = "test-secret-key-py"


class MockBrokerHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/health":
            self._send_json(200, {"status": "healthy", "version": "1.9.0"})
            return

        if path == "/api/usage/stats":
            self._send_json(
                200,
                {
                    "status": "success",
                    "records": [{"metric": "api_calls", "count": 150, "limit": 1000}],
                },
            )
            return

        if path == "/api/security/audit/export":
            self._send_json(
                200,
                {
                    "status": "success",
                    "bundle": {
                        "export_id": "aud_01",
                        "encrypted_payload": "enc_data",
                        "hmac_digest": "hmac_data",
                        "event_count": 5,
                        "generated_at": "2026-10-14T10:00:00Z",
                    },
                },
            )
            return

        if path == "/api/consensus/status":
            self._send_json(
                200,
                {
                    "cluster_id": "test-cluster",
                    "local_node": "node-1",
                    "role": "Leader",
                    "term": 1,
                    "peers": ["http://localhost:8081"],
                },
            )
            return

        if path == "/api/consensus/peers":
            self._send_json(200, {"peers": ["http://localhost:8081"]})
            return

        if path == "/api/stream/clients":
            self._send_json(
                200,
                {
                    "count": 1,
                    "clients": [
                        {
                            "id": "c1",
                            "license_key": "LIC-PY-01",
                            "hwid": "HWID-01",
                            "ip": "127.0.0.1",
                            "connected_at": "2026-10-14T10:00:00Z",
                            "last_ping": "2026-10-14T10:01:00Z",
                            "latency_ms": 5,
                        }
                    ],
                },
            )
            return

        if path == "/api/stream/telemetry":
            self._send_json(
                200,
                {
                    "status": "success",
                    "telemetry": {
                        "active_connections": 1,
                        "broadcast_events": 2,
                        "targeted_events": 1,
                        "kill_switches_fired": 0,
                    },
                },
            )
            return

        if path == "/api/zkp/params":
            self._send_json(
                200,
                {
                    "curve": "P-256",
                    "generator_g": "gen_g",
                    "generator_h": "gen_h",
                    "issuer_pubkey": "issuer_key",
                },
            )
            return

        if path == "/api/zkp/status":
            self._send_json(
                200,
                {
                    "status": "success",
                    "zkp": {
                        "verified_proofs": 42,
                        "spent_nullifiers": 10,
                        "total_credentials": 15,
                    },
                },
            )
            return

        if path == "/api/sso/status":
            self._send_json(
                200,
                {
                    "configured_providers": 2,
                    "active_sessions": 8,
                    "synced_users": 20,
                },
            )
            return

        if path == "/scim/v2/Users":
            self._send_json(
                200,
                {
                    "totalResults": 1,
                    "Resources": [
                        {
                            "id": "usr-1",
                            "userName": "alice@corp.com",
                            "active": True,
                        }
                    ],
                },
            )
            return

        if path == "/api/pqc/params":
            self._send_json(
                200,
                {
                    "status": "success",
                    "default_algorithm": "Hybrid-P256-MLDSA65",
                    "prime_modulus_q": 8380417,
                },
            )
            return

        if path == "/api/pqc/keys":
            self._send_json(
                200,
                {
                    "status": "success",
                    "count": 1,
                    "keys": [
                        {
                            "key_id": "K1",
                            "algorithm": "Hybrid-P256-MLDSA65",
                            "public_hex": "pub_hex",
                        }
                    ],
                },
            )
            return

        if path == "/api/pqc/status":
            self._send_json(
                200,
                {
                    "status": "success",
                    "pqc": {
                        "active_key_id": "K1",
                        "default_algorithm": "Hybrid-P256-MLDSA65",
                        "verified_signatures": 10,
                    },
                },
            )
            return

        if path == "/api/anomaly/score":
            self._send_json(
                200,
                {
                    "entity_id": qs.get("entity_id", [""])[0],
                    "score": 15,
                    "level": "low",
                    "factors": [],
                    "challenge_escalation": False,
                    "quarantine_triggered": False,
                },
            )
            return

        if path == "/api/anomaly/graph":
            self._send_json(
                200,
                {
                    "format": "siem-topology-v1",
                    "total_nodes": 2,
                    "total_edges": 1,
                    "nodes": [{"id": "n1", "type": "license", "risk_score": 15}],
                    "edges": [],
                },
            )
            return

        if path == "/api/anomaly/status":
            self._send_json(
                200,
                {
                    "total_observations": 100,
                    "active_monitored_entities": 15,
                    "anomalies_detected": 1,
                },
            )
            return

        if path == "/api/enclave/status":
            self._send_json(
                200,
                {
                    "telemetry": {
                        "verified_quotes": 5,
                        "active_tunnels": 2,
                        "total_evaluations": 10,
                    }
                },
            )
            return

        if path == "/api/anycast/route":
            self._send_json(
                200,
                {
                    "selected_pop": {"id": "iad", "name": "Ashburn IAD", "country": "US"},
                    "estimated_latency_ms": 10.2,
                    "signed_routing_token": "py-tok-123",
                },
            )
            return

        if path == "/api/anycast/status":
            self._send_json(
                200,
                {
                    "pop_count": 6,
                    "edge_routing_enabled": True,
                    "is_partitioned": False,
                },
            )
            return

        if path == "/api/anycast/cache/stats":
            self._send_json(
                200,
                {
                    "hits": 20,
                    "misses": 2,
                    "hit_ratio": 0.909,
                    "lookup_latency_us": 85,
                },
            )
            return

        if path == "/api/marketplace/status":
            self._send_json(
                200,
                {
                    "enabled": True,
                    "supported_providers": ["stripe", "lemonsqueezy", "paddle"],
                    "total_provisioned": 8,
                    "stripe_configured": True,
                },
            )
            return

        if path == "/api/marketplace/transactions":
            self._send_json(
                200,
                [
                    {
                        "id": "tx_py_1",
                        "provider": "stripe",
                        "action": "provision",
                        "customer_email": "py_buyer@corp.com",
                        "license_key": "LIC-PY-MKT",
                        "tier": "enterprise",
                    }
                ],
            )
            return

        if path == "/api/airgap/status":
            self._send_json(
                200,
                {
                    "vault_active": True,
                    "master_public_key": "pub_key_py_hex",
                    "total_issued_tokens": 12,
                    "total_verified_tokens": 30,
                    "total_activations": 6,
                    "rollback_tripped_count": 0,
                },
            )
            return

        if path == "/api/airgap/rollback/state":
            hwid = qs.get("hwid", ["HWID-DEFAULT"])[0]
            self._send_json(
                200,
                {
                    "status": "success",
                    "state": {
                        "vault_id": f"VAULT-{hwid}",
                        "hwid": hwid,
                        "monotonic_counter": 105,
                        "tampered": False,
                    },
                },
            )
            return

        if path == "/api/zerotrust/status":
            self._send_json(
                200,
                {
                    "ca_initialized": True,
                    "ca_root_fingerprint": "zt_ca_py_hex",
                    "mtls_enforced": True,
                    "active_peers_count": 2,
                    "hsm_enabled": True,
                    "hsm_slots_count": 3,
                },
            )
            return

        if path == "/api/zerotrust/peers":
            self._send_json(
                200,
                {
                    "peers": [
                        {
                            "node_id": "peer-py-01",
                            "role": "cluster_peer",
                            "status": "ACTIVE",
                            "serial_number": "py_serial_01",
                        }
                    ]
                },
            )
            return

        if path == "/api/zerotrust/hsm/status":
            self._send_json(
                200,
                {
                    "hsm_enabled": True,
                    "slots_count": 3,
                    "slots": [
                        {
                            "slot_id": 0,
                            "label": "Root CA Master Key Slot",
                            "key_present": True,
                            "operations_count": 8,
                            "zeroized": False,
                        }
                    ],
                },
            )
            return

        if path == "/api/healing/status":
            self._send_json(
                200,
                {
                    "bucket": {"capacity": 100.0, "mode": "normal"},
                    "active_tunnels": 2,
                    "active_leases": [],
                },
            )
            return

        if path == "/api/hsm/status":
            self._send_json(
                200,
                {
                    "initialized": True,
                    "hardware_available": True,
                    "fips_level": "FIPS_140_3_LEVEL_4",
                    "slots_total": 3,
                    "active_sessions": 1,
                    "tamper_detected": False,
                    "locked_out": False,
                    "master_key_present": True,
                    "operations_count": 50,
                    "uptime_seconds": 600,
                },
            )
            return

        if path == "/api/hsm/slots":
            self._send_json(
                200,
                {
                    "slots": [
                        {
                            "slot_id": 0,
                            "description": "Hardware Cryptoki Slot 0",
                            "token_present": True,
                            "hardware_slot": True,
                        }
                    ]
                },
            )
            return

        if path == "/api/hsm/fips/report":
            self._send_json(
                200,
                {
                    "certification_level": "FIPS_140_3_LEVEL_4",
                    "hardware_model": "FIPS-140-3-L4-VAULT",
                    "serial_number": "HSM4-ROOT-9842",
                    "tamper_state": "SECURE_NORMAL",
                    "kat_passed": True,
                },
            )
            return

        if path == "/api/pqc/kem/status":
            self._send_json(
                200,
                {
                    "initialized": True,
                    "active_keys_count": 2,
                    "default_algorithm": "ML-KEM-768",
                    "active_sessions_count": 1,
                    "quantum_enforced": False,
                    "total_encapsulations": 12,
                    "total_decapsulations": 12,
                    "total_handshakes": 6,
                    "uptime_seconds": 300,
                },
            )
            return

        if path == "/api/pqc/kem/keys":
            self._send_json(
                200,
                {
                    "keys": [
                        {
                            "key_id": "mlkem-768-py-01",
                            "algorithm": "ML-KEM-768",
                            "fingerprint": "fp-py-768-01",
                            "raw_hex": "010203040506",
                        }
                    ]
                },
            )
            return

        if path.startswith("/api/pqc/kem/sessions/verify"):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            sid = qs.get("session_id", ["sess-py-pqc-01"])[0]
            self._send_json(
                200,
                {
                    "valid": True,
                    "session_id": sid,
                    "agreed_mode": "hybrid",
                    "algorithm": "ML-KEM-768",
                    "quantum_resistant": True,
                },
            )
            return

        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b""
        body_str = body_bytes.decode("utf-8")
        payload = json.loads(body_str) if body_str else {}

        sig = self.headers.get("X-Signature")
        ts = self.headers.get("X-Timestamp")
        nonce = self.headers.get("X-Nonce")

        if sig and ts and nonce:
            b_hash = hashlib.sha256(body_bytes).hexdigest()
            canonical = f"POST\n{self.path}\n{ts}\n{nonce}\n{b_hash}"
            expected = hmac.new(
                SECRET_KEY.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(sig, expected):
                self._send_json(401, {"error": "invalid_signature", "message": "Signature mismatch"})
                return

        path = self.path

        if path == "/api/licenses/validate":
            key = payload.get("license_key")
            if key == "VALID-KEY-PY":
                self._send_json(
                    200,
                    {
                        "valid": True,
                        "message": "License active",
                        "license": {"key": key, "hwid": payload.get("hwid"), "status": "active"},
                    },
                )
            elif key == "RATE-LIMIT-TRIGGER":
                self._send_json(429, {"error": "rate_limit_exceeded", "message": "Too many requests"})
            else:
                self._send_json(401, {"valid": False, "error": "License invalid or expired"})
            return

        if path == "/api/users/login":
            if payload.get("username") == "admin" and payload.get("password") == "pass":
                self._send_json(200, {"success": True, "token": "tok_123"})
            else:
                self._send_json(401, {"success": False, "error": "Invalid credentials"})
            return

        if path == "/api/features/check":
            feat = payload.get("feature")
            self._send_json(
                200,
                {
                    "status": "success",
                    "license_key": payload.get("license_key"),
                    "feature": feat,
                    "enabled": feat == "advanced_analytics",
                    "tier": "enterprise",
                },
            )
            return

        if path == "/api/usage/record":
            self._send_json(
                200,
                {
                    "status": "success",
                    "record": {
                        "key": payload.get("license_key"),
                        "metric": payload.get("metric"),
                        "count": payload.get("units", 1),
                    },
                    "exceeded": False,
                },
            )
            return

        if path == "/api/attestation/challenge":
            self._send_json(
                200,
                {"status": "success", "challenge": "chal_hex_123", "expires_in": 300},
            )
            return

        if path == "/api/attestation/verify":
            self._send_json(200, {"status": "success", "valid": True, "pcr_digest": "pcr_val"})
            return

        if path == "/api/security/audit/export":
            self._send_json(
                200,
                {
                    "status": "success",
                    "bundle": {
                        "export_id": "aud_01",
                        "encrypted_payload": "enc_data",
                        "hmac_digest": "hmac_data",
                        "event_count": 5,
                        "generated_at": "2026-10-14T10:00:00Z",
                    },
                },
            )
            return

        if path == "/api/stream/kill":
            self._send_json(
                200,
                {"status": "revocation_pushed", "action": "revoke_license", "target": payload.get("target")},
            )
            return

        if path == "/api/zkp/credential/issue":
            self._send_json(
                200,
                {
                    "status": "success",
                    "credential": {
                        "credential_id": "cred_01",
                        "commitment": "comm_val",
                        "issuer_signature": "sig_val",
                    },
                },
            )
            return

        if path == "/api/zkp/verify":
            self._send_json(200, {"status": "success", "valid": True})
            return

        if path == "/api/sso/token/introspect":
            self._send_json(
                200,
                {
                    "active": True,
                    "authorized": True,
                    "claims": {"email": "py@corp.com", "role": "admin"},
                },
            )
            return

        if path == "/api/pqc/sign":
            self._send_json(
                200,
                {
                    "status": "success",
                    "signature": {
                        "algorithm": "Hybrid-P256-MLDSA65",
                        "key_id": "K1",
                        "quantum_sig": "qsig",
                    },
                },
            )
            return

        if path == "/api/pqc/verify":
            self._send_json(
                200,
                {
                    "status": "success",
                    "result": {
                        "valid": True,
                        "algorithm": "Hybrid-P256-MLDSA65",
                    },
                },
            )
            return

        if path == "/api/anomaly/record":
            self._send_json(
                200,
                {
                    "status": "recorded",
                    "risk_score": {"entity_id": payload.get("entity_id"), "score": 0, "level": "low"},
                },
            )
            return

        if path == "/api/anomaly/challenge/verify":
            self._send_json(
                200,
                {
                    "status": "challenge_cleared",
                    "valid": True,
                    "risk_score": {"entity_id": payload.get("entity_id"), "score": 5, "level": "low"},
                },
            )
            return

        if path == "/api/enclave/challenge":
            self._send_json(200, {"challenge": "enclave_chal_64bytes", "expires_in": 300})
            return

        if path == "/api/enclave/attest":
            self._send_json(
                200,
                {
                    "valid": True,
                    "attestation": {
                        "valid": True,
                        "platform": payload.get("platform"),
                        "svn": 2,
                    },
                },
            )
            return

        if path == "/api/enclave/tunnel/handshake":
            self._send_json(
                200,
                {
                    "established": True,
                    "session_id": "enclave-sess-py-01",
                    "broker_public_key": "pub_key_py",
                },
            )
            return

        if path == "/api/enclave/tunnel/evaluate":
            self._send_json(
                200,
                {
                    "session_id": payload.get("session_id"),
                    "payload": "evaluated_payload_hex",
                },
            )
            return

        if path == "/api/enclave/tdx/verify":
            self._send_json(
                200,
                {
                    "valid": True,
                    "attestation": {
                        "valid": True,
                        "platform": "intel_tdx",
                        "measurement": "mrtd_py_hex",
                        "rtmr0": "rtmr0_py_hex",
                        "svn": 2,
                    },
                },
            )
            return

        if path == "/api/enclave/token/issue":
            self._send_json(
                200,
                {
                    "token": {
                        "token_id": "tok_py_123",
                        "platform": payload.get("platform", "intel_tdx"),
                        "measurement": payload.get("measurement", ""),
                        "svn": payload.get("svn", 1),
                        "signature": "sig_py_123",
                    }
                },
            )
            return

        if path == "/api/enclave/token/verify":
            self._send_json(
                200,
                {
                    "valid": True,
                    "result": {
                        "valid": True,
                        "platform": "intel_tdx",
                        "svn": 2,
                    },
                },
            )
            return

        if path == "/api/enclave/isolated/decrypt":
            self._send_json(
                200,
                {
                    "result": {
                        "success": True,
                        "license_key_masked": "SLB-****-****-1111",
                        "tier": "enterprise",
                        "hardware_isolated": True,
                        "memory_zeroized": True,
                    }
                },
            )
            return

        if path == "/api/anycast/probe":
            self._send_json(200, {"status": "recorded"})
            return

        if path == "/api/anycast/verify":
            self._send_json(
                200,
                {
                    "valid": True,
                    "license_key": payload.get("license_key"),
                    "tier": "enterprise",
                    "message": "Fast verify L1 cache hit",
                },
            )
            return

        if path == "/api/marketplace/simulate":
            self._send_json(
                200,
                {
                    "status": "success",
                    "transaction": {
                        "id": "tx_sim_01",
                        "license_key": "LIC-PY-SIM",
                        "status": "PROVISIONED",
                    },
                },
            )
            return

        if path == "/api/airgap/token/issue":
            self._send_json(
                200,
                {
                    "status": "success",
                    "token": {
                        "token_id": "DONGLE-PY-001",
                        "license_key": payload.get("license_key"),
                        "hwid": payload.get("hwid"),
                        "tier": payload.get("tier", "enterprise"),
                        "counter": 5,
                    },
                    "dongle_token": "compact_py_token_base64",
                    "qr_payload": "AIRGAP:B45:1234:PYQRPAYLOAD",
                },
            )
            return

        if path == "/api/airgap/token/verify":
            self._send_json(
                200,
                {
                    "status": "success",
                    "valid": True,
                    "token": {
                        "token_id": "DONGLE-PY-001",
                        "license_key": "LIC-AIRGAP-PY-1",
                        "hwid": payload.get("hwid"),
                        "tier": "enterprise",
                    },
                },
            )
            return

        if path == "/api/airgap/activate/request":
            self._send_json(
                200,
                {
                    "status": "success",
                    "activation": {
                        "request_id": "ACT-PY-001",
                        "license_key": payload.get("license_key"),
                        "hwid": payload.get("hwid"),
                        "qr_payload": "AIRGAP:B45:5678:ACTPYQR",
                        "status": "ACTIVATED",
                    },
                },
            )
            return

        if path == "/api/airgap/activate/fulfill":
            self._send_json(
                200,
                {
                    "status": "success",
                    "token": {
                        "token_id": "DONGLE-FULFILLED-PY",
                        "license_key": "LIC-AIRGAP-PY-ACT",
                        "tier": "enterprise-airgap",
                    },
                },
            )
            return

        if path == "/api/airgap/rollback/unlock":
            self._send_json(
                200,
                {
                    "status": "success",
                    "state": {
                        "vault_id": payload.get("vault_id"),
                        "hwid": payload.get("hwid"),
                        "monotonic_counter": 106,
                        "tampered": False,
                    },
                },
            )
            return

        if path == "/api/zerotrust/peers/enroll":
            self._send_json(
                200,
                {
                    "status": "success",
                    "enrollment": {
                        "node_id": payload.get("node_id"),
                        "role": payload.get("role", "cluster_peer"),
                        "serial_number": "py_serial_new",
                        "fingerprint_sha256": "py_fp_new",
                        "certificate_pem": "-----BEGIN CERTIFICATE-----\nPY_CERT\n-----END CERTIFICATE-----",
                        "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\nPY_KEY\n-----END EC PRIVATE KEY-----",
                        "root_ca_pem": "-----BEGIN CERTIFICATE-----\nPY_ROOT\n-----END CERTIFICATE-----",
                    },
                },
            )
            return

        if path == "/api/zerotrust/peers/revoke":
            self._send_json(
                200,
                {
                    "status": "success",
                    "node_id": payload.get("node_id"),
                    "revoked": True,
                    "reason": payload.get("reason", "Revocation"),
                },
            )
            return

        if path == "/api/zerotrust/ca/rotate":
            self._send_json(
                200,
                {
                    "status": "success",
                    "message": "Rotated",
                    "root_fingerprint": "rotated_py_fp_hex",
                },
            )
            return

        if path == "/api/zerotrust/verify":
            self._send_json(
                200,
                {
                    "valid": True,
                    "reason": "valid",
                    "node_id": payload.get("node_id"),
                },
            )
            return

        if path == "/api/healing/bucket/consume":
            self._send_json(
                200,
                {
                    "allowed": True,
                    "stats": {"current_tokens": 98.0, "capacity": 100.0},
                },
            )
            return

        if path == "/api/healing/tunnel/ticket":
            self._send_json(
                200,
                {
                    "session_id": payload.get("session_id") or "sess-py-heal",
                    "client_id": payload.get("client_id"),
                    "hwid": payload.get("hwid"),
                    "signature": "py_sig_heal",
                },
            )
            return

        if path == "/api/healing/tunnel/resume":
            self._send_json(
                200,
                {
                    "status": "resumed",
                    "session": {"state": "resumed", "client_id": payload.get("client_id")},
                    "missed_events": [],
                    "missed_count": 0,
                },
            )
            return

        if path == "/api/healing/quota/borrow":
            self._send_json(
                200,
                {
                    "status": "success",
                    "lease": {
                        "lease_id": "lease-py-01",
                        "borrower_tenant": payload.get("borrower_tenant"),
                        "amount": payload.get("amount"),
                    },
                },
            )
            return

        if path == "/api/healing/quota/return":
            self._send_json(200, {"status": "returned", "lease_id": payload.get("lease_id")})
            return

        if path == "/api/healing/quota/rebalance":
            self._send_json(200, {"status": "rebalanced", "events": []})
            return

        if path == "/api/hsm/login":
            self._send_json(
                200,
                {
                    "authenticated": True,
                    "slot_id": payload.get("slot_id", 0),
                    "user_type": payload.get("user_type", "USER"),
                },
            )
            return

        if path == "/api/hsm/logout":
            self._send_json(200, {"logged_out": True, "slot_id": payload.get("slot_id", 0)})
            return

        if path == "/api/hsm/derive":
            self._send_json(
                200,
                {
                    "slot_id": payload.get("slot_id", 0),
                    "purpose": payload.get("purpose"),
                    "fingerprint": "HSM-KEY-PY-FPR-01",
                    "key_length_bits": 256,
                    "algorithm": "AES_256_GCM_HKDF_SHA256",
                },
            )
            return

        if path == "/api/hsm/encrypt":
            self._send_json(
                200,
                {
                    "slot_id": payload.get("slot_id"),
                    "ciphertext_hex": "py_cipher_hex_123",
                    "nonce_hex": "py_nonce_hex_123",
                    "key_fingerprint": "HSM-KEY-PY-FPR-01",
                    "algorithm": "AES_256_GCM_FIPS_140_3",
                },
            )
            return

        if path == "/api/hsm/decrypt":
            self._send_json(
                200,
                {
                    "slot_id": payload.get("slot_id"),
                    "plaintext": "CONFIDENTIAL-PY-DATA",
                    "authenticated": True,
                },
            )
            return

        if path == "/api/hsm/fips/selftest":
            self._send_json(
                200,
                {
                    "self_tests": [
                        {"test_name": "KAT-SHA-256", "passed": True},
                        {"test_name": "KAT-AES-GCM", "passed": True},
                    ],
                    "count": 2,
                },
            )
            return

        if path == "/api/hsm/tamper/simulate":
            self._send_json(
                200,
                {
                    "tamper_latched": True,
                    "sensor_id": payload.get("sensor_id"),
                    "zeroized": True,
                },
            )
            return

        if path == "/api/hsm/zeroize":
            self._send_json(200, {"zeroized": True})
            return

        if path == "/api/pqc/kem/keys/generate":
            algo = payload.get("algorithm", "ML-KEM-1024")
            self._send_json(
                200,
                {
                    "key_id": "mlkem-1024-py-02",
                    "algorithm": algo,
                    "fingerprint": "fp-py-1024-02",
                    "raw_hex": "aabbccddeeff",
                },
            )
            return

        if path == "/api/pqc/kem/encapsulate":
            key_id = payload.get("key_id", "mlkem-768-py-01")
            self._send_json(
                200,
                {
                    "key_id": key_id,
                    "algorithm": "ML-KEM-768",
                    "ciphertext_hex": "py_ciphertext_hex_999",
                    "shared_secret_hex": "py_shared_secret_hex_888",
                },
            )
            return

        if path == "/api/pqc/kem/decapsulate":
            self._send_json(
                200,
                {
                    "key_id": payload.get("key_id"),
                    "shared_secret_hex": "py_shared_secret_hex_888",
                },
            )
            return

        if path == "/api/pqc/kem/handshake":
            self._send_json(
                200,
                {
                    "session_id": "sess-py-pqc-01",
                    "server_ecdh_pub_hex": "04112233445566778899aabbccddeeff",
                    "ciphertext_hex": "py_ciphertext_hex_999",
                    "auth_tag_hex": "py_auth_tag_hex_777",
                    "agreed_mode": payload.get("requested_mode", "hybrid"),
                    "algorithm": payload.get("algorithm", "ML-KEM-768"),
                    "quantum_resistant": True,
                },
            )
            return

        self._send_json(404, {"error": "not_found"})

    def _send_json(self, code: int, data: Any) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class TestSheetLicenseClient(unittest.TestCase):
    server: HTTPServer
    server_thread: threading.Thread
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), MockBrokerHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_get_machine_hwid(self) -> None:
        hwid = get_machine_hwid()
        self.assertIsInstance(hwid, str)
        self.assertTrue(len(hwid) > 0)

    def test_client_validation_and_auth(self) -> None:
        client = SheetLicenseClient(
            base_url=self.base_url,
            secret_key=SECRET_KEY,
            tenant_id="tenant-py",
        )
        res = client.verify_license("VALID-KEY-PY", hwid="TEST-HWID")
        self.assertTrue(res.get("valid"))

        with self.assertRaises(LicenseValidationError):
            client.verify_license("INVALID-KEY")

        with self.assertRaises(RateLimitError):
            client.verify_license("RATE-LIMIT-TRIGGER")

    def test_tampered_secret_key_rejection(self) -> None:
        bad_client = SheetLicenseClient(
            base_url=self.base_url,
            secret_key="tampered-secret-key",
        )
        with self.assertRaises(AuthenticationError):
            bad_client.verify_license("VALID-KEY-PY")

    def test_login(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        res = client.login_user("admin", "pass")
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("token"), "tok_123")

    def test_features_and_usage(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        enabled = client.is_feature_enabled("LIC-01", "advanced_analytics")
        self.assertTrue(enabled)

        usage_res = client.record_usage("LIC-01", "api_calls", 5)
        self.assertEqual(usage_res.get("status"), "success")

        stats_res = client.get_usage("LIC-01")
        self.assertEqual(len(stats_res), 1)

    def test_attestation_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        chal = client.request_attestation_challenge("LIC-01")
        self.assertEqual(chal.get("challenge"), "chal_hex_123")

        tpm_res = client.verify_tpm_attestation("LIC-01", "chal_hex_123", {"quote": "data"})
        self.assertTrue(tpm_res.get("valid"))

    def test_audit_export(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        audit_res = client.export_audit_token()
        self.assertEqual(audit_res.get("export_id"), "aud_01")
        self.assertEqual(audit_res.get("event_count"), 5)

    def test_consensus_cluster(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        status = client.get_cluster_status()
        self.assertEqual(status.get("role"), "Leader")
        peers = client.get_cluster_peers()
        self.assertEqual(len(peers), 1)

    def test_streaming_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        clients = client.get_stream_clients()
        self.assertIsInstance(clients, list)
        self.assertEqual(len(clients), 1)

        kill_res = client.send_kill_switch("LIC-TARGET", "tampering")
        self.assertEqual(kill_res.get("status"), "revocation_pushed")

        telem = client.get_stream_telemetry()
        self.assertEqual(telem.get("active_connections"), 1)

    def test_zkp_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        params = client.get_zkp_params()
        self.assertEqual(params.get("curve"), "P-256")

        cred = client.issue_anonymous_credential("LIC-ZKP")
        self.assertEqual(cred.get("status"), "success")

        v_res = client.verify_zkp_proof({"proof_data": "sample"}, required_tier="pro")
        self.assertTrue(v_res.get("valid"))

        st = client.get_zkp_status()
        self.assertEqual(st.get("verified_proofs"), 42)

    def test_sso_and_scim(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        st = client.get_sso_status()
        self.assertEqual(st.get("configured_providers"), 2)

        claims = client.introspect_session_token("sso_tok")
        self.assertTrue(claims.get("active"))

        users = client.list_scim_users()
        self.assertEqual(users.get("totalResults"), 1)

    def test_pqc_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        params = client.get_pqc_params()
        self.assertEqual(params.get("default_algorithm"), "Hybrid-P256-MLDSA65")

        keys = client.get_pqc_public_keys()
        self.assertEqual(len(keys), 1)

        sig = client.sign_pqc_license("LIC-PQC", "payload_to_sign")
        self.assertEqual(sig.get("algorithm"), "Hybrid-P256-MLDSA65")
        self.assertEqual(sig.get("key_id"), "K1")

        v_res = client.verify_pqc_signature("payload_to_sign", sig)
        self.assertTrue(v_res.get("valid"))

        st = client.get_pqc_status()
        self.assertEqual(st.get("active_key_id"), "K1")

    def test_anomaly_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        rec = client.record_anomaly_observation({"entity_id": "LIC-ANOM", "type": "HEARTBEAT", "value": 100.0})
        self.assertEqual(rec.get("level"), "low")
        self.assertEqual(rec.get("score"), 0)

        score = client.get_anomaly_risk_score("LIC-ANOM")
        self.assertEqual(score.get("level"), "low")

        v_res = client.verify_anomaly_challenge("chal_tok")
        self.assertTrue(v_res.get("valid"))

        graph = client.export_incident_graph()
        self.assertEqual(graph.get("format"), "siem-topology-v1")

        st = client.get_anomaly_status()
        self.assertEqual(st.get("total_observations"), 100)

    def test_enclave_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        chal = client.request_enclave_challenge()
        self.assertEqual(chal, "enclave_chal_64bytes")

        att = client.attest_enclave_quote("intel_sgx", "deadbeef", chal)
        self.assertTrue(att.get("valid"))

        hs = client.establish_enclave_tunnel("intel_sgx", "deadbeef", chal, "client_pub")
        self.assertTrue(hs.get("established"))

        ev = client.evaluate_enclave_license("enclave-sess-py-01", 1, "010203", "payload_hex")
        self.assertEqual(ev.get("payload"), "evaluated_payload_hex")

        st = client.get_enclave_status()
        self.assertEqual(st.get("telemetry", {}).get("verified_quotes"), 5)

    def test_tdx_and_attestation_token_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        tdx_res = client.verify_tdx_quote("deadbeef_tdx", "nonce_py")
        self.assertTrue(tdx_res.get("valid"))
        self.assertEqual(tdx_res.get("platform"), "intel_tdx")
        self.assertEqual(tdx_res.get("measurement"), "mrtd_py_hex")

        tok = client.issue_attestation_token(platform="intel_tdx", measurement="mrtd_py_hex", rtmr0="rtmr0_py_hex", svn=2, nonce="nonce_py")
        self.assertEqual(tok.get("token_id"), "tok_py_123")

        v_tok = client.verify_attestation_token(token_id="tok_py_123", min_svn=1)
        self.assertTrue(v_tok.get("valid"))

        dec_res = client.execute_isolated_decryption(
            platform="intel_tdx",
            token_id="tok_py_123",
            encrypted_payload_hex="enc_hex",
            nonce_hex="0102030405060708090a0b0c",
            session_key_hex="32_bytes_session_key_hex_12345678",
        )
        self.assertTrue(dec_res.get("success"))
        self.assertTrue(dec_res.get("hardware_isolated"))
        self.assertTrue(dec_res.get("memory_zeroized"))
        self.assertEqual(dec_res.get("tier"), "enterprise")

    def test_anycast_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        route = client.get_anycast_route(39.0, -77.0, "US")
        self.assertEqual(route.get("selected_pop", {}).get("id"), "iad")

        probe = client.report_anycast_probe("iad", 12.5)
        self.assertEqual(probe.get("status"), "recorded")

        st = client.get_anycast_status()
        self.assertEqual(st.get("pop_count"), 6)

        stats = client.get_edge_cache_stats()
        self.assertEqual(stats.get("hits"), 20)

        fast_v = client.fast_verify_license("LIC-ANY", "HWID-01")
        self.assertTrue(fast_v.get("valid"))

    def test_marketplace_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)
        st = client.get_marketplace_status()
        self.assertTrue(st.get("enabled"))

        sim = client.simulate_marketplace_webhook("stripe", "provision", "py@corp.com", "enterprise", 2)
        self.assertEqual(sim.get("status"), "success")

        txs = client.list_marketplace_transactions()
        self.assertEqual(len(txs), 1)

    def test_airgap_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)

        st = client.get_airgap_status()
        self.assertTrue(st.get("vault_active"))
        self.assertEqual(st.get("master_public_key"), "pub_key_py_hex")

        issue = client.issue_airgap_dongle_token("LIC-AIRGAP-PY-1", hwid="HWID-PY-01", tier="enterprise", days_valid=30)
        self.assertEqual(issue.get("status"), "success")
        self.assertEqual(issue.get("dongle_token"), "compact_py_token_base64")

        v_res = client.verify_airgap_dongle_token("compact_py_token_base64", hwid="HWID-PY-01")
        self.assertTrue(v_res.get("valid"))

        act_res = client.request_airgap_activation("LIC-AIRGAP-PY-ACT", hwid="HWID-PY-01")
        self.assertEqual(act_res.get("status"), "success")
        act = act_res.get("activation", {})
        self.assertEqual(act.get("status"), "ACTIVATED")

        fulfill = client.fulfill_airgap_activation(act.get("qr_payload"))
        self.assertEqual(fulfill.get("status"), "success")

        rb = client.get_airgap_rollback_state("HWID-PY-01")
        self.assertEqual(rb.get("state", {}).get("monotonic_counter"), 105)

        unlock = client.unlock_airgap_rollback("VAULT-01", "HWID-PY-01", "nonce-1", 12345678, "admin_sig")
        self.assertEqual(unlock.get("state", {}).get("monotonic_counter"), 106)

    def test_zerotrust_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)

        st = client.get_zerotrust_status()
        self.assertTrue(st.get("ca_initialized"))
        self.assertEqual(st.get("ca_root_fingerprint"), "zt_ca_py_hex")
        self.assertTrue(st.get("mtls_enforced"))

        peers = client.list_zerotrust_peers()
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0].get("node_id"), "peer-py-01")

        enroll = client.enroll_zerotrust_peer("node-py-new", role="worker_node", validity_days=90)
        self.assertEqual(enroll.get("node_id"), "node-py-new")
        self.assertEqual(enroll.get("serial_number"), "py_serial_new")

        verify = client.verify_zerotrust_peer({"node_id": "node-py-new", "serial_number": "py_serial_new"})
        self.assertTrue(verify.get("valid"))

        revoke = client.revoke_zerotrust_peer("node-py-new", "Python decomm")
        self.assertTrue(revoke.get("revoked"))

        rotate = client.rotate_zerotrust_ca(180)
        self.assertEqual(rotate.get("root_fingerprint"), "rotated_py_fp_hex")

        hsm = client.get_zerotrust_hsm_status()
        self.assertTrue(hsm.get("hsm_enabled"))
        self.assertEqual(len(hsm.get("slots", [])), 1)

    def test_healing_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)

        st = client.get_healing_status()
        self.assertEqual(st.get("bucket", {}).get("capacity"), 100.0)
        self.assertEqual(st.get("active_tunnels"), 2)

        consume = client.consume_healing_bucket(2.0)
        self.assertTrue(consume.get("allowed"))

        ticket = client.issue_healing_ticket("client-py-01", "HWID-PY-01", "tenant-py")
        self.assertEqual(ticket.get("signature"), "py_sig_heal")

        resume = client.resume_healing_tunnel(ticket)
        self.assertEqual(resume.get("status"), "resumed")

        borrow = client.borrow_healing_quota("tenant-b", "tenant-l", 300)
        self.assertEqual(borrow.get("lease", {}).get("lease_id"), "lease-py-01")

        ret = client.return_healing_quota("lease-py-01")
        self.assertEqual(ret.get("status"), "returned")

        rebal = client.rebalance_healing_quotas()
        self.assertEqual(rebal.get("status"), "rebalanced")

    def test_hsm_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)

        st = client.get_hsm_status()
        self.assertTrue(st.get("initialized"))
        self.assertEqual(st.get("fips_level"), "FIPS_140_3_LEVEL_4")
        self.assertEqual(st.get("slots_total"), 3)

        slots = client.list_hsm_slots()
        self.assertEqual(len(slots.get("slots", [])), 1)

        login = client.hsm_login(0, "FIPS-ROOT-PIN-9842", "USER")
        self.assertTrue(login.get("authenticated"))

        logout = client.hsm_logout(0)
        self.assertTrue(logout.get("logged_out"))

        derive = client.derive_hsm_key(0, "audit_token_encryption", "PY-CTX")
        self.assertEqual(derive.get("fingerprint"), "HSM-KEY-PY-FPR-01")

        enc = client.encrypt_hsm_envelope(1, "CONFIDENTIAL-PY-DATA", "AAD-PY")
        self.assertEqual(enc.get("ciphertext_hex"), "py_cipher_hex_123")

        dec = client.decrypt_hsm_envelope(1, "py_cipher_hex_123", "py_nonce_hex_123", "AAD-PY")
        self.assertEqual(dec.get("plaintext"), "CONFIDENTIAL-PY-DATA")
        self.assertTrue(dec.get("authenticated"))

        self_tests = client.run_hsm_self_test()
        self.assertEqual(self_tests.get("count"), 2)

        report = client.get_hsm_fips_report()
        self.assertEqual(report.get("certification_level"), "FIPS_140_3_LEVEL_4")
        self.assertTrue(report.get("kat_passed"))

        tamper = client.simulate_hsm_tamper("SENSOR_TEMPERATURE_OUT_OF_BOUNDS")
        self.assertTrue(tamper.get("tamper_latched"))
        self.assertTrue(tamper.get("zeroized"))

        zeroize = client.zeroize_hsm()
        self.assertTrue(zeroize.get("zeroized"))

    def test_mlkem_methods(self) -> None:
        client = SheetLicenseClient(base_url=self.base_url)

        st = client.get_mlkem_status()
        self.assertTrue(st.get("initialized"))
        self.assertEqual(st.get("default_algorithm"), "ML-KEM-768")
        self.assertEqual(st.get("active_keys_count"), 2)

        keys = client.list_mlkem_keys()
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0].get("algorithm"), "ML-KEM-768")

        gen = client.generate_mlkem_key("ML-KEM-1024")
        self.assertEqual(gen.get("key_id"), "mlkem-1024-py-02")
        self.assertEqual(gen.get("algorithm"), "ML-KEM-1024")

        encap = client.encapsulate_mlkem(gen.get("key_id"))
        self.assertEqual(encap.get("ciphertext_hex"), "py_ciphertext_hex_999")
        self.assertEqual(encap.get("shared_secret_hex"), "py_shared_secret_hex_888")

        decap_ss = client.decapsulate_mlkem(gen.get("key_id"), encap.get("ciphertext_hex"))
        self.assertEqual(decap_ss, "py_shared_secret_hex_888")

        hs = client.hybrid_kem_handshake(
            client_ecdh_pub_hex="0411223344556677889900aabbccddeeff",
            requested_mode="hybrid",
            algorithm="ML-KEM-768",
        )
        self.assertEqual(hs.get("session_id"), "sess-py-pqc-01")
        self.assertTrue(hs.get("quantum_resistant"))

        verify = client.verify_hybrid_kem_session(hs.get("session_id"))
        self.assertTrue(verify.get("valid"))
        self.assertEqual(verify.get("session_id"), "sess-py-pqc-01")


if __name__ == "__main__":
    unittest.main()
