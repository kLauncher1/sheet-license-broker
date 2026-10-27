"""
Sheet License Broker - Python Client SDK
Zero-dependency, standalone client library for license verification, HWID device locking,
user authentication, and NoSQL storage via sheet-license-broker.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, Optional


class BrokerError(Exception):
    """Base exception for all Sheet License Broker errors."""

    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class LicenseValidationError(BrokerError):
    """Raised when a license is invalid, expired, revoked, or device-mismatched."""
    pass


class AuthenticationError(BrokerError):
    """Raised when user credentials or HMAC signatures are invalid."""
    pass


class NetworkError(BrokerError):
    """Raised when network transport or HTTP connectivity fails."""
    pass


class RateLimitError(BrokerError):
    """Raised when request rate limits or temporary reputation restrictions are exceeded."""

    def __init__(self, message: str, status_code: int = 429, details: Optional[Dict[str, Any]] = None, retry_after: int = 0):
        super().__init__(message, status_code, details)
        self.retry_after = retry_after


def get_machine_hwid() -> str:
    """
    Collects a stable, unique hardware identifier for the current machine.
    Works seamlessly across Windows, Linux, and macOS without external dependencies.
    Returns a normalized, uppercase SHA-256 fingerprint string prefixed with 'HWID-'.
    """
    system_name = platform.system().lower()
    raw_identifiers: list[str] = []

    try:
        if system_name == "windows":
            # Attempt 1: Query Windows Cryptography MachineGuid from Registry
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                    guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                    if guid:
                        raw_identifiers.append(str(guid).strip())
            except Exception:
                pass

            # Attempt 2: PowerShell ComputerSystemProduct UUID fallback
            if not raw_identifiers:
                try:
                    cmd = "powershell -NoProfile -Command \"(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID\""
                    out = subprocess.check_output(cmd, shell=True, timeout=3, stderr=subprocess.DEVNULL).decode().strip()
                    if out and len(out) > 8:
                        raw_identifiers.append(out)
                except Exception:
                    pass

        elif system_name == "linux":
            # Linux machine-id inspection
            for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"):
                if os.path.exists(candidate):
                    try:
                        with open(candidate, "r", encoding="utf-8") as f:
                            content = f.read().strip()
                            if content:
                                raw_identifiers.append(content)
                                break
                    except Exception:
                        continue

        elif system_name == "darwin":
            # macOS IOPlatformUUID
            try:
                cmd = ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"]
                out = subprocess.check_output(cmd, timeout=3, stderr=subprocess.DEVNULL).decode()
                for line in out.splitlines():
                    if "IOPlatformUUID" in line:
                        parts = line.split("=")
                        if len(parts) == 2:
                            raw_identifiers.append(parts[1].strip().strip('"'))
                            break
            except Exception:
                pass

    except Exception:
        pass

    # Universal fallback: Network MAC address + processor info
    try:
        node_val = hex(uuid.getnode())
        raw_identifiers.append(node_val)
        raw_identifiers.append(platform.processor())
        raw_identifiers.append(platform.machine())
    except Exception:
        pass

    seed = "|".join(filter(None, raw_identifiers))
    if not seed:
        seed = str(uuid.getnode())

    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest().upper()
    return f"HWID-{digest[:4]}-{digest[4:8]}-{digest[8:12]}-{digest[12:16]}"


class SheetLicenseClient:
    """
    Client for interacting with the Sheet-License-Broker gateway.
    Supports HMAC-SHA256 request signing, automatic HWID resolution,
    and complete license verification, auth, and database operations.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:9082",
        secret_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.secret_key = secret_key.encode("utf-8") if secret_key else None
        self.tenant_id = tenant_id.strip() if tenant_id else None
        self.timeout = timeout

    def _compute_body_hash(self, body_bytes: bytes) -> str:
        return hashlib.sha256(body_bytes).hexdigest()

    def _build_canonical_string(self, method: str, path: str, timestamp: int, nonce: str, body_bytes: bytes) -> str:
        b_hash = self._compute_body_hash(body_bytes)
        return f"{method.upper().strip()}\n{path.strip()}\n{timestamp}\n{nonce}\n{b_hash}"

    def _sign(self, method: str, path: str, timestamp: int, nonce: str, body_bytes: bytes) -> str:
        if not self.secret_key:
            return ""
        canonical = self._build_canonical_string(method, path, timestamp, nonce, body_bytes)
        return hmac.new(self.secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        body_bytes = json.dumps(payload).encode("utf-8") if payload is not None else b""

        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "SheetLicenseClient-Python/0.5.0",
        }

        if self.tenant_id:
            headers["X-Tenant-ID"] = self.tenant_id

        if payload is not None:
            headers["Content-Type"] = "application/json"

        # Apply HMAC security headers if secret is configured
        if self.secret_key:
            ts = int(time.time())
            nonce = uuid.uuid4().hex
            sig = self._sign(method, path, ts, nonce, body_bytes)
            headers["X-Signature"] = sig
            headers["X-Timestamp"] = str(ts)
            headers["X-Nonce"] = nonce

        req = urllib.request.Request(url, data=body_bytes if method != "GET" else None, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_text = resp.read().decode("utf-8")
                return json.loads(resp_text) if resp_text else {}
        except urllib.error.HTTPError as e:
            raw_err = e.read().decode("utf-8", errors="replace")
            try:
                err_json = json.loads(raw_err)
                err_msg = err_json.get("error") or err_json.get("message") or raw_err
            except Exception:
                err_json = {}
                err_msg = raw_err or str(e)

            if e.code == 401:
                if "signature" in err_msg.lower():
                    raise AuthenticationError(f"HMAC security error: {err_msg}", e.code, err_json)
                raise LicenseValidationError(f"License authorization failed: {err_msg}", e.code, err_json)
            if e.code == 429:
                retry_after_hdr = e.headers.get("Retry-After", "0") if hasattr(e, "headers") else "0"
                try:
                    retry_after = int(retry_after_hdr)
                except ValueError:
                    retry_after = 0
                raise RateLimitError(f"Rate limit exceeded: {err_msg}", e.code, err_json, retry_after)
            raise BrokerError(f"HTTP {e.code}: {err_msg}", e.code, err_json)
        except urllib.error.URLError as e:
            raise NetworkError(f"Connection to broker failed at {url}: {e.reason}")
        except Exception as e:
            raise NetworkError(f"Request execution failed: {str(e)}")

    def health(self) -> Dict[str, Any]:
        """Queries health status of the broker service."""
        return self._request("GET", "/health")

    def ping(self) -> Dict[str, Any]:
        """Tests live round-trip latency to the Google Apps Script backend."""
        return self._request("GET", "/api/proxy/ping")

    def verify_license(self, license_key: str, hwid: Optional[str] = None) -> Dict[str, Any]:
        """
        Validates a license key against the broker.
        Automatically resolves machine HWID if not explicitly provided.
        """
        target_hwid = hwid or get_machine_hwid()
        payload = {
            "license_key": license_key.strip(),
            "hwid": target_hwid,
        }
        return self._request("POST", "/api/licenses/validate", payload)

    def create_license(self, days: int = 30, max_devices: int = 1) -> Dict[str, Any]:
        """Generates a new formatted license key with specified validity duration."""
        return self._request("POST", "/api/licenses", {"days": days, "max_devices": max_devices})

    def revoke_license(self, license_key: str, reason: str = "") -> Dict[str, Any]:
        """Immediately revokes an active license key."""
        return self._request("POST", "/api/licenses/revoke", {"license_key": license_key, "reason": reason})

    def add_blacklist(self, target_type: str, target: str, reason: str = "") -> Dict[str, Any]:
        """Adds a target (device HWID or license key) to the blacklist."""
        return self._request("POST", "/api/security/blacklist", {
            "type": target_type,
            "target": target,
            "reason": reason,
        })

    def remove_blacklist(self, target_type: str, target: str) -> Dict[str, Any]:
        """Removes a target from the blacklist."""
        return self._request("POST", "/api/security/blacklist/remove", {
            "type": target_type,
            "target": target,
        })

    def register_user(self, username: str, password: str, role: str = "user") -> Dict[str, Any]:
        """Registers a new user with salted cryptographic password hashing."""
        return self._request("POST", "/api/users/register", {
            "username": username,
            "password": password,
            "role": role,
        })

    def login_user(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticates user credentials against the Google Sheets datastore."""
        return self._request("POST", "/api/users/login", {
            "username": username,
            "password": password,
        })

    def put_doc(self, collection: str, doc_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Saves a JSON document into the NoSQL key-value store."""
        return self._request("POST", "/api/docs", {
            "action": "put",
            "collection": collection,
            "id": doc_id,
            "payload": payload,
        })

    def get_doc(self, collection: str, doc_id: str) -> Dict[str, Any]:
        """Retrieves a JSON document by ID from the NoSQL key-value store."""
        return self._request("POST", "/api/docs", {
            "action": "get",
            "collection": collection,
            "id": doc_id,
        })

    def is_feature_enabled(self, license_key: str, feature: str) -> bool:
        """Checks if a feature entitlement is enabled for a given license key."""
        res = self._request("POST", "/api/features/check", {
            "license_key": license_key.strip(),
            "feature": feature.strip(),
        })
        return bool(res.get("enabled", False))

    def record_usage(self, license_key: str, metric: str, units: int = 1, limit: int = 0, period: str = "") -> Dict[str, Any]:
        """Reports resource consumption units for a license key with quota check."""
        payload = {
            "license_key": license_key.strip(),
            "metric": metric.strip(),
            "units": units,
            "limit": limit,
        }
        if period:
            payload["period"] = period.strip()
        return self._request("POST", "/api/usage/record", payload)

    def get_usage(self, license_key: str) -> List[Dict[str, Any]]:
        """Retrieves consumption records for all metered resources of a license key."""
        quoted = urllib.parse.quote(license_key.strip())
        res = self._request("GET", f"/api/usage/stats?license_key={quoted}")
        return res.get("records", [])

    def request_attestation_challenge(self, license_key: str, hwid: Optional[str] = None) -> Dict[str, str]:
        """Obtains a fresh single-use random nonce challenge for TPM/enclave binding."""
        target_hwid = hwid or get_machine_hwid()
        return self._request("POST", "/api/attestation/challenge", {
            "license_key": license_key.strip(),
            "hwid": target_hwid.strip(),
        })

    def verify_tpm_attestation(self, license_key: str, challenge_id: str, quote_data: Dict[str, Any], hwid: Optional[str] = None) -> Dict[str, Any]:
        """Submits a signed TPM 2.0 PCR quote to attest hardware platform integrity."""
        target_hwid = hwid or get_machine_hwid()
        return self._request("POST", "/api/attestation/verify", {
            "license_key": license_key.strip(),
            "hwid": target_hwid.strip(),
            "challenge_id": challenge_id.strip(),
            "attestation_type": "tpm2",
            "tpm_quote": quote_data,
        })

    def report_telemetry(self, license_key: str, report: Dict[str, Any], hwid: Optional[str] = None) -> Dict[str, Any]:
        """Transmits anti-debugging and memory integrity telemetry to broker."""
        target_hwid = hwid or get_machine_hwid()
        return self._request("POST", "/api/attestation/telemetry", {
            "license_key": license_key.strip(),
            "hwid": target_hwid.strip(),
            "report": report,
        })

    def export_audit_token(self, secret_key: Optional[str] = None, limit: int = 500) -> Dict[str, Any]:
        """Requests an encrypted audit bundle for enterprise compliance auditing pipelines."""
        payload: Dict[str, Any] = {"limit": limit}
        if secret_key:
            payload["secret_key"] = secret_key
        res = self._request("POST", "/api/security/audit/export", payload)
        return res.get("bundle", {})

    def get_cluster_status(self) -> Dict[str, Any]:
        """Queries the broker's distributed Raft role, quorum health, and cluster topology."""
        return self._request("GET", "/api/consensus/status")

    def get_cluster_peers(self) -> list:
        """Retrieves active peer nodes in the consensus mesh."""
        res = self._request("GET", "/api/consensus/peers")
        return res.get("peers", [])

    def get_stream_clients(self) -> list:
        """Queries active WebSocket telemetry client sessions."""
        res = self._request("GET", "/api/stream/clients")
        return res.get("clients", [])

    def send_kill_switch(self, target: str, reason: str = "Administrative remote termination directive", immediate: bool = True) -> Dict[str, Any]:
        """Dispatches an instantaneous remote kill-switch directive to targeted clients."""
        return self._request("POST", "/api/stream/kill", {
            "target": target,
            "reason": reason,
            "immediate": immediate,
        })

    def get_stream_telemetry(self) -> Dict[str, Any]:
        """Queries aggregate streaming telemetry and active client metrics."""
        res = self._request("GET", "/api/stream/telemetry")
        return res.get("telemetry", {})

    def get_zkp_params(self) -> Dict[str, Any]:
        """Fetches public curve parameters and issuer public key."""
        return self._request("GET", "/api/zkp/params")

    def issue_anonymous_credential(
        self,
        license_key: str,
        hwid: Optional[str] = None,
        tier: str = "pro",
        valid_days: int = 30,
        scope: str = "production",
        hwid_commitment: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Issues an issuer-signed anonymous entitlement credential for an authenticated license."""
        target_hwid = hwid or get_machine_hwid()
        payload = {
            "license_key": license_key,
            "hwid": target_hwid,
            "tier": tier,
            "valid_days": valid_days,
            "scope": scope,
            "tenant_id": self.tenant_id or "default",
        }
        if hwid_commitment:
            payload["hwid_commitment"] = hwid_commitment
        return self._request("POST", "/api/zkp/credential/issue", payload)

    def verify_zkp_proof(
        self,
        proof: Dict[str, Any],
        required_tier: str = "free",
        epoch: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Submits a zero-knowledge presentation proof for anonymous entitlement access."""
        payload = {
            "proof": proof,
            "required_tier": required_tier,
            "epoch": epoch or int(time.time() // 3600),
        }
        return self._request("POST", "/api/zkp/verify", payload)

    def get_zkp_status(self) -> Dict[str, Any]:
        """Queries overall telemetry on zero-knowledge verifications."""
        res = self._request("GET", "/api/zkp/status")
        return res.get("zkp", {})

    def get_sso_status(self) -> Dict[str, Any]:
        """Queries telemetry on SSO identity providers and SCIM directory status."""
        return self._request("GET", "/api/sso/status")

    def introspect_session_token(self, token: str, required_scope: Optional[str] = None) -> Dict[str, Any]:
        """Validates an ephemeral session token and evaluates permissions."""
        payload = {"token": token}
        if required_scope:
            payload["required_scope"] = required_scope
        return self._request("POST", "/api/sso/token/introspect", payload)

    def list_scim_users(self, start_index: int = 1, count: int = 50) -> Dict[str, Any]:
        """Queries SCIM 2.0 directory users list with pagination."""
        return self._request("GET", f"/scim/v2/Users?startIndex={start_index}&count={count}")

    def get_pqc_params(self) -> Dict[str, Any]:
        """Queries post-quantum cryptography parameters and active key info."""
        return self._request("GET", "/api/pqc/params")

    def get_pqc_public_keys(self) -> List[Dict[str, Any]]:
        """Retrieves active public keys for client-side lattice signature verification."""
        res = self._request("GET", "/api/pqc/keys")
        return res.get("keys", [])

    def sign_pqc_license(self, license_key: str, payload: str, hwid: Optional[str] = None) -> Dict[str, Any]:
        """Issues a quantum-resistant hybrid signature over a payload for an entitled license."""
        req_payload = {
            "license_key": license_key,
            "hwid": hwid or get_machine_hwid(),
            "payload": payload,
        }
        res = self._request("POST", "/api/pqc/sign", req_payload)
        return res.get("signature", {})

    def verify_pqc_signature(self, payload: str, signature: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies dual classical and post-quantum lattice signatures."""
        req_payload = {
            "payload": payload,
            "signature": signature,
        }
        res = self._request("POST", "/api/pqc/verify", req_payload)
        return res.get("result", {})

    def rotate_pqc_key(self, algo: Optional[str] = None, grace_days: int = 7, reason: str = "Routine rotation") -> Dict[str, Any]:
        """Requests an administrative PQC key rotation with active grace period."""
        req_payload = {
            "algorithm": algo,
            "grace_days": grace_days,
            "reason": reason,
        }
        return self._request("POST", "/api/pqc/rotate", req_payload)

    def revoke_pqc_key(self, key_id: str, reason: str = "Administrative revocation") -> Dict[str, Any]:
        """Revokes a compromised PQC key by ID."""
        req_payload = {
            "key_id": key_id,
            "reason": reason,
        }
        return self._request("POST", "/api/pqc/revoke", req_payload)

    def get_pqc_status(self) -> Dict[str, Any]:
        """Queries operational telemetry for the PQC subsystem."""
        res = self._request("GET", "/api/pqc/status")
        return res.get("pqc", {})

    def record_anomaly_observation(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        """Submits client telemetry or heartbeat to the anomaly detection engine."""
        payload = dict(observation)
        if "hwid" not in payload or not payload["hwid"]:
            payload["hwid"] = get_machine_hwid()
        res = self._request("POST", "/api/anomaly/record", payload)
        return res.get("risk_score", {})

    def get_anomaly_risk_score(self, license_key: Optional[str] = None, hwid: Optional[str] = None) -> Dict[str, Any]:
        """Queries the current adaptive risk score and factors for an entity."""
        machine_hwid = hwid or (get_machine_hwid() if not license_key else "")
        params = []
        if license_key:
            params.append(f"license_key={urllib.parse.quote(license_key)}")
        if machine_hwid:
            params.append(f"hwid={urllib.parse.quote(machine_hwid)}")
        endpoint = "/api/anomaly/score"
        if params:
            endpoint += "?" + "&".join(params)
        return self._request("GET", endpoint)

    def issue_anomaly_challenge(self, license_key: Optional[str] = None, hwid: Optional[str] = None) -> Dict[str, Any]:
        """Requests an escalation challenge token for an entity."""
        payload = {
            "license_key": license_key or "",
            "hwid": hwid or get_machine_hwid(),
        }
        return self._request("POST", "/api/anomaly/challenge/issue", payload)

    def verify_anomaly_challenge(self, challenge_token: str) -> Dict[str, Any]:
        """Submits a challenge token response to clear escalation penalties."""
        payload = {"challenge_token": challenge_token}
        return self._request("POST", "/api/anomaly/challenge/verify", payload)

    def export_incident_graph(self, min_score: Optional[int] = None, limit: Optional[int] = None) -> Dict[str, Any]:
        """Exports real-time SIEM topology graph."""
        params = []
        if min_score is not None:
            params.append(f"min_score={min_score}")
        if limit is not None:
            params.append(f"limit={limit}")
        endpoint = "/api/anomaly/graph"
        if params:
            endpoint += "?" + "&".join(params)
        return self._request("GET", endpoint)

    def get_anomaly_status(self) -> Dict[str, Any]:
        """Queries operational telemetry for the anomaly detection engine."""
        return self._request("GET", "/api/anomaly/status")

    def request_enclave_challenge(self) -> str:
        """Requests a single-use cryptographic challenge nonce for enclave attestation."""
        res = self._request("POST", "/api/enclave/challenge")
        return res.get("challenge", "")

    def attest_enclave_quote(
        self,
        platform: str,
        quote_hex: str,
        nonce: str,
        policy_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submits an Intel SGX or AMD SEV-SNP attestation quote for verification."""
        payload = {
            "platform": platform,
            "quote": quote_hex,
            "nonce": nonce,
        }
        if policy_id:
            payload["policy_id"] = policy_id
        res = self._request("POST", "/api/enclave/attest", payload)
        return res.get("attestation", {})

    def establish_enclave_tunnel(
        self,
        platform: str,
        quote_hex: str,
        nonce: str,
        client_public_key: str,
        policy_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validates an enclave quote and establishes an end-to-end encrypted session tunnel."""
        payload = {
            "platform": platform,
            "quote": quote_hex,
            "nonce": nonce,
            "client_public_key": client_public_key,
        }
        if policy_id:
            payload["policy_id"] = policy_id
        return self._request("POST", "/api/enclave/tunnel/handshake", payload)

    def evaluate_enclave_license(
        self,
        session_id: str,
        sequence: int,
        nonce_hex: str,
        payload_hex: str,
    ) -> Dict[str, Any]:
        """Submits an encrypted license query inside the zero-plaintext confidential computing enclave tunnel."""
        payload = {
            "session_id": session_id,
            "sequence": sequence,
            "nonce": nonce_hex,
            "payload": payload_hex,
        }
        return self._request("POST", "/api/enclave/tunnel/evaluate", payload)

    def get_enclave_status(self) -> Dict[str, Any]:
        """Queries confidential computing operational telemetry and registered policies."""
        return self._request("GET", "/api/enclave/status")

    def get_anycast_route(
        self,
        lat: float = 0.0,
        lon: float = 0.0,
        country: str = "",
        region: str = "",
    ) -> Dict[str, Any]:
        """Queries the nearest edge Anycast Point of Presence based on coordinates, country, or region."""
        params = []
        if lat != 0.0 or lon != 0.0:
            params.append(f"lat={lat}")
            params.append(f"lon={lon}")
        if country:
            params.append(f"country={country}")
        if region:
            params.append(f"region={region}")
        query = ("?" + "&".join(params)) if params else ""
        return self._request("GET", f"/api/anycast/route{query}")

    def report_anycast_probe(
        self,
        target_pop_id: str,
        rtt_latency_ms: float,
        source_region: str = "global",
        source_ip: str = "",
        packet_loss: float = 0.0,
        jitter_ms: float = 0.0,
    ) -> Dict[str, Any]:
        """Reports an edge latency and packet loss probe to the Anycast routing engine."""
        payload = {
            "target_pop_id": target_pop_id,
            "rtt_latency_ms": rtt_latency_ms,
            "source_region": source_region,
            "source_ip": source_ip,
            "packet_loss": packet_loss,
            "jitter_ms": jitter_ms,
        }
        return self._request("POST", "/api/anycast/probe", payload)

    def get_anycast_status(self) -> Dict[str, Any]:
        """Retrieves overall Anycast status including POP health, partition isolation, and cache metrics."""
        return self._request("GET", "/api/anycast/status")

    def get_edge_cache_stats(self) -> Dict[str, Any]:
        """Retrieves microsecond-level L1 edge cache performance telemetry."""
        return self._request("GET", "/api/anycast/cache/stats")

    def fast_verify_license(self, license_key: str, hwid: Optional[str] = None) -> Dict[str, Any]:
        """Executes a fast sub-millisecond license check against the edge L1 cache."""
        machine_hwid = hwid or get_machine_hwid()
        payload = {
            "license_key": license_key,
            "hwid": machine_hwid,
        }
        return self._request("POST", "/api/anycast/verify", payload)

    def get_marketplace_status(self) -> Dict[str, Any]:
        """Retrieves diagnostic telemetry from the automated marketplace webhooks bridge."""
        return self._request("GET", "/api/marketplace/status")

    def simulate_marketplace_webhook(
        self,
        customer_email: str,
        provider: str = "stripe",
        action: str = "provision",
        tier: str = "pro",
        seats: int = 1,
        days_valid: int = 30,
        order_id: str = "",
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Sends a synthetic purchase or cancellation webhook to test automated provisioning."""
        payload = {
            "provider": provider,
            "action": action,
            "customer_email": customer_email,
            "tier": tier,
            "seats": seats,
            "days_valid": days_valid,
            "order_id": order_id,
            "metadata": metadata or {},
        }
        return self._request("POST", "/api/marketplace/simulate", payload)

    def list_marketplace_transactions(
        self,
        provider: Optional[str] = None,
        customer_email: Optional[str] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves the transaction audit ledger of processed marketplace webhook events."""
        params = []
        if provider:
            params.append(f"provider={urllib.parse.quote(provider)}")
        if customer_email:
            params.append(f"customer_email={urllib.parse.quote(customer_email)}")
        if status:
            params.append(f"status={urllib.parse.quote(status)}")
        if limit is not None and limit > 0:
            params.append(f"limit={limit}")
        qs = ("?" + "&".join(params)) if params else ""
        return self._request("GET", f"/api/marketplace/transactions{qs}")

    def get_airgap_status(self) -> Dict[str, Any]:
        """Queries operational telemetry for the air-gapped license vault."""
        return self._request("GET", "/api/airgap/status")

    def issue_airgap_dongle_token(
        self,
        license_key: str,
        hwid: Optional[str] = None,
        tier: str = "enterprise",
        days_valid: int = 30,
        max_devices: int = 1,
        features: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Issues a cryptographically signed offline dongle token."""
        machine_hwid = hwid or get_machine_hwid()
        payload = {
            "license_key": license_key,
            "hwid": machine_hwid,
            "tier": tier,
            "days_valid": days_valid,
            "max_devices": max_devices,
            "features": features or [],
        }
        return self._request("POST", "/api/airgap/token/issue", payload)

    def verify_airgap_dongle_token(
        self,
        token: str,
        hwid: Optional[str] = None,
        timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Verifies an offline dongle token against master keys and monotonic clocks."""
        machine_hwid = hwid or get_machine_hwid()
        payload = {
            "token": token,
            "hwid": machine_hwid,
            "timestamp": timestamp or int(time.time()),
        }
        return self._request("POST", "/api/airgap/token/verify", payload)

    def request_airgap_activation(
        self,
        license_key: str,
        hwid: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Requests an offline machine activation challenge with QR payload."""
        machine_hwid = hwid or get_machine_hwid()
        payload = {
            "license_key": license_key,
            "hwid": machine_hwid,
        }
        return self._request("POST", "/api/airgap/activate/request", payload)

    def fulfill_airgap_activation(self, qr_payload: str) -> Dict[str, Any]:
        """Fulfills an offline activation from a scanned QR payload."""
        payload = {"qr_payload": qr_payload}
        return self._request("POST", "/api/airgap/activate/fulfill", payload)

    def get_airgap_rollback_state(self, hwid: Optional[str] = None) -> Dict[str, Any]:
        """Queries monotonic high-water mark and rollback tamper state."""
        machine_hwid = hwid or get_machine_hwid()
        return self._request("GET", f"/api/airgap/rollback/state?hwid={urllib.parse.quote(machine_hwid)}")

    def unlock_airgap_rollback(
        self,
        vault_id: str,
        hwid: str,
        nonce: str,
        timestamp: int,
        admin_signature: str,
    ) -> Dict[str, Any]:
        """Unlocks a tripped airgap vault using an administrative recovery token."""
        payload = {
            "vault_id": vault_id,
            "hwid": hwid,
            "nonce": nonce,
            "timestamp": timestamp,
            "admin_signature": admin_signature,
        }
        return self._request("POST", "/api/airgap/rollback/unlock", payload)

    def get_zerotrust_status(self) -> Dict[str, Any]:
        """Queries operational telemetry for the Zero-Trust mesh and internal CA."""
        return self._request("GET", "/api/zerotrust/status")

    def list_zerotrust_peers(self) -> List[Dict[str, Any]]:
        """Lists all enrolled Zero-Trust mesh peer nodes."""
        res = self._request("GET", "/api/zerotrust/peers")
        return res.get("peers", [])

    def enroll_zerotrust_peer(
        self,
        node_id: str,
        role: str = "cluster_peer",
        dns_names: Optional[List[str]] = None,
        ip_addresses: Optional[List[str]] = None,
        validity_days: int = 90,
    ) -> Dict[str, Any]:
        """Enrolls a new mesh node and issues an mTLS certificate signed by the internal CA."""
        payload = {
            "node_id": node_id,
            "role": role,
            "dns_names": dns_names or [],
            "ip_addresses": ip_addresses or [],
            "validity_days": validity_days,
        }
        res = self._request("POST", "/api/zerotrust/peers/enroll", payload)
        return res.get("enrollment", res)

    def revoke_zerotrust_peer(
        self,
        node_id: str,
        reason: str = "Administrative revocation",
    ) -> Dict[str, Any]:
        """Revokes a peer node certificate and updates the internal CRL."""
        payload = {
            "node_id": node_id,
            "reason": reason,
        }
        return self._request("POST", "/api/zerotrust/peers/revoke", payload)

    def rotate_zerotrust_ca(self, validity_days: int = 365) -> Dict[str, Any]:
        """Rotates the internal Root CA while maintaining dual-trust continuity."""
        return self._request("POST", "/api/zerotrust/ca/rotate", {"validity_days": validity_days})

    def get_zerotrust_hsm_status(self) -> Dict[str, Any]:
        """Queries hardware-backed key slot capabilities and operation counters."""
        return self._request("GET", "/api/zerotrust/hsm/status")

    def verify_zerotrust_peer(self, peer: Dict[str, Any]) -> Dict[str, Any]:
        """Cryptographically verifies whether a given peer identity is actively authorized."""
        return self._request("POST", "/api/zerotrust/verify", peer)

    def get_healing_status(self) -> Dict[str, Any]:
        """Queries autonomous healing status including bucket telemetry, active tunnels, and quota pools."""
        return self._request("GET", "/api/healing/status")

    def consume_healing_bucket(self, tokens: float = 1.0) -> Dict[str, Any]:
        """Consumes capacity tokens from the real-time auto-scaling token bucket rate limiter."""
        return self._request("POST", "/api/healing/bucket/consume", {"tokens": tokens})

    def issue_healing_ticket(
        self,
        client_id: str,
        hwid: str,
        tenant_id: str = "default",
        session_id: str = "",
        last_ack_seq: int = 0,
        ttl_seconds: int = 180,
    ) -> Dict[str, Any]:
        """Issues a cryptographically signed healing ticket allowing a client to resume an interrupted session."""
        payload = {
            "session_id": session_id,
            "client_id": client_id,
            "hwid": hwid,
            "tenant_id": tenant_id,
            "last_ack_seq": last_ack_seq,
            "ttl_seconds": ttl_seconds,
        }
        return self._request("POST", "/api/healing/tunnel/ticket", payload)

    def resume_healing_tunnel(self, ticket: Dict[str, Any]) -> Dict[str, Any]:
        """Resumes an interrupted client connection tunnel and retrieves missed state synchronization events."""
        return self._request("POST", "/api/healing/tunnel/resume", ticket)

    def borrow_healing_quota(
        self,
        borrower_tenant: str,
        lender_tenant: str,
        amount: int,
        duration_minutes: int = 15,
    ) -> Dict[str, Any]:
        """Requests a dynamic quota borrowing lease between tenant pools."""
        payload = {
            "borrower_tenant": borrower_tenant,
            "lender_tenant": lender_tenant,
            "amount": amount,
            "duration_minutes": duration_minutes,
        }
        return self._request("POST", "/api/healing/quota/borrow", payload)

    def return_healing_quota(self, lease_id: str) -> Dict[str, Any]:
        """Voluntarily returns a borrowed quota allocation before or upon expiration."""
        return self._request("POST", "/api/healing/quota/return", {"lease_id": lease_id})

    def recall_healing_quota(self, lease_id: str, reason: str = "") -> Dict[str, Any]:
        """Preemptively recalls borrowed quota when lender tenant load surges."""
        return self._request("POST", "/api/healing/quota/recall", {"lease_id": lease_id, "reason": reason})

    def rebalance_healing_quotas(self) -> Dict[str, Any]:
        """Triggers an automated distributed quota rebalancing evaluation."""
        return self._request("POST", "/api/healing/quota/rebalance", {})


if __name__ == "__main__":
    import sys

    if "--hwid" in sys.argv:
        print(f"Machine HWID: {get_machine_hwid()}")
        sys.exit(0)

    print("Sheet License Broker Python Client SDK v0.4.0")
    print(f"Current HWID: {get_machine_hwid()}")
