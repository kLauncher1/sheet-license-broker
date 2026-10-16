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


if __name__ == "__main__":
    import sys

    if "--hwid" in sys.argv:
        print(f"Machine HWID: {get_machine_hwid()}")
        sys.exit(0)

    print("Sheet License Broker Python Client SDK v0.4.0")
    print(f"Current HWID: {get_machine_hwid()}")
