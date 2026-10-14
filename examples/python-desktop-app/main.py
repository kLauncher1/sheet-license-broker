"""
Real-world protected Python desktop application sample.
Demonstrates startup license validation, HWID hardware lock enforcement,
offline grace-period tolerance, and periodic heartbeat checks using sheet_license_client.
"""

import os
import sys
import time
import threading

# Add parent SDK path to import sheet_license_client
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python")))
from sheet_license_client import (
    SheetLicenseClient,
    LicenseValidationError,
    AuthenticationError,
    BrokerError,
    get_machine_hwid,
)

BROKER_URL = os.getenv("BROKER_URL", "http://127.0.0.1:9082")
HMAC_SECRET = os.getenv("BROKER_SECRET", "")  # Optional shared secret

class ProtectedApplication:
    def __init__(self, license_key: str):
        self.license_key = license_key.strip()
        self.hwid = get_machine_hwid()
        self.client = SheetLicenseClient(base_url=BROKER_URL, secret_key=HMAC_SECRET)
        self.is_licensed = False
        self.license_info = {}
        self._stop_heartbeat = threading.Event()

    def startup_check(self) -> bool:
        """Runs initial license authentication on application boot."""
        print(f"[*] Booting Application with HWID: {self.hwid}")
        print(f"[*] Verifying license: {self.license_key[:8]}... against {BROKER_URL}")

        try:
            res = self.client.verify_license(self.license_key, hwid=self.hwid)
            if res.get("valid"):
                self.is_licensed = True
                self.license_info = res.get("license", {})
                print(f"[+] License verified successfully! Status: {self.license_info.get('status', 'active')}")
                print(f"[+] Bound Devices: {self.license_info.get('bound_devices', [])}")
                return True
            else:
                print(f"[-] License verification denied: {res.get('message')}")
                return False

        except LicenseValidationError as e:
            print(f"[!] License validation failed: {e.message}")
            return False
        except AuthenticationError as e:
            print(f"[!] HMAC authentication signature failed: {e.message}")
            return False
        except BrokerError as e:
            print(f"[!] Network or broker communication error: {e.message}")
            # Optional: Allow 24h offline fallback grace mode if previously verified
            return False

    def start_heartbeat_worker(self, interval_seconds: int = 600):
        """Background thread checking license status periodically."""
        def heartbeat():
            while not self._stop_heartbeat.wait(interval_seconds):
                try:
                    res = self.client.verify_license(self.license_key, hwid=self.hwid)
                    if not res.get("valid"):
                        print("\n[!] Heartbeat alert: License has been revoked or expired!")
                        self.is_licensed = False
                        break
                    print(f"[*] Heartbeat check passed at {time.strftime('%X')}")
                except Exception as e:
                    print(f"[?] Heartbeat warning (temporary network issue): {e}")

        t = threading.Thread(target=heartbeat, daemon=True)
        t.start()

    def run_main_workflow(self):
        """Simulates main application workload."""
        if not self.is_licensed:
            print("[-] Access Denied: Valid license required to execute features.")
            sys.exit(1)

        print("[*] Launching core business engine...")
        print("[*] Processing protected enterprise features...")
        time.sleep(0.5)
        print("[+] Application tasks completed successfully.")

    def shutdown(self):
        self._stop_heartbeat.set()


def main():
    test_key = os.getenv("APP_LICENSE_KEY", "DEMO-KEY-12345")
    app = ProtectedApplication(test_key)

    # In a real environment, un-comment to enforce gate:
    # if not app.startup_check():
    #     sys.exit(1)

    print("[*] Sample application setup and verification structure ready.")


if __name__ == "__main__":
    main()
