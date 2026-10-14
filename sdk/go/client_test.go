package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func TestGoClientHWID(t *testing.T) {
	hwid := GetMachineHWID()
	if !strings.HasPrefix(hwid, "HWID-") {
		t.Fatalf("expected HWID- prefix, got: %s", hwid)
	}
	parts := strings.Split(hwid, "-")
	if len(parts) != 5 {
		t.Fatalf("expected 5 segments, got: %d", len(parts))
	}
}

func TestGoClientVerifyLicenseWithHMAC(t *testing.T) {
	secretKey := []byte("test-go-secret-123")

	mux := http.NewServeMux()
	mux.HandleFunc("/api/licenses/validate", func(w http.ResponseWriter, r *http.Request) {
		sig := r.Header.Get(security.HeaderSignature)
		ts := r.Header.Get(security.HeaderTimestamp)
		nonce := r.Header.Get(security.HeaderNonce)

		if sig == "" || ts == "" || nonce == "" {
			http.Error(w, "missing security headers", http.StatusUnauthorized)
			return
		}

		var payload struct {
			LicenseKey string `json:"license_key"`
			HWID       string `json:"hwid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		if payload.LicenseKey == "VALID-KEY" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ValidationResult{
				Valid:   true,
				Message: "License active and valid",
				Source:  "memory",
				License: &LicenseRecord{
					Key:    payload.LicenseKey,
					Status: "active",
				},
			})
			return
		}

		http.Error(w, "license not found", http.StatusUnauthorized)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, secretKey, 5*time.Second)

	res, err := client.VerifyLicense(context.Background(), "VALID-KEY", "HWID-TEST-1234-5678-90AB")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected valid true, got false")
	}
	if res.License.Key != "VALID-KEY" {
		t.Fatalf("expected key VALID-KEY, got: %s", res.License.Key)
	}

	_, err = client.VerifyLicense(context.Background(), "INVALID-KEY", "HWID-TEST")
	if err == nil {
		t.Fatalf("expected error for invalid key, got nil")
	}
}

func TestGoClientWithTenantHeader(t *testing.T) {
	var capturedTenant string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTenant = r.Header.Get("X-Tenant-ID")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ValidationResult{Valid: true})
	}))
	defer ts.Close()

	client := NewClient(ts.URL, nil, 2*time.Second).WithTenant("tenant-corp")
	_, err := client.VerifyLicense(context.Background(), "CORP-LIC-1111-2222", "HWID-1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedTenant != "tenant-corp" {
		t.Errorf("expected X-Tenant-ID header 'tenant-corp', got '%s'", capturedTenant)
	}
}

func TestGoClientFeatureAndUsage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/features/check", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"enabled": true,
			"tier":    "pro",
		})
	})
	mux.HandleFunc("/api/usage/record", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "success",
			"exceeded": false,
			"record": UsageRecord{
				Key:    "TEST-KEY",
				Metric: "api_calls",
				Period: "2026-10-14",
				Count:  42,
				Limit:  100,
			},
		})
	})
	mux.HandleFunc("/api/usage/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"records": []UsageRecord{
				{
					Key:    "TEST-KEY",
					Metric: "api_calls",
					Period: "2026-10-14",
					Count:  42,
					Limit:  100,
				},
			},
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := NewClient(ts.URL, nil, 2*time.Second)

	// 1. IsFeatureEnabled
	enabled, tier, err := client.IsFeatureEnabled(context.Background(), "TEST-KEY", "analytics")
	if err != nil || !enabled || tier != "pro" {
		t.Errorf("expected feature enabled with pro tier; got enabled=%v, tier=%s, err=%v", enabled, tier, err)
	}

	// 2. RecordUsage
	rec, exceeded, err := client.RecordUsage(context.Background(), "TEST-KEY", "api_calls", "2026-10-14", 42, 100)
	if err != nil || rec.Count != 42 || exceeded {
		t.Errorf("unexpected record usage: count=%d, exceeded=%v, err=%v", rec.Count, exceeded, err)
	}

	// 3. GetUsage
	records, err := client.GetUsage(context.Background(), "TEST-KEY")
	if err != nil || len(records) != 1 || records[0].Count != 42 {
		t.Errorf("unexpected get usage records: len=%d, err=%v", len(records), err)
	}
}

func TestGoClientAttestationAndTelemetry(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/attestation/challenge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "success",
			"challenge_id": "ch-test-1234",
			"nonce":        "deadbeefcafebabe0102030405060708deadbeefcafebabe0102030405060708",
			"expires_at":   time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/api/attestation/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"record": map[string]interface{}{
				"license_key": "TEST-KEY",
				"trust_level": "attested_hardware",
			},
		})
	})
	mux.HandleFunc("/api/attestation/telemetry", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":       "success",
			"tamper_score": 0,
			"tampered":     false,
			"trust_level":  "software_grace",
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := NewClient(ts.URL, nil, 2*time.Second)

	// 1. RequestAttestationChallenge
	chID, nonce, _, err := client.RequestAttestationChallenge(context.Background(), "TEST-KEY", "HWID-TEST")
	if err != nil || chID != "ch-test-1234" || len(nonce) != 64 {
		t.Fatalf("challenge request failed: chID=%s, nonce=%s, err=%v", chID, nonce, err)
	}

	// 2. VerifyTPMAttestation
	rec, err := client.VerifyTPMAttestation(context.Background(), "TEST-KEY", "HWID-TEST", chID, map[string]interface{}{"dummy": true})
	if err != nil || rec["trust_level"] != "attested_hardware" {
		t.Fatalf("tpm attestation verification failed: rec=%v, err=%v", rec, err)
	}

	// 3. ReportTelemetry
	score, tampered, trust, err := client.ReportTelemetry(context.Background(), "TEST-KEY", "HWID-TEST", map[string]interface{}{"debugger_present": false})
	if err != nil || score != 0 || tampered || trust != "software_grace" {
		t.Fatalf("telemetry report failed: score=%d, tampered=%v, trust=%s, err=%v", score, tampered, trust, err)
	}
}

func TestGoClientAuditExport(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/security/audit/export", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"bundle": map[string]interface{}{
				"bundle_id":      "bundle_999",
				"record_count":   15,
				"ciphertext_hex": "abcdef123456",
			},
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := NewClient(ts.URL, nil, 2*time.Second)
	bundle, err := client.ExportAuditToken(context.Background(), "test-key", 50)
	if err != nil {
		t.Fatalf("expected export to succeed: %v", err)
	}
	if bundle["bundle_id"] != "bundle_999" {
		t.Fatalf("expected bundle_id 'bundle_999', got %v", bundle["bundle_id"])
	}
}
