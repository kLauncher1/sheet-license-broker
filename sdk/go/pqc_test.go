package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/pqc"
)

func TestGoClientPQCWorkflow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/pqc/params", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "success",
			"default_algorithm": "Hybrid-P256-MLDSA65",
			"prime_modulus_q":   8380417,
		})
	})
	mux.HandleFunc("/api/pqc/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"count":  1,
			"keys": []map[string]interface{}{
				{"key_id": "PQC-KEY-TEST-01", "algorithm": "Hybrid-P256-MLDSA65", "public_hex": "abcd1234"},
			},
		})
	})
	mux.HandleFunc("/api/pqc/sign", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"signature": pqc.HybridSignature{
				Algorithm:    "Hybrid-P256-MLDSA65",
				KeyID:        "PQC-KEY-TEST-01",
				ClassicalSig: "3045022100abcd",
				QuantumSig:   "deadbeef010203",
				Timestamp:    time.Now().UTC().Format(time.RFC3339),
			},
		})
	})
	mux.HandleFunc("/api/pqc/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"result": pqc.PQCVerificationResult{
				Valid:          true,
				Algorithm:      "Hybrid-P256-MLDSA65",
				KeyID:          "PQC-KEY-TEST-01",
				ClassicalValid: true,
				QuantumValid:   true,
			},
		})
	})
	mux.HandleFunc("/api/pqc/rotate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"rotation": map[string]interface{}{
				"new_key_id": "PQC-KEY-TEST-02",
				"old_key_id": "PQC-KEY-TEST-01",
			},
		})
	})
	mux.HandleFunc("/api/pqc/revoke", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"key_id": "PQC-KEY-TEST-01",
		})
	})
	mux.HandleFunc("/api/pqc/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"pqc": pqc.PQCStatusSummary{
				ActiveKeyID:      "PQC-KEY-TEST-02",
				DefaultAlgorithm: "Hybrid-P256-MLDSA65",
				VerifiedCount:    42,
			},
		})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := NewClient(ts.URL, nil, 2*time.Second)
	ctx := context.Background()

	// Params
	params, err := client.GetPQCParams(ctx)
	if err != nil || params["default_algorithm"] != "Hybrid-P256-MLDSA65" {
		t.Fatalf("failed to get PQC params: %v", err)
	}

	// Keys
	keys, err := client.GetPQCPublicKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0]["key_id"] != "PQC-KEY-TEST-01" {
		t.Fatalf("failed to get PQC keys: %v", err)
	}

	// Sign
	sig, err := client.SignPQCLicense(ctx, "LIC-TEST-GO", "HWID-TEST-01", "sample-payload")
	if err != nil || sig.KeyID != "PQC-KEY-TEST-01" {
		t.Fatalf("failed to sign PQC license: %v", err)
	}

	// Verify
	res, err := client.VerifyPQCSignature(ctx, "sample-payload", *sig)
	if err != nil || !res.Valid || !res.QuantumValid {
		t.Fatalf("failed to verify PQC signature: %v", err)
	}

	// Rotate
	rot, err := client.RotatePQCKey(ctx, "Hybrid-HMAC-MLDSA44", 7, "routine key rotation")
	if err != nil || rot["status"] != "success" {
		t.Fatalf("failed to rotate PQC key: %v", err)
	}

	// Revoke
	if err := client.RevokePQCKey(ctx, "PQC-KEY-TEST-01", "compromised in test"); err != nil {
		t.Fatalf("failed to revoke PQC key: %v", err)
	}

	// Status
	status, err := client.GetPQCStatus(ctx)
	if err != nil || status.VerifiedCount != 42 {
		t.Fatalf("failed to get PQC status: %v", err)
	}
}
