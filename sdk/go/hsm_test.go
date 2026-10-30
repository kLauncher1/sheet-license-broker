package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/hsm"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
)

func TestGoSDK_HSMSubsystem(t *testing.T) {
	px, err := proxy.NewProxy(proxy.ProxyConfig{
		OfflineMode: true,
	})
	if err != nil {
		t.Fatalf("Failed to init proxy: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/hsm/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(px.GetHSMStatus())
	})
	mux.HandleFunc("/api/hsm/slots", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"slots": px.ListHSMSlots()})
	})
	mux.HandleFunc("/api/hsm/login", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"authenticated": true})
	})
	mux.HandleFunc("/api/hsm/logout", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"logged_out": true})
	})
	mux.HandleFunc("/api/hsm/derive", func(w http.ResponseWriter, r *http.Request) {
		resp, _ := px.DeriveHSMKey(r.Context(), hsm.KeyDerivationRequest{
			SlotID:  0,
			Purpose: "audit_token_encryption",
			Context: "SDK-TEST-CTX",
		})
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/hsm/encrypt", func(w http.ResponseWriter, r *http.Request) {
		resp, _ := px.EncryptHSMEnvelope(hsm.EnvelopeEncryptRequest{
			SlotID:         1,
			Plaintext:      "SDK-PLAINTEXT",
			AssociatedData: "SDK-AAD",
		})
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/hsm/decrypt", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(hsm.EnvelopeDecryptResponse{
			SlotID:        1,
			Plaintext:     "SDK-PLAINTEXT",
			Authenticated: true,
		})
	})
	mux.HandleFunc("/api/hsm/fips/selftest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"self_tests": px.RunHSMSelfTest(),
			"count":      5,
		})
	})
	mux.HandleFunc("/api/hsm/fips/report", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(px.GetHSMFIPSReport())
	})
	mux.HandleFunc("/api/hsm/tamper/simulate", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"tamper_latched": true})
	})
	mux.HandleFunc("/api/hsm/zeroize", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"zeroized": true})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, nil, 5*time.Second)

	ctx := context.Background()

	// 1. Status
	status, err := client.GetHSMStatus(ctx)
	if err != nil {
		t.Fatalf("GetHSMStatus failed: %v", err)
	}
	if !status.Initialized {
		t.Errorf("Expected Initialized true")
	}

	// 2. Slots
	slots, err := client.ListHSMSlots(ctx)
	if err != nil {
		t.Fatalf("ListHSMSlots failed: %v", err)
	}
	if len(slots) != 3 {
		t.Fatalf("Expected 3 slots, got %d", len(slots))
	}

	// 3. Login & Logout
	if err := client.HSMLogin(ctx, 0, "USER", "FIPS-ROOT-PIN-9842"); err != nil {
		t.Fatalf("HSMLogin failed: %v", err)
	}
	if err := client.HSMLogout(ctx, 0); err != nil {
		t.Fatalf("HSMLogout failed: %v", err)
	}

	// 4. Derive Key
	deriv, err := client.DeriveHSMKey(ctx, hsm.KeyDerivationRequest{
		SlotID:  0,
		Purpose: "audit_token_encryption",
		Context: "SDK-TEST-CTX",
	})
	if err != nil {
		t.Fatalf("DeriveHSMKey failed: %v", err)
	}
	if deriv.Fingerprint == "" {
		t.Errorf("Expected fingerprint, got empty")
	}

	// 5. Encrypt & Decrypt
	enc, err := client.EncryptHSMEnvelope(ctx, hsm.EnvelopeEncryptRequest{
		SlotID:         1,
		Plaintext:      "SDK-PLAINTEXT",
		AssociatedData: "SDK-AAD",
	})
	if err != nil {
		t.Fatalf("EncryptHSMEnvelope failed: %v", err)
	}

	dec, err := client.DecryptHSMEnvelope(ctx, hsm.EnvelopeDecryptRequest{
		SlotID:         1,
		CiphertextHex:  enc.CiphertextHex,
		NonceHex:       enc.NonceHex,
		AssociatedData: "SDK-AAD",
	})
	if err != nil {
		t.Fatalf("DecryptHSMEnvelope failed: %v", err)
	}
	if dec.Plaintext != "SDK-PLAINTEXT" {
		t.Errorf("Plaintext mismatch: %s", dec.Plaintext)
	}

	// 6. FIPS Self-Test & Report
	tests, err := client.RunHSMSelfTest(ctx)
	if err != nil {
		t.Fatalf("RunHSMSelfTest failed: %v", err)
	}
	if len(tests) != 5 {
		t.Fatalf("Expected 5 tests, got %d", len(tests))
	}

	rep, err := client.GetHSMFIPSReport(ctx)
	if err != nil {
		t.Fatalf("GetHSMFIPSReport failed: %v", err)
	}
	if rep.CertificationLevel != hsm.FIPSLevel4 {
		t.Errorf("Expected FIPS Level 4, got %s", rep.CertificationLevel)
	}

	// 7. Tamper & Zeroize
	if err := client.SimulateHSMTamper(ctx, "VOLTAGE_SPIKE"); err != nil {
		t.Fatalf("SimulateHSMTamper failed: %v", err)
	}
	if err := client.ZeroizeHSM(ctx); err != nil {
		t.Fatalf("ZeroizeHSM failed: %v", err)
	}
}
