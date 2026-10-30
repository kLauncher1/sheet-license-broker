package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/sheet-license-broker/internal/hsm"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func newTestHSMServer(t *testing.T) *AppServer {
	px, err := proxy.NewProxy(proxy.ProxyConfig{
		OfflineMode:  true,
		GlobalSecret: "test-routes-hsm-secret",
	})
	if err != nil {
		t.Fatalf("Failed to init proxy: %v", err)
	}
	secGuard := security.NewGuard([]byte("test-routes-hsm-secret"), 0, false)
	return &AppServer{proxy: px, guard: secGuard}
}

func TestRoutesHSMLifecycle(t *testing.T) {
	server := newTestHSMServer(t)
	apiMux := http.NewServeMux()
	server.registerHSMRoutes(apiMux)

	// 1. GET /api/hsm/status
	req := httptest.NewRequest(http.MethodGet, "/api/hsm/status", nil)
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/hsm/status, got %d: %s", w.Code, w.Body.String())
	}

	var status hsm.HSMVaultStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode status: %v", err)
	}
	if !status.Initialized || status.FIPSLevel != hsm.FIPSLevel4 {
		t.Errorf("Unexpected status values: %+v", status)
	}

	// 2. GET /api/hsm/slots
	req = httptest.NewRequest(http.MethodGet, "/api/hsm/slots", nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/hsm/slots, got %d", w.Code)
	}

	var slotsResp struct {
		Slots []hsm.SlotInfo `json:"slots"`
	}
	_ = json.NewDecoder(w.Body).Decode(&slotsResp)
	if len(slotsResp.Slots) != 3 {
		t.Fatalf("Expected 3 slots, got %d", len(slotsResp.Slots))
	}

	// 3. POST /api/hsm/login
	loginBody, _ := json.Marshal(map[string]interface{}{
		"slot_id":   0,
		"user_type": "USER",
		"pin":       "FIPS-ROOT-PIN-9842",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/hsm/login", bytes.NewReader(loginBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/hsm/login, got %d: %s", w.Code, w.Body.String())
	}

	// 4. POST /api/hsm/derive
	deriveBody, _ := json.Marshal(hsm.KeyDerivationRequest{
		SlotID:  0,
		Purpose: "audit_token_encryption",
		Context: "ROUTES-TEST-CONTEXT",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/hsm/derive", bytes.NewReader(deriveBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/hsm/derive, got %d: %s", w.Code, w.Body.String())
	}

	var deriveResp hsm.KeyDerivationResponse
	_ = json.NewDecoder(w.Body).Decode(&deriveResp)
	if deriveResp.Fingerprint == "" {
		t.Errorf("Expected fingerprint, got empty")
	}

	// 5. POST /api/hsm/encrypt
	encBody, _ := json.Marshal(hsm.EnvelopeEncryptRequest{
		SlotID:         1,
		Plaintext:      "SECRET-DATA-ROUTES",
		AssociatedData: "TENANT-ROUTE-AAD",
		Purpose:        "audit_token_encryption",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/hsm/encrypt", bytes.NewReader(encBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/hsm/encrypt, got %d: %s", w.Code, w.Body.String())
	}

	var encResp hsm.EnvelopeEncryptResponse
	_ = json.NewDecoder(w.Body).Decode(&encResp)

	// 6. POST /api/hsm/decrypt
	decBody, _ := json.Marshal(hsm.EnvelopeDecryptRequest{
		SlotID:         1,
		CiphertextHex:  encResp.CiphertextHex,
		NonceHex:       encResp.NonceHex,
		AssociatedData: "TENANT-ROUTE-AAD",
		Purpose:        "audit_token_encryption",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/hsm/decrypt", bytes.NewReader(decBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/hsm/decrypt, got %d: %s", w.Code, w.Body.String())
	}

	var decResp hsm.EnvelopeDecryptResponse
	_ = json.NewDecoder(w.Body).Decode(&decResp)
	if decResp.Plaintext != "SECRET-DATA-ROUTES" {
		t.Errorf("Decrypted text mismatch: %s", decResp.Plaintext)
	}

	// 7. POST /api/hsm/fips/selftest
	req = httptest.NewRequest(http.MethodPost, "/api/hsm/fips/selftest", nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/hsm/fips/selftest, got %d", w.Code)
	}

	// 8. GET /api/hsm/fips/report
	req = httptest.NewRequest(http.MethodGet, "/api/hsm/fips/report", nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/hsm/fips/report, got %d", w.Code)
	}

	// 9. POST /api/hsm/tamper/simulate
	tamperBody, _ := json.Marshal(map[string]interface{}{
		"sensor_id": "PHYSICAL_MESH_BREACH",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/hsm/tamper/simulate", bytes.NewReader(tamperBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/hsm/tamper/simulate, got %d", w.Code)
	}

	// 10. POST /api/hsm/zeroize
	req = httptest.NewRequest(http.MethodPost, "/api/hsm/zeroize", nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/hsm/zeroize, got %d", w.Code)
	}
}
