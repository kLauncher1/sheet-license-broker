package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/sheet-license-broker/internal/mlkem"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func newTestMLKEMServer(t *testing.T) *AppServer {
	px, err := proxy.NewProxy(proxy.ProxyConfig{
		OfflineMode:          true,
		GlobalSecret:         "test-routes-mlkem-secret",
		MLKEMQuantumEnforced: false,
	})
	if err != nil {
		t.Fatalf("Failed to init proxy: %v", err)
	}
	secGuard := security.NewGuard([]byte("test-routes-mlkem-secret"), 0, false)
	return &AppServer{proxy: px, guard: secGuard}
}

func TestRoutesMLKEMLifecycle(t *testing.T) {
	server := newTestMLKEMServer(t)
	apiMux := http.NewServeMux()
	server.registerMLKEMRoutes(apiMux)

	// 1. GET /api/pqc/kem/status
	req := httptest.NewRequest(http.MethodGet, "/api/pqc/kem/status", nil)
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/pqc/kem/status, got %d: %s", w.Code, w.Body.String())
	}
	var status mlkem.MLKEMStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode status: %v", err)
	}
	if !status.Initialized || status.ActiveKeysCount < 1 {
		t.Errorf("Unexpected status values: %+v", status)
	}

	// 2. GET /api/pqc/kem/keys
	req = httptest.NewRequest(http.MethodGet, "/api/pqc/kem/keys", nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/pqc/kem/keys, got %d", w.Code)
	}
	var keysResp struct {
		Keys []*mlkem.PublicKey `json:"keys"`
	}
	if err := json.NewDecoder(w.Body).Decode(&keysResp); err != nil || len(keysResp.Keys) == 0 {
		t.Fatalf("Failed to decode keys or keys empty: %v", err)
	}
	defaultKeyID := keysResp.Keys[0].KeyID

	// 3. POST /api/pqc/kem/keys/generate
	genBody, _ := json.Marshal(map[string]string{"algorithm": mlkem.AlgoMLKEM1024})
	req = httptest.NewRequest(http.MethodPost, "/api/pqc/kem/keys/generate", bytes.NewReader(genBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/pqc/kem/keys/generate, got %d: %s", w.Code, w.Body.String())
	}
	var pk1024 mlkem.PublicKey
	if err := json.NewDecoder(w.Body).Decode(&pk1024); err != nil || pk1024.Algorithm != mlkem.AlgoMLKEM1024 {
		t.Fatalf("Failed to decode generated key: %v", err)
	}

	// 4. POST /api/pqc/kem/encapsulate
	encapBody, _ := json.Marshal(map[string]string{"key_id": defaultKeyID})
	req = httptest.NewRequest(http.MethodPost, "/api/pqc/kem/encapsulate", bytes.NewReader(encapBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/pqc/kem/encapsulate, got %d: %s", w.Code, w.Body.String())
	}
	var encapRes mlkem.EncapsulationResult
	if err := json.NewDecoder(w.Body).Decode(&encapRes); err != nil || encapRes.CiphertextHex == "" {
		t.Fatalf("Failed to decode encapsulation result: %v", err)
	}

	// 5. POST /api/pqc/kem/decapsulate
	decapBody, _ := json.Marshal(map[string]string{
		"key_id":         defaultKeyID,
		"ciphertext_hex": encapRes.CiphertextHex,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/pqc/kem/decapsulate", bytes.NewReader(decapBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/pqc/kem/decapsulate, got %d: %s", w.Code, w.Body.String())
	}
	var decapRes struct {
		KeyID           string `json:"key_id"`
		SharedSecretHex string `json:"shared_secret_hex"`
	}
	if err := json.NewDecoder(w.Body).Decode(&decapRes); err != nil || decapRes.SharedSecretHex != encapRes.SharedSecretHex {
		t.Fatalf("Decapsulation shared secret mismatch: expected %s, got %s", encapRes.SharedSecretHex, decapRes.SharedSecretHex)
	}

	// 6. POST /api/pqc/kem/handshake
	_, clientPubBytes, _ := mlkem.GenerateEphemeralECDH()
	clientPubHex := hex.EncodeToString(clientPubBytes)
	hsBody, _ := json.Marshal(mlkem.HybridHandshakeRequest{
		ClientECDHPublicKey: clientPubHex,
		RequestedMode:       mlkem.ModeHybrid,
		Algorithm:           mlkem.AlgoMLKEM768,
		ClientNonce:         "routes-test-nonce-123",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/pqc/kem/handshake", bytes.NewReader(hsBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/pqc/kem/handshake, got %d: %s", w.Code, w.Body.String())
	}
	var hsResp mlkem.HybridHandshakeResponse
	if err := json.NewDecoder(w.Body).Decode(&hsResp); err != nil || hsResp.SessionID == "" {
		t.Fatalf("Failed to decode handshake response: %v", err)
	}
	if !hsResp.QuantumResistant {
		t.Errorf("Expected quantum_resistant=true in hybrid mode")
	}

	// 7. GET /api/pqc/kem/sessions/verify
	req = httptest.NewRequest(http.MethodGet, "/api/pqc/kem/sessions/verify?session_id="+hsResp.SessionID, nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 on /api/pqc/kem/sessions/verify, got %d: %s", w.Code, w.Body.String())
	}
	var verifyResp struct {
		Valid     bool   `json:"valid"`
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&verifyResp); err != nil || !verifyResp.Valid || verifyResp.SessionID != hsResp.SessionID {
		t.Fatalf("Unexpected session verification response: %+v", verifyResp)
	}
}
