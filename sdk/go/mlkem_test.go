package sdk

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/mlkem"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
)

func TestGoSDK_MLKEMSubsystem(t *testing.T) {
	px, err := proxy.NewProxy(proxy.ProxyConfig{
		OfflineMode:          true,
		MLKEMQuantumEnforced: false,
	})
	if err != nil {
		t.Fatalf("Failed to init proxy: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/pqc/kem/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(px.GetMLKEMStatus())
	})
	mux.HandleFunc("/api/pqc/kem/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": px.ListMLKEMKeys()})
	})
	mux.HandleFunc("/api/pqc/kem/keys/generate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Algorithm string `json:"algorithm"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		pk, _ := px.GenerateMLKEMKey(req.Algorithm)
		_ = json.NewEncoder(w).Encode(pk)
	})
	mux.HandleFunc("/api/pqc/kem/encapsulate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			KeyID string `json:"key_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res, _ := px.EncapsulateMLKEM(req.KeyID)
		_ = json.NewEncoder(w).Encode(res)
	})
	mux.HandleFunc("/api/pqc/kem/decapsulate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			KeyID         string `json:"key_id"`
			CiphertextHex string `json:"ciphertext_hex"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		cBytes, _ := hex.DecodeString(req.CiphertextHex)
		ss, _ := px.DecapsulateMLKEM(req.KeyID, cBytes)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"key_id":            req.KeyID,
			"shared_secret_hex": hex.EncodeToString(ss),
		})
	})
	mux.HandleFunc("/api/pqc/kem/handshake", func(w http.ResponseWriter, r *http.Request) {
		var req mlkem.HybridHandshakeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp, _ := px.HandleHybridKEMHandshake(req)
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/pqc/kem/sessions/verify", func(w http.ResponseWriter, r *http.Request) {
		sessID := r.URL.Query().Get("session_id")
		sess, err := px.VerifyHybridKEMSession(sessID)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":      true,
			"session_id": sess.SessionID,
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, nil, 5*time.Second)

	ctx := context.Background()

	// 1. Status
	status, err := client.GetMLKEMStatus(ctx)
	if err != nil {
		t.Fatalf("GetMLKEMStatus failed: %v", err)
	}
	if !status.Initialized || status.ActiveKeysCount < 1 {
		t.Fatalf("unexpected ML-KEM status: %+v", status)
	}

	// 2. Keys
	keys, err := client.ListMLKEMKeys(ctx)
	if err != nil || len(keys) == 0 {
		t.Fatalf("ListMLKEMKeys failed: %v", err)
	}
	defaultKey := keys[0].KeyID

	// 3. Generate ML-KEM-1024
	pk1024, err := client.GenerateMLKEMKey(ctx, mlkem.AlgoMLKEM1024)
	if err != nil || pk1024.Algorithm != mlkem.AlgoMLKEM1024 {
		t.Fatalf("GenerateMLKEMKey failed: %v", err)
	}

	// 4. Encapsulate & Decapsulate
	encap, err := client.EncapsulateMLKEM(ctx, defaultKey)
	if err != nil || encap.CiphertextHex == "" {
		t.Fatalf("EncapsulateMLKEM failed: %v", err)
	}

	ssHex, err := client.DecapsulateMLKEM(ctx, defaultKey, encap.CiphertextHex)
	if err != nil || ssHex != encap.SharedSecretHex {
		t.Fatalf("DecapsulateMLKEM mismatch: %v, ssHex=%s", err, ssHex)
	}

	// 5. Hybrid Handshake
	_, clientPubBytes, _ := mlkem.GenerateEphemeralECDH()
	clientPubHex := hex.EncodeToString(clientPubBytes)
	hsResp, err := client.HybridKEMHandshake(ctx, mlkem.HybridHandshakeRequest{
		ClientECDHPublicKey: clientPubHex,
		RequestedMode:       mlkem.ModeHybrid,
		Algorithm:           mlkem.AlgoMLKEM768,
	})
	if err != nil || hsResp.SessionID == "" || !hsResp.QuantumResistant {
		t.Fatalf("HybridKEMHandshake failed: %v", err)
	}

	// 6. Verify Session
	valid, err := client.VerifyHybridKEMSession(ctx, hsResp.SessionID)
	if err != nil || !valid {
		t.Fatalf("VerifyHybridKEMSession failed: %v", err)
	}
}
