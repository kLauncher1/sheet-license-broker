package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/enclave"
)

func TestGoClientEnclaveWorkflow(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/enclave/challenge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"challenge":  "f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f",
			"expires_in": 300,
		})
	})

	mux.HandleFunc("/api/enclave/attest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": true,
			"attestation": enclave.AttestationResult{
				Valid:         true,
				Platform:      enclave.PlatformSGX,
				MREnclave:     "aabbccddeeff",
				MRSigner:      "112233445566",
				SVN:           2,
				Debug:         false,
				ReportDataHex: "00112233",
			},
		})
	})

	mux.HandleFunc("/api/enclave/tunnel/handshake", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(EnclaveHandshakeResult{
			Established:     true,
			SessionID:       "sess-mock-enclave-999",
			BrokerPublicKey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			ExpiresAt:       "2030-01-01T00:00:00Z",
		})
	})

	mux.HandleFunc("/api/enclave/tunnel/evaluate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"session_id": "sess-mock-enclave-999",
			"sequence":   1,
			"nonce":      "0102030405060708090a0b0c",
			"payload":    "cafebabedeadbeef",
		})
	})

	mux.HandleFunc("/api/enclave/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"telemetry": enclave.EnclaveTelemetry{
				VerifiedQuotes:   5,
				ActiveTunnels:    2,
				TotalEvaluations: 10,
			},
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, nil, 5*time.Second)
	ctx := context.Background()

	// 1. Request challenge
	challenge, err := client.RequestEnclaveChallenge(ctx)
	if err != nil {
		t.Fatalf("failed to request challenge: %v", err)
	}
	if len(challenge) != 64 {
		t.Fatalf("unexpected challenge: %s", challenge)
	}

	// 2. Attest quote
	attestRes, err := client.AttestEnclaveQuote(ctx, enclave.PlatformSGX, []byte("quote-bytes"), challenge, "policy-1")
	if err != nil {
		t.Fatalf("attest quote failed: %v", err)
	}
	if !attestRes.Valid || attestRes.Platform != enclave.PlatformSGX {
		t.Fatalf("unexpected attest result: %+v", attestRes)
	}

	// 3. Establish tunnel
	hsRes, err := client.EstablishEnclaveTunnel(ctx, enclave.PlatformSGX, []byte("quote-bytes"), challenge, "policy-1", "client-pub-hex")
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !hsRes.Established || hsRes.SessionID != "sess-mock-enclave-999" {
		t.Fatalf("unexpected handshake result: %+v", hsRes)
	}

	// 4. Evaluate license
	evalResp, err := client.EvaluateEnclaveLicense(ctx, &enclave.EncryptedTunnelMessage{
		SessionID:  hsRes.SessionID,
		Sequence:   1,
		NonceHex:   "0102030405060708090a0b0c",
		PayloadHex: "aabbcc",
	})
	if err != nil {
		t.Fatalf("eval failed: %v", err)
	}
	if evalResp.PayloadHex != "cafebabedeadbeef" {
		t.Fatalf("unexpected payload hex: %s", evalResp.PayloadHex)
	}

	// 5. Get status
	status, err := client.GetEnclaveStatus(ctx)
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if status["telemetry"] == nil {
		t.Fatal("expected telemetry in status response")
	}
}
