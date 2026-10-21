package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/airgap"
)

func TestGoClientAirgapWorkflow(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/airgap/status":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":                 "success",
				"vault_active":           true,
				"total_issued_tokens":    15,
				"total_verified_tokens":  40,
				"total_activations":      8,
				"rollback_tripped_count": 0,
			})

		case "/api/airgap/token/issue":
			var req airgap.IssueTokenRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(AirgapIssueResponse{
				Status: "success",
				Token: &airgap.DongleToken{
					TokenID:    "DONGLE-MOCK-001",
					LicenseKey: req.LicenseKey,
					HWID:       req.HWID,
					Tier:       req.Tier,
					IssuedAt:   time.Now().Unix(),
					ExpiresAt:  time.Now().Unix() + 86400*30,
					Counter:    5,
				},
				DongleToken: "eyJhbGciOiJFZDI1NTE5In0.eytsaWNlbnNlIjoidGVzdCJ9",
				QRPayload:   "AIRGAP:B45:11223344:MOCKBASE45",
			})

		case "/api/airgap/token/verify":
			_ = json.NewEncoder(w).Encode(AirgapVerifyResponse{
				Status: "success",
				Valid:  true,
				Token: &airgap.DongleToken{
					TokenID:    "DONGLE-MOCK-001",
					LicenseKey: "LIC-AIRGAP-GO-1",
					HWID:       "HWID-GO-CLIENT",
				},
			})

		case "/api/airgap/activate/request":
			var req airgap.ActivationRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(AirgapActivateResponse{
				Status: "success",
				Activation: &airgap.ActivationResponse{
					RequestID:   "ACT-GO-001",
					LicenseKey:  req.LicenseKey,
					HWID:        req.HWID,
					DongleToken: "mock-compact-token",
					QRPayload:   "AIRGAP:B45:AABBCCDD:ACTMOCK",
					Status:      "ACTIVATED",
				},
			})

		case "/api/airgap/activate/fulfill":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "success",
				"token": &airgap.DongleToken{
					TokenID:    "DONGLE-FULFILLED-001",
					LicenseKey: "LIC-AIRGAP-GO-1",
					HWID:       "HWID-GO-CLIENT",
				},
			})

		case "/api/airgap/rollback/state":
			_ = json.NewEncoder(w).Encode(AirgapRollbackResponse{
				Status: "success",
				State: &airgap.RollbackState{
					VaultID:          "VAULT-HWID-GO-CLIENT",
					HWID:             "HWID-GO-CLIENT",
					HighWaterMark:    time.Now().Unix(),
					MonotonicCounter: 42,
					Tampered:         false,
				},
			})

		case "/api/airgap/rollback/unlock":
			_ = json.NewEncoder(w).Encode(AirgapRollbackResponse{
				Status: "success",
				State: &airgap.RollbackState{
					VaultID:          "VAULT-HWID-GO-CLIENT",
					HWID:             "HWID-GO-CLIENT",
					HighWaterMark:    time.Now().Unix(),
					MonotonicCounter: 43,
					Tampered:         false,
					UnlockedAt:       time.Now().Unix(),
				},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	client := NewClient(mockServer.URL, []byte("test-secret"), 5*time.Second)
	ctx := context.Background()

	// 1. Get status
	st, err := client.GetAirgapStatus(ctx)
	if err != nil {
		t.Fatalf("GetAirgapStatus error: %v", err)
	}
	if st["status"] != "success" || st["vault_active"] != true {
		t.Fatalf("Status unexpected: %+v", st)
	}

	// 2. Issue token
	tok, compact, qr, err := client.IssueAirgapDongleToken(ctx, "LIC-AIRGAP-GO-1", "HWID-GO-CLIENT", "enterprise", 30, 1, []string{"airgap"})
	if err != nil {
		t.Fatalf("IssueAirgapDongleToken error: %v", err)
	}
	if tok == nil || compact == "" || qr == "" {
		t.Fatalf("Expected token, compact, qr")
	}

	// 3. Verify token
	vTok, err := client.VerifyAirgapDongleToken(ctx, compact, "HWID-GO-CLIENT")
	if err != nil {
		t.Fatalf("VerifyAirgapDongleToken error: %v", err)
	}
	if vTok.LicenseKey != "LIC-AIRGAP-GO-1" {
		t.Fatalf("Verified key mismatch: %s", vTok.LicenseKey)
	}

	// 4. Request activation
	act, err := client.RequestAirgapActivation(ctx, "LIC-AIRGAP-GO-1", "HWID-GO-CLIENT")
	if err != nil {
		t.Fatalf("RequestAirgapActivation error: %v", err)
	}
	if act.Status != "ACTIVATED" || act.QRPayload == "" {
		t.Fatalf("Activation response mismatch: %+v", act)
	}

	// 5. Fulfill activation
	fTok, err := client.FulfillAirgapActivation(ctx, act.QRPayload)
	if err != nil {
		t.Fatalf("FulfillAirgapActivation error: %v", err)
	}
	if fTok.LicenseKey != "LIC-AIRGAP-GO-1" {
		t.Fatalf("Fulfilled key mismatch: %s", fTok.LicenseKey)
	}

	// 6. Get rollback state
	rbState, err := client.GetAirgapRollbackState(ctx, "HWID-GO-CLIENT")
	if err != nil {
		t.Fatalf("GetAirgapRollbackState error: %v", err)
	}
	if rbState.MonotonicCounter != 42 {
		t.Fatalf("Expected counter 42, got %d", rbState.MonotonicCounter)
	}

	// 7. Unlock rollback
	uState, err := client.UnlockAirgapRollback(ctx, airgap.UnlockRequest{
		VaultID:        rbState.VaultID,
		HWID:           "HWID-GO-CLIENT",
		Nonce:          "NONCE-99",
		Timestamp:      time.Now().Unix(),
		AdminSignature: "MOCK_SIG",
	})
	if err != nil {
		t.Fatalf("UnlockAirgapRollback error: %v", err)
	}
	if uState.MonotonicCounter != 43 || uState.Tampered {
		t.Fatalf("Expected unlocked state: %+v", uState)
	}
}
