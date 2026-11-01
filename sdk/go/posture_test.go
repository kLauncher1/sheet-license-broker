package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/posture"
)

func TestGoSDK_PostureSubsystem(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/posture/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(posture.PostureStatus{
			ActivePolicies:   1,
			TotalEvaluations: 12,
			HealthyCount:     10,
			WarningCount:     1,
			QuarantineCount:  1,
			Version:          "2.6.0",
		})
	})

	mux.HandleFunc("/api/posture/evaluate", func(w http.ResponseWriter, r *http.Request) {
		var req posture.DevicePostureReport
		_ = json.NewDecoder(r.Body).Decode(&req)
		tier := posture.PostureTierHealthy
		score := 95.0
		if req.Integrity.DebuggerAttached {
			tier = posture.PostureTierQuarantine
			score = 20.0
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(posture.PostureVectorScores{
			DeviceID:       req.DeviceID,
			TenantID:       req.TenantID,
			Tier:           tier,
			CompositeScore: score,
			EvaluatedAt:    time.Now().UTC(),
		})
	})

	mux.HandleFunc("/api/posture/quarantine", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tenant_id": "tenant-test",
			"quarantined": []posture.QuarantinedDevice{
				{
					DeviceID:            "dev-bad-1",
					TenantID:            "tenant-test",
					Reason:              "Debugger attached",
					CompositeScore:      20.0,
					Tier:                posture.PostureTierQuarantine,
					DegradedModeAllowed: false,
				},
			},
			"count": 1,
		})
	})

	mux.HandleFunc("/api/posture/quarantine/release", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":    "released",
			"device_id": "dev-bad-1",
			"tenant_id": "tenant-test",
		})
	})

	mux.HandleFunc("/api/posture/step-up/challenge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(posture.StepUpChallenge{
			ChallengeID: "chall-12345",
			DeviceID:    "dev-step-1",
			TenantID:    "tenant-test",
			Nonce:       "nonce-abcde",
			Completed:   false,
		})
	})

	mux.HandleFunc("/api/posture/step-up/verify", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["nonce"] == "nonce-abcde" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":       "verified",
				"challenge_id": req["challenge_id"],
			})
		} else {
			http.Error(w, `{"error":"invalid nonce"}`, http.StatusUnauthorized)
		}
	})

	mux.HandleFunc("/api/posture/device", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scores": posture.PostureVectorScores{
				DeviceID:       "dev-lookup-1",
				TenantID:       "tenant-test",
				Tier:           posture.PostureTierHealthy,
				CompositeScore: 92.5,
			},
			"quarantined": false,
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, nil, 5*time.Second)
	ctx := context.Background()

	// 1. GetPostureStatus
	status, err := client.GetPostureStatus(ctx)
	if err != nil || status == nil || status.Version != "2.6.0" {
		t.Fatalf("failed to query posture status: %v", err)
	}

	// 2. EvaluateDevicePosture
	scores, err := client.EvaluateDevicePosture(ctx, posture.DevicePostureReport{
		DeviceID: "dev-clean-1",
		TenantID: "tenant-test",
	})
	if err != nil || scores.Tier != posture.PostureTierHealthy {
		t.Fatalf("failed to evaluate posture: %v", err)
	}

	// 3. GetQuarantinedDevices
	quarList, err := client.GetQuarantinedDevices(ctx, "tenant-test")
	if err != nil || len(quarList) != 1 {
		t.Fatalf("failed to query quarantined devices: %v", err)
	}

	// 4. ReleaseDeviceQuarantine
	released, err := client.ReleaseDeviceQuarantine(ctx, "tenant-test", "dev-bad-1")
	if err != nil || !released {
		t.Fatalf("failed to release quarantine: %v", err)
	}

	// 5. IssueDeviceStepUpChallenge and VerifyDeviceStepUpChallenge
	challenge, err := client.IssueDeviceStepUpChallenge(ctx, "tenant-test", "dev-step-1", []string{"mfa"})
	if err != nil || challenge.ChallengeID != "chall-12345" {
		t.Fatalf("failed to issue step-up challenge: %v", err)
	}

	verified, err := client.VerifyDeviceStepUpChallenge(ctx, challenge.ChallengeID, challenge.Nonce)
	if err != nil || !verified {
		t.Fatalf("failed to verify step-up challenge: %v", err)
	}

	// 6. GetDevicePosture
	devScore, isQ, err := client.GetDevicePosture(ctx, "tenant-test", "dev-lookup-1")
	if err != nil || isQ || devScore.CompositeScore != 92.5 {
		t.Fatalf("failed to get device posture: %v", err)
	}
}
