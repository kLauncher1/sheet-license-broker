package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/posture"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func newTestAppServerWithPosture(t *testing.T) *AppServer {
	px, err := proxy.NewProxy(proxy.ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}
	secGuard := security.NewGuard([]byte("test-secret"), 5*time.Minute, false)
	return &AppServer{proxy: px, guard: secGuard}
}

func TestRoutesPostureStatus(t *testing.T) {
	server := newTestAppServerWithPosture(t)
	defer server.proxy.Close()

	apiMux := http.NewServeMux()
	server.registerPostureRoutes(apiMux)

	req := httptest.NewRequest(http.MethodGet, "/api/posture/status", nil)
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var status posture.PostureStatus
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to parse status json: %v", err)
	}
	if status.Version != "2.6.0" {
		t.Fatalf("expected version 2.6.0, got %s", status.Version)
	}
}

func TestRoutesPostureEvaluateAndQuarantine(t *testing.T) {
	server := newTestAppServerWithPosture(t)
	defer server.proxy.Close()

	apiMux := http.NewServeMux()
	server.registerPostureRoutes(apiMux)

	// 1. Evaluate clean device
	evalReq := posture.DevicePostureReport{
		DeviceID: "dev-test-node-1",
		TenantID: "tenant-acme",
		HWID:     "HWID-TEST-001",
		OS: posture.OSVectorReport{
			OSName:            "Linux",
			OSVersion:         "Ubuntu 24.04",
			KernelVersion:     "6.8.0",
			PatchLevelDays:    4,
			MinPatchLevelDays: 30,
		},
		Hardware: posture.HardwareVectorReport{
			SecureBootEnabled:    true,
			TPMPresent:           true,
			TPMVersion:           "2.0",
			DiskEncryptionActive: true,
		},
		Endpoint: posture.EndpointVectorReport{
			AntivirusActive:    true,
			DefinitionsAgeDays: 1,
			RealtimeProtection: true,
			FirewallEnabled:    true,
		},
		Integrity: posture.IntegrityVectorReport{
			DebuggerAttached:       false,
			RootedOrJailbroken:     false,
			VirtualizationDetected: false,
			CodeIntegrityVerified:  true,
		},
		Timestamp: time.Now().UTC().Unix(),
	}

	body, _ := json.Marshal(evalReq)
	req := httptest.NewRequest(http.MethodPost, "/api/posture/evaluate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var scores posture.PostureVectorScores
	if err := json.Unmarshal(w.Body.Bytes(), &scores); err != nil {
		t.Fatalf("failed to decode scores: %v", err)
	}
	if scores.Tier != posture.PostureTierHealthy {
		t.Fatalf("expected healthy tier, got %s", scores.Tier)
	}

	// 2. Evaluate compromised device
	evalReq.DeviceID = "dev-test-node-bad"
	evalReq.Integrity.DebuggerAttached = true
	bodyBad, _ := json.Marshal(evalReq)

	reqBad := httptest.NewRequest(http.MethodPost, "/api/posture/evaluate", bytes.NewReader(bodyBad))
	wBad := httptest.NewRecorder()
	apiMux.ServeHTTP(wBad, reqBad)

	if wBad.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", wBad.Code, wBad.Body.String())
	}
	var scoresBad posture.PostureVectorScores
	_ = json.Unmarshal(wBad.Body.Bytes(), &scoresBad)
	if scoresBad.Tier != posture.PostureTierQuarantine {
		t.Fatalf("expected quarantine tier, got %s", scoresBad.Tier)
	}

	// 3. Check quarantine list
	qReq := httptest.NewRequest(http.MethodGet, "/api/posture/quarantine?tenant_id=tenant-acme", nil)
	qW := httptest.NewRecorder()
	apiMux.ServeHTTP(qW, qReq)
	if qW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", qW.Code, qW.Body.String())
	}

	// 4. Check device query
	devReq := httptest.NewRequest(http.MethodGet, "/api/posture/device?tenant_id=tenant-acme&device_id=dev-test-node-bad", nil)
	devW := httptest.NewRecorder()
	apiMux.ServeHTTP(devW, devReq)
	if devW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for device query, got %d: %s", devW.Code, devW.Body.String())
	}

	// 5. Release quarantine
	relBody, _ := json.Marshal(map[string]string{
		"tenant_id": "tenant-acme",
		"device_id": "dev-test-node-bad",
	})
	relReq := httptest.NewRequest(http.MethodPost, "/api/posture/quarantine/release", bytes.NewReader(relBody))
	relW := httptest.NewRecorder()
	apiMux.ServeHTTP(relW, relReq)
	if relW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for release, got %d: %s", relW.Code, relW.Body.String())
	}
}

func TestRoutesPostureStepUpChallengeAndVerify(t *testing.T) {
	server := newTestAppServerWithPosture(t)
	defer server.proxy.Close()

	apiMux := http.NewServeMux()
	server.registerPostureRoutes(apiMux)

	// 1. Issue challenge
	challBody, _ := json.Marshal(map[string]interface{}{
		"tenant_id": "tenant-acme",
		"device_id": "dev-step-01",
		"actions":   []string{"tpm_quote", "mfa_pin"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/posture/step-up/challenge", bytes.NewReader(challBody))
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var challenge posture.StepUpChallenge
	if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("failed to decode challenge: %v", err)
	}

	// 2. Verify with wrong nonce
	wrongVerifyBody, _ := json.Marshal(map[string]string{
		"challenge_id": challenge.ChallengeID,
		"nonce":        "incorrect-nonce-123",
	})
	wReq := httptest.NewRequest(http.MethodPost, "/api/posture/step-up/verify", bytes.NewReader(wrongVerifyBody))
	wW := httptest.NewRecorder()
	apiMux.ServeHTTP(wW, wReq)
	if wW.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for wrong nonce, got %d", wW.Code)
	}

	// 3. Verify with valid nonce
	validVerifyBody, _ := json.Marshal(map[string]string{
		"challenge_id": challenge.ChallengeID,
		"nonce":        challenge.Nonce,
	})
	vReq := httptest.NewRequest(http.MethodPost, "/api/posture/step-up/verify", bytes.NewReader(validVerifyBody))
	vW := httptest.NewRecorder()
	apiMux.ServeHTTP(vW, vReq)
	if vW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid nonce, got %d: %s", vW.Code, vW.Body.String())
	}
}
