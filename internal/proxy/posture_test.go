package proxy

import (
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/posture"
)

func TestProxy_PostureInitAndStatus(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer px.Close()

	if px.PostureManager() == nil {
		t.Fatalf("expected posture manager to be initialized")
	}

	status := px.GetPostureStatus()
	if status.Version != "2.6.0" {
		t.Fatalf("expected posture version 2.6.0, got %s", status.Version)
	}
	if status.ActivePolicies != 1 {
		t.Fatalf("expected 1 active policy, got %d", status.ActivePolicies)
	}
}

func TestProxy_EvaluateDevicePosture_HealthyAndQuarantine(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer px.Close()

	// 1. Healthy device evaluation
	healthyReport := posture.DevicePostureReport{
		DeviceID: "dev-corp-101",
		TenantID: "acme-corp",
		HWID:     "HWID-101010",
		OS: posture.OSVectorReport{
			OSName:            "Windows",
			OSVersion:         "11.0.26100",
			PatchLevelDays:    3,
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

	scores := px.EvaluateDevicePosture(healthyReport)
	if scores.Tier != posture.PostureTierHealthy {
		t.Fatalf("expected healthy tier, got %s", scores.Tier)
	}

	isQ, _ := px.IsDeviceQuarantined("acme-corp", "dev-corp-101")
	if isQ {
		t.Fatalf("healthy device should not be quarantined")
	}

	// 2. Compromised device with active debugger
	compromisedReport := healthyReport
	compromisedReport.DeviceID = "dev-corp-999"
	compromisedReport.Integrity.DebuggerAttached = true

	scoresComp := px.EvaluateDevicePosture(compromisedReport)
	if scoresComp.Tier != posture.PostureTierQuarantine {
		t.Fatalf("expected quarantine tier, got %s", scoresComp.Tier)
	}

	isQ, qDev := px.IsDeviceQuarantined("acme-corp", "dev-corp-999")
	if !isQ || qDev == nil {
		t.Fatalf("expected device to be registered in quarantine")
	}

	// Degraded mode should be disallowed due to active debugger
	if px.IsDeviceDegradedAllowed("acme-corp", "dev-corp-999") {
		t.Fatalf("degraded mode must be denied for active debugger")
	}

	// 3. Release quarantine
	released := px.ReleaseDeviceQuarantine("acme-corp", "dev-corp-999")
	if !released {
		t.Fatalf("expected successful quarantine release")
	}
	isQ, _ = px.IsDeviceQuarantined("acme-corp", "dev-corp-999")
	if isQ {
		t.Fatalf("expected device to no longer be quarantined")
	}
}

func TestProxy_StepUpChallengeLifecycle(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer px.Close()

	tenant := "acme-corp"
	device := "dev-stepup-01"

	challenge := px.IssueDeviceStepUpChallenge(tenant, device, []string{"mfa_otp", "biometric"}, 5*time.Minute)
	if challenge == nil || challenge.ChallengeID == "" {
		t.Fatalf("expected valid step-up challenge")
	}

	// Verify with invalid nonce
	ok, err := px.VerifyDeviceStepUpChallenge(challenge.ChallengeID, "invalid-nonce")
	if ok || err == nil {
		t.Fatalf("expected failure for invalid nonce")
	}

	// Verify with valid nonce
	ok, err = px.VerifyDeviceStepUpChallenge(challenge.ChallengeID, challenge.Nonce)
	if !ok || err != nil {
		t.Fatalf("expected success for valid nonce, got err: %v", err)
	}
}
