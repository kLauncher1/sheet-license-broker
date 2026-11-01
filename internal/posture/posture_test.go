package posture

import (
	"sync"
	"testing"
	"time"
)

func sampleHealthyReport() DevicePostureReport {
	return DevicePostureReport{
		DeviceID: "dev-macbook-pro-01",
		TenantID: "enterprise-acme",
		HWID:     "HWID-A1B2C3D4E5F6",
		OS: OSVectorReport{
			OSName:            "macOS",
			OSVersion:         "15.1.0",
			KernelVersion:     "Darwin 24.1.0",
			PatchLevelDays:    5,
			MinPatchLevelDays: 30,
		},
		Hardware: HardwareVectorReport{
			SecureBootEnabled:    true,
			TPMPresent:           true,
			TPMVersion:           "2.0",
			DiskEncryptionActive: true,
		},
		Endpoint: EndpointVectorReport{
			AntivirusActive:    true,
			DefinitionsAgeDays: 1,
			RealtimeProtection: true,
			FirewallEnabled:    true,
		},
		Integrity: IntegrityVectorReport{
			DebuggerAttached:       false,
			RootedOrJailbroken:     false,
			VirtualizationDetected: false,
			CodeIntegrityVerified:  true,
		},
		Timestamp:   time.Now().UTC().Unix(),
		ClientNonce: "nonce-12345",
	}
}

func TestAnalyzePosture_Healthy(t *testing.T) {
	policy := DefaultPolicyConfig()
	report := sampleHealthyReport()

	scores := AnalyzePosture(report, policy)

	if scores.Tier != PostureTierHealthy {
		t.Fatalf("expected healthy tier, got %s (violations: %v)", scores.Tier, scores.Violations)
	}
	if scores.CompositeScore < 95.0 {
		t.Fatalf("expected composite score >= 95, got %f", scores.CompositeScore)
	}
	if len(scores.Violations) != 0 {
		t.Fatalf("expected 0 violations, got %v", scores.Violations)
	}
}

func TestAnalyzePosture_WarningTier(t *testing.T) {
	policy := DefaultPolicyConfig()
	report := sampleHealthyReport()
	// Stale patches (45 days), stale AV definitions (10 days), no disk crypto, and no realtime protection
	report.OS.PatchLevelDays = 45
	report.Endpoint.DefinitionsAgeDays = 10
	report.Endpoint.RealtimeProtection = false
	report.Hardware.DiskEncryptionActive = false

	scores := AnalyzePosture(report, policy)

	if scores.Tier != PostureTierWarning {
		t.Fatalf("expected warning tier, got %s (score: %f)", scores.Tier, scores.CompositeScore)
	}
	if !scores.DegradedModeAllowed {
		t.Fatalf("expected degraded mode allowed for warning tier")
	}
	if len(scores.Violations) == 0 {
		t.Fatalf("expected violations to be recorded")
	}
}

func TestAnalyzePosture_CriticalDebuggerAttached(t *testing.T) {
	policy := DefaultPolicyConfig()
	report := sampleHealthyReport()
	report.Integrity.DebuggerAttached = true

	scores := AnalyzePosture(report, policy)

	if scores.Tier != PostureTierQuarantine {
		t.Fatalf("expected quarantine tier on debugger attachment, got %s", scores.Tier)
	}
	if scores.DegradedModeAllowed {
		t.Fatalf("expected degraded mode disallowed on active debugger")
	}
}

func TestAnalyzePosture_CriticalRootedOrJailbroken(t *testing.T) {
	policy := DefaultPolicyConfig()
	report := sampleHealthyReport()
	report.Integrity.RootedOrJailbroken = true

	scores := AnalyzePosture(report, policy)

	if scores.Tier != PostureTierQuarantine {
		t.Fatalf("expected quarantine tier on rooted device, got %s", scores.Tier)
	}
	if scores.DegradedModeAllowed {
		t.Fatalf("expected degraded mode disallowed on rooted device")
	}
}

func TestAnalyzePosture_TotalDefenseFailure(t *testing.T) {
	policy := DefaultPolicyConfig()
	report := sampleHealthyReport()
	report.Endpoint.AntivirusActive = false
	report.Endpoint.FirewallEnabled = false

	scores := AnalyzePosture(report, policy)

	if scores.Tier != PostureTierQuarantine {
		t.Fatalf("expected quarantine tier when AV and firewall are both disabled, got %s", scores.Tier)
	}
}

func TestQuarantineRegistry_LifecycleAndStepUp(t *testing.T) {
	reg := NewQuarantineRegistry()
	tenant := "acme"
	devID := "dev-untrusted-01"

	// 1. Initial state
	isQ, _ := reg.IsQuarantined(tenant, devID)
	if isQ {
		t.Fatalf("device should not be quarantined initially")
	}

	// 2. Quarantine device
	reg.QuarantineDevice(QuarantinedDevice{
		DeviceID:            devID,
		TenantID:            tenant,
		HWID:                "HWID-9999",
		Reason:              "Stale patches and unverified integrity",
		CompositeScore:      42.5,
		Tier:                PostureTierQuarantine,
		QuarantinedAt:       time.Now().UTC(),
		DegradedModeAllowed: true,
		RemediationSteps:    []string{"Update OS"},
	})

	isQ, qDev := reg.IsQuarantined(tenant, devID)
	if !isQ || qDev == nil {
		t.Fatalf("device should be quarantined")
	}
	if !reg.IsDegradedAllowed(tenant, devID) {
		t.Fatalf("expected degraded mode allowed")
	}

	// 3. Issue step-up challenge
	challenge := reg.IssueStepUpChallenge(tenant, devID, []string{"hardware_token", "biometric"}, 5*time.Minute)
	if challenge.ChallengeID == "" || challenge.Nonce == "" {
		t.Fatalf("expected valid challenge ID and nonce")
	}

	// 4. Verify invalid nonce
	success, err := reg.VerifyStepUpChallenge(challenge.ChallengeID, "", "wrong-nonce")
	if success || err == nil {
		t.Fatalf("expected failure on wrong nonce")
	}

	// 5. Verify valid nonce
	success, err = reg.VerifyStepUpChallenge(challenge.ChallengeID, "", challenge.Nonce)
	if !success || err != nil {
		t.Fatalf("expected step-up verification success, got error: %v", err)
	}

	// 6. Duplicate verification fails
	success, err = reg.VerifyStepUpChallenge(challenge.ChallengeID, "", challenge.Nonce)
	if success || err == nil {
		t.Fatalf("expected error on duplicate challenge fulfillment")
	}

	// 7. Release quarantine
	released := reg.ReleaseQuarantine(tenant, devID)
	if !released {
		t.Fatalf("expected quarantine release to succeed")
	}
	isQ, _ = reg.IsQuarantined(tenant, devID)
	if isQ {
		t.Fatalf("device should no longer be quarantined")
	}
}

func TestPostureManager_EvaluateAndComplianceListener(t *testing.T) {
	mgr := NewPostureManager(DefaultPolicyConfig())

	var alertedEvent string
	var alertMu sync.Mutex

	mgr.SetComplianceListener(func(ev string, sc PostureVectorScores) {
		alertMu.Lock()
		defer alertMu.Unlock()
		alertedEvent = ev
	})

	// 1. Submit quarantine-level report
	badReport := sampleHealthyReport()
	badReport.DeviceID = "dev-infected-01"
	badReport.Integrity.DebuggerAttached = true

	scores := mgr.EvaluateReport(badReport)
	if scores.Tier != PostureTierQuarantine {
		t.Fatalf("expected quarantine tier, got %s", scores.Tier)
	}

	isQ, _ := mgr.Registry().IsQuarantined(badReport.TenantID, badReport.DeviceID)
	if !isQ {
		t.Fatalf("expected device to be in quarantine registry")
	}

	time.Sleep(50 * time.Millisecond)
	alertMu.Lock()
	if alertedEvent != "device_quarantine_triggered" {
		t.Fatalf("expected compliance alert device_quarantine_triggered, got %s", alertedEvent)
	}
	alertMu.Unlock()

	// 2. Query status
	status := mgr.GetStatus()
	if status.TotalEvaluations != 1 {
		t.Fatalf("expected 1 total evaluation, got %d", status.TotalEvaluations)
	}
	if status.QuarantineCount != 1 {
		t.Fatalf("expected 1 quarantined device, got %d", status.QuarantineCount)
	}

	// 3. Submit healthy report for same device -> auto-lifts quarantine
	cleanReport := sampleHealthyReport()
	cleanReport.DeviceID = "dev-infected-01"
	cleanScores := mgr.EvaluateReport(cleanReport)
	if cleanScores.Tier != PostureTierHealthy {
		t.Fatalf("expected healthy tier after remediation")
	}
	isQ, _ = mgr.Registry().IsQuarantined(cleanReport.TenantID, cleanReport.DeviceID)
	if isQ {
		t.Fatalf("expected quarantine to be automatically lifted on healthy report")
	}
}

func TestPostureManager_ConcurrentEvaluations(t *testing.T) {
	mgr := NewPostureManager(DefaultPolicyConfig())

	var wg sync.WaitGroup
	numWorkers := 20

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			rep := sampleHealthyReport()
			if workerID%2 == 0 {
				rep.OS.PatchLevelDays = 40
			}
			scores := mgr.EvaluateReport(rep)
			if scores.CompositeScore <= 0.0 {
				t.Errorf("worker %d got invalid score %f", workerID, scores.CompositeScore)
			}
			_ = mgr.GetStatus()
		}(i)
	}
	wg.Wait()

	status := mgr.GetStatus()
	if status.TotalEvaluations != int64(numWorkers) {
		t.Fatalf("expected %d evaluations, got %d", numWorkers, status.TotalEvaluations)
	}
}
