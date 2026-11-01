package proxy

import (
	"context"
	"log"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/posture"
)

// initPosture initializes the adaptive zero-trust device health scoring & continuous posture attestation engine.
func (p *Proxy) initPosture(cfg ProxyConfig) {
	policy := posture.DefaultPolicyConfig()
	mgr := posture.NewPostureManager(policy)

	// Bind compliance incident alert dispatcher
	mgr.SetComplianceListener(func(eventType string, scores posture.PostureVectorScores) {
		p.BroadcastStreamEvent(eventType, map[string]interface{}{
			"device_id":        scores.DeviceID,
			"tenant_id":        scores.TenantID,
			"tier":             scores.Tier,
			"composite_score":  scores.CompositeScore,
			"violations":       scores.Violations,
			"degraded_allowed": scores.DegradedModeAllowed,
			"timestamp":        time.Now().UTC().Format(time.RFC3339),
		})
	})

	p.postureManager = mgr
	log.Printf("[Proxy] Adaptive Zero-Trust Device Health & Continuous Posture Attestation engine initialized (v2.6.0)")
}

// PostureManager returns the active posture evaluation manager.
func (p *Proxy) PostureManager() *posture.PostureManager {
	return p.postureManager
}

// GetPostureStatus returns real-time telemetry and operational stats for device posture.
func (p *Proxy) GetPostureStatus() posture.PostureStatus {
	if p.postureManager == nil {
		return posture.PostureStatus{}
	}
	return p.postureManager.GetStatus()
}

// EvaluateDevicePosture processes client device posture telemetry and enforces quarantine policies.
func (p *Proxy) EvaluateDevicePosture(report posture.DevicePostureReport) posture.PostureVectorScores {
	if p.postureManager == nil {
		return posture.PostureVectorScores{}
	}

	scores := p.postureManager.EvaluateReport(report)

	// Asynchronously record evaluation in Google Apps Script persistent backend
	if p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "posture_record_evaluation", map[string]interface{}{
				"device_id":        scores.DeviceID,
				"tenant_id":        scores.TenantID,
				"tier":             string(scores.Tier),
				"composite_score":  scores.CompositeScore,
				"os_score":         scores.OSScore,
				"hardware_score":   scores.HardwareScore,
				"endpoint_score":   scores.EndpointScore,
				"integrity_score":  scores.IntegrityScore,
				"violations":       scores.Violations,
				"degraded_allowed": scores.DegradedModeAllowed,
				"evaluated_at":     scores.EvaluatedAt.Format(time.RFC3339),
			})

			if scores.Tier == posture.PostureTierQuarantine {
				_, _ = p.gasClient.ExecuteAction(context.Background(), "posture_record_quarantine", map[string]interface{}{
					"device_id":        scores.DeviceID,
					"tenant_id":        scores.TenantID,
					"hwid":             report.HWID,
					"reason":           scores.Violations[0],
					"composite_score":  scores.CompositeScore,
					"degraded_allowed": scores.DegradedModeAllowed,
					"quarantined_at":   time.Now().UTC().Format(time.RFC3339),
				})
			}
		}()
	}

	return scores
}

// IsDeviceQuarantined checks if an endpoint is blocked by quarantine.
func (p *Proxy) IsDeviceQuarantined(tenantID, deviceID string) (bool, *posture.QuarantinedDevice) {
	if p.postureManager == nil {
		return false, nil
	}
	return p.postureManager.Registry().IsQuarantined(tenantID, deviceID)
}

// IsDeviceDegradedAllowed checks if a quarantined endpoint can operate in graceful degradation mode.
func (p *Proxy) IsDeviceDegradedAllowed(tenantID, deviceID string) bool {
	if p.postureManager == nil {
		return false
	}
	return p.postureManager.Registry().IsDegradedAllowed(tenantID, deviceID)
}

// ReleaseDeviceQuarantine removes a device from quarantine and notifies connected peers.
func (p *Proxy) ReleaseDeviceQuarantine(tenantID, deviceID string) bool {
	if p.postureManager == nil {
		return false
	}

	released := p.postureManager.ReleaseQuarantine(tenantID, deviceID)
	if released {
		p.BroadcastStreamEvent("posture_quarantine_released", map[string]interface{}{
			"device_id": deviceID,
			"tenant_id": tenantID,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		})

		if p.gasClient != nil {
			go func() {
				_, _ = p.gasClient.ExecuteAction(context.Background(), "posture_release_quarantine", map[string]interface{}{
					"device_id":   deviceID,
					"tenant_id":   tenantID,
					"released_at": time.Now().UTC().Format(time.RFC3339),
				})
			}()
		}
	}
	return released
}

// IssueDeviceStepUpChallenge generates a remediation challenge for step-up verification.
func (p *Proxy) IssueDeviceStepUpChallenge(tenantID, deviceID string, actions []string, ttl time.Duration) *posture.StepUpChallenge {
	if p.postureManager == nil {
		return nil
	}
	return p.postureManager.IssueStepUpChallenge(tenantID, deviceID, actions, ttl)
}

// VerifyDeviceStepUpChallenge validates client step-up authentication proofs.
func (p *Proxy) VerifyDeviceStepUpChallenge(challengeID, submittedNonce string) (bool, error) {
	if p.postureManager == nil {
		return false, nil
	}
	return p.postureManager.VerifyStepUpChallenge(challengeID, submittedNonce)
}
