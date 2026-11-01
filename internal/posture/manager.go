package posture

import (
	"sync"
	"sync/atomic"
	"time"
)

// ComplianceListener defines an event callback for compliance auditing and incident alerts.
type ComplianceListener func(eventType string, scores PostureVectorScores)

// PostureManager coordinates posture audits, scoring policies, and quarantine enforcement.
type PostureManager struct {
	mu             sync.RWMutex
	policy         PolicyConfig
	registry       *QuarantineRegistry
	deviceState    map[string]PostureVectorScores
	recentHistory  []PostureVectorScores
	maxHistory     int
	listener       ComplianceListener
	evalCounter    atomic.Int64
	healthyCounter atomic.Int64
	warningCounter atomic.Int64
	quarCounter    atomic.Int64
	degradedCount  atomic.Int64
}

// NewPostureManager instantiates a posture evaluation orchestrator.
func NewPostureManager(policy PolicyConfig) *PostureManager {
	return &PostureManager{
		policy:        policy,
		registry:      NewQuarantineRegistry(),
		deviceState:   make(map[string]PostureVectorScores),
		recentHistory: make([]PostureVectorScores, 0, 50),
		maxHistory:    50,
	}
}

// SetComplianceListener binds an asynchronous event listener for security incident dispatch.
func (m *PostureManager) SetComplianceListener(listener ComplianceListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listener = listener
}

// EvaluateReport analyzes a device posture report, updates states, and applies quarantine policy.
func (m *PostureManager) EvaluateReport(report DevicePostureReport) PostureVectorScores {
	scores := AnalyzePosture(report, m.policy)

	m.evalCounter.Add(1)
	switch scores.Tier {
	case PostureTierHealthy:
		m.healthyCounter.Add(1)
		// If previously quarantined and now fully healthy, auto-lift quarantine
		m.registry.ReleaseQuarantine(report.TenantID, report.DeviceID)
	case PostureTierWarning:
		m.warningCounter.Add(1)
	case PostureTierQuarantine:
		m.quarCounter.Add(1)
		if scores.DegradedModeAllowed {
			m.degradedCount.Add(1)
		}
		// Register in quarantine table
		reason := "Composite confidence score below security threshold"
		if len(scores.Violations) > 0 {
			reason = scores.Violations[0]
		}
		m.registry.QuarantineDevice(QuarantinedDevice{
			DeviceID:            report.DeviceID,
			TenantID:            report.TenantID,
			HWID:                report.HWID,
			Reason:              reason,
			CompositeScore:      scores.CompositeScore,
			Tier:                scores.Tier,
			Violations:          scores.Violations,
			QuarantinedAt:       time.Now().UTC(),
			DegradedModeAllowed: scores.DegradedModeAllowed,
			RemediationSteps:    scores.Remediations,
		})
	}

	m.mu.Lock()
	key := deviceKey(report.TenantID, report.DeviceID)
	m.deviceState[key] = scores

	// Maintain ring buffer of recent evaluations
	if len(m.recentHistory) >= m.maxHistory {
		m.recentHistory = m.recentHistory[1:]
	}
	m.recentHistory = append(m.recentHistory, scores)
	cb := m.listener
	m.mu.Unlock()

	// Notify compliance listener if bound
	if cb != nil && scores.Tier == PostureTierQuarantine {
		go cb("device_quarantine_triggered", scores)
	} else if cb != nil && scores.Tier == PostureTierWarning {
		go cb("device_warning_stepup_required", scores)
	}

	return scores
}

// GetDevicePosture retrieves the latest recorded evaluation for an endpoint.
func (m *PostureManager) GetDevicePosture(tenantID, deviceID string) (PostureVectorScores, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := deviceKey(tenantID, deviceID)
	score, ok := m.deviceState[key]
	return score, ok
}

// Registry exposes the underlying QuarantineRegistry.
func (m *PostureManager) Registry() *QuarantineRegistry {
	return m.registry
}

// IssueStepUpChallenge generates a remediation challenge for an endpoint in warning or quarantine.
func (m *PostureManager) IssueStepUpChallenge(tenantID, deviceID string, actions []string, ttl time.Duration) *StepUpChallenge {
	return m.registry.IssueStepUpChallenge(tenantID, deviceID, actions, ttl)
}

// VerifyStepUpChallenge validates a step-up challenge proof.
func (m *PostureManager) VerifyStepUpChallenge(challengeID, submittedNonce string) (bool, error) {
	return m.registry.VerifyStepUpChallenge(challengeID, "", submittedNonce)
}

// ReleaseQuarantine manually lifts an endpoint's quarantine isolation.
func (m *PostureManager) ReleaseQuarantine(tenantID, deviceID string) bool {
	return m.registry.ReleaseQuarantine(tenantID, deviceID)
}

// GetStatus returns the operational status and telemetry summary of the posture engine.
func (m *PostureManager) GetStatus() PostureStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	historyCopy := make([]PostureVectorScores, len(m.recentHistory))
	copy(historyCopy, m.recentHistory)

	quarantinedList := m.registry.ListQuarantined("")

	return PostureStatus{
		ActivePolicies:     1,
		TotalEvaluations:   m.evalCounter.Load(),
		HealthyCount:       m.healthyCounter.Load(),
		WarningCount:       m.warningCounter.Load(),
		QuarantineCount:    int64(len(quarantinedList)),
		DegradedCount:      m.degradedCount.Load(),
		RecentEvaluations:  historyCopy,
		QuarantinedDevices: quarantinedList,
		Version:            "2.6.0",
	}
}
