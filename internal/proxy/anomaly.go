package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anomaly"
	"github.com/kLauncher1/sheet-license-broker/internal/audit"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

func (p *Proxy) initAnomaly() {
	p.anomalyEngine = anomaly.NewEngine(anomaly.DefaultConfig())
}

// AnomalyEngine returns the underlying behavioral anomaly detection engine.
func (p *Proxy) AnomalyEngine() *anomaly.Engine {
	return p.anomalyEngine
}

// RecordClientTelemetry processes incoming heartbeat or telemetry pings through the anomaly engine.
func (p *Proxy) RecordClientTelemetry(ctx context.Context, obs anomaly.ClientObservation) (*anomaly.RiskScore, error) {
	if p.anomalyEngine == nil {
		p.initAnomaly()
	}

	score, hasAnomaly := p.anomalyEngine.RecordObservation(obs)

	// If critical risk / quarantine triggered, dispatch incident alerts and emergency stream action
	if score != nil && score.QuarantineTriggered {
		if p.auditCollector != nil {
			p.auditCollector.Record(audit.AuditRecord{
				EventType: "QUARANTINE_TRIGGERED",
				Severity:  "CRITICAL",
				ActorIP:   obs.IP,
				HWID:      obs.HWID,
				Details:   fmt.Sprintf("Risk score %d critical. Quarantined.", score.Score),
			})
		}

		_ = p.DispatchSecurityIncident(ctx, webhook.SecurityAlert{
			Type:      "behavioral_quarantine",
			Severity:  webhook.SeverityCritical,
			Target:    obs.HWID,
			IPAddress: obs.IP,
			Summary:   fmt.Sprintf("Behavioral anomaly quarantine for %s", obs.LicenseKey),
			Details:   fmt.Sprintf("Risk score: %d/100 critical threshold exceeded", score.Score),
			Timestamp: time.Now(),
		})

		// Push targeted kill-switch via WebSocket stream hub
		if p.streamHub != nil {
			target := obs.LicenseKey
			if target == "" {
				target = obs.HWID
			}
			p.PushKillSwitch(target, "Quarantined due to critical behavioral anomaly", true)
		}

		// Asynchronously persist incident to Google Apps Script if enabled
		if p.IsRemoteEnabled() {
			go func() {
				_, _ = p.gasClient.ExecuteAction(context.Background(), "anomaly_record", map[string]interface{}{
					"license_key": obs.LicenseKey,
					"hwid":        obs.HWID,
					"ip":          obs.IP,
					"country":     obs.Country,
					"risk_score":  score.Score,
					"reason":      "CriticalRiskQuarantine",
				})
			}()
		}
	} else if hasAnomaly && p.IsRemoteEnabled() {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "anomaly_record", map[string]interface{}{
				"license_key": obs.LicenseKey,
				"hwid":        obs.HWID,
				"ip":          obs.IP,
				"country":     obs.Country,
				"risk_score":  score.Score,
				"reason":      "AnomalyDetected",
			})
		}()
	}

	return score, nil
}

// GetAnomalyRiskScore queries the risk score for a license or device.
func (p *Proxy) GetAnomalyRiskScore(licenseKey, hwid string) *anomaly.RiskScore {
	if p.anomalyEngine == nil {
		p.initAnomaly()
	}
	entityID := licenseKey
	if entityID == "" {
		entityID = hwid
	}
	return p.anomalyEngine.GetRiskScore(entityID)
}

// IssueAnomalyChallenge triggers an explicit re-attestation challenge for an entity.
func (p *Proxy) IssueAnomalyChallenge(licenseKey, hwid string) (*anomaly.RiskScore, string, error) {
	if p.anomalyEngine == nil {
		p.initAnomaly()
	}
	entityID := licenseKey
	if entityID == "" {
		entityID = hwid
	}
	score, token := p.anomalyEngine.IssueChallenge(entityID, anomaly.ChallengeReAttestation)
	return score, token, nil
}

// VerifyAnomalyChallenge validates and clears a client's escalation challenge.
func (p *Proxy) VerifyAnomalyChallenge(token string) (string, bool, error) {
	if p.anomalyEngine == nil {
		p.initAnomaly()
	}
	entityID, valid := p.anomalyEngine.VerifyChallengeResponse(token)
	return entityID, valid, nil
}

// ExportIncidentGraph synthesizes a real-time topology graph for SIEM ingestion.
func (p *Proxy) ExportIncidentGraph(filter anomaly.GraphFilter) *anomaly.IncidentGraph {
	if p.anomalyEngine == nil {
		p.initAnomaly()
	}
	return p.anomalyEngine.ExportIncidentGraph(filter)
}

// GetAnomalyStatus delivers operational metrics on anomaly detection.
func (p *Proxy) GetAnomalyStatus() map[string]interface{} {
	if p.anomalyEngine == nil {
		p.initAnomaly()
	}
	telemetry := p.anomalyEngine.GetTelemetry()
	lastAnomalyStr := ""
	if !telemetry.LastAnomalyDetectedAt.IsZero() {
		lastAnomalyStr = telemetry.LastAnomalyDetectedAt.Format(time.RFC3339)
	}
	return map[string]interface{}{
		"total_observations":        telemetry.TotalObservations,
		"active_monitored_entities": telemetry.ActiveMonitoredEntities,
		"anomalies_detected":        telemetry.AnomaliesDetected,
		"challenges_issued":         telemetry.ChallengesIssued,
		"challenges_cleared":        telemetry.ChallengesCleared,
		"active_quarantines":        telemetry.ActiveQuarantines,
		"last_anomaly_detected_at":  lastAnomalyStr,
	}
}
