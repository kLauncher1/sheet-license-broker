package proxy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/attestation"
	"github.com/kLauncher1/sheet-license-broker/internal/metrics"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

// AttestationManager returns the hardware attestation manager.
func (p *Proxy) AttestationManager() *attestation.Manager {
	return p.attestationManager
}

// CreateAttestationChallenge generates a single-use random nonce challenge for an endpoint.
func (p *Proxy) CreateAttestationChallenge(licenseKey, hwid string) (*attestation.AttestationChallenge, error) {
	if p.attestationManager == nil {
		return nil, errors.New("attestation manager is uninitialized")
	}
	return p.attestationManager.CreateChallenge(licenseKey, hwid)
}

// VerifyTPMAttestation validates a TPM 2.0 quote and records attested hardware trust.
func (p *Proxy) VerifyTPMAttestation(ctx context.Context, licenseKey, hwid, challengeID string, quote *attestation.PCRQuote) (*attestation.AttestationRecord, error) {
	if p.attestationManager == nil {
		return nil, errors.New("attestation manager is uninitialized")
	}

	rec, err := p.attestationManager.VerifyTPMQuote(licenseKey, hwid, challengeID, quote)
	if err != nil {
		metrics.RecordVerification("attestation_failed", "default")
		return nil, err
	}

	metrics.RecordVerification("attestation_success", "default")
	return rec, nil
}

// VerifyEnclaveAttestation validates Apple Secure Enclave / Windows Hello assertions.
func (p *Proxy) VerifyEnclaveAttestation(ctx context.Context, licenseKey, hwid, challengeID string, enclave *attestation.EnclaveAttestation) (*attestation.AttestationRecord, error) {
	if p.attestationManager == nil {
		return nil, errors.New("attestation manager is uninitialized")
	}

	rec, err := p.attestationManager.VerifyEnclave(licenseKey, hwid, challengeID, enclave)
	if err != nil {
		metrics.RecordVerification("enclave_failed", "default")
		return nil, err
	}

	metrics.RecordVerification("enclave_success", "default")
	return rec, nil
}

// SubmitAttestationTelemetry evaluates client integrity telemetry, auto-tripping defense mitigations on tamper.
func (p *Proxy) SubmitAttestationTelemetry(ctx context.Context, licenseKey, hwid string, report *attestation.TelemetryReport) (int, bool, *attestation.AttestationRecord, error) {
	if p.attestationManager == nil {
		return 0, false, nil, errors.New("attestation manager is uninitialized")
	}

	score, tampered, rec, err := p.attestationManager.EvaluateTelemetry(licenseKey, hwid, report)
	if err != nil {
		return 0, false, nil, err
	}

	if tampered {
		metrics.RecordVerification("tampered", "default")
		metrics.RecordSecurityIncident("hardware_tamper")

		normKey := strings.ToUpper(strings.TrimSpace(licenseKey))
		normHWID := strings.ToUpper(strings.TrimSpace(hwid))
		reason := fmt.Sprintf("Hardware tamper detected (score: %d/100): %s", score, rec.Details)

		// 1. Immediately revoke license and ban device in local memory and remote
		_ = p.RevokeLicense(ctx, normKey, reason)
		_ = p.BlacklistDevice(ctx, normHWID, reason)

		// 2. Dispatch security incident alert to Discord / Slack channels
		_ = p.DispatchSecurityIncident(ctx, webhook.SecurityAlert{
			Type:      "hardware_tamper",
			Severity:  webhook.SeverityCritical,
			Target:    normHWID,
			Summary:   fmt.Sprintf("Anti-tamper violation detected on device %s", normHWID),
			Details:   reason,
			Timestamp: time.Now(),
		})

		// 3. Emit webhook event
		p.NotifyLicenseEvent(webhook.EventTamperDetected, normKey, normHWID, reason)
	}

	return score, tampered, rec, nil
}

// GetAttestationStatus retrieves the recorded attestation state for a device.
func (p *Proxy) GetAttestationStatus(licenseKey, hwid string) (*attestation.AttestationRecord, bool) {
	if p.attestationManager == nil {
		return nil, false
	}
	return p.attestationManager.GetRecord(licenseKey, hwid)
}

// ListAttestations returns all tracked attestation records.
func (p *Proxy) ListAttestations() []*attestation.AttestationRecord {
	if p.attestationManager == nil {
		return nil
	}
	return p.attestationManager.ListRecords()
}
