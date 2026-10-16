package proxy

import (
	"context"
	"fmt"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/audit"
	"github.com/kLauncher1/sheet-license-broker/internal/pqc"
	"github.com/kLauncher1/sheet-license-broker/internal/stream"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

func (p *Proxy) initPQC() {
	var secret []byte
	if p.dispatcher != nil {
		secret = []byte("pqc-hybrid-default-secret-salt-256")
	}
	km, err := pqc.NewKeyManager(pqc.AlgoHybridP256, secret)
	if err == nil {
		p.pqcManager = km
	}
}

// PQCManager returns the post-quantum cryptography key and signature manager.
func (p *Proxy) PQCManager() *pqc.PQCKeyManager {
	return p.pqcManager
}

// PQCVerifyHybrid evaluates a hybrid classical and post-quantum lattice signature.
func (p *Proxy) PQCVerifyHybrid(sig *pqc.HybridSignature, payload []byte) *pqc.PQCVerificationResult {
	if p.pqcManager == nil {
		return &pqc.PQCVerificationResult{
			Valid:        false,
			ErrorMessage: "PQC engine not initialized",
		}
	}

	res := p.pqcManager.Verify(payload, sig)

	// Record audit event
	action := "PQC_VERIFY_SUCCESS"
	severity := "INFO"
	if !res.Valid {
		action = "PQC_VERIFY_FAILED"
		severity = "WARNING"
	}
	if p.auditCollector != nil {
		p.auditCollector.Record(audit.AuditRecord{
			EventType: action,
			Severity:  severity,
			TenantID:  "global",
			ActorIP:   "127.0.0.1",
			Details:   fmt.Sprintf("key=%s algo=%s valid=%v classical=%v quantum=%v", sig.KeyID, sig.Algorithm, res.Valid, res.ClassicalValid, res.QuantumValid),
		})
	}

	return res
}

// PQCSignLicense issues a quantum-resistant hybrid signature over an entitled license payload.
func (p *Proxy) PQCSignLicense(ctx context.Context, licenseKey, hwid string, payload []byte) (*pqc.HybridSignature, error) {
	if p.pqcManager == nil {
		return nil, fmt.Errorf("PQC manager not initialized")
	}

	// Verify license entitlement before issuing signature
	licRes, err := p.VerifyLicense(ctx, licenseKey, hwid)
	if err != nil || !licRes.Valid {
		return nil, fmt.Errorf("cannot issue PQC signature: license check failed (%v)", err)
	}

	sig, err := p.pqcManager.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hybrid signature: %w", err)
	}

	if p.auditCollector != nil {
		p.auditCollector.Record(audit.AuditRecord{
			EventType: "PQC_SIGN_LICENSE",
			Severity:  "INFO",
			TenantID:  "global",
			ActorIP:   "127.0.0.1",
			Details:   fmt.Sprintf("key=%s algo=%s license=%s hwid=%s", sig.KeyID, sig.Algorithm, licenseKey, hwid),
		})
	}

	return sig, nil
}

// PQCRotateKey executes key rotation with a defined grace window and synchronizes with storage.
func (p *Proxy) PQCRotateKey(ctx context.Context, algo string, gracePeriod time.Duration, reason string) (*pqc.KeyRotationRecord, error) {
	if p.pqcManager == nil {
		return nil, fmt.Errorf("PQC manager not initialized")
	}

	rec, err := p.pqcManager.RotateKey(algo, gracePeriod, reason)
	if err != nil {
		return nil, err
	}

	// Forward to Google Apps Script if remote mode is active
	if p.IsRemoteEnabled() {
		newKey, _ := p.pqcManager.LookupKey(rec.NewKeyID)
		var pubHex string
		if newKey != nil && newKey.MLDSAPublic != nil {
			pubHex = newKey.MLDSAPublic.RawHex
		}
		_, _ = p.gasClient.ExecuteAction(ctx, "pqc_key_save", map[string]interface{}{
			"key_id":      rec.NewKeyID,
			"algorithm":   rec.Algorithm,
			"public_hex":  pubHex,
			"status":      "active",
			"reason":      reason,
			"grace_until": rec.GraceUntil.Format(time.RFC3339),
		})
	}

	p.NotifyLicenseEvent(webhook.EventLicenseCreated, "pqc-system", rec.NewKeyID, fmt.Sprintf("Key rotated: %s -> %s", rec.OldKeyID, rec.NewKeyID))
	return rec, nil
}

// PQCRevokeKey immediately revokes a key and pushes an emergency kill-switch broadcast.
func (p *Proxy) PQCRevokeKey(ctx context.Context, keyID string, reason string) error {
	if p.pqcManager == nil {
		return fmt.Errorf("PQC manager not initialized")
	}

	if err := p.pqcManager.RevokeKey(keyID, reason); err != nil {
		return err
	}

	if p.IsRemoteEnabled() {
		_, _ = p.gasClient.ExecuteAction(ctx, "pqc_key_revoke", map[string]interface{}{
			"key_id": keyID,
			"reason": reason,
		})
	}

	// Instant broadcast kill-switch push over WebSocket hub
	p.BroadcastStreamEvent(stream.EventKillSwitch, map[string]interface{}{
		"action":  "pqc_key_revoked",
		"key_id":  keyID,
		"reason":  reason,
		"message": "PQC cryptographic key has been revoked; discard cached credentials",
	})

	p.NotifyLicenseEvent(webhook.EventTamperDetected, "pqc-system", keyID, fmt.Sprintf("Key revoked: %s (reason: %s)", keyID, reason))
	return nil
}

// GetPQCStatus retrieves the current operational telemetry of the PQC engine.
func (p *Proxy) GetPQCStatus() pqc.PQCStatusSummary {
	if p.pqcManager == nil {
		return pqc.PQCStatusSummary{
			DefaultAlgorithm: pqc.AlgoHybridP256,
		}
	}
	return p.pqcManager.GetStatus()
}
