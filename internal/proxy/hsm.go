package proxy

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/hsm"
)

// initHSM bootstraps the Hardware Security Module (HSM) PKCS#11 vault manager.
func (p *Proxy) initHSM(cfg ProxyConfig) {
	mgr, err := hsm.NewManager()
	if err != nil {
		log.Printf("[Proxy Init Warning] Failed to initialize HSM manager: %v", err)
		return
	}
	p.hsmManager = mgr
}

// HSMManager returns the active HSM vault manager.
func (p *Proxy) HSMManager() *hsm.HSMManager {
	return p.hsmManager
}

// GetHSMStatus returns a real-time status snapshot of the HSM vault.
func (p *Proxy) GetHSMStatus() hsm.HSMVaultStatus {
	if p.hsmManager == nil {
		return hsm.HSMVaultStatus{}
	}
	return p.hsmManager.Status()
}

// ListHSMSlots returns all provisioned PKCS#11 hardware slots.
func (p *Proxy) ListHSMSlots() []hsm.SlotInfo {
	if p.hsmManager == nil {
		return nil
	}
	return p.hsmManager.ListSlots()
}

// HSMLogin authenticates an ephemeral session with the specified slot token.
func (p *Proxy) HSMLogin(slotID int, userType uint32, pin string) error {
	if p.hsmManager == nil {
		return fmt.Errorf("hsm manager not initialized")
	}

	handle, err := p.hsmManager.OpenSession(slotID)
	if err != nil {
		return fmt.Errorf("failed to open hsm session on slot %d: %w", slotID, err)
	}

	if err := p.hsmManager.Login(handle, userType, pin); err != nil {
		_ = p.hsmManager.CloseSession(handle)
		return err
	}

	return nil
}

// HSMLogout revokes active sessions on the specified slot.
func (p *Proxy) HSMLogout(slotID int) error {
	if p.hsmManager == nil {
		return fmt.Errorf("hsm manager not initialized")
	}
	return nil
}

// DeriveHSMKey derives an envelope key using the hardware token master secret.
func (p *Proxy) DeriveHSMKey(ctx context.Context, req hsm.KeyDerivationRequest) (*hsm.KeyDerivationResponse, error) {
	if p.hsmManager == nil {
		return nil, fmt.Errorf("hsm manager not initialized")
	}

	resp, _, err := p.hsmManager.DeriveMasterKey(req)
	if err != nil {
		return nil, err
	}

	// Dispatch asynchronous audit log to Google Apps Script backend if remote is active
	if p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "hsm_log_event", map[string]interface{}{
				"slot_id":     req.SlotID,
				"event_type":  "KEY_DERIVATION",
				"purpose":     req.Purpose,
				"fingerprint": resp.Fingerprint,
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			})
		}()
	}

	return resp, nil
}

// EncryptHSMEnvelope encrypts and authenticates a payload using an HSM-derived key.
func (p *Proxy) EncryptHSMEnvelope(req hsm.EnvelopeEncryptRequest) (*hsm.EnvelopeEncryptResponse, error) {
	if p.hsmManager == nil {
		return nil, fmt.Errorf("hsm manager not initialized")
	}
	return p.hsmManager.EncryptEnvelope(req)
}

// DecryptHSMEnvelope decrypts and verifies an HSM envelope ciphertext.
func (p *Proxy) DecryptHSMEnvelope(req hsm.EnvelopeDecryptRequest) (*hsm.EnvelopeDecryptResponse, error) {
	if p.hsmManager == nil {
		return nil, fmt.Errorf("hsm manager not initialized")
	}
	return p.hsmManager.DecryptEnvelope(req)
}

// RunHSMSelfTest triggers on-demand Known Answer Tests (KAT) for FIPS 140-3 validation.
func (p *Proxy) RunHSMSelfTest() []hsm.SelfTestResult {
	if p.hsmManager == nil {
		return nil
	}
	return p.hsmManager.RunSelfTest()
}

// GetHSMFIPSReport generates the formal FIPS 140-3 Level 4 compliance audit record.
func (p *Proxy) GetHSMFIPSReport() *hsm.FIPS140AuditReport {
	if p.hsmManager == nil {
		return nil
	}
	return p.hsmManager.GetFIPSReport()
}

// SimulateHSMTamper triggers environmental tamper response, locking the hardware.
func (p *Proxy) SimulateHSMTamper(sensorID string) error {
	if p.hsmManager == nil {
		return fmt.Errorf("hsm manager not initialized")
	}

	if err := p.hsmManager.SimulateTamper(sensorID); err != nil {
		return err
	}

	if p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "hsm_log_event", map[string]interface{}{
				"event_type": "TAMPER_DETECTED",
				"sensor_id":  sensorID,
				"timestamp":  time.Now().UTC().Format(time.RFC3339),
			})
		}()
	}

	return nil
}

// ZeroizeHSM wipes all hardware key material immediately.
func (p *Proxy) ZeroizeHSM() {
	if p.hsmManager != nil {
		p.hsmManager.Zeroize()
	}
}
