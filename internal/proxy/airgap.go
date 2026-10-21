package proxy

import (
	"context"
	"fmt"
	"log"

	"github.com/kLauncher1/sheet-license-broker/internal/airgap"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

// initAirGap sets up the air-gap vault manager.
func (p *Proxy) initAirGap(cfg ProxyConfig) {
	mgr, err := airgap.NewManager(nil, nil)
	if err != nil {
		log.Printf("[Proxy] Warning: Failed to initialize AirGap manager: %v", err)
		return
	}
	p.airgapManager = mgr
}

// AirGapManager returns the attached air-gap vault manager instance.
func (p *Proxy) AirGapManager() *airgap.Manager {
	return p.airgapManager
}

// IssueAirgapToken generates a signed offline dongle token and records audit events.
func (p *Proxy) IssueAirgapToken(ctx context.Context, req airgap.IssueTokenRequest) (*airgap.DongleToken, string, string, error) {
	if p.airgapManager == nil {
		return nil, "", "", fmt.Errorf("airgap manager is not initialized")
	}

	token, compact, qrPayload, err := p.airgapManager.IssueDongleToken(req)
	if err != nil {
		return nil, "", "", err
	}

	// Broadcast stream event
	p.BroadcastStreamEvent("airgap_token_issued", map[string]interface{}{
		"token_id":    token.TokenID,
		"license_key": token.LicenseKey,
		"hwid":        token.HWID,
		"tier":        token.Tier,
		"expires_at":  token.ExpiresAt,
		"counter":     token.Counter,
	})

	p.NotifyLicenseEvent(webhook.EventLicenseCreated, token.LicenseKey, token.HWID, fmt.Sprintf("AirGap Dongle Token Issued (%s)", token.TokenID))

	// If remote GAS is enabled, asynchronously record token
	if p.IsRemoteEnabled() && p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "airgap_record_token", map[string]interface{}{
				"token_id":    token.TokenID,
				"license_key": token.LicenseKey,
				"hwid":        token.HWID,
				"tier":        token.Tier,
				"issued_at":   token.IssuedAt,
				"expires_at":  token.ExpiresAt,
				"counter":     token.Counter,
				"status":      "ACTIVE",
				"signature":   token.Signature,
			})
		}()
	}

	return token, compact, qrPayload, nil
}

// VerifyAirgapToken unpacks and cryptographically validates an offline dongle token.
func (p *Proxy) VerifyAirgapToken(ctx context.Context, tokenStr, hwid string, currentTimestamp int64) (*airgap.DongleToken, error) {
	if p.airgapManager == nil {
		return nil, fmt.Errorf("airgap manager is not initialized")
	}

	token, err := p.airgapManager.VerifyDongleToken(tokenStr, hwid, currentTimestamp)
	if err != nil {
		p.BroadcastStreamEvent("airgap_verify_failed", map[string]interface{}{
			"hwid":      hwid,
			"error":     err.Error(),
			"timestamp": currentTimestamp,
		})
		p.NotifyLicenseEvent(webhook.EventTamperDetected, "", hwid, fmt.Sprintf("AirGap token verification failed: %v", err))
		return nil, err
	}

	p.BroadcastStreamEvent("airgap_token_verified", map[string]interface{}{
		"token_id":    token.TokenID,
		"license_key": token.LicenseKey,
		"hwid":        token.HWID,
		"counter":     token.Counter,
	})

	return token, nil
}

// RequestAirgapActivation processes an offline activation request.
func (p *Proxy) RequestAirgapActivation(ctx context.Context, req airgap.ActivationRequest) (*airgap.ActivationResponse, error) {
	if p.airgapManager == nil {
		return nil, fmt.Errorf("airgap manager is not initialized")
	}

	res, err := p.airgapManager.RequestActivation(req)
	if err != nil {
		return nil, err
	}

	p.BroadcastStreamEvent("airgap_activation_requested", map[string]interface{}{
		"request_id":  res.RequestID,
		"license_key": res.LicenseKey,
		"hwid":        res.HWID,
		"status":      res.Status,
	})

	return res, nil
}

// FulfillAirgapActivation consumes an air-gap QR payload and validates the embedded dongle token.
func (p *Proxy) FulfillAirgapActivation(ctx context.Context, qrPayload string) (*airgap.DongleToken, error) {
	if p.airgapManager == nil {
		return nil, fmt.Errorf("airgap manager is not initialized")
	}

	token, err := p.airgapManager.FulfillActivation(qrPayload)
	if err != nil {
		return nil, err
	}

	p.BroadcastStreamEvent("airgap_activation_fulfilled", map[string]interface{}{
		"token_id":    token.TokenID,
		"license_key": token.LicenseKey,
		"hwid":        token.HWID,
	})

	return token, nil
}

// UnlockAirgapRollback resets a tripped anti-rollback guard using an administrative unlock token.
func (p *Proxy) UnlockAirgapRollback(ctx context.Context, req airgap.UnlockRequest) (*airgap.RollbackState, error) {
	if p.airgapManager == nil {
		return nil, fmt.Errorf("airgap manager is not initialized")
	}

	st, err := p.airgapManager.UnlockRollback(req)
	if err != nil {
		return nil, err
	}

	p.BroadcastStreamEvent("airgap_vault_unlocked", map[string]interface{}{
		"vault_id":          st.VaultID,
		"hwid":              st.HWID,
		"monotonic_counter": st.MonotonicCounter,
		"unlocked_at":       st.UnlockedAt,
	})

	return st, nil
}

// GetAirgapRollbackState queries current monotonic clock and tamper status for an HWID.
func (p *Proxy) GetAirgapRollbackState(hwid string) *airgap.RollbackState {
	if p.airgapManager == nil {
		return &airgap.RollbackState{
			VaultID: "VAULT-" + hwid,
			HWID:    hwid,
		}
	}
	return p.airgapManager.GetRollbackState(hwid)
}

// GetAirgapStatus returns diagnostic telemetry for the air-gap vault subsystem.
func (p *Proxy) GetAirgapStatus() map[string]interface{} {
	if p.airgapManager == nil {
		return map[string]interface{}{
			"enabled": false,
			"status":  "disabled",
		}
	}

	st := p.airgapManager.GetStatus()
	return map[string]interface{}{
		"status":                 "success",
		"enabled":                true,
		"vault_active":           st.VaultActive,
		"master_public_key":      st.MasterPublicKey,
		"admin_public_key":       st.AdminPublicKey,
		"total_issued_tokens":    st.TotalIssuedTokens,
		"total_verified_tokens":  st.TotalVerifiedTokens,
		"total_activations":      st.TotalActivations,
		"rollback_tripped_count": st.RollbackTrippedCount,
		"last_high_water_mark":   st.LastHighWaterMark,
		"tracked_vaults":         st.TrackedVaults,
		"timestamp":              st.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
	}
}
