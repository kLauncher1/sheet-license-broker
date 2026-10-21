package sdk

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/airgap"
)

// AirgapIssueResponse captures the result of issuing an offline dongle token.
type AirgapIssueResponse struct {
	Status      string              `json:"status"`
	Token       *airgap.DongleToken `json:"token"`
	DongleToken string              `json:"dongle_token"`
	QRPayload   string              `json:"qr_payload"`
}

// AirgapVerifyResponse captures the outcome of verifying an offline dongle token.
type AirgapVerifyResponse struct {
	Status string              `json:"status"`
	Valid  bool                `json:"valid"`
	Token  *airgap.DongleToken `json:"token"`
	Error  string              `json:"error,omitempty"`
}

// AirgapActivateResponse encapsulates the result of an airgap activation challenge request.
type AirgapActivateResponse struct {
	Status     string                     `json:"status"`
	Activation *airgap.ActivationResponse `json:"activation"`
}

// AirgapRollbackResponse encapsulates the current or updated monotonic rollback state.
type AirgapRollbackResponse struct {
	Status string                `json:"status"`
	State  *airgap.RollbackState `json:"state"`
}

// GetAirgapStatus queries operational telemetry from the air-gapped license vault.
func (c *Client) GetAirgapStatus(ctx context.Context) (map[string]interface{}, error) {
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/api/airgap/status", nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// IssueAirgapDongleToken requests the broker to issue a cryptographically signed offline dongle token.
func (c *Client) IssueAirgapDongleToken(ctx context.Context, licenseKey, hwid, tier string, daysValid, maxDevices int, features []string) (*airgap.DongleToken, string, string, error) {
	req := airgap.IssueTokenRequest{
		LicenseKey: licenseKey,
		HWID:       hwid,
		Tier:       tier,
		DaysValid:  daysValid,
		MaxDevices: maxDevices,
		Features:   features,
	}

	var res AirgapIssueResponse
	if err := c.request(ctx, http.MethodPost, "/api/airgap/token/issue", req, &res); err != nil {
		return nil, "", "", err
	}
	return res.Token, res.DongleToken, res.QRPayload, nil
}

// VerifyAirgapDongleToken verifies an offline dongle token against the master key and monotonic clock.
func (c *Client) VerifyAirgapDongleToken(ctx context.Context, token, hwid string) (*airgap.DongleToken, error) {
	req := map[string]interface{}{
		"token":     token,
		"hwid":      hwid,
		"timestamp": time.Now().Unix(),
	}

	var res AirgapVerifyResponse
	if err := c.request(ctx, http.MethodPost, "/api/airgap/token/verify", req, &res); err != nil {
		return nil, err
	}
	if !res.Valid {
		return nil, fmt.Errorf("airgap verification failed: %s", res.Error)
	}
	return res.Token, nil
}

// RequestAirgapActivation generates an offline activation challenge response with QR payload.
func (c *Client) RequestAirgapActivation(ctx context.Context, licenseKey, hwid string) (*airgap.ActivationResponse, error) {
	req := airgap.ActivationRequest{
		LicenseKey: licenseKey,
		HWID:       hwid,
	}

	var res AirgapActivateResponse
	if err := c.request(ctx, http.MethodPost, "/api/airgap/activate/request", req, &res); err != nil {
		return nil, err
	}
	return res.Activation, nil
}

// FulfillAirgapActivation consumes an air-gap QR payload and returns the activated DongleToken.
func (c *Client) FulfillAirgapActivation(ctx context.Context, qrPayload string) (*airgap.DongleToken, error) {
	req := map[string]string{
		"qr_payload": qrPayload,
	}

	var res struct {
		Status string              `json:"status"`
		Token  *airgap.DongleToken `json:"token"`
		Error  string              `json:"error,omitempty"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/airgap/activate/fulfill", req, &res); err != nil {
		return nil, err
	}
	if res.Status != "success" || res.Token == nil {
		return nil, fmt.Errorf("activation fulfillment failed: %s", res.Error)
	}
	return res.Token, nil
}

// GetAirgapRollbackState retrieves the monotonic high-water mark and tamper state for an HWID.
func (c *Client) GetAirgapRollbackState(ctx context.Context, hwid string) (*airgap.RollbackState, error) {
	path := "/api/airgap/rollback/state"
	if hwid != "" {
		path += "?hwid=" + url.QueryEscape(hwid)
	}

	var res AirgapRollbackResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return res.State, nil
}

// UnlockAirgapRollback restores a tripped monotonic vault state using an administrative unlock token.
func (c *Client) UnlockAirgapRollback(ctx context.Context, req airgap.UnlockRequest) (*airgap.RollbackState, error) {
	var res AirgapRollbackResponse
	if err := c.request(ctx, http.MethodPost, "/api/airgap/rollback/unlock", req, &res); err != nil {
		return nil, err
	}
	return res.State, nil
}
