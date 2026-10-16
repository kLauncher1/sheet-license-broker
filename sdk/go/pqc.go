package sdk

import (
	"context"
	"net/http"

	"github.com/kLauncher1/sheet-license-broker/internal/pqc"
)

// GetPQCParams retrieves supported algorithms, lattice parameters, and active key metadata.
func (c *Client) GetPQCParams(ctx context.Context) (map[string]interface{}, error) {
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/api/pqc/params", nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// GetPQCPublicKeys retrieves all active and grace-period public keys for client-side lattice verification.
func (c *Client) GetPQCPublicKeys(ctx context.Context) ([]map[string]interface{}, error) {
	var res struct {
		Status string                   `json:"status"`
		Count  int                      `json:"count"`
		Keys   []map[string]interface{} `json:"keys"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/pqc/keys", nil, &res); err != nil {
		return nil, err
	}
	return res.Keys, nil
}

// SignPQCLicense issues a quantum-resistant hybrid signature over a payload for an authenticated license.
func (c *Client) SignPQCLicense(ctx context.Context, licenseKey, hwid, payload string) (*pqc.HybridSignature, error) {
	if hwid == "" {
		hwid = GetMachineHWID()
	}
	req := map[string]string{
		"license_key": licenseKey,
		"hwid":        hwid,
		"payload":     payload,
	}
	var res struct {
		Status    string            `json:"status"`
		Signature pqc.HybridSignature `json:"signature"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/pqc/sign", req, &res); err != nil {
		return nil, err
	}
	return &res.Signature, nil
}

// VerifyPQCSignature submits a hybrid classical and post-quantum signature for validation.
func (c *Client) VerifyPQCSignature(ctx context.Context, payload string, sig pqc.HybridSignature) (*pqc.PQCVerificationResult, error) {
	req := map[string]interface{}{
		"payload":   payload,
		"signature": sig,
	}
	var res struct {
		Status string                    `json:"status"`
		Result pqc.PQCVerificationResult `json:"result"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/pqc/verify", req, &res); err != nil {
		return nil, err
	}
	return &res.Result, nil
}

// RotatePQCKey requests an administrative key rotation with an active grace window.
func (c *Client) RotatePQCKey(ctx context.Context, algo string, graceDays int, reason string) (map[string]interface{}, error) {
	req := map[string]interface{}{
		"algorithm":  algo,
		"grace_days": graceDays,
		"reason":     reason,
	}
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodPost, "/api/pqc/rotate", req, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// RevokePQCKey revokes a compromised cryptographic key by ID.
func (c *Client) RevokePQCKey(ctx context.Context, keyID, reason string) error {
	req := map[string]string{
		"key_id": keyID,
		"reason": reason,
	}
	var res map[string]interface{}
	return c.request(ctx, http.MethodPost, "/api/pqc/revoke", req, &res)
}

// GetPQCStatus retrieves operational statistics for the PQC subsystem.
func (c *Client) GetPQCStatus(ctx context.Context) (*pqc.PQCStatusSummary, error) {
	var res struct {
		Status string               `json:"status"`
		PQC    pqc.PQCStatusSummary `json:"pqc"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/pqc/status", nil, &res); err != nil {
		return nil, err
	}
	return &res.PQC, nil
}
