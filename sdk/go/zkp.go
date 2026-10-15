package sdk

import (
	"context"
	"fmt"
	"math/big"
	"net/http"

	"github.com/kLauncher1/sheet-license-broker/internal/zkp"
)

// GetZKPParams fetches the public elliptic curve parameters and issuer public key.
func (c *Client) GetZKPParams(ctx context.Context) (map[string]interface{}, error) {
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/api/zkp/params", nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// IssueAnonymousCredential requests an issuer-signed zero-knowledge credential.
func (c *Client) IssueAnonymousCredential(
	ctx context.Context,
	licenseKey string,
	hwid string,
	tier string,
	validDays int,
	scope string,
) (*zkp.AnonymousCredential, *big.Int, error) {
	if hwid == "" {
		hwid = GetMachineHWID()
	}
	req := map[string]interface{}{
		"license_key": licenseKey,
		"hwid":        hwid,
		"tier":        tier,
		"valid_days":  validDays,
		"scope":       scope,
		"tenant_id":   c.tenantID,
	}
	var res struct {
		Status         string                   `json:"status"`
		Credential     *zkp.AnonymousCredential `json:"credential"`
		BlindingFactor string                   `json:"blinding_factor"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/zkp/credential/issue", req, &res); err != nil {
		return nil, nil, err
	}
	var rScalar *big.Int
	if res.BlindingFactor != "" {
		var ok bool
		rScalar, ok = new(big.Int).SetString(res.BlindingFactor, 16)
		if !ok {
			return nil, nil, fmt.Errorf("failed to parse blinding factor from response")
		}
	}
	return res.Credential, rScalar, nil
}

// VerifyZKPProof submits a zero-knowledge presentation proof for entitlement access.
func (c *Client) VerifyZKPProof(
	ctx context.Context,
	proof *zkp.ZKPProof,
	requiredTier string,
	epoch int64,
) (*zkp.VerificationResult, error) {
	req := map[string]interface{}{
		"proof":         proof,
		"required_tier": requiredTier,
		"epoch":         epoch,
	}
	var res struct {
		Status  string                  `json:"status"`
		Valid   bool                    `json:"valid"`
		Details *zkp.VerificationResult `json:"details"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/zkp/verify", req, &res); err != nil {
		return nil, err
	}
	return res.Details, nil
}

// GetZKPStatus queries overall telemetry metrics on zero-knowledge verification.
func (c *Client) GetZKPStatus(ctx context.Context) (map[string]interface{}, error) {
	var res struct {
		Status string                 `json:"status"`
		ZKP    map[string]interface{} `json:"zkp"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/zkp/status", nil, &res); err != nil {
		return nil, err
	}
	return res.ZKP, nil
}
