package sdk

import (
	"context"
	"net/http"

	"github.com/kLauncher1/sheet-license-broker/internal/hsm"
)

// HSMSlotsResponse represents the response envelope for listing PKCS#11 slots.
type HSMSlotsResponse struct {
	Slots []hsm.SlotInfo `json:"slots"`
}

// HSMSelfTestResponse represents the response envelope for Known Answer Tests.
type HSMSelfTestResponse struct {
	SelfTests []hsm.SelfTestResult `json:"self_tests"`
	Count     int                  `json:"count"`
}

// GetHSMStatus retrieves the real-time status and FIPS compliance level of the HSM.
func (c *Client) GetHSMStatus(ctx context.Context) (*hsm.HSMVaultStatus, error) {
	var res hsm.HSMVaultStatus
	if err := c.request(ctx, http.MethodGet, "/api/hsm/status", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListHSMSlots lists all hardware cryptographic slots and tokens.
func (c *Client) ListHSMSlots(ctx context.Context) ([]hsm.SlotInfo, error) {
	var res HSMSlotsResponse
	if err := c.request(ctx, http.MethodGet, "/api/hsm/slots", nil, &res); err != nil {
		return nil, err
	}
	return res.Slots, nil
}

// HSMLogin authenticates an ephemeral session with a hardware slot token.
func (c *Client) HSMLogin(ctx context.Context, slotID int, userType, pin string) error {
	payload := map[string]interface{}{
		"slot_id":   slotID,
		"user_type": userType,
		"pin":       pin,
	}
	var res map[string]interface{}
	return c.request(ctx, http.MethodPost, "/api/hsm/login", payload, &res)
}

// HSMLogout revokes the authenticated session.
func (c *Client) HSMLogout(ctx context.Context, slotID int) error {
	payload := map[string]interface{}{"slot_id": slotID}
	var res map[string]interface{}
	return c.request(ctx, http.MethodPost, "/api/hsm/logout", payload, &res)
}

// DeriveHSMKey performs master key derivation within the hardware cryptoki boundary.
func (c *Client) DeriveHSMKey(ctx context.Context, req hsm.KeyDerivationRequest) (*hsm.KeyDerivationResponse, error) {
	var res hsm.KeyDerivationResponse
	if err := c.request(ctx, http.MethodPost, "/api/hsm/derive", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// EncryptHSMEnvelope encrypts a payload under an HSM-derived key envelope.
func (c *Client) EncryptHSMEnvelope(ctx context.Context, req hsm.EnvelopeEncryptRequest) (*hsm.EnvelopeEncryptResponse, error) {
	var res hsm.EnvelopeEncryptResponse
	if err := c.request(ctx, http.MethodPost, "/api/hsm/encrypt", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// DecryptHSMEnvelope decrypts an HSM envelope ciphertext.
func (c *Client) DecryptHSMEnvelope(ctx context.Context, req hsm.EnvelopeDecryptRequest) (*hsm.EnvelopeDecryptResponse, error) {
	var res hsm.EnvelopeDecryptResponse
	if err := c.request(ctx, http.MethodPost, "/api/hsm/decrypt", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// RunHSMSelfTest triggers on-demand Known Answer Tests (KAT) for FIPS 140-3 compliance.
func (c *Client) RunHSMSelfTest(ctx context.Context) ([]hsm.SelfTestResult, error) {
	var res HSMSelfTestResponse
	if err := c.request(ctx, http.MethodPost, "/api/hsm/fips/selftest", nil, &res); err != nil {
		return nil, err
	}
	return res.SelfTests, nil
}

// GetHSMFIPSReport retrieves the full formal FIPS 140-3 Level 4 audit certificate.
func (c *Client) GetHSMFIPSReport(ctx context.Context) (*hsm.FIPS140AuditReport, error) {
	var res hsm.FIPS140AuditReport
	if err := c.request(ctx, http.MethodGet, "/api/hsm/fips/report", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// SimulateHSMTamper triggers an environmental breach event on the hardware vault.
func (c *Client) SimulateHSMTamper(ctx context.Context, sensorID string) error {
	payload := map[string]interface{}{"sensor_id": sensorID}
	var res map[string]interface{}
	return c.request(ctx, http.MethodPost, "/api/hsm/tamper/simulate", payload, &res)
}

// ZeroizeHSM triggers immediate administrative zeroization of all key materials.
func (c *Client) ZeroizeHSM(ctx context.Context) error {
	var res map[string]interface{}
	return c.request(ctx, http.MethodPost, "/api/hsm/zeroize", nil, &res)
}
