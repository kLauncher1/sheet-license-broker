package sdk

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/kLauncher1/sheet-license-broker/internal/enclave"
)

// EnclaveHandshakeResult models the outcome of an established confidential enclave tunnel.
type EnclaveHandshakeResult struct {
	Established     bool   `json:"established"`
	SessionID       string `json:"session_id"`
	BrokerPublicKey string `json:"broker_public_key"`
	ExpiresAt       string `json:"expires_at"`
}

// RequestEnclaveChallenge requests an ephemeral cryptographic nonce from the broker.
func (c *Client) RequestEnclaveChallenge(ctx context.Context) (string, error) {
	var res struct {
		Challenge string `json:"challenge"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/enclave/challenge", nil, &res); err != nil {
		return "", err
	}
	return res.Challenge, nil
}

// AttestEnclaveQuote submits an Intel SGX or AMD SEV-SNP attestation quote for policy verification.
func (c *Client) AttestEnclaveQuote(ctx context.Context, platform enclave.PlatformType, rawQuote []byte, nonce, policyID string) (*enclave.AttestationResult, error) {
	req := map[string]interface{}{
		"platform":  platform,
		"quote":     hex.EncodeToString(rawQuote),
		"nonce":     nonce,
		"policy_id": policyID,
	}
	var res struct {
		Valid       bool                       `json:"valid"`
		Attestation *enclave.AttestationResult `json:"attestation"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/enclave/attest", req, &res); err != nil {
		return nil, err
	}
	return res.Attestation, nil
}

// EstablishEnclaveTunnel validates an enclave quote and derives an end-to-end encrypted session channel.
func (c *Client) EstablishEnclaveTunnel(ctx context.Context, platform enclave.PlatformType, rawQuote []byte, nonce, policyID, clientPubHex string) (*EnclaveHandshakeResult, error) {
	req := map[string]interface{}{
		"platform":          platform,
		"quote":             hex.EncodeToString(rawQuote),
		"nonce":             nonce,
		"policy_id":         policyID,
		"client_public_key": clientPubHex,
	}
	var res EnclaveHandshakeResult
	if err := c.request(ctx, http.MethodPost, "/api/enclave/tunnel/handshake", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// EvaluateEnclaveLicense submits an encrypted license evaluation query inside the zero-plaintext tunnel.
func (c *Client) EvaluateEnclaveLicense(ctx context.Context, msg *enclave.EncryptedTunnelMessage) (*enclave.EncryptedTunnelMessage, error) {
	req := map[string]interface{}{
		"session_id": msg.SessionID,
		"sequence":   msg.Sequence,
		"nonce":      msg.NonceHex,
		"payload":    msg.PayloadHex,
	}
	var res struct {
		SessionID string `json:"session_id"`
		Sequence  uint64 `json:"sequence"`
		Nonce     string `json:"nonce"`
		Payload   string `json:"payload"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/enclave/tunnel/evaluate", req, &res); err != nil {
		return nil, err
	}
	return &enclave.EncryptedTunnelMessage{
		SessionID:  res.SessionID,
		Sequence:   res.Sequence,
		NonceHex:   res.Nonce,
		PayloadHex: res.Payload,
	}, nil
}

// GetEnclaveStatus retrieves confidential computing operational telemetry and registered policies.
func (c *Client) GetEnclaveStatus(ctx context.Context) (map[string]interface{}, error) {
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/api/enclave/status", nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}
