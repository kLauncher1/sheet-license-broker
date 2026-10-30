package sdk

import (
	"context"
	"fmt"
	"net/http"

	"github.com/kLauncher1/sheet-license-broker/internal/mlkem"
)

// MLKEMKeysResponse represents the envelope for listing public encapsulation keys.
type MLKEMKeysResponse struct {
	Keys []*mlkem.PublicKey `json:"keys"`
}

// MLKEMDecapsulateResponse represents the response envelope for decapsulation.
type MLKEMDecapsulateResponse struct {
	KeyID           string `json:"key_id"`
	SharedSecretHex string `json:"shared_secret_hex"`
}

// MLKEMVerifySessionResponse represents the verification outcome for a hybrid session.
type MLKEMVerifySessionResponse struct {
	Valid            bool   `json:"valid"`
	SessionID        string `json:"session_id"`
	AgreedMode       string `json:"agreed_mode"`
	Algorithm        string `json:"algorithm"`
	QuantumResistant bool   `json:"quantum_resistant"`
}

// GetMLKEMStatus queries real-time operational status and telemetry for ML-KEM.
func (c *Client) GetMLKEMStatus(ctx context.Context) (*mlkem.MLKEMStatus, error) {
	var res mlkem.MLKEMStatus
	if err := c.request(ctx, http.MethodGet, "/api/pqc/kem/status", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListMLKEMKeys lists all registered public encapsulation keys.
func (c *Client) ListMLKEMKeys(ctx context.Context) ([]*mlkem.PublicKey, error) {
	var res MLKEMKeysResponse
	if err := c.request(ctx, http.MethodGet, "/api/pqc/kem/keys", nil, &res); err != nil {
		return nil, err
	}
	return res.Keys, nil
}

// GenerateMLKEMKey requests generation and registration of a new lattice keypair.
func (c *Client) GenerateMLKEMKey(ctx context.Context, algo string) (*mlkem.PublicKey, error) {
	payload := map[string]string{"algorithm": algo}
	var res mlkem.PublicKey
	if err := c.request(ctx, http.MethodPost, "/api/pqc/kem/keys/generate", payload, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// EncapsulateMLKEM encapsulates a shared secret against the target encapsulation key.
func (c *Client) EncapsulateMLKEM(ctx context.Context, keyID string) (*mlkem.EncapsulationResult, error) {
	payload := map[string]string{"key_id": keyID}
	var res mlkem.EncapsulationResult
	if err := c.request(ctx, http.MethodPost, "/api/pqc/kem/encapsulate", payload, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// DecapsulateMLKEM decapsulates a ciphertext using the server-side private key.
func (c *Client) DecapsulateMLKEM(ctx context.Context, keyID, ciphertextHex string) (string, error) {
	payload := map[string]string{
		"key_id":         keyID,
		"ciphertext_hex": ciphertextHex,
	}
	var res MLKEMDecapsulateResponse
	if err := c.request(ctx, http.MethodPost, "/api/pqc/kem/decapsulate", payload, &res); err != nil {
		return "", err
	}
	return res.SharedSecretHex, nil
}

// HybridKEMHandshake establishes an authenticated forward-secrecy hybrid session.
func (c *Client) HybridKEMHandshake(ctx context.Context, req mlkem.HybridHandshakeRequest) (*mlkem.HybridHandshakeResponse, error) {
	var res mlkem.HybridHandshakeResponse
	if err := c.request(ctx, http.MethodPost, "/api/pqc/kem/handshake", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// VerifyHybridKEMSession checks whether the specified session ID is active.
func (c *Client) VerifyHybridKEMSession(ctx context.Context, sessionID string) (bool, error) {
	path := fmt.Sprintf("/api/pqc/kem/sessions/verify?session_id=%s", sessionID)
	var res MLKEMVerifySessionResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return false, err
	}
	return res.Valid, nil
}
