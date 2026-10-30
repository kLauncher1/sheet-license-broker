package proxy

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/mlkem"
)

// initMLKEM bootstraps the NIST FIPS 203 ML-KEM lattice key encapsulation engine.
func (p *Proxy) initMLKEM(cfg ProxyConfig) {
	mgr, err := mlkem.NewManager(mlkem.ManagerConfig{
		DefaultAlgorithm: mlkem.AlgoMLKEM768,
		SessionTTL:       15 * time.Minute,
		QuantumEnforced:  cfg.MLKEMQuantumEnforced,
	})
	if err != nil {
		log.Printf("[Proxy Init Warning] Failed to initialize ML-KEM manager: %v", err)
		return
	}
	p.mlkemManager = mgr
}

// MLKEMManager returns the active ML-KEM manager.
func (p *Proxy) MLKEMManager() *mlkem.Manager {
	return p.mlkemManager
}

// GetMLKEMStatus returns operational telemetry for ML-KEM and hybrid exchange.
func (p *Proxy) GetMLKEMStatus() mlkem.MLKEMStatus {
	if p.mlkemManager == nil {
		return mlkem.MLKEMStatus{}
	}
	return p.mlkemManager.Status()
}

// ListMLKEMKeys returns all registered public encapsulation keys.
func (p *Proxy) ListMLKEMKeys() []*mlkem.PublicKey {
	if p.mlkemManager == nil {
		return nil
	}
	return p.mlkemManager.ListKeys()
}

// GenerateMLKEMKey generates and registers a new post-quantum keypair.
func (p *Proxy) GenerateMLKEMKey(algo string) (*mlkem.PublicKey, error) {
	if p.mlkemManager == nil {
		return nil, fmt.Errorf("ml-kem manager not initialized")
	}

	pk, err := p.mlkemManager.GenerateKey(algo)
	if err != nil {
		return nil, err
	}

	// Dispatch asynchronous ledger audit log to Google Apps Script
	if p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "mlkem_log_key", map[string]interface{}{
				"key_id":      pk.KeyID,
				"algorithm":   pk.Algorithm,
				"fingerprint": pk.Fingerprint,
				"created_at":  pk.CreatedAt.Format(time.RFC3339),
			})
		}()
	}

	return pk, nil
}

// EncapsulateMLKEM encapsulates a shared secret against the specified public key.
func (p *Proxy) EncapsulateMLKEM(keyID string) (*mlkem.EncapsulationResult, error) {
	if p.mlkemManager == nil {
		return nil, fmt.Errorf("ml-kem manager not initialized")
	}
	return p.mlkemManager.Encapsulate(keyID)
}

// DecapsulateMLKEM decapsulates a ciphertext using the specified private key.
func (p *Proxy) DecapsulateMLKEM(keyID string, ciphertext []byte) ([]byte, error) {
	if p.mlkemManager == nil {
		return nil, fmt.Errorf("ml-kem manager not initialized")
	}
	return p.mlkemManager.Decapsulate(keyID, ciphertext)
}

// HandleHybridKEMHandshake executes a complete hybrid post-quantum key exchange.
func (p *Proxy) HandleHybridKEMHandshake(req mlkem.HybridHandshakeRequest) (*mlkem.HybridHandshakeResponse, error) {
	if p.mlkemManager == nil {
		return nil, fmt.Errorf("ml-kem manager not initialized")
	}

	resp, err := p.mlkemManager.HandleHybridHandshake(req)
	if err != nil {
		return nil, err
	}

	// Dispatch asynchronous session log to Google Apps Script
	if p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "mlkem_log_session", map[string]interface{}{
				"session_id":        resp.SessionID,
				"agreed_mode":       resp.AgreedMode,
				"algorithm":         resp.Algorithm,
				"quantum_resistant": resp.QuantumResistant,
				"expires_at":        resp.ExpiresAt.Format(time.RFC3339),
			})
		}()
	}

	return resp, nil
}

// VerifyHybridKEMSession checks if an ephemeral session is valid and active.
func (p *Proxy) VerifyHybridKEMSession(sessionID string) (*mlkem.HybridSession, error) {
	if p.mlkemManager == nil {
		return nil, fmt.Errorf("ml-kem manager not initialized")
	}
	return p.mlkemManager.VerifySession(sessionID)
}
