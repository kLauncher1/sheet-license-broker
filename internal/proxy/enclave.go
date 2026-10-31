package proxy

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/enclave"
	"github.com/kLauncher1/sheet-license-broker/internal/feature"
)

var (
	ErrEnclaveManagerNotInitialized = errors.New("enclave manager is not initialized")
)

// initEnclave sets up the confidential computing enclave coordinator.
func (p *Proxy) initEnclave() {
	p.enclaveManager = enclave.NewManager()
}

// EnclaveManager returns the active confidential computing manager.
func (p *Proxy) EnclaveManager() *enclave.Manager {
	return p.enclaveManager
}

// GenerateEnclaveChallenge generates an ephemeral cryptographic nonce for enclave attestation.
func (p *Proxy) GenerateEnclaveChallenge() (string, error) {
	if p.enclaveManager == nil {
		return "", ErrEnclaveManagerNotInitialized
	}
	return p.enclaveManager.GenerateChallenge()
}

// AttestEnclaveQuote verifies a remote Intel SGX or AMD SEV-SNP attestation quote.
func (p *Proxy) AttestEnclaveQuote(platform enclave.PlatformType, rawQuote []byte, nonce string, policyID string) (*enclave.AttestationResult, error) {
	if p.enclaveManager == nil {
		return nil, ErrEnclaveManagerNotInitialized
	}
	return p.enclaveManager.AttestQuote(platform, rawQuote, nonce, policyID)
}

// EstablishEnclaveTunnel validates an enclave quote and derives an end-to-end encrypted session tunnel.
func (p *Proxy) EstablishEnclaveTunnel(platform enclave.PlatformType, rawQuote []byte, nonce string, policyID string, clientPubHex string) (*enclave.EnclaveTunnelSession, string, error) {
	if p.enclaveManager == nil {
		return nil, "", ErrEnclaveManagerNotInitialized
	}
	return p.enclaveManager.EstablishTunnel(platform, rawQuote, nonce, policyID, clientPubHex)
}

// EvaluateLicenseInEnclave processes an encrypted license evaluation query inside a zero-plaintext memory boundary.
func (p *Proxy) EvaluateLicenseInEnclave(ctx context.Context, sessionID string, encryptedMsg *enclave.EncryptedTunnelMessage) (*enclave.EncryptedTunnelMessage, error) {
	if p.enclaveManager == nil {
		return nil, ErrEnclaveManagerNotInitialized
	}

	return p.enclaveManager.EvaluateZeroPlaintext(sessionID, encryptedMsg, func(payload *enclave.EnclaveEvalPayload) (*enclave.EnclaveEvalResponse, error) {
		key := strings.TrimSpace(payload.LicenseKey)
		hwid := strings.TrimSpace(payload.HWID)

		if key == "" {
			return &enclave.EnclaveEvalResponse{
				Valid:   false,
				Message: "License key is required",
			}, nil
		}

		vRes, err := p.VerifyLicense(ctx, key, hwid)
		if err != nil || !vRes.Valid {
			msg := "License is invalid or expired"
			if vRes != nil && vRes.Message != "" {
				msg = vRes.Message
			}
			return &enclave.EnclaveEvalResponse{
				Valid:      false,
				LicenseKey: key,
				Message:    msg,
			}, nil
		}

		// Check requested feature flag if provided
		var grantedFeatures []string
		if p.featureManager != nil {
			fallback := feature.NormalizeTier(vRes.Tier)
			if payload.RequestedFeature != "" {
				if p.featureManager.IsFeatureEnabled(key, payload.RequestedFeature, fallback) {
					grantedFeatures = append(grantedFeatures, payload.RequestedFeature)
				}
			} else {
				_, grantedFeatures = p.featureManager.GetEffectiveFeatures(key, fallback)
			}
		}

		return &enclave.EnclaveEvalResponse{
			Valid:      true,
			LicenseKey: key,
			Tier:       vRes.Tier,
			Features:   grantedFeatures,
			ExpiresAt:  vRes.ExpiresAt,
			EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
			Message:    "Hardware enclave license evaluation confirmed",
		}, nil
	})
}

// RegisterEnclavePolicy adds a new measurement policy to the enclave coordinator.
func (p *Proxy) RegisterEnclavePolicy(policy *enclave.EnclavePolicy) error {
	if p.enclaveManager == nil {
		return ErrEnclaveManagerNotInitialized
	}
	return p.enclaveManager.RegisterPolicy(policy)
}

// GetEnclaveTelemetry returns operational stats for the confidential computing subsystem.
func (p *Proxy) GetEnclaveTelemetry() enclave.EnclaveTelemetry {
	if p.enclaveManager == nil {
		return enclave.EnclaveTelemetry{}
	}
	return p.enclaveManager.GetTelemetry()
}

// VerifyTDXQuote verifies an Intel TDX Quote v4.
func (p *Proxy) VerifyTDXQuote(rawQuote []byte, nonce string, policyID string) (*enclave.AttestationResult, error) {
	if p.enclaveManager == nil {
		return nil, ErrEnclaveManagerNotInitialized
	}
	return p.enclaveManager.AttestQuote(enclave.PlatformTDX, rawQuote, nonce, policyID)
}

// IssueEnclaveAttestationToken issues a cryptographically signed attestation token.
func (p *Proxy) IssueEnclaveAttestationToken(platform enclave.PlatformType, measurement, rtmr0 string, svn uint32, debug bool, nonce, pubKey string, ttlSec int) (*enclave.AttestationToken, error) {
	if p.enclaveManager == nil || p.enclaveManager.TokenManager() == nil {
		return nil, ErrEnclaveManagerNotInitialized
	}
	ttl := time.Duration(ttlSec) * time.Second
	return p.enclaveManager.TokenManager().IssueToken(platform, measurement, rtmr0, svn, debug, nonce, pubKey, ttl)
}

// VerifyEnclaveAttestationToken verifies an attestation token against security policies.
func (p *Proxy) VerifyEnclaveAttestationToken(token *enclave.AttestationToken, minSVN uint32, allowDebug bool) (*enclave.TokenVerifyResult, error) {
	if p.enclaveManager == nil || p.enclaveManager.TokenManager() == nil {
		return nil, ErrEnclaveManagerNotInitialized
	}
	return p.enclaveManager.TokenManager().VerifyToken(token, minSVN, allowDebug)
}

// ExecuteIsolatedLicenseDecryption decrypts an encrypted license payload inside zero-wipe memory and verifies entitlements.
func (p *Proxy) ExecuteIsolatedLicenseDecryption(ctx context.Context, req *enclave.IsolatedDecryptionRequest, sessionKey []byte, token *enclave.AttestationToken) (*enclave.IsolatedDecryptionResult, error) {
	if p.enclaveManager == nil || p.enclaveManager.Sandbox() == nil {
		return nil, ErrEnclaveManagerNotInitialized
	}

	evaluator := func(cleartextKey string) (tier string, features []string, expiresAt string, valid bool, err error) {
		vRes, vErr := p.VerifyLicense(ctx, cleartextKey, "")
		if vErr != nil || vRes == nil || !vRes.Valid {
			return "", nil, "", false, nil
		}
		var grantedFeatures []string
		if p.featureManager != nil {
			fallback := feature.NormalizeTier(vRes.Tier)
			_, grantedFeatures = p.featureManager.GetEffectiveFeatures(cleartextKey, fallback)
		}
		return vRes.Tier, grantedFeatures, vRes.ExpiresAt, true, nil
	}

	return p.enclaveManager.Sandbox().ExecuteIsolatedDecryption(
		ctx,
		token,
		req.EncryptedPayloadHex,
		req.NonceHex,
		sessionKey,
		evaluator,
	)
}
