package enclave

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrTokenNotFound       = errors.New("enclave attestation token not found")
	ErrTokenExpired        = errors.New("enclave attestation token has expired")
	ErrTokenRevoked        = errors.New("enclave attestation token has been revoked")
	ErrTokenInvalidSig     = errors.New("enclave attestation token signature is invalid")
	ErrTokenSVNTooLow      = errors.New("enclave attestation token svn is below required threshold")
	ErrTokenDebugForbidden = errors.New("enclave attestation token has debug mode enabled, forbidden by policy")
)

const (
	DefaultTokenTTL = 30 * time.Minute
)

// TokenManager orchestrates cryptographic lifecycle, verification, and revocation of attestation tokens.
type TokenManager struct {
	mu         sync.RWMutex
	signingKey []byte
	tokens     map[string]*AttestationToken
	revocations map[string]string // token_id -> reason
}

// NewTokenManager initializes an in-memory attestation token manager.
func NewTokenManager(signingKey []byte) *TokenManager {
	if len(signingKey) == 0 {
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		signingKey = k
	}

	tm := &TokenManager{
		signingKey:  signingKey,
		tokens:      make(map[string]*AttestationToken),
		revocations: make(map[string]string),
	}

	go tm.cleanupLoop()
	return tm
}

// CanonicalTokenString produces the deterministic byte sequence used for HMAC signing and verification.
func CanonicalTokenString(t *AttestationToken) string {
	if t == nil {
		return ""
	}
	return fmt.Sprintf("TOKEN-v1:%s:%s:%s:%s:%d:%t:%s:%s:%d:%d",
		t.TokenID,
		t.Platform,
		t.Measurement,
		t.RTMR0,
		t.SVN,
		t.DebugAllowed,
		t.ChallengeNonce,
		t.EnclavePubKey,
		t.IssuedAt.Unix(),
		t.ExpiresAt.Unix(),
	)
}

// SignToken generates a cryptographic HMAC-SHA256 signature for the token.
func (tm *TokenManager) SignToken(t *AttestationToken) string {
	canonical := CanonicalTokenString(t)
	mac := hmac.New(sha256.New, tm.signingKey)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// IssueToken mints a fresh, cryptographically bound attestation token.
func (tm *TokenManager) IssueToken(platform PlatformType, measurement, rtmr0 string, svn uint32, debug bool, nonce, pubKey string, ttl time.Duration) (*AttestationToken, error) {
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}

	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, err
	}
	tokenID := "tok_" + hex.EncodeToString(randBytes)

	now := time.Now().UTC()
	tok := &AttestationToken{
		TokenID:        tokenID,
		Platform:       platform,
		Measurement:    strings.TrimSpace(measurement),
		RTMR0:          strings.TrimSpace(rtmr0),
		SVN:            svn,
		DebugAllowed:   debug,
		ChallengeNonce: strings.TrimSpace(nonce),
		EnclavePubKey:  strings.TrimSpace(pubKey),
		IssuedAt:       now,
		ExpiresAt:      now.Add(ttl),
	}

	tok.Signature = tm.SignToken(tok)

	tm.mu.Lock()
	tm.tokens[tokenID] = tok
	tm.mu.Unlock()

	return tok, nil
}

// VerifyToken validates cryptographic signature, expiration, revocation, and security posture.
func (tm *TokenManager) VerifyToken(token *AttestationToken, minSVN uint32, allowDebug bool) (*TokenVerifyResult, error) {
	if token == nil {
		return &TokenVerifyResult{Valid: false, ErrorMessage: "nil token provided"}, ErrTokenNotFound
	}

	// 1. Revocation check
	tm.mu.RLock()
	reason, isRevoked := tm.revocations[token.TokenID]
	tm.mu.RUnlock()
	if isRevoked {
		msg := fmt.Sprintf("%v: %s", ErrTokenRevoked, reason)
		return &TokenVerifyResult{Valid: false, Token: token, ErrorMessage: msg}, ErrTokenRevoked
	}

	// 2. Expiration check
	if time.Now().UTC().After(token.ExpiresAt) {
		return &TokenVerifyResult{Valid: false, Token: token, ErrorMessage: ErrTokenExpired.Error()}, ErrTokenExpired
	}

	// 3. Constant-time cryptographic signature validation
	expectedSig := tm.SignToken(token)
	sigBytes, err1 := hex.DecodeString(token.Signature)
	expectedBytes, err2 := hex.DecodeString(expectedSig)
	if err1 != nil || err2 != nil || subtle.ConstantTimeCompare(sigBytes, expectedBytes) != 1 {
		return &TokenVerifyResult{Valid: false, Token: token, ErrorMessage: ErrTokenInvalidSig.Error()}, ErrTokenInvalidSig
	}

	// 4. Debug Policy enforcement
	if !allowDebug && token.DebugAllowed {
		return &TokenVerifyResult{Valid: false, Token: token, ErrorMessage: ErrTokenDebugForbidden.Error()}, ErrTokenDebugForbidden
	}

	// 5. Minimum SVN requirement
	if minSVN > 0 && token.SVN < minSVN {
		msg := fmt.Sprintf("%v: svn %d < required %d", ErrTokenSVNTooLow, token.SVN, minSVN)
		return &TokenVerifyResult{Valid: false, Token: token, ErrorMessage: msg}, ErrTokenSVNTooLow
	}

	return &TokenVerifyResult{
		Valid:       true,
		Token:       token,
		Platform:    token.Platform,
		SVN:         token.SVN,
		Measurement: token.Measurement,
	}, nil
}

// GetToken retrieves an active token by ID.
func (tm *TokenManager) GetToken(tokenID string) (*AttestationToken, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	tok, exists := tm.tokens[tokenID]
	return tok, exists
}

// RevokeToken marks an active attestation token as revoked.
func (tm *TokenManager) RevokeToken(tokenID, reason string) error {
	cleanID := strings.TrimSpace(tokenID)
	if cleanID == "" {
		return errors.New("empty token id")
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if reason == "" {
		reason = "administrative revocation"
	}
	tm.revocations[cleanID] = reason
	delete(tm.tokens, cleanID)
	return nil
}

// IsRevoked checks whether a token ID is in the revocation ledger.
func (tm *TokenManager) IsRevoked(tokenID string) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	_, revoked := tm.revocations[strings.TrimSpace(tokenID)]
	return revoked
}

// ActiveCount returns current count of unexpired, non-revoked attestation tokens.
func (tm *TokenManager) ActiveCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.tokens)
}

// ListActiveTokens returns a slice of all active attestation tokens.
func (tm *TokenManager) ListActiveTokens() []*AttestationToken {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	list := make([]*AttestationToken, 0, len(tm.tokens))
	now := time.Now().UTC()
	for _, tok := range tm.tokens {
		if now.Before(tok.ExpiresAt) {
			list = append(list, tok)
		}
	}
	return list
}

func (tm *TokenManager) cleanupLoop() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		tm.mu.Lock()
		now := time.Now().UTC()
		for id, tok := range tm.tokens {
			if now.After(tok.ExpiresAt) {
				delete(tm.tokens, id)
			}
		}
		tm.mu.Unlock()
	}
}
