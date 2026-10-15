package sso

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// RoleScopeMatrix defines default allowed scopes per RBAC role.
var RoleScopeMatrix = map[string][]string{
	RoleAdmin: {
		ScopeLicenseRead,
		ScopeLicenseWrite,
		ScopeLicenseRevoke,
		ScopeAuditRead,
		ScopeTenantManage,
		ScopeSSOManage,
		ScopeSCIMManage,
	},
	RoleOperator: {
		ScopeLicenseRead,
		ScopeLicenseWrite,
		ScopeAuditRead,
	},
	RoleAuditor: {
		ScopeLicenseRead,
		ScopeAuditRead,
	},
	RoleUser: {
		ScopeLicenseRead,
	},
}

// TokenManager handles generation, signing, and verification of ephemeral session tokens.
type TokenManager struct {
	secretKey  []byte
	defaultTTL time.Duration
}

// NewTokenManager initializes an ephemeral token manager with signing secret.
func NewTokenManager(secretKey []byte, defaultTTL time.Duration) *TokenManager {
	if len(secretKey) == 0 {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		secretKey = b
	}
	if defaultTTL <= 0 {
		defaultTTL = 1 * time.Hour
	}
	return &TokenManager{
		secretKey:  secretKey,
		defaultTTL: defaultTTL,
	}
}

// MintSessionToken creates a cryptographically signed ephemeral session token.
func (tm *TokenManager) MintSessionToken(claims SessionTokenClaims) (string, error) {
	now := time.Now().UTC().Unix()
	if claims.SessionID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		claims.SessionID = fmt.Sprintf("sess-%s", hex.EncodeToString(b))
	}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = now + int64(tm.defaultTTL.Seconds())
	}
	if claims.TenantID == "" {
		claims.TenantID = "default"
	}
	if len(claims.Scopes) == 0 {
		claims.Scopes = GetScopesForRole(claims.Role)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to encode claims: %w", err)
	}

	payloadPart := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig := tm.computeSignature(payloadPart)
	sigPart := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("sso.%s.%s", payloadPart, sigPart), nil
}

// VerifySessionToken parses, validates signature in constant time, and checks expiry.
func (tm *TokenManager) VerifySessionToken(token string) (*SessionTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "sso" {
		return nil, errors.New("invalid session token format")
	}

	payloadPart := parts[1]
	sigPart := parts[2]

	expectedSig := tm.computeSignature(payloadPart)
	actualSig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return nil, errors.New("invalid token signature encoding")
	}

	// Constant-time signature verification prevents timing side-channels
	if !hmac.Equal(expectedSig, actualSig) {
		return nil, errors.New("tampered or invalid session token signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return nil, errors.New("invalid token payload encoding")
	}

	var claims SessionTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, errors.New("failed to unmarshal token claims")
	}

	now := time.Now().UTC().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, errors.New("session token has expired")
	}

	return &claims, nil
}

func (tm *TokenManager) computeSignature(payload string) []byte {
	h := hmac.New(sha256.New, tm.secretKey)
	h.Write([]byte(payload))
	return h.Sum(nil)
}

// GetScopesForRole returns the default scopes configured for a role.
func GetScopesForRole(role string) []string {
	if scopes, ok := RoleScopeMatrix[strings.ToLower(strings.TrimSpace(role))]; ok {
		return scopes
	}
	return []string{ScopeLicenseRead}
}

// HasPermission checks if the role or custom scopes list grants the required scope.
func HasPermission(role string, scopes []string, requiredScope string) bool {
	req := strings.ToLower(strings.TrimSpace(requiredScope))
	// Check custom scopes
	for _, s := range scopes {
		if strings.ToLower(strings.TrimSpace(s)) == req || s == "*" {
			return true
		}
	}
	// Check role defaults
	roleScopes := GetScopesForRole(role)
	for _, s := range roleScopes {
		if strings.ToLower(s) == req || s == "*" {
			return true
		}
	}
	return false
}
