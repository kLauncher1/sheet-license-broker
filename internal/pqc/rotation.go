package pqc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// PQCKeyManager orchestrates post-quantum and hybrid cryptographic keys, key rotation epochs, and revocation.
type PQCKeyManager struct {
	mu            sync.RWMutex
	keys          map[string]*HybridKeyPair
	activeKeyID   string
	rotations     []KeyRotationRecord
	verifiedCount uint64
	rejectedCount uint64
	defaultAlgo   string
	hmacSecret    []byte
}

// NewKeyManager initializes the PQC key manager and pre-seeds an initial active hybrid key.
func NewKeyManager(defaultAlgo string, hmacSecret []byte) (*PQCKeyManager, error) {
	if defaultAlgo == "" {
		defaultAlgo = AlgoHybridP256
	}

	km := &PQCKeyManager{
		keys:        make(map[string]*HybridKeyPair),
		defaultAlgo: defaultAlgo,
		hmacSecret:  hmacSecret,
	}

	// Bootstrap primary key
	initialKey, err := km.generateKeyPair(defaultAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate initial PQC key: %w", err)
	}

	km.keys[initialKey.KeyID] = initialKey
	km.activeKeyID = initialKey.KeyID
	return km, nil
}

// generateKeyPair creates a fresh HybridKeyPair for the requested algorithm.
func (km *PQCKeyManager) generateKeyPair(algo string) (*HybridKeyPair, error) {
	mldsaAlgo := algo
	if algo == AlgoHybridP256 {
		mldsaAlgo = AlgoMLDSA65
	} else if algo == AlgoHybridHMAC {
		mldsaAlgo = AlgoMLDSA44
	}

	mldsaPriv, mldsaPub, err := GenerateMLDSAKeyPair(mldsaAlgo)
	if err != nil {
		return nil, err
	}

	hk := &HybridKeyPair{
		KeyID:       mldsaPub.KeyID,
		Algorithm:   algo,
		MLDSAKey:    mldsaPriv,
		MLDSAPublic: mldsaPub,
		Status:      "active",
		CreatedAt:   time.Now().UTC(),
		HMACSecret:  km.hmacSecret,
	}

	if algo == AlgoHybridP256 {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ecdsa p256 key: %w", err)
		}
		hk.ECDSAKey = ecKey
		hk.ECDSAPublicX = ecKey.PublicKey.X.Text(16)
		hk.ECDSAPublicY = ecKey.PublicKey.Y.Text(16)
	}

	return hk, nil
}

// RotateKey transitions the active key into a grace period and promotes a new key to active.
func (km *PQCKeyManager) RotateKey(algo string, gracePeriod time.Duration, reason string) (*KeyRotationRecord, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	if algo == "" {
		algo = km.defaultAlgo
	}
	if gracePeriod <= 0 {
		gracePeriod = 7 * 24 * time.Hour // Default 7-day grace window
	}

	newKey, err := km.generateKeyPair(algo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rotated key: %w", err)
	}

	oldKeyID := km.activeKeyID
	now := time.Now().UTC()
	graceUntil := now.Add(gracePeriod)

	if oldKey, exists := km.keys[oldKeyID]; exists {
		oldKey.Status = "rotated"
		oldKey.RotatedAt = &now
		oldKey.GraceUntil = &graceUntil
	}

	km.keys[newKey.KeyID] = newKey
	km.activeKeyID = newKey.KeyID

	record := KeyRotationRecord{
		OldKeyID:   oldKeyID,
		NewKeyID:   newKey.KeyID,
		Algorithm:  algo,
		RotatedAt:  now,
		GraceUntil: graceUntil,
		Reason:     reason,
		Status:     "success",
	}
	km.rotations = append(km.rotations, record)
	return &record, nil
}

// RevokeKey immediately revokes a key by ID, preventing its use for verification or signing.
func (km *PQCKeyManager) RevokeKey(keyID string, reason string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	key, exists := km.keys[keyID]
	if !exists {
		return fmt.Errorf("key not found: %s", keyID)
	}

	now := time.Now().UTC()
	key.Status = "revoked"
	key.RevokedAt = &now
	key.RevokeReason = reason

	// If the revoked key was the active key, auto-rotate immediately
	if km.activeKeyID == keyID {
		newKey, err := km.generateKeyPair(km.defaultAlgo)
		if err == nil {
			km.keys[newKey.KeyID] = newKey
			km.activeKeyID = newKey.KeyID
		}
	}

	return nil
}

// ActiveKey returns a copy of the current active hybrid key pair.
func (km *PQCKeyManager) ActiveKey() *HybridKeyPair {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keys[km.activeKeyID]
}

// LookupKey retrieves a key pair by its ID.
func (km *PQCKeyManager) LookupKey(keyID string) (*HybridKeyPair, bool) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	key, exists := km.keys[keyID]
	return key, exists
}

// Sign generates a hybrid signature over payload using the active key.
func (km *PQCKeyManager) Sign(payload []byte) (*HybridSignature, error) {
	km.mu.RLock()
	active := km.keys[km.activeKeyID]
	km.mu.RUnlock()

	if active == nil {
		return nil, fmt.Errorf("no active PQC key configured")
	}
	return SignHybrid(active, payload)
}

// Verify evaluates a hybrid signature against the referenced key.
func (km *PQCKeyManager) Verify(payload []byte, sig *HybridSignature) *PQCVerificationResult {
	if sig == nil {
		atomic.AddUint64(&km.rejectedCount, 1)
		return &PQCVerificationResult{Valid: false, ErrorMessage: "nil signature"}
	}

	km.mu.RLock()
	key, exists := km.keys[sig.KeyID]
	if !exists {
		// Fallback to active key if ID matches or was unspecified
		if sig.KeyID == "" || sig.KeyID == km.activeKeyID {
			key = km.keys[km.activeKeyID]
		}
	}
	km.mu.RUnlock()

	res := VerifyHybrid(key, payload, sig)
	if res.Valid {
		atomic.AddUint64(&km.verifiedCount, 1)
	} else {
		atomic.AddUint64(&km.rejectedCount, 1)
	}
	return res
}

// GetPublicKeys returns the public parameters of all active and grace keys.
func (km *PQCKeyManager) GetPublicKeys() []*MLDSAPublicKey {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var result []*MLDSAPublicKey
	for _, key := range km.keys {
		if key.Status != "revoked" && key.MLDSAPublic != nil {
			result = append(result, key.MLDSAPublic)
		}
	}
	return result
}

// GetStatus returns a telemetry summary of the PQC engine state.
func (km *PQCKeyManager) GetStatus() PQCStatusSummary {
	km.mu.RLock()
	defer km.mu.RUnlock()

	inGrace := 0
	revoked := 0
	now := time.Now()

	for _, k := range km.keys {
		if k.Status == "revoked" {
			revoked++
		} else if k.Status == "rotated" {
			if k.GraceUntil != nil && now.Before(*k.GraceUntil) {
				inGrace++
			}
		}
	}

	return PQCStatusSummary{
		ActiveKeyID:        km.activeKeyID,
		DefaultAlgorithm:   km.defaultAlgo,
		TotalKeys:          len(km.keys),
		RotatedKeysInGrace: inGrace,
		RevokedKeys:        revoked,
		TotalRotations:     len(km.rotations),
		VerifiedCount:      atomic.LoadUint64(&km.verifiedCount),
		RejectedCount:      atomic.LoadUint64(&km.rejectedCount),
		SupportedAlgorithms: []string{
			AlgoHybridP256,
			AlgoHybridHMAC,
			AlgoMLDSA44,
			AlgoMLDSA65,
			AlgoMLDSA87,
		},
	}
}
