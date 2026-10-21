package zerotrust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// DefaultHSMPIN is the default hardware PIN for cryptographic key slot authentication.
const DefaultHSMPIN = "9842-HSM-SECURE-PIN"

// HSMKeySlot represents an isolated hardware cryptographic boundary.
type HSMKeySlot struct {
	mu         sync.RWMutex
	slotID     int
	label      string
	algorithm  string
	privateKey *ecdsa.PrivateKey
	publicKey  crypto.PublicKey
	pubPEM     string
	opsCount   int64
	zeroized   bool
}

// SoftwareHSM emulates a PKCS#11 / HSM hardware cryptographic provider.
type SoftwareHSM struct {
	mu            sync.RWMutex
	pin           []byte
	authenticated bool
	slots         map[int]*HSMKeySlot
}

// NewSoftwareHSM initializes a software HSM provider with predefined hardware slots.
func NewSoftwareHSM(pin string) (*SoftwareHSM, error) {
	if pin == "" {
		pin = DefaultHSMPIN
	}

	hsm := &SoftwareHSM{
		pin:           []byte(pin),
		authenticated: true, // Default to authenticated upon programmatic bootstrap
		slots:         make(map[int]*HSMKeySlot),
	}

	// Initialize Slot 0: Root CA Master Key
	if err := hsm.initSlot(0, "Root CA Master Key Slot"); err != nil {
		return nil, fmt.Errorf("failed to init slot 0: %w", err)
	}

	// Initialize Slot 1: Node Identity & Consensus Mesh Key
	if err := hsm.initSlot(1, "Consensus Mesh Key Slot"); err != nil {
		return nil, fmt.Errorf("failed to init slot 1: %w", err)
	}

	// Initialize Slot 2: Airgap & Enclave Attestation Key
	if err := hsm.initSlot(2, "Enclave Attestation Key Slot"); err != nil {
		return nil, fmt.Errorf("failed to init slot 2: %w", err)
	}

	return hsm, nil
}

func (h *SoftwareHSM) initSlot(slotID int, label string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	h.slots[slotID] = &HSMKeySlot{
		slotID:     slotID,
		label:      label,
		algorithm:  "ECDSA_P256_SHA256",
		privateKey: priv,
		publicKey:  priv.Public(),
		pubPEM:     string(pubPEM),
		opsCount:   0,
		zeroized:   false,
	}
	return nil
}

// Login authenticates to the HSM using constant-time PIN comparison.
func (h *SoftwareHSM) Login(pin string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if subtle.ConstantTimeCompare([]byte(pin), h.pin) != 1 {
		return ErrHSMUnauthorized
	}
	h.authenticated = true
	return nil
}

// Logout revokes the authenticated session.
func (h *SoftwareHSM) Logout() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authenticated = false
}

// IsAuthenticated reports whether the HSM session is unlocked.
func (h *SoftwareHSM) IsAuthenticated() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.authenticated
}

// GetSigner returns a crypto.Signer bound to the specified HSM slot.
func (h *SoftwareHSM) GetSigner(slotID int) (crypto.Signer, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	slot, ok := h.slots[slotID]
	if !ok {
		return nil, ErrHSMSlotNotFound
	}
	return &hsmSlotSigner{hsm: h, slot: slot}, nil
}

// Zeroize wipes all private key material across all slots with cryptographic zeroes.
func (h *SoftwareHSM) Zeroize() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, slot := range h.slots {
		slot.mu.Lock()
		if slot.privateKey != nil && slot.privateKey.D != nil {
			bytes := slot.privateKey.D.Bytes()
			for i := range bytes {
				bytes[i] = 0
			}
			slot.privateKey = nil
		}
		slot.zeroized = true
		slot.mu.Unlock()
	}
	h.authenticated = false
}

// ListSlots returns metadata for all provisioned hardware key slots.
func (h *SoftwareHSM) ListSlots() []HSMSlotInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()

	res := make([]HSMSlotInfo, 0, len(h.slots))
	for i := 0; i < len(h.slots); i++ {
		slot := h.slots[i]
		if slot == nil {
			continue
		}
		slot.mu.RLock()
		res = append(res, HSMSlotInfo{
			SlotID:          slot.slotID,
			Label:           slot.label,
			Algorithm:       slot.algorithm,
			KeyPresent:      slot.privateKey != nil,
			PublicKeyPEM:    slot.pubPEM,
			OperationsCount: atomic.LoadInt64(&slot.opsCount),
			Zeroized:        slot.zeroized,
		})
		slot.mu.RUnlock()
	}
	return res
}

// hsmSlotSigner wraps an HSM key slot as a standard crypto.Signer.
type hsmSlotSigner struct {
	hsm  *SoftwareHSM
	slot *HSMKeySlot
}

// Public returns the public key matching the private key held in the HSM slot.
func (s *hsmSlotSigner) Public() crypto.PublicKey {
	s.slot.mu.RLock()
	defer s.slot.mu.RUnlock()
	return s.slot.publicKey
}

// Sign delegates cryptographic signing to the protected hardware slot boundary.
func (s *hsmSlotSigner) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if !s.hsm.IsAuthenticated() {
		return nil, ErrHSMUnauthorized
	}

	s.slot.mu.Lock()
	defer s.slot.mu.Unlock()

	if s.slot.zeroized || s.slot.privateKey == nil {
		return nil, fmt.Errorf("HSM slot %d has been zeroized or key is absent", s.slot.slotID)
	}

	sig, err := s.slot.privateKey.Sign(randReader, digest, opts)
	if err != nil {
		return nil, err
	}

	atomic.AddInt64(&s.slot.opsCount, 1)
	return sig, nil
}
