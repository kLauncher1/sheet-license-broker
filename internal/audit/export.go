package audit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidAuditKey      = errors.New("audit key must not be empty")
	ErrTamperedAuditBundle  = errors.New("audit bundle HMAC verification failed: tampering detected")
	ErrDecryptionFailed     = errors.New("audit bundle decryption failed: invalid key or corrupted payload")
	ErrMalformedAuditBundle = errors.New("malformed audit bundle schema")
)

// AuditRecord models a single security, compliance, or operational event.
type AuditRecord struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"` // e.g. AUTH_FAILURE, TAMPER_DETECTED, IP_TEMPORARY_BAN
	Severity  string    `json:"severity"`   // INFO, WARNING, CRITICAL
	ActorIP   string    `json:"actor_ip,omitempty"`
	HWID      string    `json:"hwid,omitempty"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	Details   string    `json:"details,omitempty"`
	Digest    string    `json:"digest"`
}

// EncryptedAuditBundle encapsulates encrypted records for SIEM/SOC external ingest.
type EncryptedAuditBundle struct {
	BundleID       string    `json:"bundle_id"`
	Version        string    `json:"version"` // "1.0"
	CreatedAt      time.Time `json:"created_at"`
	RecordCount    int       `json:"record_count"`
	Algorithm      string    `json:"algorithm"` // "AES-256-GCM+HMAC-SHA256"
	KeyFingerprint string    `json:"key_fingerprint"`
	NonceHex       string    `json:"nonce_hex"`
	CiphertextHex  string    `json:"ciphertext_hex"`
	HMACSignature  string    `json:"hmac_signature"`
}

// Collector maintains recent audit events in an in-memory bounded ring buffer.
type Collector struct {
	mu       sync.RWMutex
	capacity int
	records  []AuditRecord
}

// NewCollector constructs an audit event collector.
func NewCollector(capacity int) *Collector {
	if capacity <= 0 {
		capacity = 5000
	}
	return &Collector{
		capacity: capacity,
		records:  make([]AuditRecord, 0, capacity),
	}
}

// Record adds an event to the audit trail with an automated SHA-256 digest.
func (c *Collector) Record(rec AuditRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if rec.ID == "" {
		rec.ID = fmt.Sprintf("aud_%d", time.Now().UnixNano())
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}

	// Calculate tamper-proof content digest
	content := fmt.Sprintf("%s|%s|%s|%s|%s|%s", rec.EventType, rec.Severity, rec.ActorIP, rec.HWID, rec.TenantID, rec.Details)
	h := sha256.Sum256([]byte(content))
	rec.Digest = hex.EncodeToString(h[:])

	if len(c.records) >= c.capacity {
		// Drop oldest record to maintain bounded ring
		c.records = c.records[1:]
	}
	c.records = append(c.records, rec)
}

// List returns recorded audit events with optional severity and event-type filtering.
func (c *Collector) List(limit int, severity, eventType string) []AuditRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 || limit > len(c.records) {
		limit = len(c.records)
	}

	normSev := strings.ToUpper(strings.TrimSpace(severity))
	normType := strings.ToUpper(strings.TrimSpace(eventType))

	res := make([]AuditRecord, 0, limit)
	// Traverse in reverse chronological order
	for i := len(c.records) - 1; i >= 0 && len(res) < limit; i-- {
		r := c.records[i]
		if normSev != "" && strings.ToUpper(r.Severity) != normSev {
			continue
		}
		if normType != "" && strings.ToUpper(r.EventType) != normType {
			continue
		}
		res = append(res, r)
	}
	return res
}

// deriveAESKey normalizes a variable-length key to a 32-byte AES-256 key.
func deriveAESKey(rawKey []byte) []byte {
	if len(rawKey) == 32 {
		return rawKey
	}
	h := sha256.Sum256(rawKey)
	return h[:]
}

// ExportEncrypted seals the provided records into an AES-256-GCM encrypted bundle with HMAC integrity.
func ExportEncrypted(records []AuditRecord, secretKey []byte) (*EncryptedAuditBundle, error) {
	if len(secretKey) == 0 {
		return nil, ErrInvalidAuditKey
	}

	aesKey := deriveAESKey(secretKey)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	plaintext, err := json.Marshal(records)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal records: %w", err)
	}

	bundleID := fmt.Sprintf("bundle_%d", time.Now().UnixNano())
	createdAt := time.Now().UTC()

	// Additional authenticated data binding bundle metadata
	aad := []byte(fmt.Sprintf("%s|%s|%d", bundleID, createdAt.Format(time.RFC3339), len(records)))
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Key fingerprint: first 8 bytes of key hash
	keySum := sha256.Sum256(aesKey)
	fp := hex.EncodeToString(keySum[:8])

	// Calculate outer HMAC-SHA256 signature
	mac := hmac.New(sha256.New, aesKey)
	mac.Write([]byte(bundleID))
	mac.Write([]byte(createdAt.Format(time.RFC3339)))
	mac.Write(ciphertext)
	sig := hex.EncodeToString(mac.Sum(nil))

	return &EncryptedAuditBundle{
		BundleID:       bundleID,
		Version:        "1.0",
		CreatedAt:      createdAt,
		RecordCount:    len(records),
		Algorithm:      "AES-256-GCM+HMAC-SHA256",
		KeyFingerprint: fp,
		NonceHex:       hex.EncodeToString(nonce),
		CiphertextHex:  hex.EncodeToString(ciphertext),
		HMACSignature:  sig,
	}, nil
}

// DecryptAndVerify validates bundle integrity and decrypts audit records using the provided secret key.
func DecryptAndVerify(bundle *EncryptedAuditBundle, secretKey []byte) ([]AuditRecord, error) {
	if bundle == nil || bundle.CiphertextHex == "" || bundle.NonceHex == "" {
		return nil, ErrMalformedAuditBundle
	}
	if len(secretKey) == 0 {
		return nil, ErrInvalidAuditKey
	}

	aesKey := deriveAESKey(secretKey)

	// 1. Verify HMAC signature in constant time
	ciphertext, err := hex.DecodeString(bundle.CiphertextHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ciphertext hex", ErrMalformedAuditBundle)
	}

	mac := hmac.New(sha256.New, aesKey)
	mac.Write([]byte(bundle.BundleID))
	mac.Write([]byte(bundle.CreatedAt.Format(time.RFC3339)))
	mac.Write(ciphertext)
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(bundle.HMACSignature), []byte(expectedSig)) != 1 {
		return nil, ErrTamperedAuditBundle
	}

	// 2. Decrypt with AES-256-GCM
	nonce, err := hex.DecodeString(bundle.NonceHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid nonce hex", ErrMalformedAuditBundle)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("cipher init error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init error: %w", err)
	}

	aad := []byte(fmt.Sprintf("%s|%s|%d", bundle.BundleID, bundle.CreatedAt.Format(time.RFC3339), bundle.RecordCount))
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	var records []AuditRecord
	if err := json.Unmarshal(plaintext, &records); err != nil {
		return nil, fmt.Errorf("%w: corrupted record payload", ErrDecryptionFailed)
	}

	return records, nil
}
