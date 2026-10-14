package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/auth"
	"github.com/kLauncher1/sheet-license-broker/internal/db"
	"github.com/kLauncher1/sheet-license-broker/internal/license"
	"github.com/kLauncher1/sheet-license-broker/internal/tenant"
)

var (
	ErrInvalidSnapshot  = errors.New("invalid backup snapshot data")
	ErrChecksumMismatch = errors.New("backup data integrity failure: SHA-256 checksum mismatch")
	ErrDecryptionFailed = errors.New("backup decryption failed: invalid key or corrupted payload")
	ErrKeyRequired      = errors.New("encryption secret key cannot be empty")
)

// AuditRecord models a structured security or administrative audit log.
type AuditRecord struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Actor     string `json:"actor"`
	Details   string `json:"details"`
	Status    string `json:"status"`
}

// SnapshotData groups all domain models captured in a point-in-time backup.
type SnapshotData struct {
	Tenants   []tenant.Tenant          `json:"tenants,omitempty"`
	Users     []auth.User              `json:"users,omitempty"`
	Licenses  []license.License        `json:"licenses,omitempty"`
	Blacklist []license.BlacklistEntry `json:"blacklist,omitempty"`
	AuditLogs []AuditRecord            `json:"audit_logs,omitempty"`
	Documents []db.Document            `json:"documents,omitempty"`
}

// BackupSnapshot is an authenticated, integrity-verified snapshot structure.
type BackupSnapshot struct {
	Version   string       `json:"version"`
	Timestamp time.Time    `json:"timestamp"`
	Checksum  string       `json:"checksum"`
	Data      SnapshotData `json:"data"`
}

// CalculateChecksum computes the SHA-256 digest over the serialized SnapshotData.
func CalculateChecksum(data *SnapshotData) (string, error) {
	if data == nil {
		return "", ErrInvalidSnapshot
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to serialize data for checksum: %w", err)
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

// CreateSnapshot constructs a new snapshot with automated SHA-256 checksum.
func CreateSnapshot(data SnapshotData) (*BackupSnapshot, error) {
	sum, err := CalculateChecksum(&data)
	if err != nil {
		return nil, err
	}

	return &BackupSnapshot{
		Version:   "1.0",
		Timestamp: time.Now().UTC(),
		Checksum:  sum,
		Data:      data,
	}, nil
}

// VerifyIntegrity checks whether the snapshot's checksum matches its internal data.
func (s *BackupSnapshot) VerifyIntegrity() (bool, error) {
	if s == nil {
		return false, ErrInvalidSnapshot
	}
	expected, err := CalculateChecksum(&s.Data)
	if err != nil {
		return false, err
	}
	if expected != s.Checksum {
		return false, ErrChecksumMismatch
	}
	return true, nil
}

// EncryptSnapshot serializes and encrypts the snapshot using AES-256-GCM.
func EncryptSnapshot(s *BackupSnapshot, secretKey []byte) ([]byte, error) {
	if s == nil {
		return nil, ErrInvalidSnapshot
	}
	if len(secretKey) == 0 {
		return nil, ErrKeyRequired
	}

	raw, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	key := sha256.Sum256(secretKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Output format: [12-byte Nonce][Ciphertext + Auth Tag]
	encrypted := gcm.Seal(nonce, nonce, raw, nil)
	return encrypted, nil
}

// DecryptSnapshot authenticates and decrypts an AES-256-GCM snapshot payload.
func DecryptSnapshot(encrypted []byte, secretKey []byte) (*BackupSnapshot, error) {
	if len(secretKey) == 0 {
		return nil, ErrKeyRequired
	}

	key := sha256.Sum256(secretKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize+gcm.Overhead() {
		return nil, ErrDecryptionFailed
	}

	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	var snapshot BackupSnapshot
	if err := json.Unmarshal(plaintext, &snapshot); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted json: %w", err)
	}

	if valid, err := snapshot.VerifyIntegrity(); !valid || err != nil {
		return nil, ErrChecksumMismatch
	}

	return &snapshot, nil
}
