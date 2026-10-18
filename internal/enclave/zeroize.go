package enclave

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"runtime"
	"strings"
	"sync"
)

var (
	ErrDecryptionFailed = errors.New("enclave tunnel payload decryption failed")
	ErrBufferDestroyed  = errors.New("secure buffer has already been zeroized and destroyed")
)

// Zeroize explicitly overwrites a byte slice with zeroes and preserves memory barrier.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// SecureBuffer provides an encrypted/ephemeral memory container with deterministic zeroization.
type SecureBuffer struct {
	mu        sync.Mutex
	data      []byte
	destroyed bool
}

// NewSecureBuffer copies the input byte slice into an isolated protected buffer.
// It immediately zeroes the input slice if requested.
func NewSecureBuffer(source []byte, wipeSource bool) *SecureBuffer {
	buf := make([]byte, len(source))
	copy(buf, source)
	if wipeSource {
		Zeroize(source)
	}
	return &SecureBuffer{
		data:      buf,
		destroyed: false,
	}
}

// Bytes returns a slice reference to the protected data if not destroyed.
func (sb *SecureBuffer) Bytes() ([]byte, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.destroyed {
		return nil, ErrBufferDestroyed
	}
	return sb.data, nil
}

// Len returns the byte length of the protected buffer.
func (sb *SecureBuffer) Len() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.destroyed {
		return 0
	}
	return len(sb.data)
}

// Destroy zeroes all bytes in the buffer and marks it unusable.
func (sb *SecureBuffer) Destroy() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if !sb.destroyed && sb.data != nil {
		Zeroize(sb.data)
		sb.data = nil
		sb.destroyed = true
	}
}

// ConstantTimeCompare verifies whether two byte slices are identical without timing leaks.
func ConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeCompareHex decodes and compares two hex strings in constant time.
func ConstantTimeCompareHex(hexA, hexB string) bool {
	cleanA := strings.ToLower(strings.TrimSpace(hexA))
	cleanB := strings.ToLower(strings.TrimSpace(hexB))
	if len(cleanA) != len(cleanB) {
		return false
	}
	bytesA, errA := hex.DecodeString(cleanA)
	bytesB, errB := hex.DecodeString(cleanB)
	if errA != nil || errB != nil {
		return false
	}
	defer Zeroize(bytesA)
	defer Zeroize(bytesB)
	return ConstantTimeCompare(bytesA, bytesB)
}
