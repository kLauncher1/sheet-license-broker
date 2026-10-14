package security

import (
	"errors"
	"sync"
	"time"
)

var (
	// ErrReplayDetected is returned when a nonce has already been consumed.
	ErrReplayDetected = errors.New("replay attack detected: nonce already used")
	// ErrTimestampExpired is returned when request timestamp exceeds permitted clock drift window.
	ErrTimestampExpired = errors.New("request timestamp outside acceptable window")
	// ErrMissingSecurityHeaders is returned when required signature headers are absent.
	ErrMissingSecurityHeaders = errors.New("missing required security headers")
	// ErrInvalidSignature is returned when HMAC signature verification fails.
	ErrInvalidSignature = errors.New("invalid signature: payload or key mismatch")
)

// NonceCache stores consumed nonces in-memory to prevent replay attacks.
type NonceCache struct {
	mu      sync.RWMutex
	entries map[string]time.Time
	window  time.Duration
	maxSize int
}

// NewNonceCache initializes a cache with a specific expiry window and capacity.
func NewNonceCache(window time.Duration, maxSize int) *NonceCache {
	if window <= 0 {
		window = 5 * time.Minute
	}
	if maxSize <= 0 {
		maxSize = 20000
	}
	return &NonceCache{
		entries: make(map[string]time.Time),
		window:  window,
		maxSize: maxSize,
	}
}

// CheckAndRecord verifies whether a nonce is novel within the timestamp window,
// then stores it until expiration.
func (c *NonceCache) CheckAndRecord(nonce string, reqTime time.Time, now time.Time) error {
	if nonce == "" {
		return ErrMissingSecurityHeaders
	}

	// Validate timestamp drift against allowed window
	diff := now.Sub(reqTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > c.window {
		return ErrTimestampExpired
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Opportunistic cleanup if cache size approaches capacity
	if len(c.entries) >= c.maxSize {
		c.purgeExpiredLocked(now)
	}

	// Check existing nonce
	if exp, exists := c.entries[nonce]; exists {
		if now.Before(exp) {
			return ErrReplayDetected
		}
	}

	// Record nonce with expiration set to now + window
	c.entries[nonce] = now.Add(c.window)
	return nil
}

// Len returns the current count of active nonces in cache.
func (c *NonceCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Purge removes all nonces older than current time.
func (c *NonceCache) Purge(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.purgeExpiredLocked(now)
}

func (c *NonceCache) purgeExpiredLocked(now time.Time) int {
	removed := 0
	for k, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}
