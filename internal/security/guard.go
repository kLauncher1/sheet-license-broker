package security

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// HeaderSignature holds the hex-encoded HMAC-SHA256 signature.
	HeaderSignature = "X-Signature"
	// HeaderTimestamp holds the Unix timestamp in seconds.
	HeaderTimestamp = "X-Timestamp"
	// HeaderNonce holds a unique random string per request.
	HeaderNonce = "X-Nonce"
)

// Guard enforces HMAC-SHA256 request signatures and prevents replay attacks.
type Guard struct {
	secret      []byte
	nonceWindow time.Duration
	nonceCache  *NonceCache
	enforce     bool
}

// NewGuard creates an anti-tamper security guard with the given secret key.
func NewGuard(secret []byte, window time.Duration, enforce bool) *Guard {
	if window <= 0 {
		window = 5 * time.Minute
	}
	return &Guard{
		secret:      secret,
		nonceWindow: window,
		nonceCache:  NewNonceCache(window, 20000),
		enforce:     enforce,
	}
}

// IsEnforced returns whether incoming requests are strictly required to have valid signatures.
func (g *Guard) IsEnforced() bool {
	return g.enforce
}

// SetEnforced updates enforcement mode at runtime.
func (g *Guard) SetEnforced(enforced bool) {
	g.enforce = enforced
}

// ComputeBodyHash computes hex-encoded SHA-256 digest of request body bytes.
func ComputeBodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// BuildCanonicalString constructs the normalized string used for signature signing.
func BuildCanonicalString(method, path string, timestamp int64, nonce string, body []byte) string {
	bHash := ComputeBodyHash(body)
	normMethod := strings.ToUpper(strings.TrimSpace(method))
	normPath := strings.TrimSpace(path)
	return fmt.Sprintf("%s\n%s\n%d\n%s\n%s", normMethod, normPath, timestamp, nonce, bHash)
}

// Sign generates an HMAC-SHA256 hex signature using the configured secret key.
func Sign(secret []byte, method, path string, timestamp int64, nonce string, body []byte) string {
	canonical := BuildCanonicalString(method, path, timestamp, nonce, body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify validates timestamp drift, nonce uniqueness, and HMAC signature integrity.
func (g *Guard) Verify(method, path, timestampStr, nonce, signatureHex string, body []byte) error {
	if len(g.secret) == 0 {
		return nil
	}
	if timestampStr == "" || nonce == "" || signatureHex == "" {
		return ErrMissingSecurityHeaders
	}

	ts, err := strconv.ParseInt(strings.TrimSpace(timestampStr), 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid timestamp format", ErrTimestampExpired)
	}

	// Handle millisecond timestamps gracefully
	if ts > 1e11 {
		ts = ts / 1000
	}

	reqTime := time.Unix(ts, 0)
	now := time.Now()

	// Check and record nonce in sliding replay window
	if err := g.nonceCache.CheckAndRecord(nonce, reqTime, now); err != nil {
		return err
	}

	expectedSig := Sign(g.secret, method, path, ts, nonce, body)
	sigBytes, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil {
		return ErrInvalidSignature
	}
	expectedBytes, err := hex.DecodeString(expectedSig)
	if err != nil {
		return ErrInvalidSignature
	}

	if !hmac.Equal(sigBytes, expectedBytes) {
		return ErrInvalidSignature
	}

	return nil
}

// Middleware creates standard HTTP middleware protecting selected routes.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig := r.Header.Get(HeaderSignature)
		ts := r.Header.Get(HeaderTimestamp)
		nonce := r.Header.Get(HeaderNonce)

		hasHeaders := sig != "" && ts != "" && nonce != ""

		if !g.enforce && !hasHeaders {
			next.ServeHTTP(w, r)
			return
		}

		if g.enforce && !hasHeaders {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "signature_required",
				"message": "Missing required security headers (X-Signature, X-Timestamp, X-Nonce)",
			})
			return
		}

		// Read and restore request body for downstream consumption
		var bodyBytes []byte
		if r.Body != nil {
			var err error
			bodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		if err := g.Verify(r.Method, r.URL.Path, ts, nonce, sig, bodyBytes); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "invalid_signature",
				"message": err.Error(),
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
