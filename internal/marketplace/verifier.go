package marketplace

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Verifier handles cryptographic webhook signature verification across Stripe, Lemon Squeezy, and Paddle.
type Verifier struct {
	toleranceSeconds int
}

// NewVerifier initializes a webhook signature verifier.
func NewVerifier(toleranceSeconds int) *Verifier {
	if toleranceSeconds <= 0 {
		toleranceSeconds = 300 // default 5 minutes
	}
	return &Verifier{
		toleranceSeconds: toleranceSeconds,
	}
}

// Verify verifies incoming webhook request signatures according to the provider specification.
func (v *Verifier) Verify(provider string, header http.Header, body []byte, secret string) error {
	if v == nil {
		v = NewVerifier(300)
	}
	trimmedSecret := strings.TrimSpace(secret)
	if trimmedSecret == "" {
		return fmt.Errorf("%w: webhook secret is not configured for provider %s", ErrInvalidSignature, provider)
	}

	switch strings.ToLower(strings.TrimSpace(provider)) {
	case ProviderStripe:
		return v.verifyStripe(header, body, trimmedSecret)
	case ProviderLemonSqueezy:
		return v.verifyLemonSqueezy(header, body, trimmedSecret)
	case ProviderPaddle:
		return v.verifyPaddle(header, body, trimmedSecret)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedProvider, provider)
	}
}

// verifyStripe verifies Stripe-Signature header format: t=12345,v1=abcde...
func (v *Verifier) verifyStripe(header http.Header, body []byte, secret string) error {
	sigHeader := header.Get("Stripe-Signature")
	if sigHeader == "" {
		sigHeader = header.Get("stripe-signature")
	}
	if sigHeader == "" {
		return ErrMissingSignature
	}

	var timestamp int64 = -1
	var signatures []string

	pairs := strings.Split(sigHeader, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch k {
		case "t":
			if ts, err := strconv.ParseInt(val, 10, 64); err == nil {
				timestamp = ts
			}
		case "v1":
			signatures = append(signatures, val)
		}
	}

	if timestamp == -1 || len(signatures) == 0 {
		return fmt.Errorf("%w: missing timestamp or v1 signature in Stripe-Signature", ErrInvalidSignature)
	}

	// Verify timestamp drift
	nowUnix := time.Now().Unix()
	if math.Abs(float64(nowUnix-timestamp)) > float64(v.toleranceSeconds) {
		return fmt.Errorf("%w: Stripe timestamp %d drifted from current time %d by more than %ds",
			ErrTimestampDrift, timestamp, nowUnix, v.toleranceSeconds)
	}

	// Signed payload is "${timestamp}.${body}"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	expectedSigHex := hex.EncodeToString(mac.Sum(nil))

	for _, sig := range signatures {
		if hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(sig))), []byte(expectedSigHex)) {
			return nil
		}
	}

	return fmt.Errorf("%w: signature mismatch for Stripe payload", ErrInvalidSignature)
}

// verifyLemonSqueezy verifies X-Signature header with hex HMAC-SHA256 of raw body
func (v *Verifier) verifyLemonSqueezy(header http.Header, body []byte, secret string) error {
	sigHeader := header.Get("X-Signature")
	if sigHeader == "" {
		sigHeader = header.Get("x-signature")
	}
	if sigHeader == "" {
		return ErrMissingSignature
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedSigHex := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(sigHeader))), []byte(expectedSigHex)) {
		return fmt.Errorf("%w: signature mismatch for Lemon Squeezy payload", ErrInvalidSignature)
	}

	return nil
}

// verifyPaddle verifies Paddle-Signature header (Paddle Billing v2 format: ts=12345;h1=abcde...)
// or fallback X-Paddle-Signature
func (v *Verifier) verifyPaddle(header http.Header, body []byte, secret string) error {
	sigHeader := header.Get("Paddle-Signature")
	if sigHeader == "" {
		sigHeader = header.Get("paddle-signature")
	}
	if sigHeader == "" {
		sigHeader = header.Get("X-Paddle-Signature")
	}
	if sigHeader == "" {
		return ErrMissingSignature
	}

	// Case 1: Paddle Billing v2 header format ts=...;h1=...
	if strings.Contains(sigHeader, "ts=") && strings.Contains(sigHeader, "h1=") {
		var timestamp int64 = -1
		var signatures []string

		parts := strings.Split(sigHeader, ";")
		for _, part := range parts {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			k, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
			switch k {
			case "ts":
				if ts, err := strconv.ParseInt(val, 10, 64); err == nil {
					timestamp = ts
				}
			case "h1":
				signatures = append(signatures, val)
			}
		}

		if timestamp == -1 || len(signatures) == 0 {
			return fmt.Errorf("%w: malformed Paddle-Signature header", ErrInvalidSignature)
		}

		nowUnix := time.Now().Unix()
		if math.Abs(float64(nowUnix-timestamp)) > float64(v.toleranceSeconds) {
			return fmt.Errorf("%w: Paddle timestamp %d drifted from current time %d by more than %ds",
				ErrTimestampDrift, timestamp, nowUnix, v.toleranceSeconds)
		}

		// Signed payload is "${ts}:${body}"
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
		mac.Write([]byte(":"))
		mac.Write(body)
		expectedHex := hex.EncodeToString(mac.Sum(nil))

		for _, sig := range signatures {
			if hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(sig))), []byte(expectedHex)) {
				return nil
			}
		}
		return fmt.Errorf("%w: signature mismatch for Paddle Billing payload", ErrInvalidSignature)
	}

	// Case 2: Direct raw body HMAC-SHA256 signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedHex := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(sigHeader))), []byte(expectedHex)) {
		return fmt.Errorf("%w: signature mismatch for Paddle payload", ErrInvalidSignature)
	}

	return nil
}
