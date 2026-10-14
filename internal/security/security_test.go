package security

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSignAndVerifySuccess(t *testing.T) {
	secret := []byte("super-secret-hmac-key-12345")
	guard := NewGuard(secret, 5*time.Minute, true)

	method := "POST"
	path := "/api/licenses/validate"
	ts := time.Now().Unix()
	nonce := "random-nonce-uuid-1"
	body := []byte(`{"license_key":"KEY-ABCDEF","hwid":"HWID-PC-001"}`)

	sig := Sign(secret, method, path, ts, nonce, body)
	if sig == "" {
		t.Fatalf("expected non-empty signature")
	}

	err := guard.Verify(method, path, fmt.Sprintf("%d", ts), nonce, sig, body)
	if err != nil {
		t.Fatalf("expected signature verification to pass, got: %v", err)
	}
}

func TestReplayAttackDetection(t *testing.T) {
	secret := []byte("super-secret-hmac-key-12345")
	guard := NewGuard(secret, 5*time.Minute, true)

	method := "POST"
	path := "/api/licenses/validate"
	ts := time.Now().Unix()
	nonce := "unique-nonce-001"
	body := []byte(`{"test":true}`)

	sig := Sign(secret, method, path, ts, nonce, body)

	// First attempt succeeds
	if err := guard.Verify(method, path, fmt.Sprintf("%d", ts), nonce, sig, body); err != nil {
		t.Fatalf("first verification failed: %v", err)
	}

	// Replay attempt with identical nonce fails
	if err := guard.Verify(method, path, fmt.Sprintf("%d", ts), nonce, sig, body); err != ErrReplayDetected {
		t.Fatalf("expected ErrReplayDetected, got: %v", err)
	}
}

func TestTimestampDriftExceeded(t *testing.T) {
	secret := []byte("super-secret-hmac-key-12345")
	guard := NewGuard(secret, 5*time.Minute, true)

	method := "GET"
	path := "/api/licenses"
	oldTs := time.Now().Add(-10 * time.Minute).Unix()
	nonce := "nonce-old"
	body := []byte{}

	sig := Sign(secret, method, path, oldTs, nonce, body)

	err := guard.Verify(method, path, fmt.Sprintf("%d", oldTs), nonce, sig, body)
	if err != ErrTimestampExpired {
		t.Fatalf("expected ErrTimestampExpired, got: %v", err)
	}
}

func TestTamperedBodyRejected(t *testing.T) {
	secret := []byte("super-secret-hmac-key-12345")
	guard := NewGuard(secret, 5*time.Minute, true)

	method := "POST"
	path := "/api/licenses/validate"
	ts := time.Now().Unix()
	nonce := "nonce-tamper-test"
	originalBody := []byte(`{"license_key":"KEY-123"}`)
	tamperedBody := []byte(`{"license_key":"KEY-666"}`)

	sig := Sign(secret, method, path, ts, nonce, originalBody)

	err := guard.Verify(method, path, fmt.Sprintf("%d", ts), nonce, sig, tamperedBody)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature on tampered body, got: %v", err)
	}
}

func TestMiddlewareBehavior(t *testing.T) {
	secret := []byte("key-abc-123")
	guard := NewGuard(secret, 5*time.Minute, false)

	receivedBody := ""
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		receivedBody = buf.String()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := guard.Middleware(innerHandler)

	// 1. Unsigned request allowed when enforce is false
	req1 := httptest.NewRequest("POST", "/api/test", bytes.NewBufferString("hello payload"))
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK || receivedBody != "hello payload" {
		t.Fatalf("expected 200 OK and preserved body, got: %d, body: %s", w1.Code, receivedBody)
	}

	// 2. Strict enforcement enabled: reject missing headers
	guard.SetEnforced(true)
	req2 := httptest.NewRequest("POST", "/api/test", bytes.NewBufferString("hello"))
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when enforced and headers missing, got: %d", w2.Code)
	}

	// 3. Signed request passes when enforced
	ts := time.Now().Unix()
	nonce := "nonce-middleware-ok"
	bodyBytes := []byte("hello signed payload")
	sig := Sign(secret, "POST", "/api/test", ts, nonce, bodyBytes)

	req3 := httptest.NewRequest("POST", "/api/test", bytes.NewBuffer(bodyBytes))
	req3.Header.Set(HeaderSignature, sig)
	req3.Header.Set(HeaderTimestamp, fmt.Sprintf("%d", ts))
	req3.Header.Set(HeaderNonce, nonce)

	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid signed request, got: %d", w3.Code)
	}
	if receivedBody != "hello signed payload" {
		t.Fatalf("expected preserved body 'hello signed payload', got: %s", receivedBody)
	}

	// 4. Signed GET request with query parameters passes when enforced
	ts4 := time.Now().Unix()
	nonce4 := "nonce-middleware-query-ok"
	sig4 := Sign(secret, "GET", "/api/test?license_key=SLB-TEST-12345", ts4, nonce4, nil)

	req4 := httptest.NewRequest("GET", "/api/test?license_key=SLB-TEST-12345", nil)
	req4.Header.Set(HeaderSignature, sig4)
	req4.Header.Set(HeaderTimestamp, fmt.Sprintf("%d", ts4))
	req4.Header.Set(HeaderNonce, nonce4)

	w4 := httptest.NewRecorder()
	handler.ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for signed GET request with query parameters, got: %d", w4.Code)
	}

	// 5. Tampered signature is rejected and does not poison nonce cache
	nonce5 := "nonce-tamper-protect"
	req5 := httptest.NewRequest("GET", "/api/test?license_key=SLB-TEST-12345", nil)
	req5.Header.Set(HeaderSignature, "bad-hex-signature-12345678")
	req5.Header.Set(HeaderTimestamp, fmt.Sprintf("%d", ts4))
	req5.Header.Set(HeaderNonce, nonce5)

	w5 := httptest.NewRecorder()
	handler.ServeHTTP(w5, req5)
	if w5.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for tampered signature, got: %d", w5.Code)
	}

	// Valid retry with previously failed nonce succeeds because bad signature did not poison cache
	sig5Valid := Sign(secret, "GET", "/api/test?license_key=SLB-TEST-12345", ts4, nonce5, nil)
	req5Retry := httptest.NewRequest("GET", "/api/test?license_key=SLB-TEST-12345", nil)
	req5Retry.Header.Set(HeaderSignature, sig5Valid)
	req5Retry.Header.Set(HeaderTimestamp, fmt.Sprintf("%d", ts4))
	req5Retry.Header.Set(HeaderNonce, nonce5)

	w5Retry := httptest.NewRecorder()
	handler.ServeHTTP(w5Retry, req5Retry)
	if w5Retry.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for retry with unburned nonce, got: %d", w5Retry.Code)
	}
}
