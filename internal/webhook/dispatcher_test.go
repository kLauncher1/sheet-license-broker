package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSignPayload(t *testing.T) {
	secret := "test-secret"
	body := []byte(`{"hello":"world"}`)

	sig := SignPayload(secret, body)
	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("expected sha256= prefix, got %s", sig)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedHex := hex.EncodeToString(mac.Sum(nil))

	if sig != "sha256="+expectedHex {
		t.Errorf("signature mismatch: expected %s, got %s", expectedHex, sig)
	}

	// Verify constant-time validation
	if !VerifyPayloadSignature(secret, body, sig) {
		t.Errorf("expected valid signature verification to pass")
	}
	if VerifyPayloadSignature(secret, body, "sha256=invalidhex") {
		t.Errorf("expected tampered signature to fail")
	}
	if VerifyPayloadSignature("wrong-secret", body, sig) {
		t.Errorf("expected wrong secret to fail")
	}
}

func TestDispatchSyncSuccess(t *testing.T) {
	secret := "wh-secret-key"
	received := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		if r.Header.Get("X-Broker-Event") != EventLicenseCreated {
			t.Errorf("expected event %s, got %s", EventLicenseCreated, r.Header.Get("X-Broker-Event"))
		}
		sig := r.Header.Get("X-Broker-Signature")
		body, _ := io.ReadAll(r.Body)
		expectedSig := SignPayload(secret, body)
		if sig != expectedSig {
			t.Errorf("signature header mismatch: got %s, expected %s", sig, expectedSig)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewDispatcher(Config{
		MaxRetries:  1,
		BaseBackoff: 10 * time.Millisecond,
		HTTPClient:  ts.Client(),
	})
	defer d.Close()

	evt := NewEvent(EventLicenseCreated, "tenant-test", map[string]string{"license": "KEY-1234"})
	err := d.DispatchSync(context.Background(), evt, ts.URL, secret)
	if err != nil {
		t.Fatalf("expected successful dispatch, got %v", err)
	}
	if !received {
		t.Errorf("expected server to receive webhook")
	}
}

func TestDispatchSyncRetryAndRecovery(t *testing.T) {
	var attempts int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		curr := atomic.AddInt32(&attempts, 1)
		if curr == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewDispatcher(Config{
		MaxRetries:  2,
		BaseBackoff: 10 * time.Millisecond,
		HTTPClient:  ts.Client(),
	})
	defer d.Close()

	evt := NewEvent(EventLicenseRevoked, "tenant-test", map[string]string{"license": "REV-1234"})
	err := d.DispatchSync(context.Background(), evt, ts.URL, "secret")
	if err != nil {
		t.Fatalf("expected retry recovery, got error: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 attempts before success, got %d", attempts)
	}
}

func TestDispatchAsyncRouting(t *testing.T) {
	var tenantReceived int32
	var globalReceived int32

	tenantServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tenantReceived, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer tenantServer.Close()

	globalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&globalReceived, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer globalServer.Close()

	d := NewDispatcher(Config{
		GlobalWebhookURL: globalServer.URL,
		GlobalSecret:     "global-sec",
		MaxRetries:       1,
		BaseBackoff:      5 * time.Millisecond,
		WorkerCount:      2,
		QueueSize:        32,
		HTTPClient:       tenantServer.Client(),
	})

	evt := NewEvent(EventDeviceBanned, "tenant-alpha", map[string]string{"hwid": "HWID-9999"})
	d.Dispatch(evt, tenantServer.URL, "tenant-sec")

	// Allow workers to process
	time.Sleep(100 * time.Millisecond)
	d.Close()

	if atomic.LoadInt32(&tenantReceived) != 1 {
		t.Errorf("expected tenant server to receive 1 event, got %d", tenantReceived)
	}
	if atomic.LoadInt32(&globalReceived) != 1 {
		t.Errorf("expected global server to receive 1 event, got %d", globalReceived)
	}
}
