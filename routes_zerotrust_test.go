package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
	"github.com/kLauncher1/sheet-license-broker/internal/zerotrust"
)

func newTestZeroTrustServer(t *testing.T) *AppServer {
	px, err := proxy.NewProxy(proxy.ProxyConfig{
		OfflineMode:  true,
		NodeID:       "test-routes-node",
		MTLSEnforced: false,
	})
	if err != nil {
		t.Fatalf("Failed to init proxy: %v", err)
	}
	secGuard := security.NewGuard([]byte("test-secret"), 0, false)
	return &AppServer{proxy: px, guard: secGuard}
}

func TestRoutesZeroTrustLifecycle(t *testing.T) {
	server := newTestZeroTrustServer(t)
	apiMux := http.NewServeMux()
	server.registerZeroTrustRoutes(apiMux)

	// 1. GET /api/zerotrust/status
	req := httptest.NewRequest(http.MethodGet, "/api/zerotrust/status", nil)
	w := httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /status, got %d", w.Code)
	}

	var status zerotrust.ZeroTrustStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to parse status response: %v", err)
	}
	if !status.CAInitialized {
		t.Fatal("Expected CA to be initialized")
	}

	// 2. GET /api/zerotrust/peers
	req = httptest.NewRequest(http.MethodGet, "/api/zerotrust/peers", nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /peers, got %d", w.Code)
	}

	// 3. POST /api/zerotrust/peers/enroll
	enrollBody, _ := json.Marshal(zerotrust.EnrollPeerRequest{
		NodeID:       "enrolled-peer-test",
		Role:         zerotrust.RoleWorkerNode,
		DNSNames:     []string{"peer-test.internal"},
		IPAddresses:  []string{"10.0.1.5"},
		ValidityDays: 60,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/zerotrust/peers/enroll", bytes.NewReader(enrollBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /peers/enroll, got %d: %s", w.Code, w.Body.String())
	}

	var enrollResp struct {
		Status     string                      `json:"status"`
		Enrollment *zerotrust.EnrollPeerResponse `json:"enrollment"`
	}
	if err := json.NewDecoder(w.Body).Decode(&enrollResp); err != nil {
		t.Fatalf("Failed to parse enroll response: %v", err)
	}
	if enrollResp.Enrollment == nil || enrollResp.Enrollment.NodeID != "enrolled-peer-test" {
		t.Fatalf("Invalid enrollment response: %+v", enrollResp)
	}

	// 4. POST /api/zerotrust/verify
	verifyBody, _ := json.Marshal(zerotrust.PeerIdentity{
		NodeID:            "enrolled-peer-test",
		SerialNumber:      enrollResp.Enrollment.SerialNumber,
		ExpiresAt:         enrollResp.Enrollment.ExpiresAt,
		FingerprintSHA256: enrollResp.Enrollment.FingerprintSHA256,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/zerotrust/verify", bytes.NewReader(verifyBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /verify, got %d", w.Code)
	}

	var verifyResp struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(w.Body).Decode(&verifyResp)
	if !verifyResp.Valid {
		t.Errorf("Expected valid peer, got reason: %s", verifyResp.Reason)
	}

	// 5. POST /api/zerotrust/peers/revoke
	revokeBody, _ := json.Marshal(zerotrust.RevokePeerRequest{
		NodeID: "enrolled-peer-test",
		Reason: "Automated test revocation",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/zerotrust/peers/revoke", bytes.NewReader(revokeBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /peers/revoke, got %d", w.Code)
	}

	// 6. POST /api/zerotrust/verify (should now be invalid)
	req = httptest.NewRequest(http.MethodPost, "/api/zerotrust/verify", bytes.NewReader(verifyBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	_ = json.NewDecoder(w.Body).Decode(&verifyResp)
	if verifyResp.Valid {
		t.Error("Expected revoked peer to fail verification")
	}

	// 7. GET /api/zerotrust/hsm/status
	req = httptest.NewRequest(http.MethodGet, "/api/zerotrust/hsm/status", nil)
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /hsm/status, got %d", w.Code)
	}

	// 8. POST /api/zerotrust/ca/rotate
	rotateBody, _ := json.Marshal(map[string]int{"validity_days": 180})
	req = httptest.NewRequest(http.MethodPost, "/api/zerotrust/ca/rotate", bytes.NewReader(rotateBody))
	w = httptest.NewRecorder()
	apiMux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on /ca/rotate, got %d", w.Code)
	}
}
