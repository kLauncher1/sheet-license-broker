package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
	"github.com/kLauncher1/sheet-license-broker/internal/transparency"
)

func newTestAppServerWithTransparency(t *testing.T) (*AppServer, *http.ServeMux) {
	px, err := proxy.NewProxy(proxy.ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}
	guard := security.NewGuard(nil, 0, false)
	server := &AppServer{proxy: px, guard: guard}

	apiMux := http.NewServeMux()
	server.registerTransparencyRoutes(apiMux)

	return server, apiMux
}

func TestTransparencyRoutesLifecycle(t *testing.T) {
	server, mux := newTestAppServerWithTransparency(t)
	defer server.proxy.Close()

	// 1. GET /api/transparency/status
	req := httptest.NewRequest(http.MethodGet, "/api/transparency/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /status, got %d", w.Code)
	}
	var status transparency.TransparencyStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode status: %v", err)
	}
	if status.TreeSize != 0 || status.ComplianceRFC != "RFC 6962" {
		t.Errorf("unexpected status: %+v", status)
	}

	// 2. Append 4 entries via POST /api/transparency/append
	for i := 0; i < 4; i++ {
		body, _ := json.Marshal(map[string]interface{}{
			"action":    "license_issued",
			"tenant_id": "tenant-alpha",
			"payload": map[string]string{
				"license": "SLB-TRANS-TEST-001",
			},
		})
		postReq := httptest.NewRequest(http.MethodPost, "/api/transparency/append", bytes.NewReader(body))
		postW := httptest.NewRecorder()
		mux.ServeHTTP(postW, postReq)

		if postW.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created from /append, got %d (body: %s)", postW.Code, postW.Body.String())
		}
	}

	// 3. GET /api/transparency/sth
	sthReq := httptest.NewRequest(http.MethodGet, "/api/transparency/sth", nil)
	sthW := httptest.NewRecorder()
	mux.ServeHTTP(sthW, sthReq)
	if sthW.Code != http.StatusOK {
		t.Fatalf("expected 200 from /sth, got %d", sthW.Code)
	}
	var sth transparency.SignedTreeHead
	if err := json.NewDecoder(sthW.Body).Decode(&sth); err != nil {
		t.Fatalf("failed to decode STH: %v", err)
	}
	if sth.TreeSize != 4 {
		t.Errorf("expected STH tree size 4, got %d", sth.TreeSize)
	}

	// 4. GET /api/transparency/entries?start=0&count=2
	entriesReq := httptest.NewRequest(http.MethodGet, "/api/transparency/entries?start=0&count=2", nil)
	entriesW := httptest.NewRecorder()
	mux.ServeHTTP(entriesW, entriesReq)
	if entriesW.Code != http.StatusOK {
		t.Fatalf("expected 200 from /entries, got %d", entriesW.Code)
	}

	// 5. GET /api/transparency/inclusion-proof?index=2&tree_size=4
	incReq := httptest.NewRequest(http.MethodGet, "/api/transparency/inclusion-proof?index=2&tree_size=4", nil)
	incW := httptest.NewRecorder()
	mux.ServeHTTP(incW, incReq)
	if incW.Code != http.StatusOK {
		t.Fatalf("expected 200 from /inclusion-proof, got %d: %s", incW.Code, incW.Body.String())
	}
	var incProof transparency.InclusionProof
	if err := json.NewDecoder(incW.Body).Decode(&incProof); err != nil {
		t.Fatalf("failed to decode inclusion proof: %v", err)
	}

	// 6. POST /api/transparency/inclusion-proof/verify
	incVerifyBody, _ := json.Marshal(incProof)
	incVerifyReq := httptest.NewRequest(http.MethodPost, "/api/transparency/inclusion-proof/verify", bytes.NewReader(incVerifyBody))
	incVerifyW := httptest.NewRecorder()
	mux.ServeHTTP(incVerifyW, incVerifyReq)
	if incVerifyW.Code != http.StatusOK {
		t.Fatalf("expected 200 from /inclusion-proof/verify, got %d", incVerifyW.Code)
	}
	var incRes map[string]interface{}
	_ = json.NewDecoder(incVerifyW.Body).Decode(&incRes)
	if incRes["verified"] != true {
		t.Fatalf("expected inclusion proof to be verified")
	}

	// 7. GET /api/transparency/consistency-proof?first=2&second=4
	consReq := httptest.NewRequest(http.MethodGet, "/api/transparency/consistency-proof?first=2&second=4", nil)
	consW := httptest.NewRecorder()
	mux.ServeHTTP(consW, consReq)
	if consW.Code != http.StatusOK {
		t.Fatalf("expected 200 from /consistency-proof, got %d: %s", consW.Code, consW.Body.String())
	}
	var consProof transparency.ConsistencyProof
	if err := json.NewDecoder(consW.Body).Decode(&consProof); err != nil {
		t.Fatalf("failed to decode consistency proof: %v", err)
	}

	// 8. POST /api/transparency/consistency-proof/verify
	consVerifyBody, _ := json.Marshal(consProof)
	consVerifyReq := httptest.NewRequest(http.MethodPost, "/api/transparency/consistency-proof/verify", bytes.NewReader(consVerifyBody))
	consVerifyW := httptest.NewRecorder()
	mux.ServeHTTP(consVerifyW, consVerifyReq)
	if consVerifyW.Code != http.StatusOK {
		t.Fatalf("expected 200 from /consistency-proof/verify, got %d", consVerifyW.Code)
	}
	var consRes map[string]interface{}
	_ = json.NewDecoder(consVerifyW.Body).Decode(&consRes)
	if consRes["verified"] != true {
		t.Fatalf("expected consistency proof to be verified")
	}

	// 9. GET /api/transparency/witnesses
	wReq := httptest.NewRequest(http.MethodGet, "/api/transparency/witnesses", nil)
	wResp := httptest.NewRecorder()
	mux.ServeHTTP(wResp, wReq)
	if wResp.Code != http.StatusOK {
		t.Fatalf("expected 200 from /witnesses, got %d", wResp.Code)
	}

	// 10. POST /api/transparency/witness/cosign
	cosignBody, _ := json.Marshal(map[string]string{"witness_id": "witness-enclave-sgx"})
	cosignReq := httptest.NewRequest(http.MethodPost, "/api/transparency/witness/cosign", bytes.NewReader(cosignBody))
	cosignW := httptest.NewRecorder()
	mux.ServeHTTP(cosignW, cosignReq)
	if cosignW.Code != http.StatusOK {
		t.Fatalf("expected 200 from /witness/cosign, got %d: %s", cosignW.Code, cosignW.Body.String())
	}
}
