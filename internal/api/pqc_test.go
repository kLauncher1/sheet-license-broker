package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kLauncher1/sheet-license-broker/internal/pqc"
)

func setupPQCTestServer(t *testing.T) (*AppServer, *http.ServeMux) {
	server, err := newAppServer()
	if err != nil {
		t.Fatalf("failed to init server: %v", err)
	}

	apiMux := http.NewServeMux()
	server.registerPQCRoutes(apiMux)
	apiMux.HandleFunc("/api/licenses", server.handleLicenses)
	apiMux.HandleFunc("/api/licenses/validate", server.handleValidateLicense)

	return server, apiMux
}

func TestPQCRoutesEndpoints(t *testing.T) {
	server, apiMux := setupPQCTestServer(t)
	_ = server

	// 1. GET /api/pqc/params
	req := httptest.NewRequest(http.MethodGet, "/api/pqc/params", nil)
	rr := httptest.NewRecorder()
	apiMux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/pqc/params, got %d: %s", rr.Code, rr.Body.String())
	}
	var paramsRes map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &paramsRes); err != nil {
		t.Fatalf("failed to unmarshal params: %v", err)
	}
	if paramsRes["status"] != "success" {
		t.Fatalf("expected status success in params: %+v", paramsRes)
	}

	// 2. GET /api/pqc/keys
	req = httptest.NewRequest(http.MethodGet, "/api/pqc/keys", nil)
	rr = httptest.NewRecorder()
	apiMux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/pqc/keys, got %d", rr.Code)
	}
	var keysRes map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &keysRes)
	if count, ok := keysRes["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least 1 active key, got %+v", keysRes)
	}

	// 3. Create a valid license for signing
	createLicReq := httptest.NewRequest(http.MethodPost, "/api/licenses", bytes.NewReader([]byte(`{"days":30,"max_devices":2}`)))
	rr = httptest.NewRecorder()
	apiMux.ServeHTTP(rr, createLicReq)
	if rr.Code != http.StatusCreated {
		t.Fatalf("failed to create license: %d %s", rr.Code, rr.Body.String())
	}
	var lic map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &lic)
	licenseKey := lic["license_key"].(string)

	// Bind device
	hwid := "HWID-PQC-ROUTE-TEST-1234"
	valReq := httptest.NewRequest(http.MethodPost, "/api/licenses/validate", bytes.NewReader([]byte(`{"license_key":"`+licenseKey+`","hwid":"`+hwid+`"}`)))
	rr = httptest.NewRecorder()
	apiMux.ServeHTTP(rr, valReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("failed to validate and bind device: %d", rr.Code)
	}

	// 4. POST /api/pqc/sign
	payloadText := `{"module":"cloud-license","entitlements":["pqc","attestation"]}`
	signReqBody := map[string]string{
		"license_key": licenseKey,
		"hwid":        hwid,
		"payload":     payloadText,
	}
	signBody, _ := json.Marshal(signReqBody)
	req = httptest.NewRequest(http.MethodPost, "/api/pqc/sign", bytes.NewReader(signBody))
	rr = httptest.NewRecorder()
	apiMux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/pqc/sign, got %d: %s", rr.Code, rr.Body.String())
	}
	var signRes struct {
		Status    string            `json:"status"`
		Signature pqc.HybridSignature `json:"signature"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &signRes); err != nil {
		t.Fatalf("failed to unmarshal signature response: %v", err)
	}
	if signRes.Status != "success" || signRes.Signature.KeyID == "" {
		t.Fatalf("invalid sign response: %+v", signRes)
	}

	// 5. POST /api/pqc/verify
	verifyReqBody := map[string]interface{}{
		"payload":   payloadText,
		"signature": signRes.Signature,
	}
	verifyBytes, _ := json.Marshal(verifyReqBody)
	req = httptest.NewRequest(http.MethodPost, "/api/pqc/verify", bytes.NewReader(verifyBytes))
	rr = httptest.NewRecorder()
	apiMux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/pqc/verify, got %d: %s", rr.Code, rr.Body.String())
	}
	var verifyRes struct {
		Status string                    `json:"status"`
		Result pqc.PQCVerificationResult `json:"result"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &verifyRes)
	if !verifyRes.Result.Valid || !verifyRes.Result.QuantumValid {
		t.Fatalf("expected valid hybrid verification outcome: %+v", verifyRes)
	}

	// 6. POST /api/pqc/rotate
	rotateBody := []byte(`{"algorithm":"Hybrid-HMAC-MLDSA44","grace_days":3,"reason":"Testing route rotation"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/pqc/rotate", bytes.NewReader(rotateBody))
	rr = httptest.NewRecorder()
	apiMux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/pqc/rotate, got %d: %s", rr.Code, rr.Body.String())
	}
	var rotateRes struct {
		Status   string                `json:"status"`
		Rotation pqc.KeyRotationRecord `json:"rotation"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &rotateRes)
	if rotateRes.Status != "success" || rotateRes.Rotation.NewKeyID == "" {
		t.Fatalf("invalid rotation response: %+v", rotateRes)
	}

	// 7. POST /api/pqc/revoke
	revokeBody := []byte(`{"key_id":"` + rotateRes.Rotation.OldKeyID + `","reason":"Testing route revocation"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/pqc/revoke", bytes.NewReader(revokeBody))
	rr = httptest.NewRecorder()
	apiMux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/pqc/revoke, got %d: %s", rr.Code, rr.Body.String())
	}

	// 8. GET /api/pqc/status
	req = httptest.NewRequest(http.MethodGet, "/api/pqc/status", nil)
	rr = httptest.NewRecorder()
	apiMux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/pqc/status, got %d", rr.Code)
	}
	var statusRes map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &statusRes)
	if statusRes["status"] != "success" {
		t.Fatalf("expected status success on /api/pqc/status: %+v", statusRes)
	}
}
