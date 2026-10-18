package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/attestation"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

type attestationSig struct {
	R, S *big.Int
}

func setupAttestationTestServer(t *testing.T) (*httptest.Server, *AppServer) {
	t.Helper()
	px, err := proxy.NewProxy(proxy.ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	secGuard := security.NewGuard([]byte(""), 5*time.Minute, false)
	appServer := &AppServer{proxy: px, guard: secGuard}

	apiMux := http.NewServeMux()
	appServer.registerAttestationRoutes(apiMux)

	ts := httptest.NewServer(apiMux)
	return ts, appServer
}

func generateRouteTestKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubBytes, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return priv, string(pemBytes)
}

func TestAttestationChallengeEndpoint(t *testing.T) {
	ts, _ := setupAttestationTestServer(t)
	defer ts.Close()

	payload := map[string]string{
		"license_key": "LIC-TEST-CHALLENGE",
		"hwid":        "HWID-TEST-001",
	}
	body, _ := json.Marshal(payload)

	res, err := http.Post(ts.URL+"/api/attestation/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/attestation/challenge error: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.StatusCode)
	}

	var data map[string]interface{}
	_ = json.NewDecoder(res.Body).Decode(&data)

	if data["status"] != "success" || data["nonce"] == nil || data["challenge_id"] == nil {
		t.Fatalf("unexpected challenge response: %v", data)
	}
}

func TestAttestationTPMVerifyEndpoint(t *testing.T) {
	ts, _ := setupAttestationTestServer(t)
	defer ts.Close()

	licKey := "LIC-ROUTE-TPM"
	hwid := "HWID-ROUTE-DEV"

	// 1. Request challenge
	chPayload, _ := json.Marshal(map[string]string{
		"license_key": licKey,
		"hwid":        hwid,
	})
	chRes, err := http.Post(ts.URL+"/api/attestation/challenge", "application/json", bytes.NewReader(chPayload))
	if err != nil {
		t.Fatalf("challenge request error: %v", err)
	}
	defer chRes.Body.Close()

	var chData struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
	}
	_ = json.NewDecoder(chRes.Body).Decode(&chData)

	// 2. Build and sign TPM quote
	priv, pubPEM := generateRouteTestKey(t)
	pcrVals := map[int]string{
		0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	selection := []int{0}

	compDigest, _ := attestation.ComputePCRComposite(pcrVals, selection, chData.Nonce)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, compDigest)
	sigBytes, _ := asn1.Marshal(attestationSig{R: r, S: s})

	verifyPayload := map[string]interface{}{
		"license_key":      licKey,
		"hwid":             hwid,
		"challenge_id":     chData.ChallengeID,
		"attestation_type": "tpm2",
		"tpm_quote": map[string]interface{}{
			"pcr_values":        pcrVals,
			"pcr_selection":     selection,
			"composite_digest":  hex.EncodeToString(compDigest),
			"signature":         hex.EncodeToString(sigBytes),
			"ak_public_key_pem": pubPEM,
		},
	}
	vBody, _ := json.Marshal(verifyPayload)

	vRes, err := http.Post(ts.URL+"/api/attestation/verify", "application/json", bytes.NewReader(vBody))
	if err != nil {
		t.Fatalf("POST /api/attestation/verify error: %v", err)
	}
	defer vRes.Body.Close()

	if vRes.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", vRes.StatusCode)
	}

	var vData map[string]interface{}
	_ = json.NewDecoder(vRes.Body).Decode(&vData)
	if vData["status"] != "success" {
		t.Fatalf("expected success, got %v", vData)
	}
}

func TestAttestationStatusAndTelemetryEndpoints(t *testing.T) {
	ts, _ := setupAttestationTestServer(t)
	defer ts.Close()

	licKey := "LIC-ROUTE-TELEM"
	hwid := "HWID-TELEM-01"

	// 1. Submit clean telemetry
	cleanPayload := map[string]interface{}{
		"license_key": licKey,
		"hwid":        hwid,
		"report": map[string]interface{}{
			"debugger_present":   false,
			"memory_integrity":   true,
			"sandbox_detected":   false,
			"hooks_detected":     false,
			"process_checksum":   "11223344",
			"execution_uptime_s": 60,
			"timestamp":          time.Now(),
		},
	}
	cBody, _ := json.Marshal(cleanPayload)
	tRes, err := http.Post(ts.URL+"/api/attestation/telemetry", "application/json", bytes.NewReader(cBody))
	if err != nil {
		t.Fatalf("telemetry post error: %v", err)
	}
	defer tRes.Body.Close()

	if tRes.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", tRes.StatusCode)
	}

	var tData map[string]interface{}
	_ = json.NewDecoder(tRes.Body).Decode(&tData)
	if tData["tampered"] != false || tData["tamper_score"].(float64) != 0 {
		t.Errorf("expected clean telemetry, got: %v", tData)
	}

	// 2. Query status for specific device
	stRes, err := http.Get(ts.URL + "/api/attestation/status?license_key=" + licKey + "&hwid=" + hwid)
	if err != nil {
		t.Fatalf("GET /api/attestation/status error: %v", err)
	}
	defer stRes.Body.Close()

	if stRes.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", stRes.StatusCode)
	}

	// 3. Submit tampered telemetry
	tamperedPayload := map[string]interface{}{
		"license_key": licKey,
		"hwid":        hwid,
		"report": map[string]interface{}{
			"debugger_present":   true,
			"memory_integrity":   false,
			"sandbox_detected":   false,
			"hooks_detected":     true,
			"process_checksum":   "tampered-hash",
			"execution_uptime_s": 120,
			"timestamp":          time.Now(),
		},
	}
	tamBody, _ := json.Marshal(tamperedPayload)
	tamRes, err := http.Post(ts.URL+"/api/attestation/telemetry", "application/json", bytes.NewReader(tamBody))
	if err != nil {
		t.Fatalf("tampered telemetry post error: %v", err)
	}
	defer tamRes.Body.Close()

	var tamData map[string]interface{}
	_ = json.NewDecoder(tamRes.Body).Decode(&tamData)
	if tamData["tampered"] != true || tamData["trust_level"] != string(attestation.TrustTampered) {
		t.Errorf("expected tampered=true and trust_level=tampered, got: %v", tamData)
	}
}
