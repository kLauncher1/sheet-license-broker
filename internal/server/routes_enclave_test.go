package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/enclave"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
)

func TestEnclaveRoutes(t *testing.T) {
	px, err := proxy.NewProxy(proxy.ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer px.Close()

	ctx := context.Background()
	lic, err := px.CreateLicense(ctx, 30, 1)
	if err != nil {
		t.Fatalf("failed to seed license: %v", err)
	}

	guard := security.NewGuard([]byte(""), 5*time.Minute, false)
	server := &AppServer{proxy: px, guard: guard}

	apiMux := http.NewServeMux()
	server.registerEnclaveRoutes(apiMux)

	// 1. GET /api/enclave/status
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/enclave/status", nil)
	wStatus := httptest.NewRecorder()
	apiMux.ServeHTTP(wStatus, reqStatus)
	if wStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 from status, got %d", wStatus.Code)
	}

	// 2. POST /api/enclave/challenge
	reqChall := httptest.NewRequest(http.MethodPost, "/api/enclave/challenge", nil)
	wChall := httptest.NewRecorder()
	apiMux.ServeHTTP(wChall, reqChall)
	if wChall.Code != http.StatusOK {
		t.Fatalf("expected 200 from challenge, got %d", wChall.Code)
	}
	var challResp struct {
		Challenge string `json:"challenge"`
	}
	json.NewDecoder(wChall.Body).Decode(&challResp)
	if len(challResp.Challenge) != 64 {
		t.Fatalf("expected 64 hex char challenge, got %s", challResp.Challenge)
	}

	// 3. POST /api/enclave/policy
	polReq := enclave.EnclavePolicy{
		ID:         "test-routes-policy",
		Name:       "Test Routes Policy",
		Platform:   enclave.PlatformSGX,
		MinISVSVN:  1,
		AllowDebug: false,
	}
	polBody, _ := json.Marshal(polReq)
	reqPol := httptest.NewRequest(http.MethodPost, "/api/enclave/policy", bytes.NewReader(polBody))
	wPol := httptest.NewRecorder()
	apiMux.ServeHTTP(wPol, reqPol)
	if wPol.Code != http.StatusOK {
		t.Fatalf("expected 200 from policy registration, got %d", wPol.Code)
	}

	// 4. Construct mock client enclave keys and quote
	clientPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubX := clientPriv.PublicKey.X.Bytes()
	pubY := clientPriv.PublicKey.Y.Bytes()
	clientPubBytes := make([]byte, 64)
	copy(clientPubBytes[32-len(pubX):32], pubX)
	copy(clientPubBytes[64-len(pubY):64], pubY)

	h := sha256.New()
	h.Write([]byte(challResp.Challenge))
	h.Write(clientPubBytes)
	boundDigest := h.Sum(nil)
	var reportData [64]byte
	copy(reportData[:32], boundDigest)

	attestPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mrEnclave := sha256.Sum256([]byte("workload-test"))
	mrSigner := sha256.Sum256([]byte("signer-test"))
	rawQuote, err := enclave.BuildMockSGXQuote(attestPriv, mrEnclave, mrSigner, 2, false, reportData)
	if err != nil {
		t.Fatalf("failed to build mock quote: %v", err)
	}

	// 5. POST /api/enclave/tunnel/handshake
	hsReq := enclaveHandshakeReq{
		Platform:        enclave.PlatformSGX,
		QuoteHex:        hex.EncodeToString(rawQuote),
		Nonce:           challResp.Challenge,
		PolicyID:        "test-routes-policy",
		ClientPublicKey: hex.EncodeToString(clientPubBytes),
	}
	hsBody, _ := json.Marshal(hsReq)
	reqHS := httptest.NewRequest(http.MethodPost, "/api/enclave/tunnel/handshake", bytes.NewReader(hsBody))
	wHS := httptest.NewRecorder()
	apiMux.ServeHTTP(wHS, reqHS)
	if wHS.Code != http.StatusOK {
		t.Fatalf("expected 200 from handshake, got %d: %s", wHS.Code, wHS.Body.String())
	}

	var hsResp struct {
		Established     bool   `json:"established"`
		SessionID       string `json:"session_id"`
		BrokerPublicKey string `json:"broker_public_key"`
	}
	json.NewDecoder(wHS.Body).Decode(&hsResp)
	if !hsResp.Established || hsResp.SessionID == "" || hsResp.BrokerPublicKey == "" {
		t.Fatalf("invalid handshake response: %+v", hsResp)
	}

	// 6. Derive symmetric client keys
	brokerPubBytes, _ := hex.DecodeString(hsResp.BrokerPublicKey)
	clientWriteKey, clientReadKey, err := enclave.DeriveClientTunnelKeys(clientPriv, brokerPubBytes)
	if err != nil {
		t.Fatalf("client key derivation failed: %v", err)
	}

	// 7. POST /api/enclave/tunnel/evaluate
	evalReq := enclave.EnclaveEvalPayload{
		LicenseKey: lic.LicenseKey,
		HWID:       "",
		Timestamp:  time.Now().Unix(),
	}
	evalBody, _ := json.Marshal(evalReq)

	encMsg, err := enclave.EncryptClientTunnelMessage(hsResp.SessionID, 1, clientWriteKey, evalBody)
	if err != nil {
		t.Fatalf("failed to encrypt client message: %v", err)
	}

	evalHTTPReq := enclaveTunnelMsgReq{
		SessionID: encMsg.SessionID,
		Sequence:  encMsg.Sequence,
		NonceHex:  encMsg.NonceHex,
		CipherHex: encMsg.PayloadHex,
	}
	evalHTTPBody, _ := json.Marshal(evalHTTPReq)
	reqEval := httptest.NewRequest(http.MethodPost, "/api/enclave/tunnel/evaluate", bytes.NewReader(evalHTTPBody))
	wEval := httptest.NewRecorder()
	apiMux.ServeHTTP(wEval, reqEval)
	if wEval.Code != http.StatusOK {
		t.Fatalf("expected 200 from evaluate, got %d: %s", wEval.Code, wEval.Body.String())
	}

	var evalResp struct {
		SessionID string `json:"session_id"`
		Sequence  uint64 `json:"sequence"`
		NonceHex  string `json:"nonce"`
		CipherHex string `json:"payload"`
	}
	json.NewDecoder(wEval.Body).Decode(&evalResp)

	// 8. Client decrypts and verifies verdict
	respSession := &enclave.EnclaveTunnelSession{
		SessionID:      hsResp.SessionID,
		ClientWriteKey: clientReadKey, // On client side, read key decrypts broker messages
		ExpiresAt:      time.Now().Add(10 * time.Minute),
	}
	decryptedVerdict, err := respSession.DecryptClientMessage(&enclave.EncryptedTunnelMessage{
		SessionID:  evalResp.SessionID,
		Sequence:   evalResp.Sequence,
		NonceHex:   evalResp.NonceHex,
		PayloadHex: evalResp.CipherHex,
	})
	if err != nil {
		t.Fatalf("client failed to decrypt verdict: %v", err)
	}

	var verdict enclave.EnclaveEvalResponse
	if err := json.Unmarshal(decryptedVerdict, &verdict); err != nil {
		t.Fatalf("failed to parse verdict JSON: %v", err)
	}
	if !verdict.Valid || !verdict.ZeroPlaintextGuarantee {
		t.Fatalf("expected valid zero-plaintext verdict, got: %+v", verdict)
	}
}
