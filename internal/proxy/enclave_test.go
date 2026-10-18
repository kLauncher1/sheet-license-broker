package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/enclave"
)

func TestProxyEnclaveIntegration(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	defer px.Close()

	ctx := context.Background()

	// Pre-seed an active license
	lic, err := px.CreateLicense(ctx, 30, 1)
	if err != nil {
		t.Fatalf("failed to create license: %v", err)
	}

	// 1. Generate challenge nonce
	nonce, err := px.GenerateEnclaveChallenge()
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}

	// 2. Client enclave key & quote construction
	clientPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientPubBytes := make([]byte, 64)
	copy(clientPubBytes[0:32], clientPriv.PublicKey.X.Bytes())
	copy(clientPubBytes[32:64], clientPriv.PublicKey.Y.Bytes())

	h := sha256.New()
	h.Write([]byte(nonce))
	h.Write(clientPubBytes)
	boundDigest := h.Sum(nil)
	var reportData [64]byte
	copy(reportData[:32], boundDigest)

	attestPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mrEnclave := sha256.Sum256([]byte("trusted-workload-image"))
	mrSigner := sha256.Sum256([]byte("trusted-signer-root"))
	rawQuote, err := enclave.BuildMockSGXQuote(attestPriv, mrEnclave, mrSigner, 1, false, reportData)
	if err != nil {
		t.Fatalf("failed to build quote: %v", err)
	}

	policy := &enclave.EnclavePolicy{
		ID:                "proxy-sgx-policy",
		Name:              "Proxy SGX Policy",
		Platform:          enclave.PlatformSGX,
		AllowedMREnclaves: []string{hex.EncodeToString(mrEnclave[:])},
		AllowedMRSigners:  []string{hex.EncodeToString(mrSigner[:])},
		MinISVSVN:         1,
		AllowDebug:        false,
	}
	if err := px.RegisterEnclavePolicy(policy); err != nil {
		t.Fatalf("failed to register policy: %v", err)
	}

	// Verify policy retrieval
	pol, found := px.EnclaveManager().GetPolicy("proxy-sgx-policy")
	if !found || pol.Platform != enclave.PlatformSGX {
		t.Fatal("unexpected policy retrieved")
	}

	// 3. Establish tunnel through proxy
	session, brokerPubHex, err := px.EstablishEnclaveTunnel(enclave.PlatformSGX, rawQuote, nonce, "proxy-sgx-policy", hex.EncodeToString(clientPubBytes))
	if err != nil {
		t.Fatalf("failed to establish tunnel through proxy: %v", err)
	}
	if brokerPubHex == "" || session == nil {
		t.Fatal("expected non-empty session and broker pub hex")
	}

	// 4. Derive keys and encrypt evaluation request using client key
	brokerPubBytes, _ := hex.DecodeString(brokerPubHex)
	clientWriteKey, _, err := enclave.DeriveClientTunnelKeys(clientPriv, brokerPubBytes)
	if err != nil {
		t.Fatalf("failed to derive client keys: %v", err)
	}

	evalPayload := enclave.EnclaveEvalPayload{
		LicenseKey: lic.LicenseKey,
		HWID:       "",
		Timestamp:  time.Now().Unix(),
	}
	payloadBytes, _ := json.Marshal(evalPayload)

	encMsg, err := enclave.EncryptClientTunnelMessage(session.SessionID, 1, clientWriteKey, payloadBytes)
	if err != nil {
		t.Fatalf("failed to encrypt test payload: %v", err)
	}

	// 5. Process evaluation in enclave through proxy
	respMsg, err := px.EvaluateLicenseInEnclave(ctx, session.SessionID, encMsg)
	if err != nil {
		t.Fatalf("failed to evaluate license in enclave: %v", err)
	}

	if respMsg == nil || respMsg.PayloadHex == "" {
		t.Fatal("empty response returned from enclave evaluation")
	}

	// 6. Verify telemetry
	telemetry := px.GetEnclaveTelemetry()
	if telemetry.VerifiedQuotes < 1 || telemetry.TotalEvaluations < 1 {
		t.Fatalf("enclave telemetry not recorded properly: %+v", telemetry)
	}
}
