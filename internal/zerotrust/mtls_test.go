package zerotrust

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMTLSHandshakeAndMiddleware(t *testing.T) {
	ca, err := NewCertificateAuthority(CAConfig{CommonName: "mtls-test-ca"})
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	serverCertResp, err := ca.IssuePeerCertificate(EnrollPeerRequest{
		NodeID:      "server-node",
		Role:        RoleClusterPeer,
		DNSNames:    []string{"localhost", "127.0.0.1"},
		IPAddresses: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("Failed to issue server cert: %v", err)
	}

	clientCertResp, err := ca.IssuePeerCertificate(EnrollPeerRequest{
		NodeID:      "client-node",
		Role:        RoleWorkerNode,
		DNSNames:    []string{"localhost"},
		IPAddresses: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("Failed to issue client cert: %v", err)
	}

	serverTLS, err := NewServerTLSConfig(ca, []byte(serverCertResp.CertificatePEM), []byte(serverCertResp.PrivateKeyPEM), true)
	if err != nil {
		t.Fatalf("Failed to create server TLS config: %v", err)
	}

	handler := Middleware(ca, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := PeerFromContext(r.Context())
		if !ok || peer == nil {
			http.Error(w, "missing peer in context", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("peer=" + peer.NodeID))
	}))

	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	// 1. Authorized client with valid mTLS certificate
	clientTLS, err := NewClientTLSConfig(ca, []byte(clientCertResp.CertificatePEM), []byte(clientCertResp.PrivateKeyPEM), "localhost")
	if err != nil {
		t.Fatalf("Failed to create client TLS config: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLS,
		},
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("mTLS client GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "peer=client-node" {
		t.Errorf("Unexpected body: %s", string(body))
	}

	// 2. Client without mTLS certificate (should fail TLS handshake or be rejected by server)
	noCertTLS := &tls.Config{
		RootCAs:            ca.CertPool(),
		InsecureSkipVerify: false,
	}
	noCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: noCertTLS,
		},
	}
	_, err = noCertClient.Get(server.URL)
	if err == nil {
		t.Fatal("Expected mTLS handshake failure for client without certificate")
	}

	// 3. Client with revoked certificate
	ca.RevokeSerial(clientCertResp.SerialNumber, "Compromised peer")
	client.CloseIdleConnections()
	server.CloseClientConnections()

	revokedClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLS,
		},
	}
	_, err = revokedClient.Get(server.URL)
	if err == nil {
		t.Fatal("Expected mTLS rejection for client with revoked certificate")
	}
}
