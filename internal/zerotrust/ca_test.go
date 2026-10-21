package zerotrust

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestCAGenerationAndIssuance(t *testing.T) {
	ca, err := NewCertificateAuthority(CAConfig{
		CommonName:   "test-mesh-ca",
		Organization: "test-org",
		ValidityDays: 30,
	})
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	if ca.RootCertificate() == nil {
		t.Fatal("Root certificate is nil")
	}
	if len(ca.RootCAPEM()) == 0 {
		t.Fatal("Root CA PEM is empty")
	}
	if ca.RootFingerprint() == "" {
		t.Fatal("Root fingerprint is empty")
	}

	// Issue peer certificate
	resp, err := ca.IssuePeerCertificate(EnrollPeerRequest{
		NodeID:       "node-worker-42",
		Role:         RoleWorkerNode,
		DNSNames:     []string{"worker-42.mesh.internal"},
		IPAddresses:  []string{"10.0.0.42"},
		ValidityDays: 14,
	})
	if err != nil {
		t.Fatalf("Failed to issue peer certificate: %v", err)
	}

	if resp.NodeID != "node-worker-42" {
		t.Errorf("Expected node ID node-worker-42, got %s", resp.NodeID)
	}
	if resp.SerialNumber == "" {
		t.Error("Expected non-empty serial number")
	}
	if resp.FingerprintSHA256 == "" {
		t.Error("Expected non-empty fingerprint")
	}

	// Parse and verify peer cert against CA pool
	block, _ := pem.Decode([]byte(resp.CertificatePEM))
	if block == nil {
		t.Fatal("Failed to decode peer cert PEM")
	}
	peerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse peer cert: %v", err)
	}

	opts := x509.VerifyOptions{
		Roots: ca.CertPool(),
	}
	if _, err := peerCert.Verify(opts); err != nil {
		t.Fatalf("Peer cert verification failed against CA pool: %v", err)
	}
}

func TestCARevocation(t *testing.T) {
	ca, err := NewCertificateAuthority(CAConfig{})
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	resp, err := ca.IssuePeerCertificate(EnrollPeerRequest{
		NodeID: "untrusted-node",
		Role:   RoleClusterPeer,
	})
	if err != nil {
		t.Fatalf("Failed to issue cert: %v", err)
	}

	if ca.IsSerialRevoked(resp.SerialNumber) {
		t.Error("Serial should not be revoked yet")
	}

	ca.RevokeSerial(resp.SerialNumber, "Compromised key")

	if !ca.IsSerialRevoked(resp.SerialNumber) {
		t.Error("Serial should be revoked after RevokeSerial")
	}
	if ca.RevocationCount() != 1 {
		t.Errorf("Expected 1 revocation, got %d", ca.RevocationCount())
	}
}

func TestCARotationAndDualTrust(t *testing.T) {
	ca, err := NewCertificateAuthority(CAConfig{ValidityDays: 30})
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	firstFP := ca.RootFingerprint()

	// Issue cert with first CA
	firstPeer, err := ca.IssuePeerCertificate(EnrollPeerRequest{NodeID: "peer-1"})
	if err != nil {
		t.Fatalf("Failed to issue peer-1 cert: %v", err)
	}

	// Rotate CA
	if err := ca.RotateCA(60); err != nil {
		t.Fatalf("CA rotation failed: %v", err)
	}

	secondFP := ca.RootFingerprint()
	if firstFP == secondFP {
		t.Error("Root fingerprint should change after rotation")
	}

	// Issue cert with rotated CA
	secondPeer, err := ca.IssuePeerCertificate(EnrollPeerRequest{NodeID: "peer-2"})
	if err != nil {
		t.Fatalf("Failed to issue peer-2 cert: %v", err)
	}

	// Verify both peer certificates verify successfully against the rotated dual-trust pool
	block1, _ := pem.Decode([]byte(firstPeer.CertificatePEM))
	cert1, _ := x509.ParseCertificate(block1.Bytes)
	if _, err := cert1.Verify(x509.VerifyOptions{Roots: ca.CertPool()}); err != nil {
		t.Fatalf("Old peer cert failed to verify against dual-trust pool: %v", err)
	}

	block2, _ := pem.Decode([]byte(secondPeer.CertificatePEM))
	cert2, _ := x509.ParseCertificate(block2.Bytes)
	if _, err := cert2.Verify(x509.VerifyOptions{Roots: ca.CertPool()}); err != nil {
		t.Fatalf("New peer cert failed to verify against dual-trust pool: %v", err)
	}
}
