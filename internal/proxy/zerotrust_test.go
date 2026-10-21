package proxy

import (
	"context"
	"testing"

	"github.com/kLauncher1/sheet-license-broker/internal/zerotrust"
)

func TestProxyZeroTrustIntegration(t *testing.T) {
	px, err := NewProxy(ProxyConfig{
		OfflineMode:  true,
		NodeID:       "proxy-test-node",
		MTLSEnforced: false,
	})
	if err != nil {
		t.Fatalf("Failed to initialize proxy: %v", err)
	}

	ctx := context.Background()

	// Check status
	status := px.GetZeroTrustStatus()
	if !status.CAInitialized {
		t.Fatal("Expected CA to be initialized in proxy")
	}
	if status.ActivePeersCount != 1 {
		t.Errorf("Expected 1 active peer (local node), got %d", status.ActivePeersCount)
	}

	// Check HSM slots
	slots := px.GetZeroTrustHSMStatus()
	if len(slots) < 3 {
		t.Fatalf("Expected at least 3 HSM slots, got %d", len(slots))
	}

	// Enroll a new peer
	enrollResp, err := px.EnrollZeroTrustPeer(ctx, zerotrust.EnrollPeerRequest{
		NodeID:       "remote-worker-1",
		Role:         zerotrust.RoleWorkerNode,
		DNSNames:     []string{"remote-1.local"},
		IPAddresses:  []string{"10.0.0.10"},
		ValidityDays: 45,
	})
	if err != nil {
		t.Fatalf("Failed to enroll peer: %v", err)
	}
	if enrollResp.NodeID != "remote-worker-1" {
		t.Errorf("Unexpected enrolled node ID: %s", enrollResp.NodeID)
	}

	// Verify enrolled peer
	peer, err := px.ZeroTrustManager().GetPeer("remote-worker-1")
	if err != nil {
		t.Fatalf("Failed to get enrolled peer: %v", err)
	}
	valid, reason := px.VerifyZeroTrustPeer(ctx, peer)
	if !valid {
		t.Errorf("Expected valid peer, got reason: %s", reason)
	}

	// Revoke peer
	err = px.RevokeZeroTrustPeer(ctx, zerotrust.RevokePeerRequest{
		NodeID: "remote-worker-1",
		Reason: "Decommissioning test",
	})
	if err != nil {
		t.Fatalf("Failed to revoke peer: %v", err)
	}

	// Verify revoked peer is now invalid
	peer, err = px.ZeroTrustManager().GetPeer("remote-worker-1")
	if err != nil {
		t.Fatalf("Failed to get revoked peer: %v", err)
	}
	valid, _ = px.VerifyZeroTrustPeer(ctx, peer)
	if valid {
		t.Error("Expected revoked peer to fail verification")
	}

	// Rotate CA
	err = px.RotateZeroTrustCA(ctx, 180)
	if err != nil {
		t.Fatalf("Failed to rotate CA: %v", err)
	}
}
