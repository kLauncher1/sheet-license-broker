package zerotrust

import (
	"testing"
)

func TestMeshManagerLifecycle(t *testing.T) {
	mgr, err := NewManager(ManagerConfig{
		NodeID:       "node-primary",
		HSMPIN:       DefaultHSMPIN,
		MTLSEnforced: false,
		ValidityDays: 90,
	})
	if err != nil {
		t.Fatalf("Failed to initialize ZeroTrustManager: %v", err)
	}

	status := mgr.Status()
	if !status.CAInitialized {
		t.Fatal("CA expected to be initialized")
	}
	if status.ActivePeersCount != 1 {
		t.Errorf("Expected 1 active peer (local node), got %d", status.ActivePeersCount)
	}
	if !status.HSMEnabled {
		t.Fatal("HSM expected to be enabled")
	}

	// Retrieve local peer
	localPeer, err := mgr.GetPeer("node-primary")
	if err != nil {
		t.Fatalf("Failed to retrieve local peer: %v", err)
	}
	if localPeer.NodeID != "node-primary" || localPeer.Role != RoleClusterPeer {
		t.Errorf("Unexpected local peer properties: %+v", localPeer)
	}

	// Verify local peer
	valid, reason := mgr.VerifyPeer(localPeer)
	if !valid {
		t.Errorf("Expected local peer to be valid, reason: %s", reason)
	}

	// Enroll remote peer
	enrollResp, err := mgr.EnrollPeer(EnrollPeerRequest{
		NodeID:       "node-secondary",
		Role:         RoleClusterPeer,
		DNSNames:     []string{"node-secondary.local"},
		IPAddresses:  []string{"10.0.0.2"},
		ValidityDays: 30,
	})
	if err != nil {
		t.Fatalf("Failed to enroll remote peer: %v", err)
	}

	if enrollResp.NodeID != "node-secondary" {
		t.Errorf("Expected node-secondary, got %s", enrollResp.NodeID)
	}

	peers := mgr.ListPeers()
	if len(peers) != 2 {
		t.Errorf("Expected 2 peers, got %d", len(peers))
	}

	// Revoke remote peer
	if err := mgr.RevokePeer("node-secondary", "Security decommission"); err != nil {
		t.Fatalf("Failed to revoke peer: %v", err)
	}

	remotePeer, err := mgr.GetPeer("node-secondary")
	if err != nil {
		t.Fatalf("Failed to get remote peer: %v", err)
	}
	if remotePeer.Status != PeerStatusRevoked {
		t.Errorf("Expected REVOKED status, got %s", remotePeer.Status)
	}

	valid, _ = mgr.VerifyPeer(remotePeer)
	if valid {
		t.Error("Expected revoked peer to fail VerifyPeer")
	}

	// Test CA rotation
	if err := mgr.RotateCA(120); err != nil {
		t.Fatalf("Failed to rotate CA: %v", err)
	}

	newStatus := mgr.Status()
	if newStatus.RevokedPeersCount != 1 {
		t.Errorf("Expected 1 revoked peer in status, got %d", newStatus.RevokedPeersCount)
	}
}
