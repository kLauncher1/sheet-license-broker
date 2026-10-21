package proxy

import (
	"context"
	"fmt"
	"log"

	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
	"github.com/kLauncher1/sheet-license-broker/internal/zerotrust"
)

// initZeroTrust sets up the Zero-Trust mesh manager and binds mTLS to inter-node consensus RPCs.
func (p *Proxy) initZeroTrust(cfg ProxyConfig) {
	nodeID := cfg.NodeID
	if nodeID == "" {
		nodeID = "broker-node-1"
	}

	mgr, err := zerotrust.NewManager(zerotrust.ManagerConfig{
		NodeID:       nodeID,
		HSMPIN:       cfg.HSMPIN,
		MTLSEnforced: cfg.MTLSEnforced,
		ValidityDays: 365,
	})
	if err != nil {
		log.Printf("[Proxy] Warning: Failed to initialize ZeroTrust manager: %v", err)
		return
	}
	p.zeroTrustManager = mgr

	// If consensus mesh is active, configure mutual TLS transport
	if p.p2pMesh != nil {
		clientTLS, err := mgr.CreateMeshClientTLSConfig("localhost")
		if err == nil {
			p.p2pMesh.SetTLSConfig(clientTLS)
			log.Printf("[Proxy] Zero-Trust mTLS client transport bound to consensus P2P mesh")
		}
	}
}

// ZeroTrustManager returns the active zero-trust mesh manager.
func (p *Proxy) ZeroTrustManager() *zerotrust.ZeroTrustManager {
	return p.zeroTrustManager
}

// GetZeroTrustStatus returns a snapshot of CA, active peers, and HSM slots.
func (p *Proxy) GetZeroTrustStatus() zerotrust.ZeroTrustStatus {
	if p.zeroTrustManager == nil {
		return zerotrust.ZeroTrustStatus{}
	}
	return p.zeroTrustManager.Status()
}

// EnrollZeroTrustPeer issues an mTLS certificate and registers the peer in the mesh.
func (p *Proxy) EnrollZeroTrustPeer(ctx context.Context, req zerotrust.EnrollPeerRequest) (*zerotrust.EnrollPeerResponse, error) {
	if p.zeroTrustManager == nil {
		return nil, fmt.Errorf("zero trust manager is not initialized")
	}

	resp, err := p.zeroTrustManager.EnrollPeer(req)
	if err != nil {
		return nil, err
	}

	p.BroadcastStreamEvent("zerotrust_peer_enrolled", map[string]interface{}{
		"node_id":            resp.NodeID,
		"role":               resp.Role,
		"serial_number":      resp.SerialNumber,
		"fingerprint_sha256": resp.FingerprintSHA256,
		"expires_at":         resp.ExpiresAt,
	})

	p.NotifyLicenseEvent(webhook.EventLicenseCreated, "", resp.NodeID, fmt.Sprintf("Zero-Trust Peer Enrolled (%s)", resp.NodeID))

	if p.IsRemoteEnabled() && p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "zerotrust_enroll_peer", map[string]interface{}{
				"node_id":            resp.NodeID,
				"role":               resp.Role,
				"serial_number":      resp.SerialNumber,
				"fingerprint_sha256": resp.FingerprintSHA256,
				"expires_at":         resp.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
				"status":             "ACTIVE",
			})
		}()
	}

	return resp, nil
}

// RevokeZeroTrustPeer marks a peer certificate as revoked in the internal CRL.
func (p *Proxy) RevokeZeroTrustPeer(ctx context.Context, req zerotrust.RevokePeerRequest) error {
	if p.zeroTrustManager == nil {
		return fmt.Errorf("zero trust manager is not initialized")
	}

	if err := p.zeroTrustManager.RevokePeer(req.NodeID, req.Reason); err != nil {
		return err
	}

	p.BroadcastStreamEvent("zerotrust_peer_revoked", map[string]interface{}{
		"node_id": req.NodeID,
		"reason":  req.Reason,
	})

	p.NotifyLicenseEvent(webhook.EventTamperDetected, "", req.NodeID, fmt.Sprintf("Zero-Trust Peer Revoked (%s): %s", req.NodeID, req.Reason))

	if p.IsRemoteEnabled() && p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "zerotrust_revoke_peer", map[string]interface{}{
				"node_id": req.NodeID,
				"reason":  req.Reason,
			})
		}()
	}

	return nil
}

// RotateZeroTrustCA rotates the internal CA and refreshes the trust pool.
func (p *Proxy) RotateZeroTrustCA(ctx context.Context, validityDays int) error {
	if p.zeroTrustManager == nil {
		return fmt.Errorf("zero trust manager is not initialized")
	}

	if err := p.zeroTrustManager.RotateCA(validityDays); err != nil {
		return err
	}

	status := p.zeroTrustManager.Status()
	p.BroadcastStreamEvent("zerotrust_ca_rotated", map[string]interface{}{
		"root_fingerprint": status.CARootFingerprint,
		"expires_at":       status.CAExpiresAt,
	})

	if p.IsRemoteEnabled() && p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "zerotrust_rotate_ca", map[string]interface{}{
				"root_fingerprint": status.CARootFingerprint,
				"expires_at":       status.CAExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
			})
		}()
	}

	return nil
}

// VerifyZeroTrustPeer checks the authorization and validity of a peer certificate identity.
func (p *Proxy) VerifyZeroTrustPeer(ctx context.Context, identity *zerotrust.PeerIdentity) (bool, string) {
	if p.zeroTrustManager == nil {
		return false, "zero trust manager not initialized"
	}
	return p.zeroTrustManager.VerifyPeer(identity)
}

// GetZeroTrustHSMStatus returns telemetry on provisioned hardware key slots.
func (p *Proxy) GetZeroTrustHSMStatus() []zerotrust.HSMSlotInfo {
	if p.zeroTrustManager == nil || p.zeroTrustManager.HSM() == nil {
		return nil
	}
	return p.zeroTrustManager.HSM().ListSlots()
}
