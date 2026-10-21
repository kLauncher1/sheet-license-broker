package zerotrust

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"
)

// ZeroTrustManager orchestrates internal CA operations, peer rosters, mTLS handshakes, and HSM key slots.
type ZeroTrustManager struct {
	mu           sync.RWMutex
	nodeID       string
	mtlsEnforced bool
	ca           *CertificateAuthority
	hsm          *SoftwareHSM
	peers        map[string]*PeerIdentity
	nodeCertPEM  string
	nodeKeyPEM   string
}

// ManagerConfig provides bootstrap configuration for the Zero-Trust mesh manager.
type ManagerConfig struct {
	NodeID       string
	HSMPIN       string
	MTLSEnforced bool
	ValidityDays int
}

// NewManager initializes the ZeroTrustManager with hardware-backed CA and local peer credentials.
func NewManager(cfg ManagerConfig) (*ZeroTrustManager, error) {
	if cfg.NodeID == "" {
		cfg.NodeID = "node-alpha-1"
	}
	if cfg.ValidityDays <= 0 {
		cfg.ValidityDays = 365
	}

	hsm, err := NewSoftwareHSM(cfg.HSMPIN)
	if err != nil {
		return nil, fmt.Errorf("failed to init software HSM: %w", err)
	}

	// Bind slot 0 signer to Root CA
	caSigner, err := hsm.GetSigner(0)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve CA signer from HSM: %w", err)
	}

	ca, err := NewCertificateAuthority(CAConfig{
		CommonName:   fmt.Sprintf("sheet-license-broker-%s-ca", cfg.NodeID),
		Organization: "sheet-license-broker",
		ValidityDays: cfg.ValidityDays,
		Signer:       caSigner,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to init internal CA: %w", err)
	}

	mgr := &ZeroTrustManager{
		nodeID:       cfg.NodeID,
		mtlsEnforced: cfg.MTLSEnforced,
		ca:           ca,
		hsm:          hsm,
		peers:        make(map[string]*PeerIdentity),
	}

	// Enroll local node credentials
	localEnroll, err := ca.IssuePeerCertificate(EnrollPeerRequest{
		NodeID:       cfg.NodeID,
		Role:         RoleClusterPeer,
		DNSNames:     []string{"localhost", cfg.NodeID},
		IPAddresses:  []string{"127.0.0.1", "::1"},
		ValidityDays: cfg.ValidityDays,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to enroll local node certificate: %w", err)
	}

	mgr.nodeCertPEM = localEnroll.CertificatePEM
	mgr.nodeKeyPEM = localEnroll.PrivateKeyPEM

	mgr.peers[cfg.NodeID] = &PeerIdentity{
		NodeID:            cfg.NodeID,
		Role:              RoleClusterPeer,
		CommonName:        cfg.NodeID,
		SPIFFEID:          fmt.Sprintf("spiffe://sheet-license-broker/mesh/%s", cfg.NodeID),
		SerialNumber:      localEnroll.SerialNumber,
		FingerprintSHA256: localEnroll.FingerprintSHA256,
		DNSNames:          []string{"localhost", cfg.NodeID},
		IPAddresses:       []string{"127.0.0.1", "::1"},
		IssuedAt:          time.Now().UTC(),
		ExpiresAt:         localEnroll.ExpiresAt,
		Status:            PeerStatusActive,
	}

	return mgr, nil
}

// EnrollPeer provisions an mTLS certificate and registers the peer in the mesh roster.
func (m *ZeroTrustManager) EnrollPeer(req EnrollPeerRequest) (*EnrollPeerResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if req.NodeID == "" {
		return nil, fmt.Errorf("node_id is required")
	}
	if req.Role == "" {
		req.Role = RoleClusterPeer
	}

	resp, err := m.ca.IssuePeerCertificate(req)
	if err != nil {
		return nil, err
	}

	m.peers[req.NodeID] = &PeerIdentity{
		NodeID:            req.NodeID,
		Role:              req.Role,
		CommonName:        req.NodeID,
		SPIFFEID:          fmt.Sprintf("spiffe://sheet-license-broker/mesh/%s", req.NodeID),
		SerialNumber:      resp.SerialNumber,
		FingerprintSHA256: resp.FingerprintSHA256,
		DNSNames:          req.DNSNames,
		IPAddresses:       req.IPAddresses,
		IssuedAt:          time.Now().UTC(),
		ExpiresAt:         resp.ExpiresAt,
		Status:            PeerStatusActive,
	}

	return resp, nil
}

// RevokePeer revokes a peer's certificate and marks its status as REVOKED.
func (m *ZeroTrustManager) RevokePeer(nodeID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, ok := m.peers[nodeID]
	if !ok {
		return ErrPeerNotFound
	}

	now := time.Now().UTC()
	peer.Status = PeerStatusRevoked
	peer.RevokedAt = &now
	peer.RevocationReason = reason

	m.ca.RevokeSerial(peer.SerialNumber, reason)
	return nil
}

// GetPeer looks up an enrolled peer by its node ID.
func (m *ZeroTrustManager) GetPeer(nodeID string) (*PeerIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peer, ok := m.peers[nodeID]
	if !ok {
		return nil, ErrPeerNotFound
	}
	cpy := *peer
	return &cpy, nil
}

// ListPeers returns an array of all known enrolled mesh peers.
func (m *ZeroTrustManager) ListPeers() []*PeerIdentity {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*PeerIdentity, 0, len(m.peers))
	for _, p := range m.peers {
		cpy := *p
		list = append(list, &cpy)
	}
	return list
}

// VerifyPeer validates whether a given peer certificate identity is actively authorized.
func (m *ZeroTrustManager) VerifyPeer(identity *PeerIdentity) (bool, string) {
	if identity == nil {
		return false, "empty peer identity"
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ca.IsSerialRevoked(identity.SerialNumber) {
		return false, fmt.Sprintf("certificate serial %s has been revoked", identity.SerialNumber)
	}

	if time.Now().UTC().After(identity.ExpiresAt) {
		return false, fmt.Sprintf("certificate expired at %s", identity.ExpiresAt.Format(time.RFC3339))
	}

	peer, ok := m.peers[identity.NodeID]
	if ok && peer.Status == PeerStatusRevoked {
		return false, fmt.Sprintf("peer %s is marked as revoked: %s", identity.NodeID, peer.RevocationReason)
	}

	return true, "valid"
}

// RotateCA provisions a fresh Root CA key and certificate.
func (m *ZeroTrustManager) RotateCA(validityDays int) error {
	return m.ca.RotateCA(validityDays)
}

// Status returns a high-level operational snapshot of the Zero-Trust mesh.
func (m *ZeroTrustManager) Status() ZeroTrustStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	active := 0
	revoked := 0
	for _, p := range m.peers {
		if p.Status == PeerStatusActive {
			active++
		} else if p.Status == PeerStatusRevoked {
			revoked++
		}
	}

	slots := m.hsm.ListSlots()

	return ZeroTrustStatus{
		CAInitialized:     m.ca != nil && m.ca.RootCertificate() != nil,
		CARootFingerprint: m.ca.RootFingerprint(),
		CAExpiresAt:       m.ca.RootCertificate().NotAfter,
		ActivePeersCount:  active,
		RevokedPeersCount: revoked,
		MTLSEnforced:      m.mtlsEnforced,
		HSMEnabled:        m.hsm != nil,
		HSMSlotsCount:     len(slots),
		Slots:             slots,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
	}
}

// CreateMeshClientTLSConfig generates an mTLS client configuration using the local node's credentials.
func (m *ZeroTrustManager) CreateMeshClientTLSConfig(targetServerName string) (*tls.Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return NewClientTLSConfig(m.ca, []byte(m.nodeCertPEM), []byte(m.nodeKeyPEM), targetServerName)
}

// CreateMeshServerTLSConfig generates an mTLS server configuration using the local node's credentials.
func (m *ZeroTrustManager) CreateMeshServerTLSConfig() (*tls.Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return NewServerTLSConfig(m.ca, []byte(m.nodeCertPEM), []byte(m.nodeKeyPEM), m.mtlsEnforced)
}

// CA returns the internal CertificateAuthority instance.
func (m *ZeroTrustManager) CA() *CertificateAuthority {
	return m.ca
}

// HSM returns the software HSM provider instance.
func (m *ZeroTrustManager) HSM() *SoftwareHSM {
	return m.hsm
}

// IsMTLSEnforced returns true if mutual TLS is strictly required on inter-node RPCs.
func (m *ZeroTrustManager) IsMTLSEnforced() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mtlsEnforced
}

// SetMTLSEnforced dynamically updates the mTLS enforcement policy.
func (m *ZeroTrustManager) SetMTLSEnforced(enforce bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mtlsEnforced = enforce
}
