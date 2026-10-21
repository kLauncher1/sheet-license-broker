package zerotrust

import (
	"errors"
	"time"
)

var (
	// ErrCANotInitialized indicates the internal certificate authority is uninitialized.
	ErrCANotInitialized = errors.New("certificate authority is not initialized")
	// ErrCertExpired indicates the presented certificate has expired.
	ErrCertExpired = errors.New("certificate has expired")
	// ErrCertRevoked indicates the presented certificate has been revoked.
	ErrCertRevoked = errors.New("certificate has been revoked")
	// ErrUntrustedIssuer indicates the certificate is signed by an untrusted authority.
	ErrUntrustedIssuer = errors.New("certificate issuer is untrusted")
	// ErrHSMUnauthorized indicates access to the HSM key slot was denied.
	ErrHSMUnauthorized = errors.New("invalid or missing HSM PIN")
	// ErrHSMSlotNotFound indicates the requested hardware key slot does not exist.
	ErrHSMSlotNotFound = errors.New("requested HSM slot does not exist")
	// ErrPeerNotFound indicates the specified mesh peer could not be located.
	ErrPeerNotFound = errors.New("mesh peer not found")
	// ErrMTLSMissingClientCert indicates a required client certificate was omitted.
	ErrMTLSMissingClientCert = errors.New("mutual TLS client certificate required")
)

// PeerRole defines the authorization scope of a mesh node.
type PeerRole string

const (
	// RoleClusterPeer represents an authoritative consensus voting peer.
	RoleClusterPeer PeerRole = "cluster_peer"
	// RoleWorkerNode represents an operational background worker node.
	RoleWorkerNode PeerRole = "worker_node"
	// RoleAdminAgent represents a privileged management controller.
	RoleAdminAgent PeerRole = "admin_agent"
	// RoleEdgeGateway represents an edge ingress proxy or CDN POP.
	RoleEdgeGateway PeerRole = "edge_gateway"
)

// PeerStatus tracks the operational lifecycle status of an enrolled peer.
type PeerStatus string

const (
	// PeerStatusActive marks an authorized peer with active certificate entitlements.
	PeerStatusActive PeerStatus = "ACTIVE"
	// PeerStatusSuspended marks a temporarily deactivated peer.
	PeerStatusSuspended PeerStatus = "SUSPENDED"
	// PeerStatusRevoked marks a permanently revoked peer whose certificate is rejected.
	PeerStatusRevoked PeerStatus = "REVOKED"
)

// PeerIdentity represents verified cryptographic credentials for a mesh node.
type PeerIdentity struct {
	NodeID            string     `json:"node_id"`
	Role              PeerRole   `json:"role"`
	CommonName        string     `json:"common_name"`
	SPIFFEID          string     `json:"spiffe_id"`
	SerialNumber      string     `json:"serial_number"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	DNSNames          []string   `json:"dns_names"`
	IPAddresses       []string   `json:"ip_addresses"`
	IssuedAt          time.Time  `json:"issued_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	Status            PeerStatus `json:"status"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	RevocationReason  string     `json:"revocation_reason,omitempty"`
}

// EnrollPeerRequest encapsulates options for issuing an mTLS certificate to a peer.
type EnrollPeerRequest struct {
	NodeID       string   `json:"node_id"`
	Role         PeerRole `json:"role"`
	DNSNames     []string `json:"dns_names"`
	IPAddresses  []string `json:"ip_addresses"`
	ValidityDays int      `json:"validity_days"`
}

// EnrollPeerResponse contains generated mTLS credentials for the enrolled peer.
type EnrollPeerResponse struct {
	NodeID            string    `json:"node_id"`
	Role              PeerRole  `json:"role"`
	CertificatePEM    string    `json:"certificate_pem"`
	PrivateKeyPEM     string    `json:"private_key_pem"`
	RootCAPEM         string    `json:"root_ca_pem"`
	SerialNumber      string    `json:"serial_number"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// RevokePeerRequest encapsulates parameters for revoking an active peer certificate.
type RevokePeerRequest struct {
	NodeID string `json:"node_id"`
	Reason string `json:"reason"`
}

// HSMSlotInfo describes the hardware-backed key slot capabilities.
type HSMSlotInfo struct {
	SlotID          int    `json:"slot_id"`
	Label           string `json:"label"`
	Algorithm       string `json:"algorithm"`
	KeyPresent      bool   `json:"key_present"`
	PublicKeyPEM    string `json:"public_key_pem"`
	OperationsCount int64  `json:"operations_count"`
	Zeroized        bool   `json:"zeroized"`
}

// ZeroTrustStatus summarizes the overall mesh security posture.
type ZeroTrustStatus struct {
	CAInitialized      bool          `json:"ca_initialized"`
	CARootFingerprint  string        `json:"ca_root_fingerprint"`
	CAExpiresAt        time.Time     `json:"ca_expires_at"`
	ActivePeersCount   int           `json:"active_peers_count"`
	RevokedPeersCount  int           `json:"revoked_peers_count"`
	MTLSEnforced       bool          `json:"mtls_enforced"`
	HSMEnabled         bool          `json:"hsm_enabled"`
	HSMSlotsCount      int           `json:"hsm_slots_count"`
	Slots              []HSMSlotInfo `json:"slots"`
	Timestamp          string        `json:"timestamp"`
}
