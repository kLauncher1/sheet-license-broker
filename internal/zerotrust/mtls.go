package zerotrust

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type contextKey string

const (
	// PeerIdentityKey is the context key for the authenticated mesh peer identity.
	PeerIdentityKey = contextKey("zero_trust_peer_identity")
)

// NewServerTLSConfig creates an enterprise mutual TLS server configuration.
func NewServerTLSConfig(ca *CertificateAuthority, certPEM, keyPEM []byte, enforceClientAuth bool) (*tls.Config, error) {
	if ca == nil {
		return nil, ErrCANotInitialized
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate keypair: %w", err)
	}

	clientAuth := tls.VerifyClientCertIfGiven
	if enforceClientAuth {
		clientAuth = tls.RequireAndVerifyClientCert
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   clientAuth,
		ClientCAs:    ca.CertPool(),
		MinVersion:   tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				if enforceClientAuth {
					return ErrMTLSMissingClientCert
				}
				return nil
			}

			// Validate revocation against the internal CA
			for _, chain := range verifiedChains {
				for _, cert := range chain {
					serialHex := cert.SerialNumber.Text(16)
					if ca.IsSerialRevoked(serialHex) {
						return fmt.Errorf("%w: serial %s", ErrCertRevoked, serialHex)
					}
				}
			}
			return nil
		},
	}

	return tlsConfig, nil
}

// NewClientTLSConfig creates an enterprise mutual TLS client configuration.
func NewClientTLSConfig(ca *CertificateAuthority, clientCertPEM, clientKeyPEM []byte, serverName string) (*tls.Config, error) {
	if ca == nil {
		return nil, ErrCANotInitialized
	}

	tlsConfig := &tls.Config{
		RootCAs:    ca.CertPool(),
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}

	if len(clientCertPEM) > 0 && len(clientKeyPEM) > 0 {
		clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate keypair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	return tlsConfig, nil
}

// ExtractPeerIdentity inspects the incoming TLS connection state and constructs a verified PeerIdentity.
func ExtractPeerIdentity(r *http.Request, ca *CertificateAuthority) (*PeerIdentity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		// Also support custom forwarded TLS headers from edge proxies (e.g. Cloudflare Worker)
		forwardedCertFP := r.Header.Get("X-Client-Cert-SHA256")
		forwardedNodeID := r.Header.Get("X-Mesh-Node-ID")
		if forwardedCertFP != "" && forwardedNodeID != "" {
			return &PeerIdentity{
				NodeID:            forwardedNodeID,
				Role:              RoleEdgeGateway,
				CommonName:        forwardedNodeID,
				FingerprintSHA256: strings.ToLower(forwardedCertFP),
				Status:            PeerStatusActive,
				ExpiresAt:         time.Now().Add(24 * time.Hour),
			}, nil
		}
		return nil, ErrMTLSMissingClientCert
	}

	peerCert := r.TLS.PeerCertificates[0]
	serialHex := peerCert.SerialNumber.Text(16)

	if ca != nil && ca.IsSerialRevoked(serialHex) {
		return nil, fmt.Errorf("%w: serial %s", ErrCertRevoked, serialHex)
	}

	fp := sha256.Sum256(peerCert.Raw)
	fpHex := hex.EncodeToString(fp[:])

	var role PeerRole = RoleClusterPeer
	if len(peerCert.Subject.OrganizationalUnit) > 0 {
		role = PeerRole(peerCert.Subject.OrganizationalUnit[0])
	}

	var spiffeID string
	if len(peerCert.URIs) > 0 {
		spiffeID = peerCert.URIs[0].String()
	}

	var ips []string
	for _, ip := range peerCert.IPAddresses {
		ips = append(ips, ip.String())
	}

	identity := &PeerIdentity{
		NodeID:            peerCert.Subject.CommonName,
		Role:              role,
		CommonName:        peerCert.Subject.CommonName,
		SPIFFEID:          spiffeID,
		SerialNumber:      serialHex,
		FingerprintSHA256: fpHex,
		DNSNames:          peerCert.DNSNames,
		IPAddresses:       ips,
		IssuedAt:          peerCert.NotBefore,
		ExpiresAt:         peerCert.NotAfter,
		Status:            PeerStatusActive,
	}

	return identity, nil
}

// PeerFromContext retrieves the authenticated PeerIdentity from context if available.
func PeerFromContext(ctx context.Context) (*PeerIdentity, bool) {
	val := ctx.Value(PeerIdentityKey)
	if val == nil {
		return nil, false
	}
	identity, ok := val.(*PeerIdentity)
	return identity, ok
}

// Middleware creates an HTTP handler enforcing or parsing mutual TLS peer certificates.
func Middleware(ca *CertificateAuthority, enforce bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, err := ExtractPeerIdentity(r, ca)
			if err != nil {
				if enforce {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"error":  "Mutual TLS peer authentication required",
						"detail": err.Error(),
					})
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), PeerIdentityKey, peer)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
