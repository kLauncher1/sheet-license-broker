package zerotrust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sync"
	"time"
)

// CertificateAuthority manages the internal PKI lifecycle, root trust, and certificate rotation.
type CertificateAuthority struct {
	mu             sync.RWMutex
	rootCert       *x509.Certificate
	rootKey        crypto.Signer
	rootPEM        []byte
	rootPool       *x509.CertPool
	previousRoots  []*x509.Certificate
	revokedSerials map[string]string // serialHex -> reason
}

// CAConfig defines initialization parameters for the Certificate Authority.
type CAConfig struct {
	CommonName   string
	Organization string
	ValidityDays int
	Signer       crypto.Signer // Optional hardware HSM signer
}

// NewCertificateAuthority creates and initializes a new self-signed internal Root CA.
func NewCertificateAuthority(cfg CAConfig) (*CertificateAuthority, error) {
	if cfg.CommonName == "" {
		cfg.CommonName = "sheet-license-broker-mesh-ca"
	}
	if cfg.Organization == "" {
		cfg.Organization = "sheet-license-broker"
	}
	if cfg.ValidityDays <= 0 {
		cfg.ValidityDays = 365
	}

	var rootKey crypto.Signer
	var pubKey crypto.PublicKey
	if cfg.Signer != nil {
		rootKey = cfg.Signer
		pubKey = cfg.Signer.Public()
	} else {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA private key: %w", err)
		}
		rootKey = priv
		pubKey = priv.Public()
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: []string{cfg.Organization},
		},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.AddDate(0, 0, cfg.ValidityDays),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create self-signed CA certificate: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA cert: %w", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	pool := x509.NewCertPool()
	pool.AddCert(parsedCert)

	return &CertificateAuthority{
		rootCert:       parsedCert,
		rootKey:        rootKey,
		rootPEM:        pemBlock,
		rootPool:       pool,
		revokedSerials: make(map[string]string),
	}, nil
}

// IssuePeerCertificate generates and signs a new mutual TLS certificate for a mesh peer node.
func (ca *CertificateAuthority) IssuePeerCertificate(req EnrollPeerRequest) (*EnrollPeerResponse, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ca.rootCert == nil {
		return nil, ErrCANotInitialized
	}

	if req.ValidityDays <= 0 {
		req.ValidityDays = 90
	}

	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate peer private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate peer certificate serial: %w", err)
	}

	spiffeURI, _ := url.Parse(fmt.Sprintf("spiffe://sheet-license-broker/mesh/%s", req.NodeID))

	parsedIPs := make([]net.IP, 0, len(req.IPAddresses))
	for _, ipStr := range req.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			parsedIPs = append(parsedIPs, ip)
		}
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:         req.NodeID,
			Organization:       []string{"sheet-license-broker"},
			OrganizationalUnit: []string{string(req.Role)},
		},
		NotBefore:   now.Add(-10 * time.Minute),
		NotAfter:    now.AddDate(0, 0, req.ValidityDays),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    req.DNSNames,
		IPAddresses: parsedIPs,
	}

	if spiffeURI != nil {
		template.URIs = []*url.URL{spiffeURI}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca.rootCert, peerKey.Public(), ca.rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign peer certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	privKeyBytes, err := x509.MarshalECPrivateKey(peerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal peer private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	fingerprint := sha256.Sum256(derBytes)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	return &EnrollPeerResponse{
		NodeID:            req.NodeID,
		Role:              req.Role,
		CertificatePEM:    string(certPEM),
		PrivateKeyPEM:     string(keyPEM),
		RootCAPEM:         string(ca.rootPEM),
		SerialNumber:      serialNum.Text(16),
		FingerprintSHA256: fingerprintHex,
		ExpiresAt:         template.NotAfter,
	}, nil
}

// RevokeSerial marks a certificate serial number as permanently revoked.
func (ca *CertificateAuthority) RevokeSerial(serialHex, reason string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.revokedSerials[serialHex] = reason
}

// IsSerialRevoked returns true if the serial number has been placed on the CRL.
func (ca *CertificateAuthority) IsSerialRevoked(serialHex string) bool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	_, exists := ca.revokedSerials[serialHex]
	return exists
}

// RotateCA provisions a fresh Root CA while retaining previous roots in the trust pool for seamless transition.
func (ca *CertificateAuthority) RotateCA(validityDays int) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if validityDays <= 0 {
		validityDays = 365
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate rotated CA private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("failed to generate rotated CA serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject: pkix.Name{
			CommonName:   ca.rootCert.Subject.CommonName,
			Organization: ca.rootCert.Subject.Organization,
		},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.AddDate(0, 0, validityDays),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return fmt.Errorf("failed to create rotated CA certificate: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("failed to parse rotated CA cert: %w", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	ca.previousRoots = append(ca.previousRoots, ca.rootCert)
	ca.rootCert = parsedCert
	ca.rootKey = priv
	ca.rootPEM = pemBlock

	// Build dual-trust CertPool
	newPool := x509.NewCertPool()
	newPool.AddCert(parsedCert)
	for _, oldRoot := range ca.previousRoots {
		newPool.AddCert(oldRoot)
	}
	ca.rootPool = newPool

	return nil
}

// RootCertificate returns the active X.509 Root CA certificate.
func (ca *CertificateAuthority) RootCertificate() *x509.Certificate {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.rootCert
}

// RootCAPEM returns the PEM-encoded Root CA certificate.
func (ca *CertificateAuthority) RootCAPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.rootPEM
}

// CertPool returns the active trust pool including current and valid rotated root certificates.
func (ca *CertificateAuthority) CertPool() *x509.CertPool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.rootPool
}

// RootFingerprint returns the SHA-256 fingerprint of the current Root CA certificate.
func (ca *CertificateAuthority) RootFingerprint() string {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.rootCert == nil {
		return ""
	}
	fp := sha256.Sum256(ca.rootCert.Raw)
	return hex.EncodeToString(fp[:])
}

// RevocationCount returns the total number of revoked certificates.
func (ca *CertificateAuthority) RevocationCount() int {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return len(ca.revokedSerials)
}
