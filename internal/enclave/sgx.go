package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	ErrSGXQuoteTooShort      = errors.New("sgx quote length is below minimum required bytes")
	ErrSGXUnsupportedVersion = errors.New("unsupported sgx quote version; only version 3 and 4 are supported")
	ErrSGXInvalidSignature   = errors.New("sgx quote ecdsa signature verification failed")
	ErrSGXReportDataMismatch = errors.New("sgx quote report data does not match expected challenge nonce/key")
	ErrSGXDebugNotAllowed    = errors.New("sgx enclave has debug mode enabled, disallowed by security policy")
	ErrSGXMREnclaveMismatch  = errors.New("sgx enclave mrenclave measurement is not in authorized policy whitelist")
	ErrSGXMRSignerMismatch   = errors.New("sgx enclave mrsigner identity is not in authorized policy whitelist")
	ErrSGXISVSVNTooLow       = errors.New("sgx enclave isv_svn security version number is below policy minimum")
)

// ParseSGXQuote parses a raw Intel SGX Quote v3/v4 byte slice into structured components.
func ParseSGXQuote(raw []byte) (*SGXQuoteV3, error) {
	// Header (48) + Enclave Report (384) + SigDataLen (4) = 436 minimum
	if len(raw) < 436 {
		return nil, ErrSGXQuoteTooShort
	}

	q := &SGXQuoteV3{}
	q.Version = binary.LittleEndian.Uint16(raw[0:2])
	if q.Version != 3 && q.Version != 4 {
		return nil, fmt.Errorf("%w: got %d", ErrSGXUnsupportedVersion, q.Version)
	}

	q.AttestationKeyType = binary.LittleEndian.Uint16(raw[2:4])
	q.TeeType = binary.LittleEndian.Uint32(raw[4:8])
	q.QESVN = binary.LittleEndian.Uint16(raw[8:10])
	q.PCESVN = binary.LittleEndian.Uint16(raw[10:12])
	copy(q.VendorID[:], raw[12:28])
	copy(q.UserData[:], raw[28:48])

	// Parse Enclave Report (offset 48 to 432)
	repBytes := raw[48:432]
	copy(q.EnclaveReport.CPUSVN[:], repBytes[0:16])
	q.EnclaveReport.MiscSelect = binary.LittleEndian.Uint32(repBytes[16:20])
	copy(q.EnclaveReport.Attributes[:], repBytes[48:64])
	copy(q.EnclaveReport.MREnclave[:], repBytes[64:96])
	copy(q.EnclaveReport.MRSigner[:], repBytes[128:160])
	q.EnclaveReport.ISVProdID = binary.LittleEndian.Uint16(repBytes[256:258])
	q.EnclaveReport.ISVSVN = binary.LittleEndian.Uint16(repBytes[258:260])
	copy(q.EnclaveReport.ReportData[:], repBytes[320:384])

	sigDataLen := binary.LittleEndian.Uint32(raw[432:436])
	if len(raw) < 436+int(sigDataLen) || sigDataLen < 128 {
		return nil, errors.New("malformed sgx signature block length")
	}

	sigBlock := raw[436 : 436+sigDataLen]
	q.Signature = make([]byte, 64)
	copy(q.Signature, sigBlock[0:64])

	q.AttestationKey = make([]byte, 64)
	copy(q.AttestationKey, sigBlock[64:128])

	return q, nil
}

// VerifySGXQuote verifies the cryptographic signature and security policy of an Intel SGX Quote.
func VerifySGXQuote(quote *SGXQuoteV3, rawHeaderAndReport []byte, expectedReportData []byte, policy *EnclavePolicy) (*AttestationResult, error) {
	if quote == nil {
		return nil, errors.New("nil quote provided")
	}

	// 1. Verify cryptographic ECDSA P-256 signature over Header + EnclaveReport (432 bytes)
	if len(rawHeaderAndReport) < 432 {
		return nil, errors.New("raw header and report buffer must be at least 432 bytes")
	}
	signedPayload := rawHeaderAndReport[:432]

	if len(quote.AttestationKey) != 64 || len(quote.Signature) != 64 {
		return nil, ErrSGXInvalidSignature
	}

	pubX := new(big.Int).SetBytes(quote.AttestationKey[0:32])
	pubY := new(big.Int).SetBytes(quote.AttestationKey[32:64])
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     pubX,
		Y:     pubY,
	}

	sigR := new(big.Int).SetBytes(quote.Signature[0:32])
	sigS := new(big.Int).SetBytes(quote.Signature[32:64])

	digest := sha256.Sum256(signedPayload)
	if !ecdsa.Verify(pubKey, digest[:], sigR, sigS) {
		return nil, ErrSGXInvalidSignature
	}

	// 2. Validate ReportData against expected payload / challenge nonce
	if len(expectedReportData) > 0 {
		exp64 := make([]byte, 64)
		if len(expectedReportData) <= 64 {
			copy(exp64, expectedReportData)
		} else {
			h := sha256.Sum256(expectedReportData)
			copy(exp64, h[:])
		}
		if !ConstantTimeCompare(quote.EnclaveReport.ReportData[:], exp64) {
			return nil, ErrSGXReportDataMismatch
		}
	}

	// 3. Security Policy evaluation
	mrEnclaveHex := hex.EncodeToString(quote.EnclaveReport.MREnclave[:])
	mrSignerHex := hex.EncodeToString(quote.EnclaveReport.MRSigner[:])
	isDebug := (quote.EnclaveReport.Attributes[0] & 0x02) != 0

	if policy != nil {
		// Strict production debug check
		if isDebug && !policy.AllowDebug {
			return nil, ErrSGXDebugNotAllowed
		}

		// Minimum Security Version Number (ISVSVN)
		if policy.MinISVSVN > 0 && quote.EnclaveReport.ISVSVN < policy.MinISVSVN {
			return nil, fmt.Errorf("%w: enclave isv_svn %d < policy minimum %d",
				ErrSGXISVSVNTooLow, quote.EnclaveReport.ISVSVN, policy.MinISVSVN)
		}

		// Whitelist checks for MREnclave
		if len(policy.AllowedMREnclaves) > 0 {
			matched := false
			for _, allowed := range policy.AllowedMREnclaves {
				if strings.EqualFold(allowed, mrEnclaveHex) {
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("%w: %s", ErrSGXMREnclaveMismatch, mrEnclaveHex)
			}
		}

		// Whitelist checks for MRSigner
		if len(policy.AllowedMRSigners) > 0 {
			matched := false
			for _, allowed := range policy.AllowedMRSigners {
				if strings.EqualFold(allowed, mrSignerHex) {
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("%w: %s", ErrSGXMRSignerMismatch, mrSignerHex)
			}
		}
	}

	return &AttestationResult{
		Valid:         true,
		Platform:      PlatformSGX,
		MREnclave:     mrEnclaveHex,
		MRSigner:      mrSignerHex,
		SVN:           uint32(quote.EnclaveReport.ISVSVN),
		Debug:         isDebug,
		ReportDataHex: hex.EncodeToString(quote.EnclaveReport.ReportData[:]),
		VerifiedAt:    time.Now().UTC(),
	}, nil
}

// BuildMockSGXQuote creates a cryptographically signed SGX Quote v3 byte array for testing and client SDK simulations.
func BuildMockSGXQuote(priv *ecdsa.PrivateKey, mrEnclave [32]byte, mrSigner [32]byte, isvSVN uint16, debug bool, reportData [64]byte) ([]byte, error) {
	if priv == nil {
		var err error
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	raw := make([]byte, 48+384+4+128)
	// Header (48 bytes)
	binary.LittleEndian.PutUint16(raw[0:2], 3) // Version 3
	binary.LittleEndian.PutUint16(raw[2:4], 2) // ECDSA-256
	binary.LittleEndian.PutUint32(raw[4:8], 0) // SGX
	binary.LittleEndian.PutUint16(raw[8:10], 1)
	binary.LittleEndian.PutUint16(raw[10:12], 1)

	// Enclave Report (offset 48 to 432)
	rep := raw[48:432]
	if debug {
		rep[48] = 0x02 // bit 1 set = DEBUG mode
	} else {
		rep[48] = 0x01 // bit 0 set = initialized, non-debug
	}
	copy(rep[64:96], mrEnclave[:])
	copy(rep[128:160], mrSigner[:])
	binary.LittleEndian.PutUint16(rep[256:258], 1)
	binary.LittleEndian.PutUint16(rep[258:260], isvSVN)
	copy(rep[320:384], reportData[:])

	// Sign Header + Enclave Report
	digest := sha256.Sum256(raw[:432])
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}

	// SigDataLen
	binary.LittleEndian.PutUint32(raw[432:436], 128)

	// Signature block: Sig (64 bytes) + AttestationKey (64 bytes)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(raw[436+32-len(rBytes):436+32], rBytes)
	copy(raw[436+64-len(sBytes):436+64], sBytes)

	pubX := priv.PublicKey.X.Bytes()
	pubY := priv.PublicKey.Y.Bytes()
	copy(raw[500+32-len(pubX):500+32], pubX)
	copy(raw[500+64-len(pubY):500+64], pubY)

	return raw, nil
}
