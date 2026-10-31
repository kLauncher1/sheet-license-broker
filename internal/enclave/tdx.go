package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	ErrTDXQuoteTooShort      = errors.New("tdx quote length is below minimum specification")
	ErrTDXInvalidVersion     = errors.New("unsupported tdx quote version, expected version 4")
	ErrTDXInvalidTeeType     = errors.New("invalid tee type in quote header, expected intel tdx (0x00000081)")
	ErrTDXInvalidSignature   = errors.New("tdx quote ecdsa signature verification failed")
	ErrTDXReportDataMismatch = errors.New("tdx report data does not match expected challenge nonce/key binding")
	ErrTDXDebugNotAllowed    = errors.New("tdx trust domain has debug attribute set, disallowed by production policy")
	ErrTDXMeasurementMismatch = errors.New("tdx mrtd launch measurement is not authorized in policy whitelist")
	ErrTDXSVNTooLow          = errors.New("tdx tcb security version number is below policy minimum requirement")
)

const (
	TDXQuoteVersion4 uint16 = 4
	TDXTeeType       uint32 = 0x00000081

	TDXHeaderSize = 48
	TDXReportSize = 584
	TDXSignedSize = TDXHeaderSize + TDXReportSize // 632 bytes
	TDXMinSize    = TDXSignedSize + 128           // 632 + 64 sig + 64 pubkey = 760 bytes
)

// ParseTDXQuote parses a raw Intel TDX Quote (Version 4).
func ParseTDXQuote(raw []byte) (*TDXQuoteV4, error) {
	if len(raw) < TDXMinSize {
		return nil, fmt.Errorf("%w: got %d bytes, minimum required %d", ErrTDXQuoteTooShort, len(raw), TDXMinSize)
	}

	version := binary.LittleEndian.Uint16(raw[0:2])
	if version != TDXQuoteVersion4 {
		return nil, fmt.Errorf("%w: got %d", ErrTDXInvalidVersion, version)
	}

	teeType := binary.LittleEndian.Uint32(raw[4:8])
	if teeType != TDXTeeType {
		return nil, fmt.Errorf("%w: got 0x%08x", ErrTDXInvalidTeeType, teeType)
	}

	q := &TDXQuoteV4{
		Version:            version,
		AttestationKeyType: binary.LittleEndian.Uint16(raw[2:4]),
		TeeType:            teeType,
		QESVN:              binary.LittleEndian.Uint16(raw[8:10]),
		PCESVN:             binary.LittleEndian.Uint16(raw[10:12]),
	}
	copy(q.VendorID[:], raw[12:28])
	copy(q.UserData[:], raw[28:48])

	// Parse TDReport (offset 48 .. 632)
	rep := &q.Report
	rep.TeeType = binary.LittleEndian.Uint32(raw[48:52])
	copy(rep.TeeTcbSvn[:], raw[52:68])
	copy(rep.MRSeam[:], raw[68:116])
	copy(rep.MRSignerSeam[:], raw[116:164])
	copy(rep.SeamAttributes[:], raw[164:172])
	copy(rep.TDAttributes[:], raw[172:180])
	copy(rep.XFAM[:], raw[180:188])
	copy(rep.MRTD[:], raw[188:236])

	// 4 RTMRs (each 48 bytes)
	for i := 0; i < 4; i++ {
		start := 236 + (i * 48)
		copy(rep.RTMR[i][:], raw[start:start+48])
	}
	copy(rep.ReportData[:], raw[428:492])

	// Signature and Attestation Key
	sigOffset := TDXSignedSize
	if q.AttestationKeyType == 3 {
		// ECDSA P-384
		sigLen := 96
		pubLen := 96
		if len(raw) < sigOffset+sigLen+pubLen {
			return nil, ErrTDXQuoteTooShort
		}
		q.Signature = make([]byte, sigLen)
		copy(q.Signature, raw[sigOffset:sigOffset+sigLen])
		q.AttestationKey = make([]byte, pubLen)
		copy(q.AttestationKey, raw[sigOffset+sigLen:sigOffset+sigLen+pubLen])
	} else {
		// ECDSA P-256 (default)
		sigLen := 64
		pubLen := 64
		if len(raw) < sigOffset+sigLen+pubLen {
			return nil, ErrTDXQuoteTooShort
		}
		q.Signature = make([]byte, sigLen)
		copy(q.Signature, raw[sigOffset:sigOffset+sigLen])
		q.AttestationKey = make([]byte, pubLen)
		copy(q.AttestationKey, raw[sigOffset+sigLen:sigOffset+sigLen+pubLen])
	}

	return q, nil
}

// VerifyTDXQuote validates the cryptographic signature, report data, and policy constraints of a TDX Quote v4.
func VerifyTDXQuote(quote *TDXQuoteV4, rawQuote []byte, expectedReportData []byte, attestationKey *ecdsa.PublicKey, policy *EnclavePolicy) (*AttestationResult, error) {
	if quote == nil {
		return nil, errors.New("nil tdx quote provided")
	}
	if len(rawQuote) < TDXSignedSize {
		return nil, ErrTDXQuoteTooShort
	}

	// 1. Signature Verification over Header + TDReport
	signedHeader := rawQuote[:TDXSignedSize]
	pub := attestationKey

	if pub == nil && len(quote.AttestationKey) >= 64 {
		// Reconstruct public key from embedded attestation key in quote
		if quote.AttestationKeyType == 3 && len(quote.AttestationKey) >= 96 {
			pub = &ecdsa.PublicKey{
				Curve: elliptic.P384(),
				X:     new(big.Int).SetBytes(quote.AttestationKey[:48]),
				Y:     new(big.Int).SetBytes(quote.AttestationKey[48:96]),
			}
		} else {
			pub = &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(quote.AttestationKey[:32]),
				Y:     new(big.Int).SetBytes(quote.AttestationKey[32:64]),
			}
		}
	}

	if pub != nil && len(quote.Signature) >= 64 {
		var validSig bool
		if pub.Curve == elliptic.P384() && len(quote.Signature) >= 96 {
			rBytes := quote.Signature[:48]
			sBytes := quote.Signature[48:96]
			sigR := new(big.Int).SetBytes(rBytes)
			sigS := new(big.Int).SetBytes(sBytes)
			digest := sha512.Sum384(signedHeader)
			validSig = ecdsa.Verify(pub, digest[:], sigR, sigS)
		} else {
			rBytes := quote.Signature[:32]
			sBytes := quote.Signature[32:64]
			sigR := new(big.Int).SetBytes(rBytes)
			sigS := new(big.Int).SetBytes(sBytes)
			digest := sha256.Sum256(signedHeader)
			validSig = ecdsa.Verify(pub, digest[:], sigR, sigS)
		}

		if !validSig {
			return nil, ErrTDXInvalidSignature
		}
	}

	// 2. ReportData Validation (Constant-time check)
	if len(expectedReportData) > 0 {
		var paddedExpected [64]byte
		copy(paddedExpected[:], expectedReportData)
		if subtle.ConstantTimeCompare(quote.Report.ReportData[:], paddedExpected[:]) != 1 {
			return nil, ErrTDXReportDataMismatch
		}
	}

	// 3. Debug Attribute Policy Check (bit 0 = debug)
	isDebug := (quote.Report.TDAttributes[0] & 0x01) != 0
	if policy != nil && !policy.AllowDebug && isDebug {
		return nil, ErrTDXDebugNotAllowed
	}

	// 4. Minimum TCB / Guest SVN Check
	svn := uint32(quote.Report.TeeTcbSvn[0])
	if policy != nil && policy.MinGuestSVN > 0 && svn < policy.MinGuestSVN {
		return nil, fmt.Errorf("%w: tdx tcb svn %d < required %d", ErrTDXSVNTooLow, svn, policy.MinGuestSVN)
	}

	// 5. MRTD Launch Measurement Whitelist
	mrtdHex := hex.EncodeToString(quote.Report.MRTD[:])
	if policy != nil {
		allowed := append(policy.AllowedMeasurements, policy.AllowedMREnclaves...)
		if len(allowed) > 0 {
			matched := false
			for _, m := range allowed {
				if strings.EqualFold(strings.TrimSpace(m), mrtdHex) {
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("%w: mrtd %s not in whitelist", ErrTDXMeasurementMismatch, mrtdHex)
			}
		}
	}

	rtmr0Hex := hex.EncodeToString(quote.Report.RTMR[0][:])
	return &AttestationResult{
		Valid:         true,
		Platform:      PlatformTDX,
		Measurement:   mrtdHex,
		MRTD:          mrtdHex,
		RTMR0:         rtmr0Hex,
		SVN:           svn,
		Debug:         isDebug,
		ReportDataHex: hex.EncodeToString(quote.Report.ReportData[:]),
		VerifiedAt:    time.Now().UTC(),
	}, nil
}

// GenerateMockTDXQuote constructs an authentic-format Intel TDX Quote v4 for unit testing and local simulation.
func GenerateMockTDXQuote(mrtd [48]byte, rtmr [4][48]byte, reportData [64]byte, tcbSvn [16]byte, debug bool, privKey *ecdsa.PrivateKey) ([]byte, error) {
	totalSize := TDXMinSize
	if privKey != nil && privKey.Curve == elliptic.P384() {
		totalSize = TDXSignedSize + 96 + 96 // 824 bytes for P-384
	}
	raw := make([]byte, totalSize)

	// Header (48 bytes)
	binary.LittleEndian.PutUint16(raw[0:2], TDXQuoteVersion4)
	curveType := uint16(2) // ECDSA P-256
	if privKey != nil && privKey.Curve == elliptic.P384() {
		curveType = 3
	}
	binary.LittleEndian.PutUint16(raw[2:4], curveType)
	binary.LittleEndian.PutUint32(raw[4:8], TDXTeeType)
	binary.LittleEndian.PutUint16(raw[8:10], 1)  // QE_SVN
	binary.LittleEndian.PutUint16(raw[10:12], 1) // PCE_SVN

	// Intel Vendor ID
	intelVendor, _ := hex.DecodeString("939a7233f79c4ca9940a0dbd49f4e05f")
	copy(raw[12:28], intelVendor)

	// TDReport (offset 48 .. 632)
	binary.LittleEndian.PutUint32(raw[48:52], TDXTeeType)
	copy(raw[52:68], tcbSvn[:])

	// TDAttributes
	if debug {
		raw[172] = 0x01 // bit 0 debug
	} else {
		raw[172] = 0x00
	}

	// MRTD
	copy(raw[188:236], mrtd[:])

	// RTMR[0..3]
	for i := 0; i < 4; i++ {
		start := 236 + (i * 48)
		copy(raw[start:start+48], rtmr[i][:])
	}

	// ReportData
	copy(raw[428:492], reportData[:])

	// Generate ECDSA Signature & Attestation Key
	signedHeader := raw[:TDXSignedSize]
	var key *ecdsa.PrivateKey = privKey
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	sigOffset := TDXSignedSize
	if key.Curve == elliptic.P384() {
		digest := sha512.Sum384(signedHeader)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return nil, err
		}
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(raw[sigOffset+48-len(rBytes):sigOffset+48], rBytes)
		copy(raw[sigOffset+96-len(sBytes):sigOffset+96], sBytes)

		xBytes := key.PublicKey.X.Bytes()
		yBytes := key.PublicKey.Y.Bytes()
		copy(raw[sigOffset+96+48-len(xBytes):sigOffset+96+48], xBytes)
		copy(raw[sigOffset+96+96-len(yBytes):sigOffset+96+96], yBytes)
	} else {
		digest := sha256.Sum256(signedHeader)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return nil, err
		}
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(raw[sigOffset+32-len(rBytes):sigOffset+32], rBytes)
		copy(raw[sigOffset+64-len(sBytes):sigOffset+64], sBytes)

		xBytes := key.PublicKey.X.Bytes()
		yBytes := key.PublicKey.Y.Bytes()
		copy(raw[sigOffset+64+32-len(xBytes):sigOffset+64+32], xBytes)
		copy(raw[sigOffset+64+64-len(yBytes):sigOffset+64+64], yBytes)
	}

	return raw, nil
}
