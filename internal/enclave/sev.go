package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	ErrSEVReportTooShort      = errors.New("sev-snp report length is below 1184 bytes standard specification")
	ErrSEVInvalidSignature    = errors.New("sev-snp report ecdsa signature verification failed")
	ErrSEVReportDataMismatch  = errors.New("sev-snp report data does not match expected challenge nonce/key")
	ErrSEVDebugNotAllowed     = errors.New("sev-snp enclave has debug policy enabled, disallowed by security policy")
	ErrSEVMeasurementMismatch = errors.New("sev-snp launch measurement is not in authorized policy whitelist")
	ErrSEVGuestSVNTooLow      = errors.New("sev-snp guest svn is below policy minimum requirement")
)

const (
	SEVSNPReportSize = 1184
	SEVSNPSignedSize = 672
)

// ParseSEVSNPReport parses a binary AMD SEV-SNP attestation report.
func ParseSEVSNPReport(raw []byte) (*SEVSNPReport, error) {
	if len(raw) < SEVSNPReportSize {
		return nil, fmt.Errorf("%w: got %d bytes, expected %d", ErrSEVReportTooShort, len(raw), SEVSNPReportSize)
	}

	r := &SEVSNPReport{}
	r.Version = binary.LittleEndian.Uint32(raw[0:4])
	r.GuestSVN = binary.LittleEndian.Uint32(raw[4:8])
	r.Policy = binary.LittleEndian.Uint64(raw[8:16])
	copy(r.FamilyID[:], raw[16:32])
	copy(r.ImageID[:], raw[32:48])
	r.VMPL = binary.LittleEndian.Uint32(raw[48:52])
	r.SignatureAlgo = binary.LittleEndian.Uint32(raw[52:56])
	r.CurrentTCB = binary.LittleEndian.Uint64(raw[56:64])

	copy(r.ReportData[:], raw[80:144])
	copy(r.Measurement[:], raw[144:192])
	copy(r.HostData[:], raw[192:224])
	copy(r.IDKeyDigest[:], raw[224:272])
	copy(r.AuthorKeyDigest[:], raw[272:320])
	copy(r.ReportID[:], raw[320:352])
	copy(r.ReportIDMA[:], raw[352:384])
	r.ReportTCB = binary.LittleEndian.Uint64(raw[384:392])
	copy(r.ChipID[:], raw[416:480])

	r.Signature = make([]byte, 512)
	copy(r.Signature, raw[SEVSNPSignedSize:SEVSNPReportSize])

	return r, nil
}

// VerifySEVSNPReport validates the cryptographic signature, report data, and policy of an AMD SEV-SNP report.
func VerifySEVSNPReport(report *SEVSNPReport, rawReport []byte, expectedReportData []byte, vcekPubKey *ecdsa.PublicKey, policy *EnclavePolicy) (*AttestationResult, error) {
	if report == nil {
		return nil, errors.New("nil sev-snp report provided")
	}
	if len(rawReport) < SEVSNPReportSize {
		return nil, ErrSEVReportTooShort
	}

	// 1. Cryptographic ECDSA Signature Verification over bytes 0..672
	signedHeader := rawReport[:SEVSNPSignedSize]
	sigBlock := report.Signature

	// SEV-SNP Signature block layout: R (offset 0..72), S (offset 72..144) for ECDSA P-384, or P-256 for test
	if vcekPubKey != nil {
		var validSig bool
		if vcekPubKey.Curve == elliptic.P384() {
			rBytes := sigBlock[0:48]
			sBytes := sigBlock[72 : 72+48]
			sigR := new(big.Int).SetBytes(rBytes)
			sigS := new(big.Int).SetBytes(sBytes)
			digest := sha512.Sum384(signedHeader)
			validSig = ecdsa.Verify(vcekPubKey, digest[:], sigR, sigS)
		} else {
			// P-256 fallback for testing / custom roots
			rBytes := sigBlock[0:32]
			sBytes := sigBlock[72 : 72+32]
			sigR := new(big.Int).SetBytes(rBytes)
			sigS := new(big.Int).SetBytes(sBytes)
			digest := sha256.Sum256(signedHeader)
			validSig = ecdsa.Verify(vcekPubKey, digest[:], sigR, sigS)
		}

		if !validSig {
			return nil, ErrSEVInvalidSignature
		}
	}

	// 2. Validate ReportData (nonce or session public key digest)
	if len(expectedReportData) > 0 {
		exp64 := make([]byte, 64)
		if len(expectedReportData) <= 64 {
			copy(exp64, expectedReportData)
		} else {
			h := sha256.Sum256(expectedReportData)
			copy(exp64, h[:])
		}
		if !ConstantTimeCompare(report.ReportData[:], exp64) {
			return nil, ErrSEVReportDataMismatch
		}
	}

	// 3. Evaluate Security Policy
	measurementHex := hex.EncodeToString(report.Measurement[:])
	// Policy bit 17 = DEBUG allowed (1 = debug enabled)
	isDebug := (report.Policy & (1 << 17)) != 0

	if policy != nil {
		if isDebug && !policy.AllowDebug {
			return nil, ErrSEVDebugNotAllowed
		}

		if policy.MinGuestSVN > 0 && report.GuestSVN < policy.MinGuestSVN {
			return nil, fmt.Errorf("%w: guest svn %d < policy minimum %d",
				ErrSEVGuestSVNTooLow, report.GuestSVN, policy.MinGuestSVN)
		}

		if len(policy.AllowedMeasurements) > 0 {
			matched := false
			for _, allowed := range policy.AllowedMeasurements {
				if strings.EqualFold(allowed, measurementHex) {
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("%w: %s", ErrSEVMeasurementMismatch, measurementHex)
			}
		}

		if policy.RequiredHostData != "" {
			hostDataHex := hex.EncodeToString(report.HostData[:])
			if !strings.EqualFold(policy.RequiredHostData, hostDataHex) {
				return nil, errors.New("sev-snp host data does not match required policy")
			}
		}
	}

	return &AttestationResult{
		Valid:         true,
		Platform:      PlatformSEVSNP,
		Measurement:   measurementHex,
		SVN:           report.GuestSVN,
		Debug:         isDebug,
		ReportDataHex: hex.EncodeToString(report.ReportData[:]),
		VerifiedAt:    time.Now().UTC(),
	}, nil
}

// BuildMockSEVSNPReport constructs an authentic 1184-byte AMD SEV-SNP attestation report for testing.
func BuildMockSEVSNPReport(priv *ecdsa.PrivateKey, measurement [48]byte, guestSVN uint32, debug bool, reportData [64]byte) ([]byte, error) {
	if priv == nil {
		var err error
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	raw := make([]byte, SEVSNPReportSize)
	binary.LittleEndian.PutUint32(raw[0:4], 1) // Version 1
	binary.LittleEndian.PutUint32(raw[4:8], guestSVN)

	var policy uint64 = 0x10000 // Standard production policy (debug disabled)
	if debug {
		policy |= (1 << 17) // Bit 17 set: Debugging allowed
	}
	binary.LittleEndian.PutUint64(raw[8:16], policy)

	copy(raw[80:144], reportData[:])
	copy(raw[144:192], measurement[:])

	// Sign bytes 0..672
	var r, s *big.Int
	var err error
	if priv.Curve == elliptic.P384() {
		digest := sha512.Sum384(raw[:SEVSNPSignedSize])
		r, s, err = ecdsa.Sign(rand.Reader, priv, digest[:])
	} else {
		digest := sha256.Sum256(raw[:SEVSNPSignedSize])
		r, s, err = ecdsa.Sign(rand.Reader, priv, digest[:])
	}
	if err != nil {
		return nil, err
	}

	// Copy signature into offset 672..1184 (R at 672, S at 672+72)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(raw[SEVSNPSignedSize+32-len(rBytes):SEVSNPSignedSize+32], rBytes)
	copy(raw[SEVSNPSignedSize+72+32-len(sBytes):SEVSNPSignedSize+72+32], sBytes)

	return raw, nil
}
