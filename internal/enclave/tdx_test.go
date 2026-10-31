package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestTDXQuoteParsingAndVerification(t *testing.T) {
	// 1. Setup mock TDX quote parameters
	var mrtd [48]byte
	var rtmr [4][48]byte
	var reportData [64]byte
	var svn [16]byte

	copy(mrtd[:], []byte("intel_tdx_mrtd_launch_digest_mock_384_bytes_0000"))
	copy(rtmr[0][:], []byte("intel_tdx_rtmr_0_kernel_measurement_mock_bytes00"))
	copy(reportData[:], []byte("challenge_nonce_32_bytes_plus_padding_000000000000000000000000000"))
	svn[0] = 3 // Guest / TCB SVN = 3

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA test key: %v", err)
	}

	rawQuote, err := GenerateMockTDXQuote(mrtd, rtmr, reportData, svn, false, privKey)
	if err != nil {
		t.Fatalf("Failed to generate mock TDX quote: %v", err)
	}

	// 2. Parse quote
	parsed, err := ParseTDXQuote(rawQuote)
	if err != nil {
		t.Fatalf("ParseTDXQuote failed: %v", err)
	}

	if parsed.Version != TDXQuoteVersion4 {
		t.Errorf("expected version %d, got %d", TDXQuoteVersion4, parsed.Version)
	}
	if parsed.TeeType != TDXTeeType {
		t.Errorf("expected tee type 0x%08x, got 0x%08x", TDXTeeType, parsed.TeeType)
	}
	if parsed.Report.TeeTcbSvn[0] != 3 {
		t.Errorf("expected SVN 3, got %d", parsed.Report.TeeTcbSvn[0])
	}

	// 3. Verify quote with valid policy
	policy := &EnclavePolicy{
		ID:                  "test-tdx-policy",
		Platform:            PlatformTDX,
		AllowedMeasurements: []string{hex.EncodeToString(mrtd[:])},
		MinGuestSVN:         2,
		AllowDebug:          false,
	}

	res, err := VerifyTDXQuote(parsed, rawQuote, reportData[:], &privKey.PublicKey, policy)
	if err != nil {
		t.Fatalf("VerifyTDXQuote failed on valid quote: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected verification result Valid=true, got false")
	}
	if res.Platform != PlatformTDX {
		t.Errorf("expected PlatformTDX, got %s", res.Platform)
	}
	if res.SVN != 3 {
		t.Errorf("expected SVN 3, got %d", res.SVN)
	}
	if res.MRTD != hex.EncodeToString(mrtd[:]) {
		t.Errorf("expected MRTD %s, got %s", hex.EncodeToString(mrtd[:]), res.MRTD)
	}
}

func TestTDXQuoteDebugRejection(t *testing.T) {
	var mrtd [48]byte
	var rtmr [4][48]byte
	var reportData [64]byte
	var svn [16]byte
	svn[0] = 5

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// debug = true
	rawQuote, err := GenerateMockTDXQuote(mrtd, rtmr, reportData, svn, true, privKey)
	if err != nil {
		t.Fatalf("failed to generate debug quote: %v", err)
	}

	parsed, err := ParseTDXQuote(rawQuote)
	if err != nil {
		t.Fatalf("ParseTDXQuote failed: %v", err)
	}

	policyStrict := &EnclavePolicy{
		ID:          "strict-no-debug",
		Platform:    PlatformTDX,
		AllowDebug:  false, // production: disallow debug
		MinGuestSVN: 1,
	}

	_, err = VerifyTDXQuote(parsed, rawQuote, reportData[:], &privKey.PublicKey, policyStrict)
	if err == nil || err != ErrTDXDebugNotAllowed {
		t.Errorf("expected ErrTDXDebugNotAllowed on debug quote, got %v", err)
	}

	// Allowed when policy permits debug
	policyDebug := &EnclavePolicy{
		ID:          "permissive-debug",
		Platform:    PlatformTDX,
		AllowDebug:  true,
		MinGuestSVN: 1,
	}
	res, err := VerifyTDXQuote(parsed, rawQuote, reportData[:], &privKey.PublicKey, policyDebug)
	if err != nil || !res.Valid {
		t.Errorf("expected success when debug allowed by policy, got err: %v", err)
	}
}

func TestTDXQuoteReportDataMismatch(t *testing.T) {
	var mrtd [48]byte
	var rtmr [4][48]byte
	var reportData [64]byte
	var svn [16]byte
	svn[0] = 2
	copy(reportData[:], []byte("correct_report_data"))

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rawQuote, _ := GenerateMockTDXQuote(mrtd, rtmr, reportData, svn, false, privKey)
	parsed, _ := ParseTDXQuote(rawQuote)

	wrongData := []byte("tampered_nonce_report_data")
	_, err := VerifyTDXQuote(parsed, rawQuote, wrongData, &privKey.PublicKey, nil)
	if err == nil || err != ErrTDXReportDataMismatch {
		t.Errorf("expected ErrTDXReportDataMismatch, got %v", err)
	}
}

func TestTDXQuoteMeasurementWhitelistAndSVN(t *testing.T) {
	var mrtd [48]byte
	var rtmr [4][48]byte
	var reportData [64]byte
	var svn [16]byte
	copy(mrtd[:], []byte("actual_mrtd_measurement_bytes_000000000000000000"))
	svn[0] = 2 // SVN = 2

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rawQuote, _ := GenerateMockTDXQuote(mrtd, rtmr, reportData, svn, false, privKey)
	parsed, _ := ParseTDXQuote(rawQuote)

	// 1. Measurement not in whitelist
	policyWrongMeasurement := &EnclavePolicy{
		ID:                  "wrong-measurement",
		Platform:            PlatformTDX,
		AllowedMeasurements: []string{"deadbeefcafe1234"},
	}
	_, err := VerifyTDXQuote(parsed, rawQuote, reportData[:], &privKey.PublicKey, policyWrongMeasurement)
	if err == nil {
		t.Errorf("expected error for measurement mismatch, got nil")
	}

	// 2. SVN too low
	policyHighSVN := &EnclavePolicy{
		ID:          "high-svn",
		Platform:    PlatformTDX,
		MinGuestSVN: 10,
	}
	_, err = VerifyTDXQuote(parsed, rawQuote, reportData[:], &privKey.PublicKey, policyHighSVN)
	if err == nil {
		t.Errorf("expected error for SVN too low, got nil")
	}
}

func TestTDXQuoteMalformedData(t *testing.T) {
	shortData := make([]byte, 100)
	_, err := ParseTDXQuote(shortData)
	if err == nil {
		t.Errorf("expected error on short quote, got nil")
	}

	invalidVer := make([]byte, TDXMinSize)
	invalidVer[0] = 99 // version 99
	invalidVer[4] = 0x81
	_, err = ParseTDXQuote(invalidVer)
	if err == nil {
		t.Errorf("expected error on invalid version, got nil")
	}
}

func TestTDXQuoteECDSA_P384(t *testing.T) {
	var mrtd [48]byte
	var rtmr [4][48]byte
	var reportData [64]byte
	var svn [16]byte
	svn[0] = 4

	privKeyP384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-384 key: %v", err)
	}

	rawQuote, err := GenerateMockTDXQuote(mrtd, rtmr, reportData, svn, false, privKeyP384)
	if err != nil {
		t.Fatalf("failed to generate mock P-384 TDX quote: %v", err)
	}

	parsed, err := ParseTDXQuote(rawQuote)
	if err != nil {
		t.Fatalf("ParseTDXQuote failed for P-384 quote: %v", err)
	}

	if parsed.AttestationKeyType != 3 {
		t.Errorf("expected AttestationKeyType 3 for P-384, got %d", parsed.AttestationKeyType)
	}

	res, err := VerifyTDXQuote(parsed, rawQuote, reportData[:], &privKeyP384.PublicKey, nil)
	if err != nil {
		t.Fatalf("VerifyTDXQuote failed for P-384 quote: %v", err)
	}
	if !res.Valid {
		t.Errorf("expected valid verification for P-384 quote")
	}
}
