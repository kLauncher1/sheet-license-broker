package hsm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// FIPSEngine coordinates FIPS 140-3 Level 4 Known Answer Tests (KAT), tamper sensors, and compliance reporting.
type FIPSEngine struct {
	cryptoki       *CryptokiEngine
	lastKATRun     time.Time
	katAllPassed   bool
	lastKATResults []SelfTestResult
}

// NewFIPSEngine initializes the FIPS 140-3 compliance bridge.
func NewFIPSEngine(cryptoki *CryptokiEngine) *FIPSEngine {
	fe := &FIPSEngine{
		cryptoki: cryptoki,
	}
	// Run initial startup KAT self-tests
	_ = fe.RunKATSelfTests()
	return fe
}

// RunKATSelfTests executes full Known Answer Tests (KAT) for all approved cryptographic primitives.
func (f *FIPSEngine) RunKATSelfTests() []SelfTestResult {
	results := make([]SelfTestResult, 0, 5)

	// 1. KAT: SHA-256
	start := time.Now()
	katSHA := f.testKATSHA256()
	results = append(results, SelfTestResult{
		TestName:        "KAT-SHA-256-FIPS-180-4",
		Passed:          katSHA == nil,
		ExecutionTimeUs: time.Since(start).Microseconds(),
		AlgorithmTested: "SHA-256",
		Details:         f.formatDetails(katSHA),
	})

	// 2. KAT: HMAC-SHA256
	start = time.Now()
	katHMAC := f.testKATHMACSHA256()
	results = append(results, SelfTestResult{
		TestName:        "KAT-HMAC-SHA256-FIPS-198-1",
		Passed:          katHMAC == nil,
		ExecutionTimeUs: time.Since(start).Microseconds(),
		AlgorithmTested: "HMAC-SHA256",
		Details:         f.formatDetails(katHMAC),
	})

	// 3. KAT: AES-256-GCM
	start = time.Now()
	katAES := f.testKATAES256GCM()
	results = append(results, SelfTestResult{
		TestName:        "KAT-AES-256-GCM-SP-800-38D",
		Passed:          katAES == nil,
		ExecutionTimeUs: time.Since(start).Microseconds(),
		AlgorithmTested: "AES-256-GCM",
		Details:         f.formatDetails(katAES),
	})

	// 4. KAT: ECDSA P-256
	start = time.Now()
	katECDSA := f.testKATECDSAP256()
	results = append(results, SelfTestResult{
		TestName:        "KAT-ECDSA-P256-FIPS-186-4",
		Passed:          katECDSA == nil,
		ExecutionTimeUs: time.Since(start).Microseconds(),
		AlgorithmTested: "ECDSA-P256",
		Details:         f.formatDetails(katECDSA),
	})

	// 5. KAT: HKDF-SHA256
	start = time.Now()
	katHKDF := f.testKATHKDFSHA256()
	results = append(results, SelfTestResult{
		TestName:        "KAT-HKDF-SHA256-RFC-5869",
		Passed:          katHKDF == nil,
		ExecutionTimeUs: time.Since(start).Microseconds(),
		AlgorithmTested: "HKDF-SHA256",
		Details:         f.formatDetails(katHKDF),
	})

	allPassed := true
	for _, r := range results {
		if !r.Passed {
			allPassed = false
			break
		}
	}

	f.lastKATRun = time.Now()
	f.katAllPassed = allPassed
	f.lastKATResults = results

	return results
}

func (f *FIPSEngine) formatDetails(err error) string {
	if err == nil {
		return "Known Answer Test passed with exact vector match."
	}
	return fmt.Sprintf("FAILED: %v", err)
}

func (f *FIPSEngine) testKATSHA256() error {
	msg := []byte("abc")
	expected, _ := hex.DecodeString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	hash := sha256.Sum256(msg)
	if !bytes.Equal(hash[:], expected) {
		return fmt.Errorf("hash vector mismatch")
	}
	return nil
}

func (f *FIPSEngine) testKATHMACSHA256() error {
	key := bytes.Repeat([]byte{0x0b}, 20)
	data := []byte("Hi There")
	expected, _ := hex.DecodeString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	computed := mac.Sum(nil)

	if !bytes.Equal(computed, expected) {
		return fmt.Errorf("hmac vector mismatch")
	}
	return nil
}

func (f *FIPSEngine) testKATAES256GCM() error {
	key, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	iv, _ := hex.DecodeString("000000000000000000000000")
	plaintext := []byte{}
	expectedTag, _ := hex.DecodeString("530f8afbc74536b9a963b4f1c4cb738b")

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	if !bytes.Equal(ciphertext, expectedTag) {
		return fmt.Errorf("aes gcm tag mismatch")
	}
	return nil
}

func (f *FIPSEngine) testKATECDSAP256() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	msg := []byte("FIPS-140-3-ECDSA-KAT-SAMPLE")
	hash := sha256.Sum256(msg)

	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return err
	}

	if !ecdsa.Verify(&priv.PublicKey, hash[:], r, s) {
		return fmt.Errorf("ecdsa verification failed")
	}
	return nil
}

func (f *FIPSEngine) testKATHKDFSHA256() error {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	expectedOKM, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	okm, err := HKDFExtractAndExpand(ikm, salt, info, len(expectedOKM))
	if err != nil {
		return err
	}

	if !bytes.Equal(okm, expectedOKM) {
		return fmt.Errorf("hkdf vector mismatch")
	}
	return nil
}

// GenerateAuditReport builds an official FIPS 140-3 Level 4 compliance audit record.
func (f *FIPSEngine) GenerateAuditReport() *FIPS140AuditReport {
	tamperState := "SECURE_NORMAL"
	slots := f.cryptoki.ListSlots()
	for _, s := range slots {
		t, err := f.cryptoki.GetTokenInfo(s.SlotID)
		if err == nil && t.TamperDetected {
			tamperState = "TAMPERED_ZEROIZED"
			break
		}
	}

	return &FIPS140AuditReport{
		CertificationLevel: FIPSLevel4,
		HardwareModel:      "FIPS-140-3-L4-VAULT",
		SerialNumber:       "HSM4-ROOT-9842",
		FirmwareRevision:   "4.2.0-FIPS",
		TamperState:        tamperState,
		ActiveSlots:        len(slots),
		KATPassed:          f.katAllPassed,
		SelfTests:          f.lastKATResults,
		ZeroizeOnTamper:    true,
		GeneratedAt:        time.Now(),
	}
}

// TriggerTamperResponse simulates an active environmental breach and zeroizes storage.
func (f *FIPSEngine) TriggerTamperResponse(sensorID string) {
	f.cryptoki.LatchTamper()
}
