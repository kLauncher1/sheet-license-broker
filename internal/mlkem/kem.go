package mlkem

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// GenerateKeyPair generates a new NIST FIPS 203 ML-KEM keypair for the given algorithm.
func GenerateKeyPair(algo string) (*PublicKey, *PrivateKey, error) {
	params := GetParams(algo)

	var rho [32]byte
	if _, err := rand.Read(rho[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to sample random seed rho: %w", err)
	}

	var z [32]byte
	if _, err := rand.Read(z[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to sample rejection seed z: %w", err)
	}

	seedS := make([]byte, 32)
	if _, err := rand.Read(seedS); err != nil {
		return nil, nil, fmt.Errorf("failed to sample noise seed: %w", err)
	}

	// Sample matrix A in R_q^(k x k)
	A := SampleMatrixA(rho, params.K)

	// Sample secret s and error e vectors
	s := make(PolyVec, params.K)
	e := make(PolyVec, params.K)
	for i := 0; i < params.K; i++ {
		s[i] = SampleCBD(seedS, byte(i), params.Eta1)
		e[i] = SampleCBD(seedS, byte(i+params.K), params.Eta1)
	}

	// Compute public vector t = A * s + e
	As := MatrixVecMul(A, s)
	t := PolyVecAdd(As, e)

	tBytes := CompressVec(t, 12)
	rawBytes := append(rho[:], tBytes...)
	rawHex := hex.EncodeToString(rawBytes)

	fpHash := sha256.Sum256(rawBytes)
	fp := hex.EncodeToString(fpHash[:16])
	keyID := fmt.Sprintf("mlkem-%s-%s", strings.ToLower(params.Name), fp[:8])

	hEk := sha256.Sum256(rawBytes)

	pk := &PublicKey{
		KeyID:       keyID,
		Algorithm:   params.Name,
		Fingerprint: fp,
		T:           t,
		Rho:         rho,
		H_ek:        hEk,
		RawHex:      rawHex,
		CreatedAt:   time.Now().UTC(),
	}

	sk := &PrivateKey{
		KeyID:     keyID,
		Algorithm: params.Name,
		S:         s,
		PublicKey: pk,
		H_ek:      hEk,
		Z:         z,
		CreatedAt: pk.CreatedAt,
	}

	return pk, sk, nil
}

// Encapsulate encapsulates a 32-byte shared secret against the public encapsulation key.
func Encapsulate(pk *PublicKey) (*EncapsulationResult, error) {
	if pk == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	params := GetParams(pk.Algorithm)

	var m [32]byte
	if _, err := rand.Read(m[:]); err != nil {
		return nil, fmt.Errorf("failed to generate encapsulation message: %w", err)
	}

	// Derive (K, r) from message and H(ek)
	h512 := sha512.New()
	h512.Write(m[:])
	h512.Write(pk.H_ek[:])
	kr := h512.Sum(nil)
	kSeed := kr[:32]
	rSeed := kr[32:64]

	// Sample matrix A from pk.Rho
	A := SampleMatrixA(pk.Rho, params.K)

	// Sample r, e1, e2 from rSeed
	rVec := make(PolyVec, params.K)
	e1 := make(PolyVec, params.K)
	for i := 0; i < params.K; i++ {
		rVec[i] = SampleCBD(rSeed, byte(i), params.Eta1)
		e1[i] = SampleCBD(rSeed, byte(i+params.K), params.Eta2)
	}
	e2 := SampleCBD(rSeed, byte(2*params.K), params.Eta2)

	// u = A^T * r + e1
	u := TransposeMatrixVecMul(A, rVec)
	u = PolyVecAdd(u, e1)

	// v = t^T * r + e2 + Decompress(m)
	tr := InnerProduct(pk.T, rVec)
	v := PolyAdd(tr, e2)
	msgPoly := EncodeMessage(m)
	v = PolyAdd(v, msgPoly)

	// Compress ciphertext: c = (Compress(u, du), Compress(v, dv))
	uBytes := CompressVec(u, params.Du)
	vBytes := CompressPoly(v, params.Dv)
	ciphertext := append(uBytes, vBytes...)

	cHash := sha256.Sum256(ciphertext)

	// Shared secret = H(K || H(c))
	ssHash := sha256.New()
	ssHash.Write(kSeed)
	ssHash.Write(cHash[:])
	sharedSecret := ssHash.Sum(nil)

	return &EncapsulationResult{
		KeyID:           pk.KeyID,
		Algorithm:       pk.Algorithm,
		CiphertextHex:   hex.EncodeToString(ciphertext),
		SharedSecretHex: hex.EncodeToString(sharedSecret),
		EncapsulatedAt:  time.Now().UTC(),
	}, nil
}

// Decapsulate decapsulates a ciphertext using the private key with Fujisaki-Okamoto implicit rejection.
func Decapsulate(sk *PrivateKey, ciphertext []byte) ([]byte, error) {
	if sk == nil || sk.PublicKey == nil {
		return nil, fmt.Errorf("private key or public key cannot be nil")
	}
	params := GetParams(sk.Algorithm)

	uLen := params.K * ((DegreeN*params.Du + 7) / 8)
	vLen := (DegreeN*params.Dv + 7) / 8

	if len(ciphertext) != uLen+vLen {
		// Length mismatch: perform implicit rejection using pseudorandom seed Z
		cHash := sha256.Sum256(ciphertext)
		rejHash := sha256.New()
		rejHash.Write(sk.Z[:])
		rejHash.Write(cHash[:])
		return rejHash.Sum(nil), nil
	}

	uBytes := ciphertext[:uLen]
	vBytes := ciphertext[uLen:]

	u := DecompressVec(uBytes, params.K, params.Du)
	v := DecompressPoly(vBytes, params.Dv)

	// Decrypt message m' = v - s^T * u
	su := InnerProduct(sk.S, u)
	diff := PolySub(v, su)
	mPrime := DecodeMessage(diff)

	// Recompute (K', r')
	h512 := sha512.New()
	h512.Write(mPrime[:])
	h512.Write(sk.H_ek[:])
	krPrime := h512.Sum(nil)
	kPrime := krPrime[:32]
	rPrime := krPrime[32:64]

	// Re-encrypt C'
	A := SampleMatrixA(sk.PublicKey.Rho, params.K)
	rVec := make(PolyVec, params.K)
	e1 := make(PolyVec, params.K)
	for i := 0; i < params.K; i++ {
		rVec[i] = SampleCBD(rPrime, byte(i), params.Eta1)
		e1[i] = SampleCBD(rPrime, byte(i+params.K), params.Eta2)
	}
	e2 := SampleCBD(rPrime, byte(2*params.K), params.Eta2)

	uPrime := TransposeMatrixVecMul(A, rVec)
	uPrime = PolyVecAdd(uPrime, e1)

	trPrime := InnerProduct(sk.PublicKey.T, rVec)
	vPrime := PolyAdd(trPrime, e2)
	msgPoly := EncodeMessage(mPrime)
	vPrime = PolyAdd(vPrime, msgPoly)

	cPrime := append(CompressVec(uPrime, params.Du), CompressPoly(vPrime, params.Dv)...)

	cHash := sha256.Sum256(ciphertext)

	// Constant-time ciphertext check (Fujisaki-Okamoto transform)
	valid := subtle.ConstantTimeCompare(ciphertext, cPrime)

	// Select key material in constant time: valid ? kPrime : sk.Z
	selectedSeed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b := byte(valid)*kPrime[i] | byte(1-valid)*sk.Z[i]
		selectedSeed[i] = b
	}

	ssHash := sha256.New()
	ssHash.Write(selectedSeed)
	ssHash.Write(cHash[:])
	return ssHash.Sum(nil), nil
}
