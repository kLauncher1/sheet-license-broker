package pqc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// GenerateMLDSAKeyPair generates a fresh ML-DSA lattice key pair for the given algorithm.
func GenerateMLDSAKeyPair(algo string) (*MLDSAPrivateKey, *MLDSAPublicKey, error) {
	params := GetParams(algo)

	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to sample entropy: %w", err)
	}

	// Expand master seed into rho (public matrix seed), rhoPrime (secret vector seed), and K (signing seed)
	h := sha512.New()
	h.Write([]byte("PQC-KEYGEN-V1"))
	h.Write(seed[:])
	expanded := h.Sum(nil)

	var rho, kSeed [32]byte
	copy(rho[:], expanded[0:32])
	copy(kSeed[:], expanded[32:64])

	// Secret vector seed
	hPrime := sha512.New()
	hPrime.Write([]byte("PQC-SECRET-SEED-V1"))
	hPrime.Write(seed[:])
	rhoPrime := hPrime.Sum(nil)

	// Expand public matrix A
	A := ExpandMatrixA(rho[:], params.K, params.L)

	// Sample secret vectors s1 and s2
	s1 := make(PolyVec, params.L)
	for i := 0; i < params.L; i++ {
		s1[i] = SamplePolyEta(rhoPrime, uint16(i), params.Eta)
	}

	s2 := make(PolyVec, params.K)
	for i := 0; i < params.K; i++ {
		s2[i] = SamplePolyEta(rhoPrime, uint16(params.L+i), params.Eta)
	}

	// Compute t = A * s1 + s2
	As1 := MatrixVectorMul(A, s1)
	t := make(PolyVec, params.K)
	t1 := make(PolyVec, params.K)
	t0 := make(PolyVec, params.K)

	for i := 0; i < params.K; i++ {
		t[i] = PolyAdd(As1[i], s2[i])
		for j := 0; j < DegreeN; j++ {
			r1, r0 := Power2Round(t[i][j], PowerD)
			t1[i][j] = r1
			t0[i][j] = r0
		}
	}

	keyID := fmt.Sprintf("PQC-%s-%s", params.Name, hex.EncodeToString(rho[0:6]))

	pub := &MLDSAPublicKey{
		KeyID:     keyID,
		Algorithm: params.Name,
		Rho:       rho,
		T1:        t1,
		CreatedAt: time.Now().UTC(),
	}
	pub.RawHex = EncodePublicKey(pub)

	priv := &MLDSAPrivateKey{
		KeyID:     keyID,
		Algorithm: params.Name,
		Rho:       rho,
		K:         kSeed,
		S1:        s1,
		S2:        s2,
		T0:        t0,
		PublicKey: pub,
	}

	return priv, pub, nil
}

// computeMessageDigest computes the domain-separated message hash mu.
func computeMessageDigest(pub *MLDSAPublicKey, msg []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("PQC-MLDSA-DIGEST-V1"))
	h.Write([]byte(pub.Algorithm))
	h.Write(pub.Rho[:])
	for i := 0; i < len(pub.T1); i++ {
		for j := 0; j < DegreeN; j++ {
			var b [4]byte
			b[0] = byte(pub.T1[i][j])
			b[1] = byte(pub.T1[i][j] >> 8)
			b[2] = byte(pub.T1[i][j] >> 16)
			b[3] = byte(pub.T1[i][j] >> 24)
			h.Write(b[:])
		}
	}
	h.Write(msg)
	var mu [32]byte
	copy(mu[:], h.Sum(nil))
	return mu
}

// SignMLDSA generates a lattice digital signature (c, z, h) under the given private key.
func SignMLDSA(priv *MLDSAPrivateKey, msg []byte) (*MLDSASignature, error) {
	params := GetParams(priv.Algorithm)
	mu := computeMessageDigest(priv.PublicKey, msg)
	A := ExpandMatrixA(priv.Rho[:], params.K, params.L)

	alpha := 2 * params.Gamma2

	for attempt := 0; attempt < 512; attempt++ {
		var rndSeed [32]byte
		if _, err := rand.Read(rndSeed[:]); err != nil {
			return nil, err
		}

		// Sample masking vector y
		y := make(PolyVec, params.L)
		for i := 0; i < params.L; i++ {
			y[i] = SamplePolyGamma1(rndSeed[:], uint16(i+attempt*params.L), params.Gamma1)
		}

		// Compute w = A * y
		w := MatrixVectorMul(A, y)

		// Decompose w into w1 (high bits)
		w1 := make(PolyVec, params.K)
		for i := 0; i < params.K; i++ {
			for j := 0; j < DegreeN; j++ {
				w1[i][j] = HighBits(w[i][j], alpha)
			}
		}

		// Compute challenge hash c_seed = H(mu || w1)
		ch := sha256.New()
		ch.Write([]byte("PQC-CHALLENGE-V1"))
		ch.Write(mu[:])
		for i := 0; i < params.K; i++ {
			for j := 0; j < DegreeN; j++ {
				var b [4]byte
				b[0] = byte(w1[i][j])
				b[1] = byte(w1[i][j] >> 8)
				b[2] = byte(w1[i][j] >> 16)
				b[3] = byte(w1[i][j] >> 24)
				ch.Write(b[:])
			}
		}
		var cSeed [32]byte
		copy(cSeed[:], ch.Sum(nil))

		// Sample challenge polynomial c
		cPoly := SampleChallengePoly(cSeed[:], params.Tau)

		// Compute response vector z = y + c * s1
		z := make(PolyVec, params.L)
		zValid := true
		for i := 0; i < params.L; i++ {
			cs1 := PolyMul(cPoly, priv.S1[i])
			z[i] = PolyAdd(y[i], cs1)
			norm := PolyInfinityNorm(z[i])
			thresh := params.Gamma1 - params.Beta
			if norm >= thresh {
				zValid = false
				break
			}
		}
		if !zValid {
			continue
		}

		// Low-order bounds check: || LowBits(w - c * s2) ||_inf < Gamma2 - Beta
		lowValid := true
		hints := make([][]int, params.K)
		totalHints := 0

		for i := 0; i < params.K; i++ {
			cs2 := PolyMul(cPoly, priv.S2[i])
			wMinusCs2 := PolySub(w[i], cs2)
			ct0 := PolyMul(cPoly, priv.T0[i])

			var rowHints []int
			for j := 0; j < DegreeN; j++ {
				r0 := LowBits(wMinusCs2[j], alpha)
				if absInt32(r0) >= (params.Gamma2 - params.Beta) {
					lowValid = false
					break
				}
				offset := modQ(int64(cs2[j]) - int64(ct0[j]))
				r := modQ(int64(wMinusCs2[j]) + int64(ct0[j]))
				hBit := MakeHint(offset, r, alpha)
				if hBit == 1 {
					rowHints = append(rowHints, j)
					totalHints++
				}
			}
			if !lowValid {
				break
			}
			hints[i] = rowHints
		}

		if !lowValid || totalHints > params.Omega {
			continue
		}

		sig := &MLDSASignature{
			Algorithm: priv.Algorithm,
			KeyID:     priv.KeyID,
			Challenge: cSeed,
			Z:         z,
			Hints:     hints,
		}
		sig.RawHex = EncodeSignature(sig)
		return sig, nil
	}

	return nil, fmt.Errorf("rejection sampling threshold exceeded after 512 attempts")
}

// VerifyMLDSA verifies a signature against the public key and message.
func VerifyMLDSA(pub *MLDSAPublicKey, msg []byte, sig *MLDSASignature) bool {
	if pub == nil || sig == nil {
		return false
	}
	params := GetParams(pub.Algorithm)
	if len(sig.Z) != params.L {
		return false
	}

	// 1. Norm bound check on response vector z
	for i := 0; i < params.L; i++ {
		if PolyInfinityNorm(sig.Z[i]) >= (params.Gamma1 - params.Beta) {
			return false
		}
	}

	// 2. Reconstruct matrix A and digest mu
	mu := computeMessageDigest(pub, msg)
	A := ExpandMatrixA(pub.Rho[:], params.K, params.L)

	// 3. Compute challenge polynomial c
	cPoly := SampleChallengePoly(sig.Challenge[:], params.Tau)

	// 4. Compute Az - c * (t1 * 2^d)
	Az := MatrixVectorMul(A, sig.Z)
	alpha := 2 * params.Gamma2
	w1Prime := make(PolyVec, params.K)

	// Build lookup set for hint bits
	for i := 0; i < params.K; i++ {
		hintMap := make(map[int]bool)
		if i < len(sig.Hints) {
			for _, idx := range sig.Hints[i] {
				hintMap[idx] = true
			}
		}

		ct1 := PolyMul(cPoly, pub.T1[i])
		ct1Scaled := PolyScalarMul(1<<PowerD, ct1)
		diff := PolySub(Az[i], ct1Scaled)

		for j := 0; j < DegreeN; j++ {
			hBit := 0
			if hintMap[j] {
				hBit = 1
			}
			w1Prime[i][j] = UseHint(hBit, diff[j], alpha)
		}
	}

	// 5. Hash w1Prime and compare with signature challenge
	ch := sha256.New()
	ch.Write([]byte("PQC-CHALLENGE-V1"))
	ch.Write(mu[:])
	for i := 0; i < params.K; i++ {
		for j := 0; j < DegreeN; j++ {
			var b [4]byte
			b[0] = byte(w1Prime[i][j])
			b[1] = byte(w1Prime[i][j] >> 8)
			b[2] = byte(w1Prime[i][j] >> 16)
			b[3] = byte(w1Prime[i][j] >> 24)
			ch.Write(b[:])
		}
	}
	expectedChallenge := ch.Sum(nil)

	return subtle.ConstantTimeCompare(expectedChallenge, sig.Challenge[:]) == 1
}

// EncodePublicKey serializes an ML-DSA public key to JSON-hex.
func EncodePublicKey(pub *MLDSAPublicKey) string {
	type rawPubKey struct {
		KeyID     string    `json:"key_id"`
		Algorithm string    `json:"algorithm"`
		RhoHex    string    `json:"rho_hex"`
		T1        PolyVec   `json:"t1"`
		CreatedAt time.Time `json:"created_at"`
	}
	r := rawPubKey{
		KeyID:     pub.KeyID,
		Algorithm: pub.Algorithm,
		RhoHex:    hex.EncodeToString(pub.Rho[:]),
		T1:        pub.T1,
		CreatedAt: pub.CreatedAt,
	}
	b, _ := json.Marshal(r)
	return hex.EncodeToString(b)
}

// DecodePublicKey deserializes an ML-DSA public key from JSON-hex.
func DecodePublicKey(rawHex string) (*MLDSAPublicKey, error) {
	data, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in public key: %w", err)
	}
	type rawPubKey struct {
		KeyID     string    `json:"key_id"`
		Algorithm string    `json:"algorithm"`
		RhoHex    string    `json:"rho_hex"`
		T1        PolyVec   `json:"t1"`
		CreatedAt time.Time `json:"created_at"`
	}
	var r rawPubKey
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("invalid json in public key: %w", err)
	}
	rhoBytes, err := hex.DecodeString(r.RhoHex)
	if err != nil || len(rhoBytes) != 32 {
		return nil, fmt.Errorf("invalid rho seed in public key")
	}
	var rho [32]byte
	copy(rho[:], rhoBytes)

	pub := &MLDSAPublicKey{
		KeyID:     r.KeyID,
		Algorithm: r.Algorithm,
		Rho:       rho,
		T1:        r.T1,
		RawHex:    rawHex,
		CreatedAt: r.CreatedAt,
	}
	return pub, nil
}

// EncodeSignature serializes an ML-DSA signature to JSON-hex.
func EncodeSignature(sig *MLDSASignature) string {
	type rawSig struct {
		Algorithm string   `json:"algo"`
		KeyID     string   `json:"key_id"`
		Challenge string   `json:"c_hex"`
		Z         PolyVec  `json:"z"`
		Hints     [][]int  `json:"hints"`
	}
	r := rawSig{
		Algorithm: sig.Algorithm,
		KeyID:     sig.KeyID,
		Challenge: hex.EncodeToString(sig.Challenge[:]),
		Z:         sig.Z,
		Hints:     sig.Hints,
	}
	b, _ := json.Marshal(r)
	return hex.EncodeToString(b)
}

// DecodeSignature deserializes an ML-DSA signature from JSON-hex.
func DecodeSignature(rawHex string) (*MLDSASignature, error) {
	data, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in signature: %w", err)
	}
	type rawSig struct {
		Algorithm string   `json:"algo"`
		KeyID     string   `json:"key_id"`
		Challenge string   `json:"c_hex"`
		Z         PolyVec  `json:"z"`
		Hints     [][]int  `json:"hints"`
	}
	var r rawSig
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("invalid json in signature: %w", err)
	}
	cBytes, err := hex.DecodeString(r.Challenge)
	if err != nil || len(cBytes) != 32 {
		return nil, fmt.Errorf("invalid challenge in signature")
	}
	var c [32]byte
	copy(c[:], cBytes)

	sig := &MLDSASignature{
		Algorithm: r.Algorithm,
		KeyID:     r.KeyID,
		Challenge: c,
		Z:         r.Z,
		Hints:     r.Hints,
		RawHex:    rawHex,
	}
	return sig, nil
}
