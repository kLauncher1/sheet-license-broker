package pqc

import (
	"crypto/sha512"
	"encoding/binary"
)

// modQ reduces an int64 integer modulo ModulusQ into [0, ModulusQ-1].
func modQ(x int64) int32 {
	rem := x % ModulusQ
	if rem < 0 {
		rem += ModulusQ
	}
	return int32(rem)
}

// centerQ shifts an element in [0, ModulusQ-1] to [-(ModulusQ-1)/2, (ModulusQ-1)/2].
func centerQ(x int32) int32 {
	if x > (ModulusQ-1)/2 {
		return x - ModulusQ
	}
	return x
}

func absInt32(x int32) int32 {
	if x < 0 {
		return -x
	}
	return x
}

// PolyAdd returns the polynomial sum a + b in R_q.
func PolyAdd(a, b Poly) Poly {
	var c Poly
	for i := 0; i < DegreeN; i++ {
		sum := int64(a[i]) + int64(b[i])
		if sum >= ModulusQ {
			sum -= ModulusQ
		}
		c[i] = int32(sum)
	}
	return c
}

// PolySub returns the polynomial difference a - b in R_q.
func PolySub(a, b Poly) Poly {
	var c Poly
	for i := 0; i < DegreeN; i++ {
		diff := int64(a[i]) - int64(b[i])
		if diff < 0 {
			diff += ModulusQ
		}
		c[i] = int32(diff)
	}
	return c
}

// PolyScalarMul multiplies a polynomial by a scalar in R_q.
func PolyScalarMul(s int32, a Poly) Poly {
	var c Poly
	for i := 0; i < DegreeN; i++ {
		c[i] = modQ(int64(s) * int64(a[i]))
	}
	return c
}

// PolyMul returns the polynomial product a * b in R_q = Z_q[X]/(X^256 + 1).
// Since X^256 = -1, for i+j >= 256 the term wraps around with a negative sign.
func PolyMul(a, b Poly) Poly {
	var c Poly
	for k := 0; k < DegreeN; k++ {
		var sum int64
		for i := 0; i <= k; i++ {
			sum += int64(a[i]) * int64(b[k-i])
		}
		for i := k + 1; i < DegreeN; i++ {
			sum -= int64(a[i]) * int64(b[DegreeN+k-i])
		}
		c[k] = modQ(sum)
	}
	return c
}

// PolyInfinityNorm returns the L-infinity norm of p over centered coefficients.
func PolyInfinityNorm(p Poly) int32 {
	var maxVal int32
	for i := 0; i < DegreeN; i++ {
		val := absInt32(centerQ(p[i]))
		if val > maxVal {
			maxVal = val
		}
	}
	return maxVal
}

// PolyVecInfinityNorm returns the maximum infinity norm across all polynomials in the vector.
func PolyVecInfinityNorm(v PolyVec) int32 {
	var maxVal int32
	for _, p := range v {
		val := PolyInfinityNorm(p)
		if val > maxVal {
			maxVal = val
		}
	}
	return maxVal
}

// Power2Round decomposes r in [0, ModulusQ-1] into r1 * 2^d + r0 with -2^(d-1) < r0 <= 2^(d-1).
func Power2Round(r int32, d uint) (int32, int32) {
	mask := int32((1 << d) - 1)
	half := int32(1 << (d - 1))
	r0 := r & mask
	if r0 > half {
		r0 -= 1 << d
	}
	r1 := (r - r0) >> d
	return r1, r0
}

// Decompose decomposes r into high bits r1 and low bits r0 such that r = r1*alpha + r0.
func Decompose(r int32, alpha int32) (int32, int32) {
	half := alpha / 2
	r0 := r % alpha
	if r0 > half {
		r0 -= alpha
	}
	if r-r0 == ModulusQ-1 {
		return 0, r0 - 1
	}
	return (r - r0) / alpha, r0
}

// HighBits extracts the high bits of r using modulus alpha = 2*Gamma2.
func HighBits(r int32, alpha int32) int32 {
	r1, _ := Decompose(r, alpha)
	return r1
}

// LowBits extracts the low bits of r using modulus alpha = 2*Gamma2.
func LowBits(r int32, alpha int32) int32 {
	_, r0 := Decompose(r, alpha)
	return r0
}

// MakeHint checks if the high bits of r change when adding z.
func MakeHint(z, r, alpha int32) int {
	r1 := HighBits(r, alpha)
	v1 := HighBits(modQ(int64(r)+int64(z)), alpha)
	if r1 != v1 {
		return 1
	}
	return 0
}

// UseHint recovers the high bits of r using hint bit h.
func UseHint(h int, r, alpha int32) int32 {
	m := (ModulusQ - 1) / alpha
	r1, r0 := Decompose(r, alpha)
	if h == 1 {
		if r0 > 0 {
			return (r1 + 1) % m
		}
		return (r1 - 1 + m) % m
	}
	return r1
}

// expandStream generates a pseudo-random byte stream from seed and domain identifiers using SHA-512.
func expandStream(seed []byte, domain uint16, length int) []byte {
	out := make([]byte, 0, length)
	var counter uint32
	domBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(domBytes, domain)

	for len(out) < length {
		cntBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(cntBytes, counter)
		h := sha512.New()
		h.Write([]byte("PQC-EXPAND-STREAM-V1"))
		h.Write(seed)
		h.Write(domBytes)
		h.Write(cntBytes)
		sum := h.Sum(nil)
		out = append(out, sum...)
		counter++
	}
	return out[:length]
}

// SamplePolyEta samples a polynomial with uniform coefficients in [-eta, eta].
func SamplePolyEta(seed []byte, domain uint16, eta int32) Poly {
	stream := expandStream(seed, domain, DegreeN*4)
	var p Poly
	rangeSize := uint32(2*eta + 1)
	idx := 0
	coeffIdx := 0

	for coeffIdx < DegreeN && idx+4 <= len(stream) {
		val := binary.LittleEndian.Uint32(stream[idx : idx+4])
		idx += 4
		c := int32(val%rangeSize) - eta
		p[coeffIdx] = modQ(int64(c))
		coeffIdx++
	}
	return p
}

// SamplePolyGamma1 samples a polynomial with coefficients uniformly in [-Gamma1+1, Gamma1-1].
func SamplePolyGamma1(seed []byte, domain uint16, gamma1 int32) Poly {
	stream := expandStream(seed, domain, DegreeN*8)
	var p Poly
	span := uint64(2*gamma1 - 1)
	idx := 0
	coeffIdx := 0

	for coeffIdx < DegreeN && idx+4 <= len(stream) {
		val := binary.LittleEndian.Uint32(stream[idx : idx+4])
		idx += 4
		c := int32(uint64(val)%span) - (gamma1 - 1)
		p[coeffIdx] = modQ(int64(c))
		coeffIdx++
	}
	return p
}

// SampleChallengePoly samples a sparse challenge polynomial with exactly tau +/-1 coefficients.
func SampleChallengePoly(seed []byte, tau int) Poly {
	stream := expandStream(seed, 0xFF01, 1024)
	var p Poly
	signs := binary.LittleEndian.Uint64(stream[0:8])
	idx := 8
	chosen := make(map[int]bool)

	for len(chosen) < tau && idx < len(stream) {
		pos := int(stream[idx])
		idx++
		if !chosen[pos] {
			chosen[pos] = true
			sign := int32(1)
			if (signs & (1 << (len(chosen) - 1))) != 0 {
				sign = -1
			}
			p[pos] = modQ(int64(sign))
		}
	}
	return p
}

// ExpandMatrixA deterministically expands a public matrix A in R_q^(k x l) from seed rho.
func ExpandMatrixA(rho []byte, k, l int) [][]Poly {
	A := make([][]Poly, k)
	for i := 0; i < k; i++ {
		A[i] = make([]Poly, l)
		for j := 0; j < l; j++ {
			domain := uint16((i << 8) | j)
			stream := expandStream(rho, domain, DegreeN*4)
			var p Poly
			for c := 0; c < DegreeN; c++ {
				raw := binary.LittleEndian.Uint32(stream[c*4 : (c+1)*4])
				p[c] = modQ(int64(raw))
			}
			A[i][j] = p
		}
	}
	return A
}

// MatrixVectorMul computes the matrix-vector product A * v in R_q.
func MatrixVectorMul(A [][]Poly, v PolyVec) PolyVec {
	k := len(A)
	l := len(v)
	res := make(PolyVec, k)
	for i := 0; i < k; i++ {
		var rowSum Poly
		for j := 0; j < l; j++ {
			prod := PolyMul(A[i][j], v[j])
			rowSum = PolyAdd(rowSum, prod)
		}
		res[i] = rowSum
	}
	return res
}
