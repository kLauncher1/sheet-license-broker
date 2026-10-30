package mlkem

import (
	"crypto/sha256"
	"encoding/binary"
)

// PolyAdd performs polynomial addition in R_q: (a + b) mod q.
func PolyAdd(a, b Poly) Poly {
	var res Poly
	for i := 0; i < DegreeN; i++ {
		sum := int32(a[i]) + int32(b[i])
		res[i] = int16(sum % ModulusQ)
	}
	return res
}

// PolySub performs polynomial subtraction in R_q: (a - b) mod q.
func PolySub(a, b Poly) Poly {
	var res Poly
	for i := 0; i < DegreeN; i++ {
		diff := int32(a[i]) - int32(b[i]) + ModulusQ
		res[i] = int16(diff % ModulusQ)
	}
	return res
}

// PolyMul performs polynomial multiplication in R_q = Z_q[X]/(X^256 + 1).
func PolyMul(a, b Poly) Poly {
	var acc [DegreeN]int32
	for i := 0; i < DegreeN; i++ {
		ai := int32(a[i])
		if ai == 0 {
			continue
		}
		for j := 0; j < DegreeN; j++ {
			bj := int32(b[j])
			prod := ai * bj
			idx := i + j
			if idx < DegreeN {
				acc[idx] += prod
			} else {
				acc[idx-DegreeN] -= prod
			}
		}
	}

	var res Poly
	for i := 0; i < DegreeN; i++ {
		v := acc[i] % ModulusQ
		if v < 0 {
			v += ModulusQ
		}
		res[i] = int16(v)
	}
	return res
}

// PolyVecAdd computes vector addition u + v.
func PolyVecAdd(u, v PolyVec) PolyVec {
	k := len(u)
	res := make(PolyVec, k)
	for i := 0; i < k; i++ {
		res[i] = PolyAdd(u[i], v[i])
	}
	return res
}

// MatrixVecMul computes matrix-vector multiplication A * s where A is k x k and s is k.
func MatrixVecMul(A [][]Poly, s PolyVec) PolyVec {
	k := len(s)
	res := make(PolyVec, k)
	for i := 0; i < k; i++ {
		var sum Poly
		for j := 0; j < k; j++ {
			prod := PolyMul(A[i][j], s[j])
			sum = PolyAdd(sum, prod)
		}
		res[i] = sum
	}
	return res
}

// TransposeMatrixVecMul computes A^T * r where A is k x k and r is k.
func TransposeMatrixVecMul(A [][]Poly, r PolyVec) PolyVec {
	k := len(r)
	res := make(PolyVec, k)
	for i := 0; i < k; i++ {
		var sum Poly
		for j := 0; j < k; j++ {
			prod := PolyMul(A[j][i], r[j])
			sum = PolyAdd(sum, prod)
		}
		res[i] = sum
	}
	return res
}

// InnerProduct computes vector dot product u^T * v in R_q.
func InnerProduct(u, v PolyVec) Poly {
	var sum Poly
	for i := 0; i < len(u); i++ {
		prod := PolyMul(u[i], v[i])
		sum = PolyAdd(sum, prod)
	}
	return sum
}

// SampleCBD samples a polynomial from the Centered Binomial Distribution CBD_eta.
func SampleCBD(seed []byte, nonce byte, eta int) Poly {
	var res Poly
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte{nonce, byte(eta)})
	buf := h.Sum(nil)

	// Expand buffer deterministically
	extended := make([]byte, 256)
	for chunk := 0; chunk < 8; chunk++ {
		ch := sha256.New()
		ch.Write(buf)
		ch.Write([]byte{byte(chunk)})
		copy(extended[chunk*32:(chunk+1)*32], ch.Sum(nil))
	}

	for i := 0; i < DegreeN; i++ {
		b := extended[i]
		// Sample bits for eta = 2
		a1 := int32((b >> 0) & 1)
		a2 := int32((b >> 1) & 1)
		b1 := int32((b >> 2) & 1)
		b2 := int32((b >> 3) & 1)
		diff := (a1 + a2) - (b1 + b2)
		v := diff % ModulusQ
		if v < 0 {
			v += ModulusQ
		}
		res[i] = int16(v)
	}
	return res
}

// SampleMatrixA samples a k x k polynomial matrix deterministically from seed rho.
func SampleMatrixA(rho [32]byte, k int) [][]Poly {
	A := make([][]Poly, k)
	for i := 0; i < k; i++ {
		A[i] = make([]Poly, k)
		for j := 0; j < k; j++ {
			A[i][j] = sampleUniformPoly(rho, byte(i), byte(j))
		}
	}
	return A
}

// sampleUniformPoly samples a uniform polynomial in R_q using rejection sampling from SHA-256 stream.
func sampleUniformPoly(rho [32]byte, i, j byte) Poly {
	var p Poly
	counter := byte(0)
	coeffIdx := 0

	for coeffIdx < DegreeN {
		h := sha256.New()
		h.Write(rho[:])
		h.Write([]byte{i, j, counter})
		digest := h.Sum(nil)
		counter++

		for idx := 0; idx+2 <= len(digest) && coeffIdx < DegreeN; idx += 2 {
			val := binary.LittleEndian.Uint16(digest[idx : idx+2]) & 0x0FFF
			if val < ModulusQ {
				p[coeffIdx] = int16(val)
				coeffIdx++
			}
		}
	}
	return p
}

// Compress scalar coefficient x into d bits.
func Compress(x int16, d int) int16 {
	u := (int32(x)%ModulusQ + ModulusQ) % ModulusQ
	scaled := (u * (1 << d)) + (ModulusQ / 2)
	res := (scaled / ModulusQ) & ((1 << d) - 1)
	return int16(res)
}

// Decompress d-bit value y back into R_q.
func Decompress(y int16, d int) int16 {
	scaled := (int32(y) * ModulusQ) + (1 << (d - 1))
	res := scaled >> d
	return int16(res % ModulusQ)
}

// CompressPoly compresses a polynomial to d bits per coefficient.
func CompressPoly(p Poly, d int) []byte {
	out := make([]byte, (DegreeN*d+7)/8)
	bitPos := 0
	for i := 0; i < DegreeN; i++ {
		val := uint32(Compress(p[i], d))
		for b := 0; b < d; b++ {
			if (val>>b)&1 == 1 {
				out[bitPos/8] |= 1 << (bitPos % 8)
			}
			bitPos++
		}
	}
	return out
}

// DecompressPoly decompresses bytes back to a polynomial using d bits per coefficient.
func DecompressPoly(data []byte, d int) Poly {
	var p Poly
	bitPos := 0
	mask := uint32((1 << d) - 1)
	for i := 0; i < DegreeN; i++ {
		var val uint32
		for b := 0; b < d; b++ {
			byteIdx := bitPos / 8
			if byteIdx < len(data) {
				if (data[byteIdx]>>(bitPos%8))&1 == 1 {
					val |= 1 << b
				}
			}
			bitPos++
		}
		p[i] = Decompress(int16(val&mask), d)
	}
	return p
}

// CompressVec compresses a vector of polynomials.
func CompressVec(v PolyVec, d int) []byte {
	var res []byte
	for i := 0; i < len(v); i++ {
		res = append(res, CompressPoly(v[i], d)...)
	}
	return res
}

// DecompressVec decompresses a byte slice into a vector of k polynomials.
func DecompressVec(data []byte, k, d int) PolyVec {
	polyBytes := (DegreeN*d + 7) / 8
	res := make(PolyVec, k)
	for i := 0; i < k; i++ {
		start := i * polyBytes
		end := start + polyBytes
		if end <= len(data) {
			res[i] = DecompressPoly(data[start:end], d)
		}
	}
	return res
}

// EncodeMessage encodes 32 bytes (256 bits) into a polynomial in R_q.
func EncodeMessage(m [32]byte) Poly {
	var p Poly
	for i := 0; i < 32; i++ {
		b := m[i]
		for bit := 0; bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				p[i*8+bit] = int16((ModulusQ + 1) / 2) // 1665
			} else {
				p[i*8+bit] = 0
			}
		}
	}
	return p
}

// DecodeMessage decodes a polynomial in R_q into 32 bytes (256 bits).
func DecodeMessage(p Poly) [32]byte {
	var m [32]byte
	for i := 0; i < 32; i++ {
		var b byte
		for bit := 0; bit < 8; bit++ {
			val := Compress(p[i*8+bit], 1)
			if val == 1 {
				b |= 1 << bit
			}
		}
		m[i] = b
	}
	return m
}
