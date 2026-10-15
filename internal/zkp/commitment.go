package zkp

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
)

var (
	curveInstance elliptic.Curve
	curveParams   *CurveParams
	curveOnce     sync.Once
)

// GetCurve returns the singleton P-256 curve and Pedersen generators.
func GetCurve() (elliptic.Curve, *CurveParams) {
	curveOnce.Do(func() {
		curveInstance = elliptic.P256()
		params := curveInstance.Params()

		// Generate independent generator H via hash-to-curve try-and-increment
		// to guarantee discrete log log_G(H) is unknown.
		hx, hy := hashToCurve(params, []byte("SheetLicenseBroker-ZKP-Pedersen-H-v1.2.0"))

		curveParams = &CurveParams{
			Gx: params.Gx,
			Gy: params.Gy,
			Hx: hx,
			Hy: hy,
			N:  params.N,
		}
	})
	return curveInstance, curveParams
}

// hashToCurve deterministically finds a valid point on P-256 from a seed.
func hashToCurve(params *elliptic.CurveParams, seed []byte) (*big.Int, *big.Int) {
	counter := uint32(0)
	for {
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		digest := h.Sum(nil)

		x := new(big.Int).SetBytes(digest)
		x.Mod(x, params.P)

		// Equation: y^2 = x^3 - 3x + b (mod p)
		x3 := new(big.Int).Mul(x, x)
		x3.Mul(x3, x)
		threeX := new(big.Int).Mul(big.NewInt(3), x)
		y2 := new(big.Int).Sub(x3, threeX)
		y2.Add(y2, params.B)
		y2.Mod(y2, params.P)

		// Check if y2 is quadratic residue (Euler's criterion: y2^((p-1)/2) == 1 mod p)
		exp := new(big.Int).Sub(params.P, big.NewInt(1))
		exp.Div(exp, big.NewInt(2))
		res := new(big.Int).Exp(y2, exp, params.P)

		if res.Cmp(big.NewInt(1)) == 0 {
			// Quadratic residue exists, compute square root via Tonelli-Shanks / p mod 4 == 3
			// For P-256, p = 3 mod 4, so sqrt = y2^((p+1)/4) mod p
			rootExp := new(big.Int).Add(params.P, big.NewInt(1))
			rootExp.Div(rootExp, big.NewInt(4))
			y := new(big.Int).Exp(y2, rootExp, params.P)

			// Point is (x, y)
			return x, y
		}
		counter++
	}
}

// HashToScalar converts an arbitrary string (such as HWID) to a scalar mod N.
func HashToScalar(input string) *big.Int {
	h := sha256.Sum256([]byte(input))
	scalar := new(big.Int).SetBytes(h[:])
	_, cp := GetCurve()
	scalar.Mod(scalar, cp.N)
	if scalar.Sign() == 0 {
		scalar.SetInt64(1)
	}
	return scalar
}

// RandomScalar generates a cryptographically secure scalar in [1, N-1].
func RandomScalar() (*big.Int, error) {
	_, cp := GetCurve()
	for {
		k, err := rand.Int(rand.Reader, cp.N)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random scalar: %w", err)
		}
		if k.Sign() > 0 {
			return k, nil
		}
	}
}

// CommitPedersen creates a commitment C = v*G + r*H.
func CommitPedersen(v, r *big.Int) *PedersenCommitment {
	curve, cp := GetCurve()

	// v * G
	vGx, vGy := curve.ScalarMult(cp.Gx, cp.Gy, v.Bytes())
	// r * H
	rHx, rHy := curve.ScalarMult(cp.Hx, cp.Hy, r.Bytes())
	// C = v*G + r*H
	cx, cy := curve.Add(vGx, vGy, rHx, rHy)

	return &PedersenCommitment{
		X: cx,
		Y: cy,
	}
}

// ComputeNullifier derives an un-linkable, deterministic nullifier per epoch and tenant:
// Nullifier = HMAC-SHA256(v_scalar_bytes, "epoch:tenant").
func ComputeNullifier(v *big.Int, epoch int64, tenantID string) string {
	key := v.Bytes()
	message := fmt.Sprintf("epoch:%d:tenant:%s", epoch, tenantID)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// String returns a compact hex representation of the commitment point.
func (c *PedersenCommitment) String() string {
	if c == nil || c.X == nil || c.Y == nil {
		return ""
	}
	return fmt.Sprintf("%064x%064x", c.X, c.Y)
}

// Equal checks if two commitments represent the identical elliptic curve point.
func (c *PedersenCommitment) Equal(other *PedersenCommitment) bool {
	if c == nil || other == nil {
		return c == other
	}
	if c.X == nil || c.Y == nil || other.X == nil || other.Y == nil {
		return false
	}
	return c.X.Cmp(other.X) == 0 && c.Y.Cmp(other.Y) == 0
}
