package transparency

import (
	"bytes"
	"crypto/sha256"
	"math/bits"
)

const (
	// LeafHashPrefix is the domain-separation byte (0x00) prepended to leaf payloads per RFC 6962.
	LeafHashPrefix = byte(0x00)
	// NodeHashPrefix is the domain-separation byte (0x01) prepended to interior node payloads per RFC 6962.
	NodeHashPrefix = byte(0x01)
)

// ComputeLeafHash returns the RFC 6962 SHA-256 leaf hash for the given raw data: SHA-256(0x00 || data).
func ComputeLeafHash(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{LeafHashPrefix})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeNodeHash returns the RFC 6962 SHA-256 interior node hash: SHA-256(0x01 || left || right).
func ComputeNodeHash(left, right []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{NodeHashPrefix})
	h.Write(left)
	h.Write(right)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// LargestPowerOf2LessThan returns the largest power of 2 strictly less than n (for n > 1).
func LargestPowerOf2LessThan(n int64) int64 {
	if n <= 1 {
		return 0
	}
	// Return 1 << (floor(log2(n - 1)))
	shift := bits.Len64(uint64(n-1)) - 1
	return int64(1) << shift
}

// BuildMerkleTreeRoot calculates the RFC 6962 Merkle Tree Hash (MTH) for a slice of leaf hashes.
func BuildMerkleTreeRoot(leaves [][]byte) [32]byte {
	n := int64(len(leaves))
	if n == 0 {
		return sha256.Sum256(nil)
	}
	if n == 1 {
		var out [32]byte
		copy(out[:], leaves[0])
		return out
	}

	k := LargestPowerOf2LessThan(n)
	leftRoot := BuildMerkleTreeRoot(leaves[:k])
	rightRoot := BuildMerkleTreeRoot(leaves[k:])
	return ComputeNodeHash(leftRoot[:], rightRoot[:])
}

// ComputeInclusionProof generates an RFC 6962 audit path for leaf index m (0-based) in tree of size n.
func ComputeInclusionProof(leaves [][]byte, m, n int64) ([][]byte, error) {
	if n <= 0 || int64(len(leaves)) < n {
		return nil, ErrInvalidTreeSize
	}
	if m < 0 || m >= n {
		return nil, ErrInvalidLeafIndex
	}
	return subPath(leaves[:n], m, n), nil
}

func subPath(leaves [][]byte, m, n int64) [][]byte {
	if n == 1 {
		return [][]byte{}
	}
	k := LargestPowerOf2LessThan(n)
	if m < k {
		p := subPath(leaves[:k], m, k)
		rightRoot := BuildMerkleTreeRoot(leaves[k:n])
		sibling := make([]byte, 32)
		copy(sibling, rightRoot[:])
		return append(p, sibling)
	}
	p := subPath(leaves[k:n], m-k, n-k)
	leftRoot := BuildMerkleTreeRoot(leaves[:k])
	sibling := make([]byte, 32)
	copy(sibling, leftRoot[:])
	return append(p, sibling)
}

// VerifyInclusionProof verifies an RFC 6962 audit path for leafIndex in treeSize against rootHash.
func VerifyInclusionProof(leafIndex, treeSize int64, leafHash, rootHash []byte, proof [][]byte) bool {
	if treeSize <= 0 || leafIndex < 0 || leafIndex >= treeSize || len(leafHash) != 32 || len(rootHash) != 32 {
		return false
	}
	if treeSize == 1 {
		return len(proof) == 0 && bytes.Equal(leafHash, rootHash)
	}

	type step struct {
		isLeft bool
	}
	var steps []step
	idx := leafIndex
	sz := treeSize
	for sz > 1 {
		k := LargestPowerOf2LessThan(sz)
		if idx < k {
			steps = append(steps, step{isLeft: true})
			sz = k
		} else {
			steps = append(steps, step{isLeft: false})
			idx -= k
			sz -= k
		}
	}

	if len(proof) != len(steps) {
		return false
	}

	curr := make([]byte, 32)
	copy(curr, leafHash)

	// Fold bottom-up using proof hashes (proof[0] is deepest sibling)
	for i := len(steps) - 1; i >= 0; i-- {
		st := steps[i]
		sibling := proof[len(steps)-1-i]
		if len(sibling) != 32 {
			return false
		}
		var parent [32]byte
		if st.isLeft {
			parent = ComputeNodeHash(curr, sibling)
		} else {
			parent = ComputeNodeHash(sibling, curr)
		}
		curr = parent[:]
	}

	return bytes.Equal(curr, rootHash)
}

// ComputeConsistencyProof generates RFC 6962 intermediate hashes proving append-only evolution from m to n.
func ComputeConsistencyProof(leaves [][]byte, m, n int64) ([][]byte, error) {
	if m <= 0 || n <= 0 || int64(len(leaves)) < n {
		return nil, ErrInvalidTreeSize
	}
	if m > n {
		return nil, ErrInvalidConsistencyRange
	}
	if m == n {
		return [][]byte{}, nil
	}
	return subProof(leaves[:n], m, n, true), nil
}

func subProof(leaves [][]byte, m, n int64, b bool) [][]byte {
	if m == n {
		if b {
			return [][]byte{}
		}
		root := BuildMerkleTreeRoot(leaves[:m])
		node := make([]byte, 32)
		copy(node, root[:])
		return [][]byte{node}
	}

	k := LargestPowerOf2LessThan(n)
	if m <= k {
		p := subProof(leaves[:k], m, k, b)
		rightRoot := BuildMerkleTreeRoot(leaves[k:n])
		sibling := make([]byte, 32)
		copy(sibling, rightRoot[:])
		return append(p, sibling)
	}

	p := subProof(leaves[k:n], m-k, n-k, false)
	leftRoot := BuildMerkleTreeRoot(leaves[:k])
	sibling := make([]byte, 32)
	copy(sibling, leftRoot[:])
	return append(p, sibling)
}

type consistencyAction struct {
	isRightSibling bool
	appliesToFirst bool
}

func recordConsistencyActions(m, n int64, b bool, out *[]consistencyAction) {
	if m == n {
		return
	}
	k := LargestPowerOf2LessThan(n)
	if m <= k {
		recordConsistencyActions(m, k, b, out)
		*out = append(*out, consistencyAction{isRightSibling: true, appliesToFirst: false})
	} else {
		recordConsistencyActions(m-k, n-k, false, out)
		*out = append(*out, consistencyAction{isRightSibling: false, appliesToFirst: true})
	}
}

// VerifyConsistencyProof verifies RFC 6962 consistency between firstRoot (size m) and secondRoot (size n).
func VerifyConsistencyProof(firstSize, secondSize int64, firstRoot, secondRoot []byte, proof [][]byte) bool {
	if firstSize <= 0 || secondSize <= 0 || firstSize > secondSize || len(firstRoot) != 32 || len(secondRoot) != 32 {
		return false
	}
	if firstSize == secondSize {
		return len(proof) == 0 && bytes.Equal(firstRoot, secondRoot)
	}

	isPowerOf2 := (firstSize & (firstSize - 1)) == 0
	var fn, sn []byte
	var path [][]byte

	if isPowerOf2 {
		fn = make([]byte, 32)
		copy(fn, firstRoot)
		sn = make([]byte, 32)
		copy(sn, firstRoot)
		path = proof
	} else {
		if len(proof) == 0 || len(proof[0]) != 32 {
			return false
		}
		fn = make([]byte, 32)
		copy(fn, proof[0])
		sn = make([]byte, 32)
		copy(sn, proof[0])
		path = proof[1:]
	}

	var actions []consistencyAction
	recordConsistencyActions(firstSize, secondSize, true, &actions)

	if len(path) != len(actions) {
		return false
	}

	for i, act := range actions {
		sibling := path[i]
		if len(sibling) != 32 {
			return false
		}
		if act.isRightSibling {
			res := ComputeNodeHash(sn, sibling)
			sn = res[:]
		} else {
			res := ComputeNodeHash(sibling, sn)
			sn = res[:]
			if act.appliesToFirst {
				fres := ComputeNodeHash(sibling, fn)
				fn = fres[:]
			}
		}
	}

	return bytes.Equal(fn, firstRoot) && bytes.Equal(sn, secondRoot)
}
