package transparency

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestMerkleBasicHashes(t *testing.T) {
	data := []byte("license-issued:tenant-1:key-xyz")
	leaf := ComputeLeafHash(data)

	// Verify domain separation prefix 0x00
	expectedLeaf := sha256.Sum256(append([]byte{LeafHashPrefix}, data...))
	if !bytes.Equal(leaf[:], expectedLeaf[:]) {
		t.Fatalf("leaf hash mismatch")
	}

	left := ComputeLeafHash([]byte("a"))
	right := ComputeLeafHash([]byte("b"))
	node := ComputeNodeHash(left[:], right[:])

	// Verify domain separation prefix 0x01
	expectedNode := sha256.Sum256(append([]byte{NodeHashPrefix}, append(left[:], right[:]...)...))
	if !bytes.Equal(node[:], expectedNode[:]) {
		t.Fatalf("node hash mismatch")
	}
}

func TestLargestPowerOf2(t *testing.T) {
	cases := []struct {
		n   int64
		exp int64
	}{
		{0, 0},
		{1, 0},
		{2, 1},
		{3, 2},
		{4, 2},
		{5, 4},
		{6, 4},
		{7, 4},
		{8, 4},
		{9, 8},
		{16, 8},
		{17, 16},
	}
	for _, tc := range cases {
		got := LargestPowerOf2LessThan(tc.n)
		if got != tc.exp {
			t.Errorf("LargestPowerOf2LessThan(%d) = %d, expected %d", tc.n, got, tc.exp)
		}
	}
}

func TestInclusionProofsAcrossTreeSizes(t *testing.T) {
	// Test trees of size 1 through 20
	for size := 1; size <= 20; size++ {
		var leaves [][]byte
		for i := 0; i < size; i++ {
			h := ComputeLeafHash([]byte(fmt.Sprintf("entry-%d", i)))
			leaves = append(leaves, h[:])
		}
		root := BuildMerkleTreeRoot(leaves)

		for m := 0; m < size; m++ {
			proof, err := ComputeInclusionProof(leaves, int64(m), int64(size))
			if err != nil {
				t.Fatalf("size=%d, leaf=%d: ComputeInclusionProof error: %v", size, m, err)
			}

			valid := VerifyInclusionProof(int64(m), int64(size), leaves[m], root[:], proof)
			if !valid {
				t.Fatalf("size=%d, leaf=%d: VerifyInclusionProof returned false", size, m)
			}

			// Tampered leaf hash must fail verification
			tamperedLeaf := append([]byte{}, leaves[m]...)
			tamperedLeaf[0] ^= 0xFF
			if VerifyInclusionProof(int64(m), int64(size), tamperedLeaf, root[:], proof) {
				t.Fatalf("size=%d, leaf=%d: tampered leaf unexpectedly passed", size, m)
			}

			// Tampered root hash must fail verification
			tamperedRoot := append([]byte{}, root[:]...)
			tamperedRoot[0] ^= 0xFF
			if VerifyInclusionProof(int64(m), int64(size), leaves[m], tamperedRoot, proof) {
				t.Fatalf("size=%d, leaf=%d: tampered root unexpectedly passed", size, m)
			}

			// Tampered audit path must fail verification
			if len(proof) > 0 {
				tamperedProof := make([][]byte, len(proof))
				for pi, p := range proof {
					tamperedProof[pi] = append([]byte{}, p...)
				}
				tamperedProof[0][0] ^= 0x55
				if VerifyInclusionProof(int64(m), int64(size), leaves[m], root[:], tamperedProof) {
					t.Fatalf("size=%d, leaf=%d: tampered proof unexpectedly passed", size, m)
				}
			}
		}
	}
}

func TestConsistencyProofsAcrossTreeSizes(t *testing.T) {
	// Generate up to 16 leaves
	const maxLeaves = 16
	var allLeaves [][]byte
	for i := 0; i < maxLeaves; i++ {
		h := ComputeLeafHash([]byte(fmt.Sprintf("consistency-entry-%d", i)))
		allLeaves = append(allLeaves, h[:])
	}

	// Test consistency proof between all pairs (m, n) where 1 <= m <= n <= maxLeaves
	for n := 1; n <= maxLeaves; n++ {
		rootN := BuildMerkleTreeRoot(allLeaves[:n])
		for m := 1; m <= n; m++ {
			rootM := BuildMerkleTreeRoot(allLeaves[:m])

			proof, err := ComputeConsistencyProof(allLeaves, int64(m), int64(n))
			if err != nil {
				t.Fatalf("m=%d, n=%d: ComputeConsistencyProof failed: %v", m, n, err)
			}

			valid := VerifyConsistencyProof(int64(m), int64(n), rootM[:], rootN[:], proof)
			if !valid {
				t.Fatalf("m=%d, n=%d: VerifyConsistencyProof returned false (proofLen=%d)", m, n, len(proof))
			}

			if m < n {
				// Tampering with first root must fail
				tamperedRootM := append([]byte{}, rootM[:]...)
				tamperedRootM[0] ^= 0xAA
				if VerifyConsistencyProof(int64(m), int64(n), tamperedRootM, rootN[:], proof) {
					t.Fatalf("m=%d, n=%d: tampered first root passed consistency", m, n)
				}

				// Tampering with second root must fail
				tamperedRootN := append([]byte{}, rootN[:]...)
				tamperedRootN[0] ^= 0xBB
				if VerifyConsistencyProof(int64(m), int64(n), rootM[:], tamperedRootN, proof) {
					t.Fatalf("m=%d, n=%d: tampered second root passed consistency", m, n)
				}
			}
		}
	}
}

func TestInclusionAndConsistencyErrorCases(t *testing.T) {
	l1 := ComputeLeafHash([]byte("1"))
	l2 := ComputeLeafHash([]byte("2"))
	leaves := [][]byte{
		l1[:],
		l2[:],
	}

	// Invalid leaf index
	if _, err := ComputeInclusionProof(leaves, -1, 2); err != ErrInvalidLeafIndex {
		t.Errorf("expected ErrInvalidLeafIndex, got %v", err)
	}
	if _, err := ComputeInclusionProof(leaves, 2, 2); err != ErrInvalidLeafIndex {
		t.Errorf("expected ErrInvalidLeafIndex, got %v", err)
	}

	// Invalid tree size
	if _, err := ComputeInclusionProof(leaves, 0, 0); err != ErrInvalidTreeSize {
		t.Errorf("expected ErrInvalidTreeSize, got %v", err)
	}
	if _, err := ComputeInclusionProof(leaves, 0, 5); err != ErrInvalidTreeSize {
		t.Errorf("expected ErrInvalidTreeSize, got %v", err)
	}

	// Invalid consistency range
	if _, err := ComputeConsistencyProof(leaves, 3, 2); err != ErrInvalidConsistencyRange {
		t.Errorf("expected ErrInvalidConsistencyRange, got %v", err)
	}
	if _, err := ComputeConsistencyProof(leaves, 0, 2); err != ErrInvalidTreeSize {
		t.Errorf("expected ErrInvalidTreeSize, got %v", err)
	}
}
