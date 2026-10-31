package transparency

import (
	"encoding/hex"
	"testing"
)

func TestWitnessPoolRegistrationAndCosigning(t *testing.T) {
	pool := NewWitnessPool()
	pool.RegisterWitness("witness-01", []byte("witness-secret-01"))
	pool.RegisterWitness("witness-02", []byte("witness-secret-02"))

	if pool.Count() != 2 {
		t.Fatalf("expected 2 witnesses, got %d", pool.Count())
	}

	h1 := ComputeLeafHash([]byte("data-1"))
	h2 := ComputeLeafHash([]byte("data-2"))
	leaves := [][]byte{
		h1[:],
		h2[:],
	}
	root := BuildMerkleTreeRoot(leaves)

	sth := &SignedTreeHead{
		TreeSize:    2,
		Timestamp:   1234567890,
		RootHashHex: hex.EncodeToString(root[:]),
		LogID:       "log-test",
	}

	// Successful co-sign
	sig, err := pool.CoSign(sth, "witness-01", leaves)
	if err != nil || sig == nil {
		t.Fatalf("CoSign failed: %v", err)
	}
	if sig.Status != "verified" || sig.WitnessID != "witness-01" {
		t.Errorf("unexpected sig status: %+v", sig)
	}

	// Validate co-signature
	if !pool.ValidateWitnessSignature(sig) {
		t.Fatalf("expected signature validation to pass")
	}

	// Tampered signature must fail
	tamperedSig := *sig
	tamperedSig.Signature = "badc0ffee"
	if pool.ValidateWitnessSignature(&tamperedSig) {
		t.Fatalf("tampered signature unexpectedly passed validation")
	}

	// Unknown witness
	if _, err := pool.CoSign(sth, "unknown-witness", leaves); err != ErrWitnessNotFound {
		t.Errorf("expected ErrWitnessNotFound, got %v", err)
	}
}

func TestSplitViewAttackDetection(t *testing.T) {
	pool := NewWitnessPool()
	pool.RegisterWitness("witness-strict", []byte("strict-secret"))

	hOrig := ComputeLeafHash([]byte("original-leaf"))
	leavesA := [][]byte{
		hOrig[:],
	}
	rootA := BuildMerkleTreeRoot(leavesA)

	sthA := &SignedTreeHead{
		TreeSize:    1,
		Timestamp:   1000,
		RootHashHex: hex.EncodeToString(rootA[:]),
		LogID:       "log-test",
	}

	// Witness witnesses tree A at size 1
	sigA, err := pool.CoSign(sthA, "witness-strict", leavesA)
	if err != nil || sigA.Status != "verified" {
		t.Fatalf("first co-sign failed: %v", err)
	}

	// Attacker attempts split-view attack: presents different tree head at same size 1
	hFork := ComputeLeafHash([]byte("malicious-fork-leaf"))
	leavesB := [][]byte{
		hFork[:],
	}
	rootB := BuildMerkleTreeRoot(leavesB)

	sthFork := &SignedTreeHead{
		TreeSize:    1,
		Timestamp:   1005,
		RootHashHex: hex.EncodeToString(rootB[:]),
		LogID:       "log-test",
	}

	// Witness must detect split-view attack!
	sigFork, err := pool.CoSign(sthFork, "witness-strict", leavesB)
	if err != ErrSplitViewAttackDetected {
		t.Fatalf("expected ErrSplitViewAttackDetected, got %v", err)
	}
	if sigFork == nil || sigFork.Status != "conflict" {
		t.Errorf("expected conflict status, got %+v", sigFork)
	}

	// Rollback attempt (size 0) must also be rejected
	sthRollback := &SignedTreeHead{
		TreeSize:    0,
		Timestamp:   1010,
		RootHashHex: "0000",
		LogID:       "log-test",
	}
	if _, err := pool.CoSign(sthRollback, "witness-strict", nil); err != ErrSplitViewAttackDetected {
		t.Fatalf("expected ErrSplitViewAttackDetected for tree size rollback, got %v", err)
	}
}
