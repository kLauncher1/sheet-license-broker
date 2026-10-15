package zkp

import (
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"
)

func TestPedersenCommitmentHidingAndBinding(t *testing.T) {
	hwid1 := "HWID-TEST-0001-ALPHA"
	hwid2 := "HWID-TEST-0002-BRAVO"

	v1 := HashToScalar(hwid1)
	v2 := HashToScalar(hwid2)

	r1, err := RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate r1: %v", err)
	}
	r2, err := RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate r2: %v", err)
	}

	c1 := CommitPedersen(v1, r1)
	c2 := CommitPedersen(v2, r2)
	c1Alt := CommitPedersen(v1, r2) // same value, different blinding factor

	if c1.Equal(c2) {
		t.Errorf("Commitments for different values should not be equal")
	}
	if c1.Equal(c1Alt) {
		t.Errorf("Commitments for same value with different blinding factor should not be equal (hiding violated)")
	}

	curve, _ := GetCurve()
	if !curve.IsOnCurve(c1.X, c1.Y) {
		t.Errorf("Commitment c1 is not on elliptic curve P-256")
	}
	if !curve.IsOnCurve(c2.X, c2.Y) {
		t.Errorf("Commitment c2 is not on elliptic curve P-256")
	}
}

func TestZKPProofGenerationAndVerification(t *testing.T) {
	verifier, err := NewVerifier(nil)
	if err != nil {
		t.Fatalf("Failed to initialize verifier: %v", err)
	}

	hwid := "HWID-WIN-9876-DEVICE"
	v := HashToScalar(hwid)
	r, err := RandomScalar()
	if err != nil {
		t.Fatalf("Failed to generate scalar r: %v", err)
	}

	comm := CommitPedersen(v, r)

	// Issue credential for Pro tier
	cred, err := verifier.IssueCredential(comm, TierPro, 2, 30, "production", "tenant-test")
	if err != nil {
		t.Fatalf("Failed to issue credential: %v", err)
	}

	epoch := time.Now().Unix() / 3600
	proof, err := GenerateZKPProof(hwid, r, cred, epoch, "tenant-test")
	if err != nil {
		t.Fatalf("Failed to generate ZKP proof: %v", err)
	}

	// Verify demanding Pro tier
	res := verifier.VerifyProof(proof, TierPro, epoch)
	if !res.Valid {
		t.Fatalf("Proof verification failed: %s", res.Reason)
	}
	if res.ClaimedTier != TierPro {
		t.Errorf("Expected ClaimedTier %d, got %d", TierPro, res.ClaimedTier)
	}
	if res.TierName != "pro" {
		t.Errorf("Expected TierName 'pro', got '%s'", res.TierName)
	}
	if res.TenantID != "tenant-test" {
		t.Errorf("Expected TenantID 'tenant-test', got '%s'", res.TenantID)
	}

	// Verify status telemetry
	status := verifier.Status()
	if status.TotalCredentialsIssued != 1 {
		t.Errorf("Expected 1 credential issued, got %d", status.TotalCredentialsIssued)
	}
	if status.TotalProofsVerified != 1 {
		t.Errorf("Expected 1 proof verified, got %d", status.TotalProofsVerified)
	}
	if status.SpentNullifiersCount != 1 {
		t.Errorf("Expected 1 spent nullifier, got %d", status.SpentNullifiersCount)
	}
}

func TestZKPInsufficientTierRejected(t *testing.T) {
	verifier, _ := NewVerifier(nil)

	hwid := "HWID-MAC-FREE-TIER"
	v := HashToScalar(hwid)
	r, _ := RandomScalar()
	comm := CommitPedersen(v, r)

	// Issue Free tier credential
	cred, _ := verifier.IssueCredential(comm, TierFree, 1, 30, "default", "tenant-alpha")
	epoch := time.Now().Unix() / 3600

	proof, err := GenerateZKPProof(hwid, r, cred, epoch, "tenant-alpha")
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Demand Enterprise tier
	res := verifier.VerifyProof(proof, TierEnterprise, epoch)
	if res.Valid {
		t.Errorf("Verification should have failed due to insufficient tier")
	}
	if res.Reason == "" {
		t.Errorf("Expected non-empty failure reason")
	}
}

func TestZKPExpiredCredentialRejected(t *testing.T) {
	verifier, _ := NewVerifier(nil)

	hwid := "HWID-LINUX-EXPIRED"
	v := HashToScalar(hwid)
	r, _ := RandomScalar()
	comm := CommitPedersen(v, r)

	// Issue credential with negative days (already expired)
	cred, _ := verifier.IssueCredential(comm, TierPro, 1, 30, "default", "tenant-alpha")
	cred.ExpiresAt = time.Now().Unix() - 100 // Force expired timestamp

	epoch := time.Now().Unix() / 3600
	proof, _ := GenerateZKPProof(hwid, r, cred, epoch, "tenant-alpha")

	res := verifier.VerifyProof(proof, TierPro, epoch)
	if res.Valid {
		t.Errorf("Verification should have failed for expired credential")
	}
}

func TestZKPDuplicateNullifierRejected(t *testing.T) {
	verifier, _ := NewVerifier(nil)

	hwid := "HWID-REPLAY-ATTACK"
	v := HashToScalar(hwid)
	r, _ := RandomScalar()
	comm := CommitPedersen(v, r)

	cred, _ := verifier.IssueCredential(comm, TierPro, 1, 30, "default", "tenant-alpha")
	epoch := time.Now().Unix() / 3600

	proof, _ := GenerateZKPProof(hwid, r, cred, epoch, "tenant-alpha")

	// First presentation succeeds
	res1 := verifier.VerifyProof(proof, TierPro, epoch)
	if !res1.Valid {
		t.Fatalf("Initial verification failed: %s", res1.Reason)
	}

	// Second presentation in the same epoch with same nullifier must fail
	res2 := verifier.VerifyProof(proof, TierPro, epoch)
	if res2.Valid {
		t.Errorf("Expected duplicate nullifier presentation to be rejected (anti-replay)")
	}

	spent, spentEpoch := verifier.CheckNullifier(proof.Nullifier)
	if !spent || spentEpoch != epoch {
		t.Errorf("Expected nullifier to be recorded as spent at epoch %d", epoch)
	}
}

func TestZKPTamperedAnnouncementOrResponseRejected(t *testing.T) {
	verifier, _ := NewVerifier(nil)

	hwid := "HWID-TAMPER-PROOF"
	v := HashToScalar(hwid)
	r, _ := RandomScalar()
	comm := CommitPedersen(v, r)

	cred, _ := verifier.IssueCredential(comm, TierPro, 1, 30, "default", "tenant-alpha")
	epoch := time.Now().Unix() / 3600

	proof, _ := GenerateZKPProof(hwid, r, cred, epoch, "tenant-alpha")

	// Tamper response scalar Sv
	proof.ResponseV = new(big.Int).Add(proof.ResponseV, big.NewInt(1))

	res := verifier.VerifyProof(proof, TierPro, epoch)
	if res.Valid {
		t.Errorf("Tampered response Sv should have failed verification")
	}
}

func TestZKPTamperedSignatureRejected(t *testing.T) {
	verifier, _ := NewVerifier(nil)

	hwid := "HWID-TAMPER-SIG"
	v := HashToScalar(hwid)
	r, _ := RandomScalar()
	comm := CommitPedersen(v, r)

	cred, _ := verifier.IssueCredential(comm, TierPro, 1, 30, "default", "tenant-alpha")
	epoch := time.Now().Unix() / 3600

	proof, _ := GenerateZKPProof(hwid, r, cred, epoch, "tenant-alpha")

	// Tamper signature R
	proof.SignatureR = new(big.Int).Add(proof.SignatureR, big.NewInt(1))

	res := verifier.VerifyProof(proof, TierPro, epoch)
	if res.Valid {
		t.Errorf("Tampered signature should have failed verification")
	}
}

func TestZKPConcurrentVerification(t *testing.T) {
	verifier, _ := NewVerifier(nil)
	var wg sync.WaitGroup
	workers := 20
	errChan := make(chan error, workers)

	epoch := time.Now().Unix() / 3600

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hwid := fmt.Sprintf("HWID-CONCURRENT-WORKER-%04d", id)
			v := HashToScalar(hwid)
			r, err := RandomScalar()
			if err != nil {
				errChan <- fmt.Errorf("worker %d: random scalar failed: %w", id, err)
				return
			}
			comm := CommitPedersen(v, r)
			cred, err := verifier.IssueCredential(comm, TierEnterprise, 5, 60, "cluster", "tenant-multi")
			if err != nil {
				errChan <- fmt.Errorf("worker %d: credential issuance failed: %w", id, err)
				return
			}
			proof, err := GenerateZKPProof(hwid, r, cred, epoch, "tenant-multi")
			if err != nil {
				errChan <- fmt.Errorf("worker %d: proof generation failed: %w", id, err)
				return
			}
			res := verifier.VerifyProof(proof, TierPro, epoch)
			if !res.Valid {
				errChan <- fmt.Errorf("worker %d: verification failed: %s", id, res.Reason)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Fatal(err)
	}

	status := verifier.Status()
	if int(status.TotalCredentialsIssued) != workers {
		t.Errorf("Expected %d credentials, got %d", workers, status.TotalCredentialsIssued)
	}
	if int(status.TotalProofsVerified) != workers {
		t.Errorf("Expected %d proofs verified, got %d", workers, status.TotalProofsVerified)
	}
}
