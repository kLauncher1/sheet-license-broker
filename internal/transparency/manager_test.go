package transparency

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestTransparencyManagerIntegration(t *testing.T) {
	mgr := NewManager("test-transparency-hub", []byte("master-test-key-32b-length!!"))

	status := mgr.GetStatus()
	if status.TreeSize != 0 || status.ActiveWitnesses != 3 {
		t.Fatalf("unexpected initial status: %+v", status)
	}

	// Append multiple audit entries
	for i := 0; i < 8; i++ {
		payload, _ := json.Marshal(map[string]interface{}{
			"action":    "license_issued",
			"license":   fmt.Sprintf("LIC-%04d", i),
			"device_id": fmt.Sprintf("HWID-%04d", i),
		})
		entry, sth, err := mgr.AppendAuditEntry("license_issued", "tenant-prime", payload)
		if err != nil {
			t.Fatalf("AppendAuditEntry %d failed: %v", i, err)
		}
		if entry.Index != int64(i) {
			t.Errorf("expected entry index %d, got %d", i, entry.Index)
		}
		if sth.TreeSize != int64(i+1) {
			t.Errorf("expected tree size %d, got %d", i+1, sth.TreeSize)
		}
		// Since autoCosign is enabled, all 3 witnesses should have signed
		if len(sth.WitnessSignatures) != 3 {
			t.Errorf("expected 3 witness co-signatures, got %d", len(sth.WitnessSignatures))
		}
	}

	// Verify status after inserts
	statusAfter := mgr.GetStatus()
	if statusAfter.TreeSize != 8 || statusAfter.TotalEntries != 8 {
		t.Errorf("expected tree size 8, got %d", statusAfter.TreeSize)
	}

	// Test Inclusion Proof generation & verification via Manager
	incProof, err := mgr.GetInclusionProof(3, 8)
	if err != nil {
		t.Fatalf("GetInclusionProof failed: %v", err)
	}
	if !mgr.VerifyInclusionProof(incProof) {
		t.Fatalf("VerifyInclusionProof returned false for valid proof")
	}

	// Corrupt inclusion proof and verify failure
	corruptedInc := *incProof
	corruptedInc.AuditPathHex = append([]string{}, incProof.AuditPathHex...)
	if len(corruptedInc.AuditPathHex) > 0 {
		corruptedInc.AuditPathHex[0] = "deadbeef" + corruptedInc.AuditPathHex[0][8:]
		if mgr.VerifyInclusionProof(&corruptedInc) {
			t.Fatalf("corrupted inclusion proof unexpectedly passed")
		}
	}

	// Test Consistency Proof generation & verification via Manager
	consProof, err := mgr.GetConsistencyProof(3, 8)
	if err != nil {
		t.Fatalf("GetConsistencyProof failed: %v", err)
	}
	if !mgr.VerifyConsistencyProof(consProof) {
		t.Fatalf("VerifyConsistencyProof returned false for valid proof")
	}

	// Corrupt consistency proof and verify failure
	corruptedCons := *consProof
	corruptedCons.FirstRootHex = "0000000000000000000000000000000000000000000000000000000000000000"
	if mgr.VerifyConsistencyProof(&corruptedCons) {
		t.Fatalf("corrupted consistency proof unexpectedly passed")
	}

	// Register a dynamic witness and manually co-sign
	mgr.RegisterWitness("witness-external-custom", []byte("external-secret-key-999"))
	sig, err := mgr.WitnessCosign("witness-external-custom")
	if err != nil || sig == nil {
		t.Fatalf("WitnessCosign failed: %v", err)
	}
	if sig.WitnessID != "witness-external-custom" || sig.Status != "verified" {
		t.Errorf("unexpected dynamic witness signature: %+v", sig)
	}

	latestSTH := mgr.GetSTH()
	if len(latestSTH.WitnessSignatures) != 4 {
		t.Errorf("expected 4 witness signatures on latest STH, got %d", len(latestSTH.WitnessSignatures))
	}
}
