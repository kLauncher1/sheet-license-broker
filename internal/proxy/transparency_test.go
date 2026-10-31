package proxy

import (
	"encoding/json"
	"testing"
)

func TestProxyTransparencyLifecycle(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("NewProxy failed: %v", err)
	}
	defer px.Close()

	status := px.GetTransparencyStatus()
	if status.TreeSize != 0 || status.ComplianceRFC != "RFC 6962" {
		t.Fatalf("unexpected initial transparency status: %+v", status)
	}

	// Append 5 audit entries through proxy
	for i := 0; i < 5; i++ {
		payload, _ := json.Marshal(map[string]interface{}{
			"event":  "license_key_generated",
			"key_id": i + 100,
		})
		entry, sth, err := px.AppendTransparencyAudit("license_key_generated", "tenant-test", payload)
		if err != nil {
			t.Fatalf("AppendTransparencyAudit %d failed: %v", i, err)
		}
		if entry.Index != int64(i) {
			t.Errorf("expected entry index %d, got %d", i, entry.Index)
		}
		if sth.TreeSize != int64(i+1) {
			t.Errorf("expected tree size %d, got %d", i+1, sth.TreeSize)
		}
	}

	// Verify STH
	sth := px.GetTransparencySTH()
	if sth == nil || sth.TreeSize != 5 {
		t.Fatalf("unexpected STH: %+v", sth)
	}

	// Verify entry retrieval
	e2, err := px.GetTransparencyEntry(2)
	if err != nil || e2 == nil {
		t.Fatalf("GetTransparencyEntry(2) failed: %v", err)
	}
	if e2.Index != 2 {
		t.Errorf("expected index 2, got %d", e2.Index)
	}

	// Range query
	entries, err := px.GetTransparencyEntries(1, 3)
	if err != nil || len(entries) != 3 {
		t.Fatalf("GetTransparencyEntries(1, 3) failed, len=%d: %v", len(entries), err)
	}

	// Inclusion Proof
	incProof, err := px.GetTransparencyInclusionProof(2, 5)
	if err != nil {
		t.Fatalf("GetTransparencyInclusionProof failed: %v", err)
	}
	if !px.VerifyTransparencyInclusionProof(incProof) {
		t.Fatalf("VerifyTransparencyInclusionProof returned false")
	}

	// Consistency Proof
	consProof, err := px.GetTransparencyConsistencyProof(2, 5)
	if err != nil {
		t.Fatalf("GetTransparencyConsistencyProof failed: %v", err)
	}
	if !px.VerifyTransparencyConsistencyProof(consProof) {
		t.Fatalf("VerifyTransparencyConsistencyProof returned false")
	}

	// Witnesses
	witnesses := px.ListTransparencyWitnesses()
	if len(witnesses) < 3 {
		t.Fatalf("expected at least 3 witnesses, got %d", len(witnesses))
	}

	// Co-sign
	sig, err := px.WitnessCosignTransparency(witnesses[0])
	if err != nil || sig == nil {
		t.Fatalf("WitnessCosignTransparency failed: %v", err)
	}
	if sig.Status != "verified" {
		t.Errorf("unexpected witness signature status: %s", sig.Status)
	}
}
