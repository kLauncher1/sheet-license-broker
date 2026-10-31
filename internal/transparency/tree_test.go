package transparency

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestTransparencyTreeLifecycle(t *testing.T) {
	tree := NewTransparencyTree("test-log-001", []byte("secret-key-123"))

	if tree.Size() != 0 {
		t.Fatalf("expected empty tree size 0, got %d", tree.Size())
	}

	initialSTH := tree.LatestSTH()
	if initialSTH == nil || initialSTH.TreeSize != 0 {
		t.Fatalf("unexpected initial STH: %+v", initialSTH)
	}

	// Append 10 entries
	for i := 0; i < 10; i++ {
		payload, _ := json.Marshal(map[string]interface{}{
			"license": fmt.Sprintf("LIC-TEST-%03d", i),
			"tier":    "pro",
			"active":  true,
		})
		entry, sth, err := tree.AppendEntry("license_created", "tenant-alpha", payload)
		if err != nil {
			t.Fatalf("AppendEntry failed at index %d: %v", i, err)
		}
		if entry.Index != int64(i) {
			t.Errorf("expected entry index %d, got %d", i, entry.Index)
		}
		if sth.TreeSize != int64(i+1) {
			t.Errorf("expected STH size %d, got %d", i+1, sth.TreeSize)
		}
	}

	if tree.Size() != 10 {
		t.Fatalf("expected tree size 10, got %d", tree.Size())
	}

	// Verify retrieval by index
	entry3, err := tree.GetEntry(3)
	if err != nil || entry3 == nil {
		t.Fatalf("GetEntry(3) failed: %v", err)
	}
	if entry3.Index != 3 || entry3.Action != "license_created" {
		t.Errorf("unexpected entry3 contents: %+v", entry3)
	}

	// Out of bounds get
	if _, err := tree.GetEntry(10); err != ErrInvalidLeafIndex {
		t.Errorf("expected ErrInvalidLeafIndex for index 10, got %v", err)
	}

	// Range query
	slice, err := tree.GetEntries(2, 4)
	if err != nil {
		t.Fatalf("GetEntries(2, 4) failed: %v", err)
	}
	if len(slice) != 4 {
		t.Fatalf("expected 4 entries in slice, got %d", len(slice))
	}
	if slice[0].Index != 2 || slice[3].Index != 5 {
		t.Errorf("unexpected slice indices: first=%d, last=%d", slice[0].Index, slice[3].Index)
	}

	// Generate and verify inclusion proof for leaf 5 in tree size 10
	incProof, err := tree.GenerateInclusionProof(5, 10)
	if err != nil {
		t.Fatalf("GenerateInclusionProof failed: %v", err)
	}
	if incProof.LeafIndex != 5 || incProof.TreeSize != 10 {
		t.Errorf("unexpected incProof metadata: %+v", incProof)
	}

	// Generate and verify consistency proof between size 4 and size 10
	consProof, err := tree.GenerateConsistencyProof(4, 10)
	if err != nil {
		t.Fatalf("GenerateConsistencyProof failed: %v", err)
	}
	if consProof.FirstSize != 4 || consProof.SecondSize != 10 {
		t.Errorf("unexpected consProof metadata: %+v", consProof)
	}
}
