package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/transparency"
)

func TestClientTransparency(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/transparency/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transparency.TransparencyStatus{
			LogID:           "test-log",
			TreeSize:        5,
			RootHashHex:     "abcd1234",
			ActiveWitnesses: 3,
			ComplianceRFC:   "RFC 6962",
		})
	})

	mux.HandleFunc("/api/transparency/append", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"entry": &transparency.LogEntry{
				Index:       5,
				Action:      "license_created",
				TenantID:    "tenant-1",
				LeafHashHex: "beefcafe",
			},
			"sth": &transparency.SignedTreeHead{
				TreeSize:    6,
				RootHashHex: "feedface",
			},
		})
	})

	mux.HandleFunc("/api/transparency/sth", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transparency.SignedTreeHead{
			TreeSize:    6,
			RootHashHex: "feedface",
		})
	})

	mux.HandleFunc("/api/transparency/entries", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"start": 0,
			"count": 1,
			"entries": []*transparency.LogEntry{
				{Index: 0, Action: "init"},
			},
		})
	})

	mux.HandleFunc("/api/transparency/inclusion-proof", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transparency.InclusionProof{
			LeafIndex:    2,
			TreeSize:     6,
			AuditPathHex: []string{"hash1", "hash2"},
		})
	})

	mux.HandleFunc("/api/transparency/inclusion-proof/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"verified": true})
	})

	mux.HandleFunc("/api/transparency/consistency-proof", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transparency.ConsistencyProof{
			FirstSize:  3,
			SecondSize: 6,
			ProofHex:   []string{"hash3"},
		})
	})

	mux.HandleFunc("/api/transparency/consistency-proof/verify", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"verified": true})
	})

	mux.HandleFunc("/api/transparency/witness/cosign", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(transparency.WitnessSignature{
			WitnessID: "witness-01",
			Status:    "verified",
		})
	})

	mux.HandleFunc("/api/transparency/witnesses", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"witnesses": []string{"witness-01", "witness-02"},
			"count":     2,
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, nil, 5*time.Second)
	ctx := context.Background()

	status, err := client.GetTransparencyStatus(ctx)
	if err != nil || status.TreeSize != 5 {
		t.Fatalf("GetTransparencyStatus failed: %v", err)
	}

	entry, sth, err := client.AppendTransparencyEntry(ctx, "license_created", "tenant-1", map[string]string{"k": "v"})
	if err != nil || entry.Index != 5 || sth.TreeSize != 6 {
		t.Fatalf("AppendTransparencyEntry failed: %v", err)
	}

	curSTH, err := client.GetTransparencySTH(ctx)
	if err != nil || curSTH.TreeSize != 6 {
		t.Fatalf("GetTransparencySTH failed: %v", err)
	}

	entries, err := client.GetTransparencyEntries(ctx, 0, 1)
	if err != nil || len(entries) != 1 {
		t.Fatalf("GetTransparencyEntries failed: %v", err)
	}

	inc, err := client.GetTransparencyInclusionProof(ctx, 2, 6)
	if err != nil || len(inc.AuditPathHex) != 2 {
		t.Fatalf("GetTransparencyInclusionProof failed: %v", err)
	}

	validInc, err := client.VerifyTransparencyInclusionProof(ctx, inc)
	if err != nil || !validInc {
		t.Fatalf("VerifyTransparencyInclusionProof failed: %v", err)
	}

	cons, err := client.GetTransparencyConsistencyProof(ctx, 3, 6)
	if err != nil || len(cons.ProofHex) != 1 {
		t.Fatalf("GetTransparencyConsistencyProof failed: %v", err)
	}

	validCons, err := client.VerifyTransparencyConsistencyProof(ctx, cons)
	if err != nil || !validCons {
		t.Fatalf("VerifyTransparencyConsistencyProof failed: %v", err)
	}

	sig, err := client.CosignTransparencySTH(ctx, "witness-01")
	if err != nil || sig.Status != "verified" {
		t.Fatalf("CosignTransparencySTH failed: %v", err)
	}

	witnesses, err := client.ListTransparencyWitnesses(ctx)
	if err != nil || len(witnesses) != 2 {
		t.Fatalf("ListTransparencyWitnesses failed: %v", err)
	}
}
