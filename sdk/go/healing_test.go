package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/healing"
)

func TestClient_HealingOperations(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/healing/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(healing.HealingStatus{
			Bucket: healing.TokenBucketStats{
				Capacity: 100,
			},
			ActiveTunnels: 2,
		})
	})

	mux.HandleFunc("/api/healing/bucket/consume", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(HealingConsumeResponse{
			Allowed: true,
			Stats: healing.TokenBucketStats{
				CurrentTokens: 95,
				Capacity:      100,
			},
		})
	})

	mux.HandleFunc("/api/healing/tunnel/ticket", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(healing.HealingTicket{
			SessionID: "sess-sdk-test",
			ClientID:  "client-sdk",
			Signature: "valid-sig-123",
		})
	})

	mux.HandleFunc("/api/healing/tunnel/resume", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(HealingResumeResponse{
			Status: "resumed",
			Session: &healing.HealingSession{
				SessionID: "sess-sdk-test",
				ClientID:  "client-sdk",
				State:     healing.TunnelStateResumed,
			},
			MissedCount: 0,
		})
	})

	mux.HandleFunc("/api/healing/quota/borrow", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(HealingBorrowResponse{
			Status: "success",
			Lease: &healing.QuotaLease{
				LeaseID: "lease-sdk-test",
				Amount:  500,
			},
		})
	})

	mux.HandleFunc("/api/healing/quota/return", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "returned"})
	})

	mux.HandleFunc("/api/healing/quota/rebalance", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(HealingRebalanceResponse{
			Status: "rebalanced",
			Events: []healing.QuotaRebalanceEvent{},
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, []byte("test-secret"), 5*time.Second)
	ctx := context.Background()

	// 1. Status
	status, err := client.GetHealingStatus(ctx)
	if err != nil || status.Bucket.Capacity != 100 {
		t.Fatalf("GetHealingStatus failed: %v", err)
	}

	// 2. Consume
	consumeRes, err := client.ConsumeHealingBucket(ctx, 5.0)
	if err != nil || !consumeRes.Allowed {
		t.Fatalf("ConsumeHealingBucket failed: %v", err)
	}

	// 3. Issue ticket
	ticket, err := client.IssueHealingTicket(ctx, "sess-sdk-test", "client-sdk", "HWID-1", "tenant-1", 0, 180)
	if err != nil || ticket.Signature == "" {
		t.Fatalf("IssueHealingTicket failed: %v", err)
	}

	// 4. Resume tunnel
	resumeRes, err := client.ResumeHealingTunnel(ctx, ticket)
	if err != nil || resumeRes.Session.State != healing.TunnelStateResumed {
		t.Fatalf("ResumeHealingTunnel failed: %v", err)
	}

	// 5. Borrow quota
	borrowRes, err := client.BorrowHealingQuota(ctx, "t-borrower", "t-lender", 500, 15)
	if err != nil || borrowRes.Lease.LeaseID != "lease-sdk-test" {
		t.Fatalf("BorrowHealingQuota failed: %v", err)
	}

	// 6. Return quota
	err = client.ReturnHealingQuota(ctx, borrowRes.Lease.LeaseID)
	if err != nil {
		t.Fatalf("ReturnHealingQuota failed: %v", err)
	}

	// 7. Rebalance
	rebalRes, err := client.RebalanceHealingQuotas(ctx)
	if err != nil || rebalRes.Status != "rebalanced" {
		t.Fatalf("RebalanceHealingQuotas failed: %v", err)
	}
}
