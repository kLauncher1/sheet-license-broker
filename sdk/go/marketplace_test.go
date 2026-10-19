package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/marketplace"
)

func TestGoClientMarketplaceWorkflow(t *testing.T) {
	mux := http.NewServeMux()

	// 1. /api/marketplace/status
	mux.HandleFunc("/api/marketplace/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":                  true,
			"stripe_configured":        true,
			"lemon_squeezy_configured": true,
			"paddle_configured":        true,
			"total_provisioned":        10,
		})
	})

	// 2. /api/marketplace/simulate
	mux.HandleFunc("/api/marketplace/simulate", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(MarketplaceSimulateResponse{
			Status: "success",
			Event: &marketplace.NormalizedEvent{
				Provider:      "stripe",
				EventType:     "checkout.session.completed",
				Action:        "provision",
				CustomerEmail: "buyer@example.com",
				Tier:          "enterprise",
				Seats:         5,
				DaysValid:     365,
				Timestamp:     time.Now().UTC(),
			},
			Transaction: &marketplace.TransactionRecord{
				ID:            "tx_12345",
				EventID:       "sim_stripe_1",
				Provider:      "stripe",
				Action:        "provision",
				CustomerEmail: "buyer@example.com",
				LicenseKey:    "KEY-MKT-PROV-1",
				Tier:          "enterprise",
				Seats:         5,
				Status:        "PROVISIONED",
				ProcessedAt:   time.Now().UTC(),
			},
		})
	})

	// 3. /api/marketplace/transactions
	mux.HandleFunc("/api/marketplace/transactions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]marketplace.TransactionRecord{
			{
				ID:            "tx_12345",
				EventID:       "sim_stripe_1",
				Provider:      "stripe",
				Action:        "provision",
				CustomerEmail: "buyer@example.com",
				LicenseKey:    "KEY-MKT-PROV-1",
				Tier:          "enterprise",
				Seats:         5,
				Status:        "PROVISIONED",
				ProcessedAt:   time.Now().UTC(),
			},
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(server.URL, []byte("test-secret"), 5*time.Second)
	ctx := context.Background()

	// Test GetMarketplaceStatus
	status, err := client.GetMarketplaceStatus(ctx)
	if err != nil {
		t.Fatalf("GetMarketplaceStatus failed: %v", err)
	}
	if status["enabled"] != true || status["total_provisioned"].(float64) != 10 {
		t.Fatalf("unexpected status: %+v", status)
	}

	// Test SimulateMarketplaceWebhook
	simRes, err := client.SimulateMarketplaceWebhook(ctx, "stripe", "provision", "buyer@example.com", "enterprise", 5, 365)
	if err != nil {
		t.Fatalf("SimulateMarketplaceWebhook failed: %v", err)
	}
	if simRes.Transaction.LicenseKey != "KEY-MKT-PROV-1" || simRes.Transaction.Status != "PROVISIONED" {
		t.Fatalf("unexpected simulate response: %+v", simRes)
	}

	// Test ListMarketplaceTransactions
	txList, err := client.ListMarketplaceTransactions(ctx)
	if err != nil {
		t.Fatalf("ListMarketplaceTransactions failed: %v", err)
	}
	if len(txList) != 1 || txList[0].LicenseKey != "KEY-MKT-PROV-1" {
		t.Fatalf("unexpected transactions: %+v", txList)
	}

	// Test ListMarketplaceTransactionsWithOptions
	txFiltered, err := client.ListMarketplaceTransactionsWithOptions(ctx, MarketplaceFilterOptions{
		Provider:      "stripe",
		CustomerEmail: "buyer@example.com",
		Status:        "PROVISIONED",
		Limit:         10,
	})
	if err != nil {
		t.Fatalf("ListMarketplaceTransactionsWithOptions failed: %v", err)
	}
	if len(txFiltered) != 1 || txFiltered[0].Provider != "stripe" {
		t.Fatalf("unexpected filtered transactions: %+v", txFiltered)
	}
}
