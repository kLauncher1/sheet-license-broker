package gas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientBlacklistAndRevoke(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		action, _ := req["action"].(string)

		w.Header().Set("Content-Type", "application/json")

		switch action {
		case "revoke_license":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "success",
				"message": "License successfully revoked",
			})
		case "blacklist_add":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "success",
				"message": "Target blacklisted",
				"type":    req["type"],
				"target":  req["target"],
			})
		case "blacklist_list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "success",
				"entries": []map[string]string{
					{
						"type":       "device",
						"target":     "HWID-TEST-001",
						"reason":     "Breach",
						"created_at": "2026-10-14T00:00:00Z",
					},
				},
			})
		case "blacklist_remove":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "success",
				"message": "Target unblacklisted",
			})
		default:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": "Unknown action"})
		}
	}))
	defer ts.Close()

	client, err := NewClient(ClientConfig{
		WebAppURL: ts.URL,
		Timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()

	// 1. Revoke License
	revRes, err := client.RevokeLicense(ctx, "KEY-XYZ-999", "Fraudulent transaction")
	if err != nil || revRes.Status != "success" {
		t.Fatalf("RevokeLicense failed: %v", err)
	}

	// 2. Blacklist Add
	addRes, err := client.BlacklistAdd(ctx, "device", "HWID-TEST-001", "Breach")
	if err != nil || addRes.Status != "success" {
		t.Fatalf("BlacklistAdd failed: %v", err)
	}

	// 3. Blacklist List
	listRes, err := client.BlacklistList(ctx)
	if err != nil || len(listRes.Entries) != 1 {
		t.Fatalf("BlacklistList failed: %v, entries: %d", err, len(listRes.Entries))
	}

	// 4. Blacklist Remove
	remRes, err := client.BlacklistRemove(ctx, "device", "HWID-TEST-001")
	if err != nil || remRes.Status != "success" {
		t.Fatalf("BlacklistRemove failed: %v", err)
	}
}
