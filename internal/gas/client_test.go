package gas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientLifecycle(t *testing.T) {
	// Mock Google Apps Script server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		action, _ := payload["action"].(string)
		w.Header().Set("Content-Type", "application/json")

		switch action {
		case "ping":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "success",
				"message":   "Sheet-License-Broker live",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			})

		case "register":
			username := payload["username"].(string)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":   "success",
				"user_id":  "usr_12345678",
				"username": username,
			})

		case "login":
			username := payload["username"].(string)
			password := payload["password"].(string)
			if password == "valid-pass" {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":   "success",
					"user_id":  "usr_12345678",
					"username": username,
					"role":     "admin",
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":  "error",
					"message": "Invalid credentials",
				})
			}

		case "create_license":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "success",
				"license_key": "KEY-DEMO-001",
				"expires_at":  time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
			})

		case "verify_license":
			key := payload["license_key"].(string)
			hwid := payload["hwid"].(string)
			if key == "KEY-VALID" && (hwid == "HWID-1" || hwid == "") {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":     "success",
					"verified":   true,
					"hwid_bound": "HWID-1",
					"expires_at": time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
				})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"status":   "error",
					"verified": false,
					"message":  "Device mismatch or invalid key",
				})
			}

		case "db_put":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "success",
				"action":     "created",
				"collection": payload["collection"],
				"doc_id":      payload["doc_id"],
			})

		case "db_get":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "success",
				"collection": payload["collection"],
				"doc_id":      payload["doc_id"],
				"data":       map[string]interface{}{"setting": "dark_mode"},
				"updated_at": time.Now().UTC().Format(time.RFC3339),
			})

		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"message": "Unknown action",
			})
		}
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		WebAppURL:   server.URL,
		Timeout:     5 * time.Second,
		MaxRetries:  2,
		BackoffBase: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to initialize client: %v", err)
	}

	ctx := context.Background()

	// 1. Ping test
	ping, err := client.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
	if ping.Status != "success" {
		t.Errorf("Unexpected ping status: %s", ping.Status)
	}

	// 2. Register test
	reg, err := client.RegisterUser(ctx, "testuser", "securepass")
	if err != nil {
		t.Fatalf("RegisterUser failed: %v", err)
	}
	if reg.UserID != "usr_12345678" {
		t.Errorf("Unexpected user id: %s", reg.UserID)
	}

	// 3. Login test (success and failure)
	login, err := client.LoginUser(ctx, "testuser", "valid-pass")
	if err != nil {
		t.Fatalf("LoginUser valid failed: %v", err)
	}
	if login.Role != "admin" {
		t.Errorf("Unexpected role: %s", login.Role)
	}

	_, err = client.LoginUser(ctx, "testuser", "wrong-pass")
	if err == nil {
		t.Fatal("Expected error on invalid password, got nil")
	}

	// 4. Create & Verify License
	lic, err := client.CreateLicense(ctx, "KEY-DEMO-001", 30, 1)
	if err != nil {
		t.Fatalf("CreateLicense failed: %v", err)
	}
	if lic.LicenseKey != "KEY-DEMO-001" {
		t.Errorf("Unexpected license key: %s", lic.LicenseKey)
	}

	verify, err := client.VerifyLicense(ctx, "KEY-VALID", "HWID-1")
	if err != nil {
		t.Fatalf("VerifyLicense failed: %v", err)
	}
	if !verify.Verified || verify.HWIDBound != "HWID-1" {
		t.Errorf("Unexpected verification result: %+v", verify)
	}

	_, err = client.VerifyLicense(ctx, "KEY-INVALID", "HWID-1")
	if err == nil {
		t.Fatal("Expected error on invalid license, got nil")
	}

	// 5. KV Put and Get
	putDoc, err := client.PutDocument(ctx, "settings", "theme", map[string]string{"mode": "dark"})
	if err != nil {
		t.Fatalf("PutDocument failed: %v", err)
	}
	if putDoc.Action != "created" {
		t.Errorf("Unexpected action: %s", putDoc.Action)
	}

	getDoc, err := client.GetDocument(ctx, "settings", "theme")
	if err != nil {
		t.Fatalf("GetDocument failed: %v", err)
	}
	if getDoc.Collection != "settings" {
		t.Errorf("Unexpected collection: %s", getDoc.Collection)
	}
}

func TestClientRedirectAndRetry(t *testing.T) {
	// Simulate Google Apps Script 302 redirect behavior to echo endpoint
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"message": "echo content",
		})
	}))
	defer echoServer.Close()

	var attempts int32
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		curr := atomic.AddInt32(&attempts, 1)
		if curr == 1 {
			// First attempt returns 429 to trigger retry logic
			http.Error(w, "Rate limited", http.StatusTooManyRequests)
			return
		}
		// Second attempt issues 302 redirect to echoServer
		http.Redirect(w, r, echoServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	client, err := NewClient(ClientConfig{
		WebAppURL:   redirectServer.URL,
		Timeout:     5 * time.Second,
		MaxRetries:  3,
		BackoffBase: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	resp, err := client.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping with redirect and retry failed: %v", err)
	}
	if resp.Status != "success" || resp.Message != "echo content" {
		t.Errorf("Unexpected response: %+v", resp)
	}
}
