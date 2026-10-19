package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/marketplace"
	"github.com/kLauncher1/sheet-license-broker/internal/proxy"
	"github.com/kLauncher1/sheet-license-broker/internal/security"
	"github.com/kLauncher1/sheet-license-broker/internal/stream"
)

func setupMarketplaceTestServer(t *testing.T, stripeSecret, lsSecret, pdlSecret string) (*AppServer, http.Handler) {
	t.Helper()
	px, err := proxy.NewProxy(proxy.ProxyConfig{
		OfflineMode:               true,
		StripeWebhookSecret:       stripeSecret,
		LemonSqueezyWebhookSecret: lsSecret,
		PaddleWebhookSecret:       pdlSecret,
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	secGuard := security.NewGuard([]byte("test-secret"), 5*time.Minute, false)
	server := &AppServer{proxy: px, guard: secGuard}

	apiMux := http.NewServeMux()
	mux := http.NewServeMux()
	mux.Handle("/api/", server.guard.Middleware(apiMux))
	server.registerMarketplaceRoutes(apiMux, mux)
	return server, mux
}

func makeStripeSig(secret string, body []byte, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.%s", ts, string(body))))
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func TestMarketplaceStatusEndpoint(t *testing.T) {
	server, handler := setupMarketplaceTestServer(t, "stripe_sec", "ls_sec", "pdl_sec")
	defer server.proxy.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/marketplace/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", w.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	if res["enabled"] != true {
		t.Fatalf("expected enabled marketplace")
	}
	if res["stripe_configured"] != true || res["lemon_squeezy_configured"] != true || res["paddle_configured"] != true {
		t.Fatalf("expected all providers configured: %+v", res)
	}
}

func TestMarketplaceStripeWebhookEndpoint(t *testing.T) {
	stripeSecret := "whsec_stripe_endpoint_secret"
	server, handler := setupMarketplaceTestServer(t, stripeSecret, "", "")
	defer server.proxy.Close()

	body := []byte(`{"id":"evt_endpoint_stripe_1","type":"checkout.session.completed","created":12345,"data":{"object":{"id":"cs_order_endpoint_1","customer_email":"stripe_api_user@test.com","metadata":{"tier":"enterprise","seats":"10"}}}}`)
	nowUnix := time.Now().Unix()
	sig := makeStripeSig(stripeSecret, body, nowUnix)

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/webhook/stripe", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", w.Code, w.Body.String())
	}

	var res struct {
		Status      string                         `json:"status"`
		Provider    string                         `json:"provider"`
		Transaction *marketplace.TransactionRecord `json:"transaction"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res.Status != "success" || res.Transaction.Status != "PROVISIONED" {
		t.Fatalf("unexpected response: %+v", res)
	}

	// Tampered webhook test
	reqTampered := httptest.NewRequest(http.MethodPost, "/api/marketplace/webhook/stripe", bytes.NewReader([]byte(`tampered`)))
	reqTampered.Header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", nowUnix, sig))
	wTampered := httptest.NewRecorder()
	handler.ServeHTTP(wTampered, reqTampered)
	if wTampered.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on tampered webhook, got: %d", wTampered.Code)
	}
}

func TestMarketplaceLemonSqueezyWebhookEndpoint(t *testing.T) {
	lsSecret := "ls_endpoint_secret_key"
	server, handler := setupMarketplaceTestServer(t, "", lsSecret, "")
	defer server.proxy.Close()

	body := []byte(`{
		"meta": {
			"event_name": "order_created",
			"custom_data": {"tier": "pro", "seats": "3"}
		},
		"data": {
			"id": "ls_endpoint_ord_1",
			"type": "orders",
			"attributes": {
				"user_email": "ls_user@test.com",
				"order_number": 5544,
				"total": 4900,
				"currency": "USD"
			}
		}
	}`)

	mac := hmac.New(sha256.New, []byte(lsSecret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/webhook/lemonsqueezy", bytes.NewReader(body))
	req.Header.Set("X-Signature", sig)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestMarketplacePaddleWebhookEndpoint(t *testing.T) {
	pdlSecret := "pdl_endpoint_secret_key"
	server, handler := setupMarketplaceTestServer(t, "", "", pdlSecret)
	defer server.proxy.Close()

	body := []byte(`{
		"event_id": "evt_endpoint_pdl_1",
		"event_type": "transaction.completed",
		"occurred_at": "2026-10-19T10:00:00Z",
		"data": {
			"id": "txn_endpoint_pdl_1",
			"customer": {
				"email": "pdl_user@test.com",
				"name": "Paddle User"
			},
			"custom_data": {"tier": "pro", "seats": "2"},
			"details": {
				"totals": {"total": "39.00", "currency_code": "USD"}
			}
		}
	}`)

	nowUnix := time.Now().Unix()
	payload := fmt.Sprintf("%d:%s", nowUnix, string(body))
	mac := hmac.New(sha256.New, []byte(pdlSecret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/webhook/paddle", bytes.NewReader(body))
	req.Header.Set("Paddle-Signature", fmt.Sprintf("ts=%d;h1=%s", nowUnix, sig))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestMarketplaceSimulateAndTransactionsEndpoint(t *testing.T) {
	server, handler := setupMarketplaceTestServer(t, "", "", "")
	defer server.proxy.Close()

	// 1. Simulate provision
	simReqBody := []byte(`{
		"provider": "stripe",
		"action": "provision",
		"customer_email": "simulated@example.com",
		"tier": "enterprise",
		"seats": 5,
		"days_valid": 90
	}`)

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/simulate", bytes.NewReader(simReqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on simulate, got: %d", w.Code)
	}

	var res struct {
		Status      string                         `json:"status"`
		Transaction *marketplace.TransactionRecord `json:"transaction"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode simulate response: %v", err)
	}

	if res.Transaction.Status != "PROVISIONED" || res.Transaction.Tier != "enterprise" || res.Transaction.Seats != 5 {
		t.Fatalf("unexpected simulate transaction: %+v", res.Transaction)
	}

	// 2. Query transactions endpoint
	reqTx := httptest.NewRequest(http.MethodGet, "/api/marketplace/transactions", nil)
	wTx := httptest.NewRecorder()
	handler.ServeHTTP(wTx, reqTx)

	if wTx.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on transactions, got: %d", wTx.Code)
	}

	var txList []marketplace.TransactionRecord
	if err := json.Unmarshal(wTx.Body.Bytes(), &txList); err != nil {
		t.Fatalf("failed to decode transactions list: %v", err)
	}

	if len(txList) != 1 || txList[0].CustomerEmail != "simulated@example.com" {
		t.Fatalf("unexpected transactions list: %+v", txList)
	}

	// 3. Simulate revoke for same customer
	simRevokeBody := []byte(`{
		"provider": "stripe",
		"action": "revoke",
		"customer_email": "simulated@example.com"
	}`)
	reqRevoke := httptest.NewRequest(http.MethodPost, "/api/marketplace/simulate", bytes.NewReader(simRevokeBody))
	wRevoke := httptest.NewRecorder()
	handler.ServeHTTP(wRevoke, reqRevoke)

	if wRevoke.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on simulate revoke, got: %d", wRevoke.Code)
	}
}

func TestMarketplaceMalformedPayloadWithValidHMAC(t *testing.T) {
	stripeSecret := "whsec_stripe_endpoint_secret"
	server, handler := setupMarketplaceTestServer(t, stripeSecret, "", "")
	defer server.proxy.Close()

	body := []byte(`{not-a-valid-json: [corrupt_bytes}`)
	nowUnix := time.Now().Unix()
	sig := makeStripeSig(stripeSecret, body, nowUnix)

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/webhook/stripe", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Signature verification succeeds, but payload normalization fails with 400 Bad Request
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on malformed payload with valid HMAC, got: %d (%s)", w.Code, w.Body.String())
	}
}

func TestMarketplaceSecurityEnforcementMode(t *testing.T) {
	stripeSecret := "whsec_stripe_endpoint_secret"
	server, handler := setupMarketplaceTestServer(t, stripeSecret, "", "")
	defer server.proxy.Close()

	// Turn on strict internal HMAC signature enforcement
	server.guard.SetEnforced(true)

	// 1. Inbound Stripe webhook without internal HMAC headers should SUCCEED
	body := []byte(`{"id":"evt_enforced_1","type":"checkout.session.completed","created":12345,"data":{"object":{"id":"cs_enforced_1","customer_email":"enforced@example.com"}}}`)
	nowUnix := time.Now().Unix()
	sig := makeStripeSig(stripeSecret, body, nowUnix)

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/webhook/stripe", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for external webhook even under enforcement mode, got: %d (%s)", w.Code, w.Body.String())
	}

	// 2. Internal /api/marketplace/simulate WITHOUT internal HMAC headers should be BLOCKED (401)
	reqSim := httptest.NewRequest(http.MethodPost, "/api/marketplace/simulate", bytes.NewReader([]byte(`{"action":"provision"}`)))
	wSim := httptest.NewRecorder()
	handler.ServeHTTP(wSim, reqSim)

	if wSim.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated internal simulate endpoint under enforcement mode, got: %d", wSim.Code)
	}
}

func TestMarketplaceRevocationSSEKillSwitchPush(t *testing.T) {
	server, handler := setupMarketplaceTestServer(t, "", "", "")
	defer server.proxy.Close()

	// 1. Provision license via simulate
	simReqBody := []byte(`{
		"provider": "stripe",
		"action": "provision",
		"customer_email": "stream_user@example.com",
		"tier": "enterprise"
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/simulate", bytes.NewReader(simReqBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("simulate provision failed: %d (%s)", w.Code, w.Body.String())
	}

	var res struct {
		Transaction *marketplace.TransactionRecord `json:"transaction"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	issuedKey := res.Transaction.LicenseKey
	if issuedKey == "" {
		t.Fatalf("expected issued license key")
	}

	// 2. Register mock active stream client
	hub := server.proxy.StreamHub()
	mockClient := stream.NewClient("client-test-01", nil, hub, stream.ClientInfo{
		LicenseKey: issuedKey,
		HWID:       "HWID-REVOKE-TEST",
	})
	hub.Register(mockClient)
	defer hub.Unregister(mockClient)

	// 3. Simulate revoke for same customer
	simRevokeBody := []byte(`{
		"provider": "stripe",
		"action": "revoke",
		"customer_email": "stream_user@example.com"
	}`)
	reqRevoke := httptest.NewRequest(http.MethodPost, "/api/marketplace/simulate", bytes.NewReader(simRevokeBody))
	wRevoke := httptest.NewRecorder()
	handler.ServeHTTP(wRevoke, reqRevoke)

	if wRevoke.Code != http.StatusOK {
		t.Fatalf("simulate revoke failed: %d (%s)", wRevoke.Code, wRevoke.Body.String())
	}

	// 4. Verify stream client channel received kill switch message
	select {
	case msgBytes := <-mockClient.SendChanForTest():
		if !strings.Contains(string(msgBytes), "stream:revocation") && !strings.Contains(string(msgBytes), "stream:kill_switch") {
			t.Fatalf("expected stream:revocation or stream:kill_switch event, got: %s", string(msgBytes))
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timed out waiting for kill switch push on active stream client")
	}
}

func TestMarketplaceDownstreamExecutionErrorReturns500(t *testing.T) {
	stripeSecret := "whsec_stripe_endpoint_secret"
	server, handler := setupMarketplaceTestServer(t, stripeSecret, "", "")
	defer server.proxy.Close()

	// Simulate downstream provisioning failure (e.g., database connection error)
	server.proxy.MarketplaceManager().SetProvisioner(func(daysValid, maxDevices int, tier string, features []string) (string, error) {
		return "", fmt.Errorf("database connection refused")
	})

	body := []byte(`{"id":"evt_downstream_fail_1","type":"checkout.session.completed","created":12345,"data":{"object":{"id":"cs_order_fail_1","customer_email":"fail_buyer@test.com"}}}`)
	nowUnix := time.Now().Unix()
	sig := makeStripeSig(stripeSecret, body, nowUnix)

	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/webhook/stripe", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Must return 500 so upstream provider retries
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 InternalServerError on downstream execution failure, got: %d (%s)", w.Code, w.Body.String())
	}
}

func TestMarketplaceGenericWebhookWithoutTrailingSlash(t *testing.T) {
	stripeSecret := "whsec_stripe_endpoint_secret"
	server, handler := setupMarketplaceTestServer(t, stripeSecret, "", "")
	defer server.proxy.Close()

	server.guard.SetEnforced(true)

	body := []byte(`{"id":"evt_generic_noslash_1","type":"checkout.session.completed","created":12345,"data":{"object":{"id":"cs_generic_noslash_1","customer_email":"generic@example.com"}}}`)
	nowUnix := time.Now().Unix()
	sig := makeStripeSig(stripeSecret, body, nowUnix)

	// Request sent to /api/marketplace/webhook?provider=stripe without trailing slash
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/webhook?provider=stripe", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/marketplace/webhook without trailing slash, got: %d (%s)", w.Code, w.Body.String())
	}
}

func TestMarketplaceTransactionsFiltering(t *testing.T) {
	server, handler := setupMarketplaceTestServer(t, "", "", "")
	defer server.proxy.Close()

	// Seed multiple transactions
	buyers := []struct {
		email    string
		provider string
	}{
		{"alice@test.com", "stripe"},
		{"bob@test.com", "lemonsqueezy"},
		{"charlie@test.com", "stripe"},
	}

	for _, b := range buyers {
		simBody, _ := json.Marshal(map[string]interface{}{
			"provider":       b.provider,
			"action":         "provision",
			"customer_email": b.email,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/marketplace/simulate", bytes.NewReader(simBody))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("seed failed for %s", b.email)
		}
	}

	// 1. Filter by limit
	reqLimit := httptest.NewRequest(http.MethodGet, "/api/marketplace/transactions?limit=1", nil)
	wLimit := httptest.NewRecorder()
	handler.ServeHTTP(wLimit, reqLimit)
	var listLimit []marketplace.TransactionRecord
	_ = json.Unmarshal(wLimit.Body.Bytes(), &listLimit)
	if len(listLimit) != 1 {
		t.Fatalf("expected 1 record with limit=1, got: %d", len(listLimit))
	}

	// 2. Filter by provider
	reqProv := httptest.NewRequest(http.MethodGet, "/api/marketplace/transactions?provider=lemonsqueezy", nil)
	wProv := httptest.NewRecorder()
	handler.ServeHTTP(wProv, reqProv)
	var listProv []marketplace.TransactionRecord
	_ = json.Unmarshal(wProv.Body.Bytes(), &listProv)
	if len(listProv) != 1 || listProv[0].CustomerEmail != "bob@test.com" {
		t.Fatalf("expected only bob@test.com for lemonsqueezy, got: %+v", listProv)
	}

	// 3. Filter by email
	reqEmail := httptest.NewRequest(http.MethodGet, "/api/marketplace/transactions?customer_email=alice@test.com", nil)
	wEmail := httptest.NewRecorder()
	handler.ServeHTTP(wEmail, reqEmail)
	var listEmail []marketplace.TransactionRecord
	_ = json.Unmarshal(wEmail.Body.Bytes(), &listEmail)
	if len(listEmail) != 1 || listEmail[0].CustomerEmail != "alice@test.com" {
		t.Fatalf("expected only alice@test.com, got: %+v", listEmail)
	}
}

func TestMarketplaceSimulateErrorHandling(t *testing.T) {
	server, handler := setupMarketplaceTestServer(t, "", "", "")
	defer server.proxy.Close()

	// Unsupported provider simulation returns 400 Bad Request
	badBody := []byte(`{"provider": "unsupported_pay", "customer_email": "bad@test.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/simulate", bytes.NewReader(badBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for unsupported provider simulate, got %d", w.Code)
	}
}
