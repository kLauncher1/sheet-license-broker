package marketplace

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStripeWebhookVerification(t *testing.T) {
	secret := "whsec_test_stripe_secret_key_123"
	verifier := NewVerifier(300)

	body := []byte(`{"id":"evt_stripe_test_1","type":"checkout.session.completed","data":{"object":{"id":"cs_123","customer_email":"buyer@example.com"}}}`)
	nowUnix := time.Now().Unix()

	// 1. Generate valid Stripe-Signature
	signedPayload := fmt.Sprintf("%d.%s", nowUnix, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	validSig := hex.EncodeToString(mac.Sum(nil))

	header := make(http.Header)
	header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", nowUnix, validSig))

	if err := verifier.Verify(ProviderStripe, header, body, secret); err != nil {
		t.Fatalf("expected valid stripe verification, got: %v", err)
	}

	// 2. Tampered body
	tamperedBody := []byte(`{"id":"evt_stripe_test_1","type":"checkout.session.completed","tampered":true}`)
	if err := verifier.Verify(ProviderStripe, header, tamperedBody, secret); err == nil {
		t.Fatalf("expected error on tampered body, got nil")
	}

	// 3. Expired timestamp (> 300s)
	oldTimestamp := nowUnix - 400
	oldSignedPayload := fmt.Sprintf("%d.%s", oldTimestamp, string(body))
	oldMac := hmac.New(sha256.New, []byte(secret))
	oldMac.Write([]byte(oldSignedPayload))
	oldSig := hex.EncodeToString(oldMac.Sum(nil))

	oldHeader := make(http.Header)
	oldHeader.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", oldTimestamp, oldSig))

	if err := verifier.Verify(ProviderStripe, oldHeader, body, secret); err == nil {
		t.Fatalf("expected timestamp drift error, got nil")
	}

	// 4. Missing signature
	emptyHeader := make(http.Header)
	if err := verifier.Verify(ProviderStripe, emptyHeader, body, secret); err == nil {
		t.Fatalf("expected missing signature error, got nil")
	}
}

func TestLemonSqueezyWebhookVerification(t *testing.T) {
	secret := "ls_test_webhook_secret_xyz"
	verifier := NewVerifier(300)

	body := []byte(`{"meta":{"event_name":"order_created"},"data":{"id":"1001","attributes":{"user_email":"buyer@lemonsqueezy.com"}}}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	validSig := hex.EncodeToString(mac.Sum(nil))

	header := make(http.Header)
	header.Set("X-Signature", validSig)

	if err := verifier.Verify(ProviderLemonSqueezy, header, body, secret); err != nil {
		t.Fatalf("expected valid lemon squeezy verification, got: %v", err)
	}

	// Tampered body
	if err := verifier.Verify(ProviderLemonSqueezy, header, []byte(`tampered`), secret); err == nil {
		t.Fatalf("expected error on tampered lemon squeezy body, got nil")
	}

	// Missing header
	if err := verifier.Verify(ProviderLemonSqueezy, make(http.Header), body, secret); err == nil {
		t.Fatalf("expected error on missing X-Signature header, got nil")
	}
}

func TestPaddleWebhookVerification(t *testing.T) {
	secret := "pdl_test_secret_paddle_999"
	verifier := NewVerifier(300)

	body := []byte(`{"event_id":"evt_pdl_1","event_type":"transaction.completed","data":{"id":"txn_99"}}`)
	nowUnix := time.Now().Unix()

	signedPayload := fmt.Sprintf("%d:%s", nowUnix, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	validSig := hex.EncodeToString(mac.Sum(nil))

	header := make(http.Header)
	header.Set("Paddle-Signature", fmt.Sprintf("ts=%d;h1=%s", nowUnix, validSig))

	if err := verifier.Verify(ProviderPaddle, header, body, secret); err != nil {
		t.Fatalf("expected valid paddle verification, got: %v", err)
	}

	// Tampered body
	if err := verifier.Verify(ProviderPaddle, header, []byte(`tampered`), secret); err == nil {
		t.Fatalf("expected error on tampered paddle body, got nil")
	}
}

func TestNormalizer(t *testing.T) {
	norm := NewNormalizer("pro", 1, 30)

	// 1. Stripe Checkout
	stripePayload := []byte(`{
		"id": "evt_stripe_1",
		"type": "checkout.session.completed",
		"created": 1700000000,
		"data": {
			"object": {
				"id": "cs_test_order",
				"customer_email": "stripe_customer@test.com",
				"metadata": {"tier": "enterprise", "seats": "5"},
				"amount_total": 4900,
				"currency": "usd"
			}
		}
	}`)
	ev, err := norm.Normalize(ProviderStripe, stripePayload)
	if err != nil {
		t.Fatalf("failed to normalize stripe: %v", err)
	}
	if ev.Action != ActionProvision || ev.CustomerEmail != "stripe_customer@test.com" || ev.Tier != "enterprise" || ev.Seats != 5 {
		t.Fatalf("unexpected stripe normalized event: %+v", ev)
	}

	// 2. Lemon Squeezy Order
	lsPayload := []byte(`{
		"meta": {
			"event_name": "order_created",
			"custom_data": {"tier": "pro", "seats": "2"}
		},
		"data": {
			"id": "ls_order_123",
			"type": "orders",
			"attributes": {
				"user_email": "lemon@test.com",
				"user_name": "Lemon User",
				"order_number": 9876,
				"total": 2900,
				"currency": "USD"
			}
		}
	}`)
	evLS, err := norm.Normalize(ProviderLemonSqueezy, lsPayload)
	if err != nil {
		t.Fatalf("failed to normalize lemon squeezy: %v", err)
	}
	if evLS.Action != ActionProvision || evLS.CustomerEmail != "lemon@test.com" || evLS.OrderID != "9876" {
		t.Fatalf("unexpected lemon squeezy normalized event: %+v", evLS)
	}

	// 3. Paddle Billing Transaction
	pdlPayload := []byte(`{
		"event_id": "evt_pdl_01",
		"event_type": "transaction.completed",
		"occurred_at": "2026-10-19T10:00:00Z",
		"data": {
			"id": "txn_pdl_01",
			"customer": {
				"email": "paddle@test.com",
				"name": "Paddle Buyer"
			},
			"custom_data": {"tier": "starter", "seats": "1"},
			"details": {
				"totals": {"total": "19.99", "currency_code": "USD"}
			}
		}
	}`)
	evPdl, err := norm.Normalize(ProviderPaddle, pdlPayload)
	if err != nil {
		t.Fatalf("failed to normalize paddle: %v", err)
	}
	if evPdl.Action != ActionProvision || evPdl.CustomerEmail != "paddle@test.com" || evPdl.Tier != "starter" {
		t.Fatalf("unexpected paddle normalized event: %+v", evPdl)
	}
}

func TestIdempotencyAndAutomatedProvisioning(t *testing.T) {
	stripeSecret := "whsec_test_secret"
	cfg := MarketplaceConfig{
		StripeWebhookSecret: stripeSecret,
		DefaultDaysValid:    30,
		DefaultTier:         "pro",
		DefaultSeats:        1,
		ToleranceSeconds:    300,
	}

	issuedKeys := make([]string, 0)
	revokedKeys := make([]string, 0)

	provisionFn := func(daysValid, maxDevices int, tier string, features []string) (string, error) {
		k := fmt.Sprintf("KEY-PROV-%d", len(issuedKeys)+1)
		issuedKeys = append(issuedKeys, k)
		return k, nil
	}

	revokeFn := func(licenseKey, reason string) error {
		revokedKeys = append(revokedKeys, licenseKey)
		return nil
	}

	mgr := NewManager(cfg, provisionFn, revokeFn)

	// 1. Process initial Stripe provision webhook
	body := []byte(`{
		"id": "evt_order_1001",
		"type": "checkout.session.completed",
		"created": ` + fmt.Sprintf("%d", time.Now().Unix()) + `,
		"data": {
			"object": {
				"id": "cs_order_1001",
				"customer_email": "customer1@example.com",
				"metadata": {"tier": "enterprise", "seats": "10"}
			}
		}
	}`)

	nowUnix := time.Now().Unix()
	signedPayload := fmt.Sprintf("%d.%s", nowUnix, string(body))
	mac := hmac.New(sha256.New, []byte(stripeSecret))
	mac.Write([]byte(signedPayload))
	sig := hex.EncodeToString(mac.Sum(nil))

	header := make(http.Header)
	header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", nowUnix, sig))

	event, tx, err := mgr.ProcessWebhook(ProviderStripe, header, body)
	if err != nil {
		t.Fatalf("failed to process webhook: %v", err)
	}

	if tx.Status != "PROVISIONED" || tx.LicenseKey != "KEY-PROV-1" {
		t.Fatalf("expected PROVISIONED tx with KEY-PROV-1, got: %+v", tx)
	}
	if len(issuedKeys) != 1 {
		t.Fatalf("expected 1 issued key, got: %d", len(issuedKeys))
	}

	// 2. Re-send identical webhook (idempotency test)
	_, txDup, err := mgr.ProcessWebhook(ProviderStripe, header, body)
	if err != nil {
		t.Fatalf("duplicate webhook returned error: %v", err)
	}
	if txDup.Status != "DUPLICATE" {
		t.Fatalf("expected DUPLICATE status, got: %s", txDup.Status)
	}
	if len(issuedKeys) != 1 {
		t.Fatalf("provisionFn should not be invoked on duplicate event!")
	}

	// 3. Process revocation event for the same customer (e.g. charge.refunded)
	refundBody := []byte(`{
		"id": "evt_refund_2001",
		"type": "charge.refunded",
		"created": ` + fmt.Sprintf("%d", time.Now().Unix()) + `,
		"data": {
			"object": {
				"id": "ch_refund_2001",
				"customer_email": "customer1@example.com"
			}
		}
	}`)
	nowUnix = time.Now().Unix()
	signedRefund := fmt.Sprintf("%d.%s", nowUnix, string(refundBody))
	macRefund := hmac.New(sha256.New, []byte(stripeSecret))
	macRefund.Write([]byte(signedRefund))
	sigRefund := hex.EncodeToString(macRefund.Sum(nil))

	headerRefund := make(http.Header)
	headerRefund.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", nowUnix, sigRefund))

	_, txRevoke, err := mgr.ProcessWebhook(ProviderStripe, headerRefund, refundBody)
	if err != nil {
		t.Fatalf("failed to process refund webhook: %v", err)
	}
	if txRevoke.Status != "REVOKED" || txRevoke.LicenseKey != "KEY-PROV-1" {
		t.Fatalf("expected REVOKED status with KEY-PROV-1, got: %+v", txRevoke)
	}
	if len(revokedKeys) != 1 || revokedKeys[0] != "KEY-PROV-1" {
		t.Fatalf("expected KEY-PROV-1 revoked, got: %v", revokedKeys)
	}

	// 4. Verify diagnostic status
	status := mgr.GetStatus()
	if status.TotalProcessedEvents != 3 || status.TotalProvisioned != 1 || status.TotalRevoked != 1 || status.TotalDuplicates != 1 {
		t.Fatalf("unexpected telemetry status: %+v", status)
	}
	_ = event
}

func TestMalformedJSONWithValidSignature(t *testing.T) {
	secret := "whsec_corrupt_test_secret"
	cfg := MarketplaceConfig{
		StripeWebhookSecret:       secret,
		LemonSqueezyWebhookSecret: secret,
		PaddleWebhookSecret:       secret,
		DefaultDaysValid:          30,
		DefaultTier:               "pro",
		DefaultSeats:              1,
		ToleranceSeconds:          300,
	}

	mgr := NewManager(cfg, nil, nil)
	corruptBytes := []byte(`{"id": "evt_bad", "type": invalid_json_here`)

	// 1. Stripe with valid HMAC over corrupt bytes
	nowUnix := time.Now().Unix()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.%s", nowUnix, string(corruptBytes))))
	stripeSig := hex.EncodeToString(mac.Sum(nil))

	stripeHdr := make(http.Header)
	stripeHdr.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", nowUnix, stripeSig))

	_, _, err := mgr.ProcessWebhook(ProviderStripe, stripeHdr, corruptBytes)
	if err == nil {
		t.Fatalf("expected error processing corrupt JSON with valid Stripe HMAC, got nil")
	}

	// 2. Lemon Squeezy with valid HMAC over corrupt bytes
	lsMac := hmac.New(sha256.New, []byte(secret))
	lsMac.Write(corruptBytes)
	lsSig := hex.EncodeToString(lsMac.Sum(nil))

	lsHdr := make(http.Header)
	lsHdr.Set("X-Signature", lsSig)

	_, _, err = mgr.ProcessWebhook(ProviderLemonSqueezy, lsHdr, corruptBytes)
	if err == nil {
		t.Fatalf("expected error processing corrupt JSON with valid Lemon Squeezy HMAC, got nil")
	}

	// 3. Paddle with valid HMAC over corrupt bytes
	pdlMac := hmac.New(sha256.New, []byte(secret))
	pdlMac.Write([]byte(fmt.Sprintf("%d:%s", nowUnix, string(corruptBytes))))
	pdlSig := hex.EncodeToString(pdlMac.Sum(nil))

	pdlHdr := make(http.Header)
	pdlHdr.Set("Paddle-Signature", fmt.Sprintf("ts=%d;h1=%s", nowUnix, pdlSig))

	_, _, err = mgr.ProcessWebhook(ProviderPaddle, pdlHdr, corruptBytes)
	if err == nil {
		t.Fatalf("expected error processing corrupt JSON with valid Paddle HMAC, got nil")
	}
}

func TestProviderPayloadSchemaVariations(t *testing.T) {
	norm := NewNormalizer("pro", 1, 30)

	// Lemon Squeezy with customer_email and custom_data inside attributes
	lsPayload := []byte(`{
		"meta": {
			"event_name": "order_created"
		},
		"data": {
			"id": "ls_alt_01",
			"type": "orders",
			"attributes": {
				"customer_email": "alt_lemon@example.com",
				"user_name": "Alt Lemon",
				"order_number": 12345,
				"custom_data": {"tier": "enterprise", "quantity": 8, "license_key": "KEY-ALT-LS"}
			}
		}
	}`)
	evLS, err := norm.Normalize(ProviderLemonSqueezy, lsPayload)
	if err != nil {
		t.Fatalf("failed to normalize Lemon Squeezy schema variation: %v", err)
	}
	if evLS.CustomerEmail != "alt_lemon@example.com" || evLS.Tier != "enterprise" || evLS.Seats != 8 || evLS.LicenseKey != "KEY-ALT-LS" {
		t.Fatalf("unexpected Lemon Squeezy variation result: %+v", evLS)
	}

	// Paddle Billing v2 with nested items custom data and plan alias
	pdlPayload := []byte(`{
		"event_id": "evt_pdl_alt",
		"event_type": "transaction.completed",
		"occurred_at": "2026-10-19T10:00:00Z",
		"data": {
			"id": "txn_pdl_alt",
			"custom_data": {"email": "alt_paddle@example.com"},
			"items": [
				{
					"price": {
						"custom_data": {"plan": "starter", "seat_count": "3", "license": "KEY-ALT-PDL"}
					}
				}
			]
		}
	}`)
	evPdl, err := norm.Normalize(ProviderPaddle, pdlPayload)
	if err != nil {
		t.Fatalf("failed to normalize Paddle Billing v2 variation: %v", err)
	}
	if evPdl.CustomerEmail != "alt_paddle@example.com" || evPdl.Tier != "starter" || evPdl.Seats != 3 || evPdl.LicenseKey != "KEY-ALT-PDL" {
		t.Fatalf("unexpected Paddle Billing variation result: %+v", evPdl)
	}
}

func TestUnbindCustomerKey(t *testing.T) {
	mgr := NewManager(MarketplaceConfig{ToleranceSeconds: 300}, nil, nil)

	mgr.bindCustomerKey("alice@test.com", "ord_1", "sub_1", "KEY-ALICE-1")
	if k := mgr.findCustomerKey("alice@test.com", "ord_1", "sub_1"); k != "KEY-ALICE-1" {
		t.Fatalf("expected KEY-ALICE-1, got %s", k)
	}

	mgr.unbindCustomerKey("alice@test.com", "ord_1", "sub_1", "KEY-ALICE-1")
	if k := mgr.findCustomerKey("alice@test.com", "ord_1", "sub_1"); k != "" {
		t.Fatalf("expected empty key after unbind, got %s", k)
	}
}

func TestConcurrentDuplicateWebhooks(t *testing.T) {
	stripeSecret := "whsec_concurrent_secret"
	cfg := MarketplaceConfig{
		StripeWebhookSecret: stripeSecret,
		DefaultDaysValid:    30,
		DefaultTier:         "pro",
		DefaultSeats:        1,
		ToleranceSeconds:    300,
	}

	var provisionCount int64
	provisionFn := func(daysValid, maxDevices int, tier string, features []string) (string, error) {
		time.Sleep(10 * time.Millisecond) // simulate database latency
		atomic.AddInt64(&provisionCount, 1)
		return "KEY-CONCURRENT-1", nil
	}

	mgr := NewManager(cfg, provisionFn, nil)

	body := []byte(`{
		"id": "evt_concurrent_1001",
		"type": "checkout.session.completed",
		"created": ` + fmt.Sprintf("%d", time.Now().Unix()) + `,
		"data": {
			"object": {
				"id": "cs_concurrent_1001",
				"customer_email": "concurrent@example.com"
			}
		}
	}`)
	nowUnix := time.Now().Unix()
	signedPayload := fmt.Sprintf("%d.%s", nowUnix, string(body))
	mac := hmac.New(sha256.New, []byte(stripeSecret))
	mac.Write([]byte(signedPayload))
	sig := hex.EncodeToString(mac.Sum(nil))

	header := make(http.Header)
	header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", nowUnix, sig))

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_, _, _ = mgr.ProcessWebhook(ProviderStripe, header, body)
		}()
	}
	wg.Wait()

	if provisionCount != 1 {
		t.Fatalf("expected exactly 1 provision call under concurrency, got: %d", provisionCount)
	}
}

