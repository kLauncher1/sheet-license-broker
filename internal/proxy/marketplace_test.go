package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/marketplace"
)

func TestProxyMarketplaceIntegration(t *testing.T) {
	secret := "whsec_proxy_stripe_test"
	px, err := NewProxy(ProxyConfig{
		OfflineMode:         true,
		StripeWebhookSecret: secret,
	})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}
	defer px.Close()

	ctx := context.Background()

	// 1. Send Stripe Checkout Webhook
	body := []byte(`{
		"id": "evt_px_test_1",
		"type": "checkout.session.completed",
		"created": ` + fmt.Sprintf("%d", time.Now().Unix()) + `,
		"data": {
			"object": {
				"id": "cs_px_001",
				"customer_email": "buyer_px@test.com",
				"metadata": {"tier": "enterprise", "seats": "3"}
			}
		}
	}`)

	nowUnix := time.Now().Unix()
	signedPayload := fmt.Sprintf("%d.%s", nowUnix, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	sig := hex.EncodeToString(mac.Sum(nil))

	header := make(http.Header)
	header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", nowUnix, sig))

	event, tx, err := px.ProcessMarketplaceWebhook(ctx, marketplace.ProviderStripe, header, body)
	if err != nil {
		t.Fatalf("ProcessMarketplaceWebhook failed: %v", err)
	}

	if tx.Status != "PROVISIONED" || tx.LicenseKey == "" {
		t.Fatalf("expected PROVISIONED status, got: %+v", tx)
	}

	// Verify license exists in proxy's license manager
	licenses := px.ListLicenses()
	found := false
	for _, l := range licenses {
		if l.LicenseKey == tx.LicenseKey {
			found = true
			if l.Tier != "enterprise" || l.MaxDevices != 3 {
				t.Fatalf("unexpected license tier/devices: %+v", l)
			}
			break
		}
	}
	if !found {
		t.Fatalf("license %s not found in proxy license list", tx.LicenseKey)
	}

	// Verify transaction listed
	txList := px.ListMarketplaceTransactions()
	if len(txList) == 0 || txList[0].LicenseKey != tx.LicenseKey {
		t.Fatalf("transaction not properly recorded in proxy: %+v", txList)
	}

	// 2. Send refund webhook for same customer
	refundBody := []byte(`{
		"id": "evt_px_refund_1",
		"type": "charge.refunded",
		"created": ` + fmt.Sprintf("%d", time.Now().Unix()) + `,
		"data": {
			"object": {
				"id": "ch_px_001",
				"customer_email": "buyer_px@test.com"
			}
		}
	}`)

	nowUnix = time.Now().Unix()
	signedRefund := fmt.Sprintf("%d.%s", nowUnix, string(refundBody))
	macRefund := hmac.New(sha256.New, []byte(secret))
	macRefund.Write([]byte(signedRefund))
	sigRefund := hex.EncodeToString(macRefund.Sum(nil))

	headerRefund := make(http.Header)
	headerRefund.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", nowUnix, sigRefund))

	_, txRefund, err := px.ProcessMarketplaceWebhook(ctx, marketplace.ProviderStripe, headerRefund, refundBody)
	if err != nil {
		t.Fatalf("failed to process refund: %v", err)
	}
	if txRefund.Status != "REVOKED" || txRefund.LicenseKey != tx.LicenseKey {
		t.Fatalf("expected REVOKED status with key %s, got: %+v", tx.LicenseKey, txRefund)
	}

	// Verify license is marked revoked
	licListAfter := px.ListLicenses()
	for _, l := range licListAfter {
		if l.LicenseKey == tx.LicenseKey {
			if l.Status != "REVOKED" {
				t.Fatalf("expected license %s to have REVOKED status, got: %s", l.LicenseKey, l.Status)
			}
		}
	}

	// 3. Status check
	st := px.GetMarketplaceStatus()
	if st["enabled"] != true || st["total_provisioned"].(int64) != 1 || st["total_revoked"].(int64) != 1 {
		t.Fatalf("unexpected marketplace status: %+v", st)
	}
	_ = event
}

func TestProxyMarketplaceSimulate(t *testing.T) {
	px, err := NewProxy(ProxyConfig{OfflineMode: true})
	if err != nil {
		t.Fatalf("failed to init proxy: %v", err)
	}
	defer px.Close()

	simEvent := &marketplace.NormalizedEvent{
		Provider:      marketplace.ProviderLemonSqueezy,
		EventType:     "order_created",
		Action:        marketplace.ActionProvision,
		CustomerEmail: "simulated_buyer@test.com",
		Tier:          "pro",
		Seats:         2,
		DaysValid:     60,
	}

	tx, err := px.SimulateMarketplaceWebhook(context.Background(), simEvent)
	if err != nil {
		t.Fatalf("SimulateMarketplaceWebhook failed: %v", err)
	}
	if tx.Status != "PROVISIONED" || tx.LicenseKey == "" {
		t.Fatalf("expected simulated PROVISIONED tx, got: %+v", tx)
	}
}
