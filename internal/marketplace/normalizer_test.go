package marketplace

import (
	"errors"
	"testing"
)

func TestLemonSqueezyEmptyCustomDataArrayAndZeroOrderNumber(t *testing.T) {
	norm := NewNormalizer("pro", 1, 30)

	// In PHP/Laravel, empty associative arrays encode as `[]` rather than `{}`
	payloadWithEmptyArrays := []byte(`{
		"meta": {
			"event_name": "subscription_created",
			"custom_data": []
		},
		"data": {
			"id": "sub_ls_12345",
			"type": "subscriptions",
			"attributes": {
				"customer_email": "subscriber@example.com",
				"order_number": 0,
				"total": 1900,
				"currency": "USD",
				"custom_data": []
			}
		}
	}`)

	ev, err := norm.Normalize(ProviderLemonSqueezy, payloadWithEmptyArrays)
	if err != nil {
		t.Fatalf("failed to normalize Lemon Squeezy with empty array custom_data: %v", err)
	}

	if ev.CustomerEmail != "subscriber@example.com" {
		t.Fatalf("expected email subscriber@example.com, got %s", ev.CustomerEmail)
	}
	if ev.OrderID == "0" {
		t.Fatalf("orderID should never be set to '0' on missing order_number: got %s", ev.OrderID)
	}
	if ev.SubscriptionID != "sub_ls_12345" {
		t.Fatalf("expected subscriptionID sub_ls_12345, got %s", ev.SubscriptionID)
	}
	if ev.AmountCents != 1900 {
		t.Fatalf("expected amount 1900, got %d", ev.AmountCents)
	}
}

func TestPaddleEmptyCustomDataArrayAndNull(t *testing.T) {
	norm := NewNormalizer("pro", 1, 30)

	// Paddle Billing v2 with empty array custom_data and items
	payload := []byte(`{
		"event_id": "evt_pdl_empty_cd",
		"event_type": "transaction.completed",
		"data": {
			"id": "txn_pdl_empty",
			"customer": {
				"email": "pdl_user@example.com"
			},
			"custom_data": [],
			"details": {
				"totals": {"total": "49.00", "currency_code": "USD"}
			},
			"items": []
		}
	}`)

	ev, err := norm.Normalize(ProviderPaddle, payload)
	if err != nil {
		t.Fatalf("failed to normalize Paddle with empty array custom_data: %v", err)
	}
	if ev.CustomerEmail != "pdl_user@example.com" {
		t.Fatalf("expected email pdl_user@example.com, got %s", ev.CustomerEmail)
	}
	if ev.AmountCents != 4900 {
		t.Fatalf("expected amount 4900, got %d", ev.AmountCents)
	}
}

func TestPaddlePayloadMissingEventTypeAndAlertNameRejected(t *testing.T) {
	norm := NewNormalizer("pro", 1, 30)

	// Arbitrary JSON payload sent to Paddle endpoint
	arbitraryJSON := []byte(`{"arbitrary_key": "arbitrary_value", "nested": {"foo": "bar"}}`)
	_, err := norm.Normalize(ProviderPaddle, arbitraryJSON)
	if err == nil {
		t.Fatalf("expected ErrInvalidPayload on arbitrary payload without event_type or alert_name, got nil")
	}
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected errors.Is(err, ErrInvalidPayload), got: %v", err)
	}
}

func TestCustomerKeyZeroStringIgnoredInBindings(t *testing.T) {
	mgr := NewManager(MarketplaceConfig{ToleranceSeconds: 300}, nil, nil)

	// Binds customer 1 with order_number 0
	mgr.bindCustomerKey("user1@test.com", "0", "sub_1", "KEY-USER-1")
	// Binds customer 2 with order_number 0
	mgr.bindCustomerKey("user2@test.com", "0", "sub_2", "KEY-USER-2")

	// Neither should be bound to "0"
	if k := mgr.findCustomerKey("", "0", ""); k != "" {
		t.Fatalf("refToKey['0'] should never be bound, but returned: %s", k)
	}

	// Should resolve by subscription ID correctly
	if k := mgr.findCustomerKey("user1@test.com", "0", "sub_1"); k != "KEY-USER-1" {
		t.Fatalf("expected KEY-USER-1, got %s", k)
	}
	if k := mgr.findCustomerKey("user2@test.com", "0", "sub_2"); k != "KEY-USER-2" {
		t.Fatalf("expected KEY-USER-2, got %s", k)
	}
}
