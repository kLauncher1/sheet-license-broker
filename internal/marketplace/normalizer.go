package marketplace

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Normalizer transforms provider-specific JSON webhook payloads into a unified NormalizedEvent.
type Normalizer struct {
	defaultTier      string
	defaultSeats     int
	defaultDaysValid int
}

// NewNormalizer creates an event normalizer with fallback defaults.
func NewNormalizer(defaultTier string, defaultSeats, defaultDaysValid int) *Normalizer {
	if defaultTier == "" {
		defaultTier = "pro"
	}
	if defaultSeats <= 0 {
		defaultSeats = 1
	}
	if defaultDaysValid <= 0 {
		defaultDaysValid = 30
	}
	return &Normalizer{
		defaultTier:      defaultTier,
		defaultSeats:     defaultSeats,
		defaultDaysValid: defaultDaysValid,
	}
}

// Normalize parses and normalizes the payload based on the provider.
func (n *Normalizer) Normalize(provider string, body []byte) (*NormalizedEvent, error) {
	if len(body) == 0 {
		return nil, ErrInvalidPayload
	}

	switch strings.ToLower(strings.TrimSpace(provider)) {
	case ProviderStripe:
		return n.normalizeStripe(body)
	case ProviderLemonSqueezy:
		return n.normalizeLemonSqueezy(body)
	case ProviderPaddle:
		return n.normalizePaddle(body)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProvider, provider)
	}
}

// normalizeStripe handles Stripe event formats (checkout.session.completed, charge.refunded, etc.)
func (n *Normalizer) normalizeStripe(body []byte) (*NormalizedEvent, error) {
	var raw struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Created int64  `json:"created"`
		Data    struct {
			Object map[string]interface{} `json:"object"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%w: stripe json decode error: %v", ErrInvalidPayload, err)
	}

	if raw.ID == "" {
		return nil, fmt.Errorf("%w: stripe payload missing event id", ErrInvalidPayload)
	}

	obj := raw.Data.Object
	if obj == nil {
		obj = make(map[string]interface{})
	}

	// Determine action
	action := ActionIgnore
	switch raw.Type {
	case "checkout.session.completed", "customer.subscription.created", "invoice.payment_succeeded", "invoice.paid":
		action = ActionProvision
	case "customer.subscription.deleted", "charge.refunded", "customer.subscription.paused", "invoice.payment_failed":
		action = ActionRevoke
	case "customer.subscription.updated":
		action = ActionUpdate
	}

	// Extract customer email & name
	email, name := "", ""
	for _, field := range []string{"customer_email", "receipt_email"} {
		if em, _ := obj[field].(string); em != "" && email == "" {
			email = em
		}
	}
	for _, nested := range []string{"customer_details", "billing_details"} {
		if sub, ok := obj[nested].(map[string]interface{}); ok {
			if em, _ := sub["email"].(string); em != "" && email == "" {
				email = em
			}
			if nm, _ := sub["name"].(string); nm != "" && name == "" {
				name = nm
			}
		}
	}

	// Extract metadata
	metaMap := make(map[string]string)
	if m, ok := obj["metadata"].(map[string]interface{}); ok {
		for k, v := range m {
			metaMap[k] = fmt.Sprintf("%v", v)
		}
	}

	orderID, _ := obj["id"].(string)
	subID, _ := obj["subscription"].(string)

	tier := n.extractTier(metaMap, "")
	seats := n.extractSeats(metaMap, 1)
	daysValid := n.extractDays(metaMap, n.defaultDaysValid)
	licKey := n.extractLicenseKey(metaMap)

	var amountCents int64
	if amt, ok := obj["amount_total"].(float64); ok {
		amountCents = int64(amt)
	} else if amt, ok := obj["amount"].(float64); ok {
		amountCents = int64(amt)
	}
	currency, _ := obj["currency"].(string)

	ts := time.Now().UTC()
	if raw.Created > 0 {
		ts = time.Unix(raw.Created, 0).UTC()
	}

	return &NormalizedEvent{
		EventID:        raw.ID,
		Provider:       ProviderStripe,
		EventType:      raw.Type,
		Action:         action,
		CustomerEmail:  strings.ToLower(strings.TrimSpace(email)),
		CustomerName:   strings.TrimSpace(name),
		LicenseKey:     strings.TrimSpace(licKey),
		Tier:           tier,
		Seats:          seats,
		DaysValid:      daysValid,
		OrderID:        orderID,
		SubscriptionID: subID,
		AmountCents:    amountCents,
		Currency:       strings.ToUpper(currency),
		Metadata:       metaMap,
		Timestamp:      ts,
	}, nil
}

// normalizeLemonSqueezy handles Lemon Squeezy webhook payloads
func (n *Normalizer) normalizeLemonSqueezy(body []byte) (*NormalizedEvent, error) {
	var raw struct {
		Meta struct {
			EventName  string      `json:"event_name"`
			CustomData interface{} `json:"custom_data"`
		} `json:"meta"`
		Data struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				UserEmail     string      `json:"user_email"`
				CustomerEmail string      `json:"customer_email"`
				UserName      string      `json:"user_name"`
				OrderNumber   interface{} `json:"order_number"`
				Status        string      `json:"status"`
				ProductName   string      `json:"product_name"`
				VariantName   string      `json:"variant_name"`
				Total         interface{} `json:"total"`
				Currency      string      `json:"currency"`
				CreatedAt     string      `json:"created_at"`
				CustomData    interface{} `json:"custom_data"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("%w: lemon squeezy json decode error: %v", ErrInvalidPayload, err)
	}

	eventName := strings.ToLower(strings.TrimSpace(raw.Meta.EventName))
	if eventName == "" {
		return nil, fmt.Errorf("%w: missing lemon squeezy event_name", ErrInvalidPayload)
	}

	action := ActionIgnore
	switch eventName {
	case "order_created", "subscription_created", "subscription_resumed":
		action = ActionProvision
	case "subscription_cancelled", "subscription_expired", "order_refunded":
		action = ActionRevoke
	case "subscription_updated":
		action = ActionUpdate
	}

	metaMap := make(map[string]string)
	n.parseCustomData(raw.Meta.CustomData, metaMap)
	n.parseCustomData(raw.Data.Attributes.CustomData, metaMap)

	userEmail := raw.Data.Attributes.UserEmail
	if userEmail == "" {
		userEmail = raw.Data.Attributes.CustomerEmail
	}
	if userEmail == "" {
		if em, ok := metaMap["customer_email"]; ok {
			userEmail = em
		} else if em, ok := metaMap["email"]; ok {
			userEmail = em
		}
	}

	tier := n.extractTier(metaMap, raw.Data.Attributes.VariantName)
	seats := n.extractSeats(metaMap, 1)
	daysValid := n.extractDays(metaMap, n.defaultDaysValid)
	licKey := n.extractLicenseKey(metaMap)

	eventID := fmt.Sprintf("ls_%s_%s", eventName, raw.Data.ID)
	if raw.Data.ID == "" {
		eventID = fmt.Sprintf("ls_%s_%d", eventName, time.Now().UnixNano())
	}

	ts := time.Now().UTC()
	if tParsed, err := time.Parse(time.RFC3339, raw.Data.Attributes.CreatedAt); err == nil {
		ts = tParsed
	}

	orderNum := parseNumber(raw.Data.Attributes.OrderNumber)
	orderID := ""
	if orderNum > 0 {
		orderID = strconv.FormatInt(orderNum, 10)
	} else if strings.EqualFold(raw.Data.Type, "orders") && raw.Data.ID != "" {
		orderID = raw.Data.ID
	}

	subID := ""
	if strings.EqualFold(raw.Data.Type, "subscriptions") || strings.Contains(eventName, "subscription") {
		subID = raw.Data.ID
	}

	return &NormalizedEvent{
		EventID:        eventID,
		Provider:       ProviderLemonSqueezy,
		EventType:      eventName,
		Action:         action,
		CustomerEmail:  strings.ToLower(strings.TrimSpace(userEmail)),
		CustomerName:   strings.TrimSpace(raw.Data.Attributes.UserName),
		LicenseKey:     strings.TrimSpace(licKey),
		Tier:           tier,
		Seats:          seats,
		DaysValid:      daysValid,
		OrderID:        orderID,
		SubscriptionID: subID,
		AmountCents:    parseNumber(raw.Data.Attributes.Total),
		Currency:       strings.ToUpper(raw.Data.Attributes.Currency),
		Metadata:       metaMap,
		Timestamp:      ts,
	}, nil
}

// normalizePaddle handles Paddle Billing v2 and classic webhook payloads
func (n *Normalizer) normalizePaddle(body []byte) (*NormalizedEvent, error) {
	// Try Paddle Billing v2 schema first
	var rawV2 struct {
		EventID    string `json:"event_id"`
		EventType  string `json:"event_type"`
		OccurredAt string `json:"occurred_at"`
		Data       struct {
			ID         string      `json:"id"`
			CustomerID string      `json:"customer_id"`
			CustomData interface{} `json:"custom_data"`
			Customer   struct {
				Email string `json:"email"`
				Name  string `json:"name"`
			} `json:"customer"`
			Details struct {
				Totals struct {
					Total    string `json:"total"`
					Currency string `json:"currency_code"`
				} `json:"totals"`
			} `json:"details"`
			Items []struct {
				Price struct {
					CustomData interface{} `json:"custom_data"`
				} `json:"price"`
			} `json:"items"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &rawV2); err == nil && rawV2.EventType != "" {
		action := ActionIgnore
		switch strings.ToLower(rawV2.EventType) {
		case "transaction.completed", "transaction.paid", "subscription.created", "subscription.activated":
			action = ActionProvision
		case "subscription.canceled", "subscription.past_due", "transaction.revoked":
			action = ActionRevoke
		case "subscription.updated":
			action = ActionUpdate
		}

		metaMap := make(map[string]string)
		n.parseCustomData(rawV2.Data.CustomData, metaMap)
		for _, item := range rawV2.Data.Items {
			n.parseCustomData(item.Price.CustomData, metaMap)
		}

		email := strings.ToLower(strings.TrimSpace(rawV2.Data.Customer.Email))
		if email == "" {
			if em, ok := metaMap["customer_email"]; ok {
				email = strings.ToLower(strings.TrimSpace(em))
			} else if em, ok := metaMap["email"]; ok {
				email = strings.ToLower(strings.TrimSpace(em))
			}
		}

		tier := n.extractTier(metaMap, "")
		seats := n.extractSeats(metaMap, 1)
		daysValid := n.extractDays(metaMap, n.defaultDaysValid)
		licKey := n.extractLicenseKey(metaMap)

		var totalCents int64
		if f, err := strconv.ParseFloat(rawV2.Data.Details.Totals.Total, 64); err == nil {
			totalCents = int64(f * 100)
		}

		ts := time.Now().UTC()
		if tParsed, err := time.Parse(time.RFC3339, rawV2.OccurredAt); err == nil {
			ts = tParsed
		}

		eventID := rawV2.EventID
		if eventID == "" {
			eventID = fmt.Sprintf("pdl_%s_%s", rawV2.EventType, rawV2.Data.ID)
		}

		return &NormalizedEvent{
			EventID:        eventID,
			Provider:       ProviderPaddle,
			EventType:      rawV2.EventType,
			Action:         action,
			CustomerEmail:  email,
			CustomerName:   strings.TrimSpace(rawV2.Data.Customer.Name),
			LicenseKey:     strings.TrimSpace(licKey),
			Tier:           tier,
			Seats:          seats,
			DaysValid:      daysValid,
			OrderID:        rawV2.Data.ID,
			SubscriptionID: rawV2.Data.ID,
			AmountCents:    totalCents,
			Currency:       strings.ToUpper(rawV2.Data.Details.Totals.Currency),
			Metadata:       metaMap,
			Timestamp:      ts,
		}, nil
	}

	// Fallback to Paddle Classic webhook schema
	var rawClassic struct {
		AlertID        string `json:"alert_id"`
		AlertName      string `json:"alert_name"`
		Email          string `json:"email"`
		OrderId        string `json:"p_order_id"`
		SubscriptionId string `json:"subscription_id"`
		Passthrough    string `json:"passthrough"`
		EventTime      string `json:"event_time"`
	}

	if err := json.Unmarshal(body, &rawClassic); err != nil {
		return nil, fmt.Errorf("%w: paddle json decode error: %v", ErrInvalidPayload, err)
	}

	if strings.TrimSpace(rawClassic.AlertName) == "" {
		return nil, fmt.Errorf("%w: paddle payload missing event_type or alert_name", ErrInvalidPayload)
	}

	action := ActionIgnore
	switch strings.ToLower(rawClassic.AlertName) {
	case "payment_succeeded", "subscription_created":
		action = ActionProvision
	case "subscription_cancelled", "payment_refunded":
		action = ActionRevoke
	}

	metaMap := make(map[string]string)
	if rawClassic.Passthrough != "" {
		_ = json.Unmarshal([]byte(rawClassic.Passthrough), &metaMap)
	}

	tier := n.extractTier(metaMap, "")
	seats := n.extractSeats(metaMap, 1)
	daysValid := n.extractDays(metaMap, n.defaultDaysValid)
	licKey := n.extractLicenseKey(metaMap)

	eventID := rawClassic.AlertID
	if eventID == "" {
		eventID = fmt.Sprintf("pdl_%s_%d", rawClassic.AlertName, time.Now().UnixNano())
	}

	return &NormalizedEvent{
		EventID:        eventID,
		Provider:       ProviderPaddle,
		EventType:      rawClassic.AlertName,
		Action:         action,
		CustomerEmail:  strings.ToLower(strings.TrimSpace(rawClassic.Email)),
		LicenseKey:     strings.TrimSpace(licKey),
		Tier:           tier,
		Seats:          seats,
		DaysValid:      daysValid,
		OrderID:        rawClassic.OrderId,
		SubscriptionID: rawClassic.SubscriptionId,
		Metadata:       metaMap,
		Timestamp:      time.Now().UTC(),
	}, nil
}

func (n *Normalizer) parseCustomData(src interface{}, dst map[string]string) {
	if m, ok := src.(map[string]interface{}); ok && m != nil {
		for k, v := range m {
			if _, exists := dst[k]; !exists {
				dst[k] = fmt.Sprintf("%v", v)
			}
		}
	}
}

func parseNumber(val interface{}) int64 {
	switch v := val.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return i
		}
	}
	return 0
}

func (n *Normalizer) extractTier(meta map[string]string, fallbackName string) string {
	for _, k := range []string{"tier", "plan"} {
		if t := strings.TrimSpace(meta[k]); t != "" {
			return strings.ToLower(t)
		}
	}
	if fallbackName != "" {
		lower := strings.ToLower(fallbackName)
		switch {
		case strings.Contains(lower, "enterprise"):
			return "enterprise"
		case strings.Contains(lower, "starter"), strings.Contains(lower, "basic"):
			return "starter"
		case strings.Contains(lower, "pro"):
			return "pro"
		}
	}
	return n.defaultTier
}

func (n *Normalizer) extractSeats(meta map[string]string, defaultSeats int) int {
	for _, k := range []string{"seats", "seat_count", "max_devices", "quantity"} {
		if val, err := strconv.Atoi(strings.TrimSpace(meta[k])); err == nil && val > 0 {
			return val
		}
	}
	if defaultSeats > 0 {
		return defaultSeats
	}
	return n.defaultSeats
}

func (n *Normalizer) extractDays(meta map[string]string, defaultDays int) int {
	for _, k := range []string{"days", "days_valid", "validity_days", "period_days"} {
		if val, err := strconv.Atoi(strings.TrimSpace(meta[k])); err == nil && val > 0 {
			return val
		}
	}
	return defaultDays
}

func (n *Normalizer) extractLicenseKey(meta map[string]string) string {
	for _, k := range []string{"license_key", "licenseKey", "license", "key"} {
		if v := strings.TrimSpace(meta[k]); v != "" {
			return v
		}
	}
	return ""
}
