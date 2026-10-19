package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/marketplace"
)

// registerMarketplaceRoutes mounts REST endpoints for automated reseller & marketplace webhooks.
func (s *AppServer) registerMarketplaceRoutes(apiMux *http.ServeMux, rootMux ...*http.ServeMux) {
	// If rootMux is supplied, register webhook endpoints directly on rootMux
	// (wrapped in security rate limiting) so that inbound external provider webhooks
	// (Stripe, Lemon Squeezy, Paddle) with third-party HMAC signatures are not blocked
	// by internal broker client HMAC signature enforcement (guard.Middleware).
	targetWebhookMux := apiMux
	var webhookWrapper func(http.HandlerFunc) http.HandlerFunc = func(h http.HandlerFunc) http.HandlerFunc { return h }

	if len(rootMux) > 0 && rootMux[0] != nil {
		targetWebhookMux = rootMux[0]
		webhookWrapper = func(h http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				s.securityRateLimitMiddleware(http.HandlerFunc(h)).ServeHTTP(w, r)
			}
		}
	}

	targetWebhookMux.HandleFunc("/api/marketplace/webhook/stripe", webhookWrapper(s.handleMarketplaceWebhookStripe))
	targetWebhookMux.HandleFunc("/api/marketplace/webhook/lemonsqueezy", webhookWrapper(s.handleMarketplaceWebhookLemonSqueezy))
	targetWebhookMux.HandleFunc("/api/marketplace/webhook/paddle", webhookWrapper(s.handleMarketplaceWebhookPaddle))
	targetWebhookMux.HandleFunc("/api/marketplace/webhook", webhookWrapper(s.handleMarketplaceWebhookGeneric))
	targetWebhookMux.HandleFunc("/api/marketplace/webhook/", webhookWrapper(s.handleMarketplaceWebhookGeneric))

	// Internal management and query endpoints remain on apiMux
	apiMux.HandleFunc("/api/marketplace/status", s.handleMarketplaceStatus)
	apiMux.HandleFunc("/api/marketplace/transactions", s.handleMarketplaceTransactions)
	apiMux.HandleFunc("/api/marketplace/simulate", s.handleMarketplaceSimulate)
}

func (s *AppServer) handleMarketplaceWebhookStripe(w http.ResponseWriter, r *http.Request) {
	s.processProviderWebhook(w, r, marketplace.ProviderStripe)
}

func (s *AppServer) handleMarketplaceWebhookLemonSqueezy(w http.ResponseWriter, r *http.Request) {
	s.processProviderWebhook(w, r, marketplace.ProviderLemonSqueezy)
}

func (s *AppServer) handleMarketplaceWebhookPaddle(w http.ResponseWriter, r *http.Request) {
	s.processProviderWebhook(w, r, marketplace.ProviderPaddle)
}

func (s *AppServer) handleMarketplaceWebhookGeneric(w http.ResponseWriter, r *http.Request) {
	provider := strings.TrimPrefix(r.URL.Path, "/api/marketplace/webhook/")
	if provider == r.URL.Path {
		provider = strings.TrimPrefix(r.URL.Path, "/api/marketplace/webhook")
	}
	provider = strings.Trim(provider, "/")
	if provider == "" {
		provider = r.URL.Query().Get("provider")
	}
	s.processProviderWebhook(w, r, provider)
}

func (s *AppServer) processProviderWebhook(w http.ResponseWriter, r *http.Request, provider string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	normProvider := strings.ToLower(strings.TrimSpace(provider))
	if normProvider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider is required"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read payload"})
		return
	}

	event, tx, err := s.proxy.ProcessMarketplaceWebhook(r.Context(), normProvider, r.Header, body)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if errors.Is(err, marketplace.ErrInvalidSignature) || errors.Is(err, marketplace.ErrMissingSignature) || errors.Is(err, marketplace.ErrTimestampDrift) {
			statusCode = http.StatusUnauthorized
		} else if errors.Is(err, marketplace.ErrUnsupportedProvider) || errors.Is(err, marketplace.ErrInvalidPayload) || errors.Is(err, marketplace.ErrMissingCustomer) {
			statusCode = http.StatusBadRequest
		}
		writeJSON(w, statusCode, map[string]interface{}{
			"error":    err.Error(),
			"provider": normProvider,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "success",
		"provider":    normProvider,
		"event":       event,
		"transaction": tx,
	})
}

func (s *AppServer) handleMarketplaceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.GetMarketplaceStatus())
}

func (s *AppServer) handleMarketplaceTransactions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	provider := strings.ToLower(strings.TrimSpace(q.Get("provider")))
	email := strings.ToLower(strings.TrimSpace(q.Get("customer_email")))
	if email == "" {
		email = strings.ToLower(strings.TrimSpace(q.Get("email")))
	}
	status := strings.ToUpper(strings.TrimSpace(q.Get("status")))
	limitStr := q.Get("limit")
	limit := 0
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	txs := s.proxy.ListMarketplaceTransactions()
	if provider != "" || email != "" || status != "" || limit > 0 {
		filtered := make([]marketplace.TransactionRecord, 0, len(txs))
		for _, tx := range txs {
			if provider != "" && strings.ToLower(tx.Provider) != provider {
				continue
			}
			if email != "" && strings.ToLower(tx.CustomerEmail) != email {
				continue
			}
			if status != "" && strings.ToUpper(tx.Status) != status {
				continue
			}
			filtered = append(filtered, tx)
			if limit > 0 && len(filtered) >= limit {
				break
			}
		}
		txs = filtered
	}

	writeJSON(w, http.StatusOK, txs)
}

type marketplaceSimulateReq struct {
	Provider      string            `json:"provider"`
	EventType     string            `json:"event_type"`
	Action        string            `json:"action"` // "provision", "revoke"
	CustomerEmail string            `json:"customer_email"`
	CustomerName  string            `json:"customer_name,omitempty"`
	LicenseKey    string            `json:"license_key,omitempty"`
	Tier          string            `json:"tier,omitempty"`
	Seats         int               `json:"seats,omitempty"`
	DaysValid     int               `json:"days_valid,omitempty"`
	OrderID       string            `json:"order_id,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

func (s *AppServer) handleMarketplaceSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req marketplaceSimulateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
		return
	}

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if provider == "" {
		provider = marketplace.ProviderStripe
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = marketplace.ActionProvision
	}

	eventType := strings.TrimSpace(req.EventType)
	if eventType == "" {
		if action == marketplace.ActionRevoke {
			eventType = "simulated.revoke"
		} else {
			eventType = "simulated.checkout.completed"
		}
	}

	tier := strings.TrimSpace(req.Tier)
	if tier == "" {
		tier = "pro"
	}

	seats := req.Seats
	if seats <= 0 {
		seats = 1
	}

	days := req.DaysValid
	if days <= 0 {
		days = 30
	}

	event := &marketplace.NormalizedEvent{
		Provider:      provider,
		EventType:     eventType,
		Action:        action,
		CustomerEmail: strings.ToLower(strings.TrimSpace(req.CustomerEmail)),
		CustomerName:  strings.TrimSpace(req.CustomerName),
		LicenseKey:    strings.TrimSpace(req.LicenseKey),
		Tier:          tier,
		Seats:         seats,
		DaysValid:     days,
		OrderID:       strings.TrimSpace(req.OrderID),
		Metadata:      req.Metadata,
	}

	tx, err := s.proxy.SimulateMarketplaceWebhook(r.Context(), event)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if errors.Is(err, marketplace.ErrUnsupportedProvider) || errors.Is(err, marketplace.ErrInvalidPayload) || errors.Is(err, marketplace.ErrMissingCustomer) {
			statusCode = http.StatusBadRequest
		}
		writeJSON(w, statusCode, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "success",
		"event":       event,
		"transaction": tx,
	})
}
