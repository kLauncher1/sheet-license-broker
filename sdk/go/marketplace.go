package sdk

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/kLauncher1/sheet-license-broker/internal/marketplace"
)

// MarketplaceSimulateResponse encapsulates the result of a simulated webhook event.
type MarketplaceSimulateResponse struct {
	Status      string                         `json:"status"`
	Event       *marketplace.NormalizedEvent   `json:"event"`
	Transaction *marketplace.TransactionRecord `json:"transaction"`
}

// MarketplaceFilterOptions specifies optional query parameters for listing transactions.
type MarketplaceFilterOptions struct {
	Provider      string
	CustomerEmail string
	Status        string
	Limit         int
}

// GetMarketplaceStatus retrieves diagnostic telemetry from the marketplace webhooks bridge.
func (c *Client) GetMarketplaceStatus(ctx context.Context) (map[string]interface{}, error) {
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/api/marketplace/status", nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// SimulateMarketplaceWebhook sends a synthetic purchase or cancellation webhook to test automated provisioning.
func (c *Client) SimulateMarketplaceWebhook(ctx context.Context, provider, action, customerEmail, tier string, seats, daysValid int) (*MarketplaceSimulateResponse, error) {
	req := map[string]interface{}{
		"provider":       provider,
		"action":         action,
		"customer_email": customerEmail,
		"tier":           tier,
		"seats":          seats,
		"days_valid":     daysValid,
	}

	var res MarketplaceSimulateResponse
	if err := c.request(ctx, http.MethodPost, "/api/marketplace/simulate", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListMarketplaceTransactions retrieves the transaction ledger of processed marketplace events.
func (c *Client) ListMarketplaceTransactions(ctx context.Context) ([]marketplace.TransactionRecord, error) {
	return c.ListMarketplaceTransactionsWithOptions(ctx, MarketplaceFilterOptions{})
}

// ListMarketplaceTransactionsWithOptions retrieves transactions matching filter criteria.
func (c *Client) ListMarketplaceTransactionsWithOptions(ctx context.Context, opts MarketplaceFilterOptions) ([]marketplace.TransactionRecord, error) {
	path := "/api/marketplace/transactions"
	q := url.Values{}
	if opts.Provider != "" {
		q.Set("provider", opts.Provider)
	}
	if opts.CustomerEmail != "" {
		q.Set("customer_email", opts.CustomerEmail)
	}
	if opts.Status != "" {
		q.Set("status", opts.Status)
	}
	if opts.Limit > 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	var res []marketplace.TransactionRecord
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}
