package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/kLauncher1/sheet-license-broker/internal/marketplace"
	"github.com/kLauncher1/sheet-license-broker/internal/webhook"
)

// initMarketplace sets up the marketplace manager and automated provisioning/revocation bindings.
func (p *Proxy) initMarketplace(cfg ProxyConfig) {
	mpCfg := marketplace.MarketplaceConfig{
		StripeWebhookSecret:       strings.TrimSpace(cfg.StripeWebhookSecret),
		LemonSqueezyWebhookSecret: strings.TrimSpace(cfg.LemonSqueezyWebhookSecret),
		PaddleWebhookSecret:       strings.TrimSpace(cfg.PaddleWebhookSecret),
		DefaultDaysValid:          365,
		DefaultTier:               "pro",
		DefaultSeats:              1,
		ToleranceSeconds:          300,
	}

	provisionFn := func(daysValid, maxDevices int, tier string, features []string) (string, error) {
		lic, err := p.CreateLicenseWithTier(context.Background(), daysValid, maxDevices, tier, features)
		if err != nil {
			return "", err
		}
		// Notify stream hub and audit collector
		p.BroadcastStreamEvent("license_provisioned", map[string]interface{}{
			"license_key": lic.LicenseKey,
			"tier":        lic.Tier,
			"seats":       maxDevices,
			"expires_at":  lic.ExpiresAt,
			"source":      "marketplace",
		})
		p.NotifyLicenseEvent(webhook.EventLicenseCreated, lic.LicenseKey, "", fmt.Sprintf("Provisioned via Marketplace (Tier: %s, Seats: %d)", lic.Tier, maxDevices))
		return lic.LicenseKey, nil
	}

	revokeFn := func(licenseKey, reason string) error {
		return p.RevokeLicense(context.Background(), licenseKey, reason)
	}

	p.marketplaceMgr = marketplace.NewManager(mpCfg, provisionFn, revokeFn)
}

// MarketplaceManager returns the attached marketplace manager instance.
func (p *Proxy) MarketplaceManager() *marketplace.Manager {
	return p.marketplaceMgr
}

// ProcessMarketplaceWebhook processes an incoming webhook from Stripe, Lemon Squeezy, or Paddle.
func (p *Proxy) ProcessMarketplaceWebhook(ctx context.Context, provider string, header http.Header, body []byte) (*marketplace.NormalizedEvent, *marketplace.TransactionRecord, error) {
	if p.marketplaceMgr == nil {
		return nil, nil, fmt.Errorf("marketplace manager is not initialized")
	}
	return p.marketplaceMgr.ProcessWebhook(provider, header, body)
}

// SimulateMarketplaceWebhook processes a simulated webhook event (for testing and admin console).
func (p *Proxy) SimulateMarketplaceWebhook(ctx context.Context, event *marketplace.NormalizedEvent) (*marketplace.TransactionRecord, error) {
	if p.marketplaceMgr == nil {
		return nil, fmt.Errorf("marketplace manager is not initialized")
	}
	return p.marketplaceMgr.SimulateEvent(event)
}

// ListMarketplaceTransactions returns the audit trail of processed marketplace webhook transactions.
func (p *Proxy) ListMarketplaceTransactions() []marketplace.TransactionRecord {
	if p.marketplaceMgr == nil {
		return []marketplace.TransactionRecord{}
	}
	return p.marketplaceMgr.ListTransactions()
}

// GetMarketplaceStatus returns diagnostic status summary of marketplace integration.
func (p *Proxy) GetMarketplaceStatus() map[string]interface{} {
	if p.marketplaceMgr == nil {
		return map[string]interface{}{
			"status":  "disabled",
			"enabled": false,
		}
	}

	st := p.marketplaceMgr.GetStatus()
	return map[string]interface{}{
		"status":                   "success",
		"enabled":                  true,
		"supported_providers":      st.SupportedProviders,
		"total_processed_events":   st.TotalProcessedEvents,
		"total_transactions":       st.TotalProcessedEvents,
		"total_provisioned":        st.TotalProvisioned,
		"total_revoked":            st.TotalRevoked,
		"total_duplicates":         st.TotalDuplicates,
		"total_failed":             st.TotalFailed,
		"recent_transactions":      st.RecentTransactions,
		"stripe_configured":        st.StripeConfigured,
		"lemon_squeezy_configured": st.LemonSqueezyConfigured,
		"paddle_configured":        st.PaddleConfigured,
		"providers": map[string]interface{}{
			"stripe":       map[string]interface{}{"active": st.StripeConfigured},
			"lemonsqueezy": map[string]interface{}{"active": st.LemonSqueezyConfigured},
			"paddle":       map[string]interface{}{"active": st.PaddleConfigured},
		},
		"idempotency_cache": map[string]interface{}{
			"size":     p.marketplaceMgr.IdempotencyCount(),
			"capacity": 10000,
		},
		"timestamp": st.Timestamp,
	}
}
