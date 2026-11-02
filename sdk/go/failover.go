package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kLauncher1/sheet-license-broker/internal/failover"
)

type multiCloudProvidersResponse struct {
	Providers []failover.CloudProvider `json:"providers"`
	Count     int                      `json:"count"`
}

type multiCloudRouteResponse struct {
	Provider failover.CloudProvider         `json:"provider"`
	Token    failover.MultiCloudRoutingToken `json:"token"`
}

type multiCloudProbeResponse struct {
	Success       bool                    `json:"success"`
	FailoverEvent *failover.FailoverEvent `json:"failover_event"`
}

type multiCloudDeltaResponse struct {
	Success bool               `json:"success"`
	Delta   failover.SyncDelta `json:"delta"`
}

type multiCloudPendingResponse struct {
	ProviderID string               `json:"provider_id"`
	Pending    []failover.SyncDelta `json:"pending"`
	Count      int                  `json:"count"`
}

// GetMultiCloudStatus queries real-time status and telemetry for the multi-cloud mesh.
func (c *Client) GetMultiCloudStatus(ctx context.Context) (*failover.MultiCloudStatus, error) {
	var res failover.MultiCloudStatus
	if err := c.request(ctx, http.MethodGet, "/api/multicloud/status", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListMultiCloudProviders returns the configured active-active cloud edge providers.
func (c *Client) ListMultiCloudProviders(ctx context.Context) ([]failover.CloudProvider, error) {
	var res multiCloudProvidersResponse
	if err := c.request(ctx, http.MethodGet, "/api/multicloud/providers", nil, &res); err != nil {
		return nil, err
	}
	return res.Providers, nil
}

// RouteMultiCloud calculates the optimal cloud provider and signed token for a client request.
func (c *Client) RouteMultiCloud(ctx context.Context, clientRegion, clientIP string) (*failover.CloudProvider, *failover.MultiCloudRoutingToken, error) {
	body := map[string]string{
		"client_region": clientRegion,
		"client_ip":     clientIP,
	}
	var res multiCloudRouteResponse
	if err := c.request(ctx, http.MethodPost, "/api/multicloud/route", body, &res); err != nil {
		return nil, nil, err
	}
	return &res.Provider, &res.Token, nil
}

// SubmitMultiCloudProbe records a synthetic health probe result with the broker.
func (c *Client) SubmitMultiCloudProbe(ctx context.Context, probe failover.HealthProbeResult) (*failover.FailoverEvent, error) {
	var res multiCloudProbeResponse
	if err := c.request(ctx, http.MethodPost, "/api/multicloud/probe", probe, &res); err != nil {
		return nil, err
	}
	return res.FailoverEvent, nil
}

// SubmitMultiCloudDelta commits a state mutation for cross-cloud zero-packet-loss synchronization.
func (c *Client) SubmitMultiCloudDelta(ctx context.Context, originProvider, action string, payload []byte) (*failover.SyncDelta, error) {
	body := map[string]interface{}{
		"origin_provider": originProvider,
		"action":          action,
		"payload":         json.RawMessage(payload),
	}
	var res multiCloudDeltaResponse
	if err := c.request(ctx, http.MethodPost, "/api/multicloud/sync/delta", body, &res); err != nil {
		return nil, err
	}
	return &res.Delta, nil
}

// GetMultiCloudPendingSync queries uncommitted deltas for a cloud provider.
func (c *Client) GetMultiCloudPendingSync(ctx context.Context, providerID string, limit int) ([]failover.SyncDelta, error) {
	path := fmt.Sprintf("/api/multicloud/sync/pending?provider_id=%s", providerID)
	if limit > 0 {
		path = fmt.Sprintf("%s&limit=%d", path, limit)
	}
	var res multiCloudPendingResponse
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return res.Pending, nil
}

// AcknowledgeMultiCloudSync clears a delta from a provider's replay backlog.
func (c *Client) AcknowledgeMultiCloudSync(ctx context.Context, providerID, deltaID string, voucher *failover.SyncVoucher) error {
	body := map[string]interface{}{
		"provider_id": providerID,
		"delta_id":    deltaID,
		"voucher":     voucher,
	}
	return c.request(ctx, http.MethodPost, "/api/multicloud/sync/acknowledge", body, nil)
}

// SimulateMultiCloudFailover triggers an administrative failover drill.
func (c *Client) SimulateMultiCloudFailover(ctx context.Context, providerID, reason string) (*failover.FailoverEvent, error) {
	body := map[string]string{
		"provider_id": providerID,
		"reason":      reason,
	}
	var res struct {
		Success       bool                    `json:"success"`
		FailoverEvent *failover.FailoverEvent `json:"failover_event"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/multicloud/failover/simulate", body, &res); err != nil {
		return nil, err
	}
	return res.FailoverEvent, nil
}
