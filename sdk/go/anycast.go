package sdk

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/kLauncher1/sheet-license-broker/internal/anycast"
)

// GetAnycastRoute queries the broker's geo-routing engine to find the nearest Point of Presence.
func (c *Client) GetAnycastRoute(ctx context.Context, lat, lon float64, country, preferredRegion string) (*anycast.RoutingDecision, error) {
	params := url.Values{}
	if lat != 0 || lon != 0 {
		params.Set("lat", fmt.Sprintf("%f", lat))
		params.Set("lon", fmt.Sprintf("%f", lon))
	}
	if country != "" {
		params.Set("country", country)
	}
	if preferredRegion != "" {
		params.Set("region", preferredRegion)
	}

	endpoint := "/api/anycast/route"
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}

	var res anycast.RoutingDecision
	if err := c.request(ctx, http.MethodGet, endpoint, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ReportAnycastProbe submits edge RTT latency and packet loss telemetry to the broker.
func (c *Client) ReportAnycastProbe(ctx context.Context, probe anycast.TelemetryProbe) error {
	var res map[string]interface{}
	return c.request(ctx, http.MethodPost, "/api/anycast/probe", probe, &res)
}

// GetAnycastStatus retrieves global POPs, partition isolation states, and cache status.
func (c *Client) GetAnycastStatus(ctx context.Context) (map[string]interface{}, error) {
	var res map[string]interface{}
	if err := c.request(ctx, http.MethodGet, "/api/anycast/status", nil, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// GetEdgeCacheStats retrieves microsecond-level L1 edge cache performance telemetry.
func (c *Client) GetEdgeCacheStats(ctx context.Context) (*anycast.EdgeCacheStats, error) {
	var res anycast.EdgeCacheStats
	if err := c.request(ctx, http.MethodGet, "/api/anycast/cache/stats", nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// FastVerifyLicense executes a sub-millisecond license check against the edge L1 cache.
func (c *Client) FastVerifyLicense(ctx context.Context, licenseKey, hwid string) (*ValidationResult, error) {
	req := map[string]string{
		"license_key": licenseKey,
		"hwid":       hwid,
	}
	var res ValidationResult
	if err := c.request(ctx, http.MethodPost, "/api/anycast/verify", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
