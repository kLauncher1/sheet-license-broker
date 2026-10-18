package proxy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/anycast"
)

var (
	ErrAnycastNotInitialized = errors.New("anycast subsystem is not initialized")
)

// initAnycast initializes the Anycast Router, Sub-millisecond L1 Edge Cache, and Partition Mitigator.
func (p *Proxy) initAnycast(cfg ProxyConfig) {
	secret := []byte(cfg.GlobalSecret)
	if len(secret) == 0 {
		secret = []byte("default-sheet-license-broker-anycast-key-32b")
	}

	region := strings.TrimSpace(cfg.ClusterRegion)
	if region == "" {
		region = "us-east"
	}

	p.anycastRouter = anycast.NewAnycastRouter(secret)
	p.partitionMitigator = anycast.NewPartitionMitigator(region, secret, 24*time.Hour)

	// L1 Edge Cache with 15s fresh TTL, 60s stale grace, and background revalidation
	p.anycastCache = anycast.NewSubMillisecondEdgeCache(15*time.Second, 60*time.Second, func(key string) (interface{}, error) {
		parts := strings.Split(key, "::")
		licenseKey := parts[0]
		hwid := ""
		if len(parts) > 1 {
			hwid = parts[1]
		}
		res, err := p.VerifyLicense(context.Background(), licenseKey, hwid)
		if err != nil {
			return nil, err
		}
		return res, nil
	})
}

// AnycastRouter returns the active anycast router.
func (p *Proxy) AnycastRouter() *anycast.AnycastRouter {
	return p.anycastRouter
}

// AnycastCache returns the sub-millisecond edge cache.
func (p *Proxy) AnycastCache() *anycast.SubMillisecondEdgeCache {
	return p.anycastCache
}

// PartitionMitigator returns the geographic partition mitigator.
func (p *Proxy) PartitionMitigator() *anycast.PartitionMitigator {
	return p.partitionMitigator
}

// RouteNearestPOP computes the optimal POP based on geographic coordinates and latency scores.
func (p *Proxy) RouteNearestPOP(clientLat, clientLon float64, clientIP, preferredRegion string) (*anycast.RoutingDecision, error) {
	if p.anycastRouter == nil {
		return nil, ErrAnycastNotInitialized
	}
	return p.anycastRouter.RouteNearest(clientLat, clientLon, clientIP, preferredRegion)
}

// VerifyRoutingToken validates an Anycast routing token.
func (p *Proxy) VerifyRoutingToken(tokenStr string) (*anycast.RoutingTokenClaims, error) {
	if p.anycastRouter == nil {
		return nil, ErrAnycastNotInitialized
	}
	return p.anycastRouter.VerifyRoutingToken(tokenStr)
}

// FastVerifyLicense checks the sub-millisecond edge cache first before falling back to full verification.
// If a geographic partition is detected, an emergency mitigation lease is issued.
func (p *Proxy) FastVerifyLicense(ctx context.Context, licenseKey, hwid string) (*VerifyResult, error) {
	cacheKey := fmt.Sprintf("%s::%s", strings.TrimSpace(licenseKey), strings.TrimSpace(hwid))

	// 1. Sub-millisecond L1 cache hit check (<1ms)
	if p.anycastCache != nil {
		if val, found := p.anycastCache.Get(cacheKey); found {
			if res, ok := val.(*VerifyResult); ok {
				return res, nil
			}
		}
	}

	// 2. Check if local region is under geographic partition
	if p.partitionMitigator != nil && p.partitionMitigator.IsLocalPartitioned() {
		// Issue emergency mitigation lease token during cloud blackout
		emergencyToken, err := p.partitionMitigator.IssueEmergencyLease(licenseKey, hwid, p.partitionMitigator.LocalRegion())
		if err == nil {
			res := &VerifyResult{
				Valid:      true,
				LicenseKey: licenseKey,
				HWIDBound:  hwid,
				Tier:       "enterprise",
				Source:     "partition_emergency_lease",
				Message:    fmt.Sprintf("Partition mitigated: emergency offline lease granted (expires: %s)", emergencyToken.LeaseExpiry.Format(time.RFC3339)),
				ExpiresAt:  emergencyToken.LeaseExpiry.Format(time.RFC3339),
			}
			return res, nil
		}
	}

	// 3. Normal path: full license verification
	res, err := p.VerifyLicense(ctx, licenseKey, hwid)
	if err != nil {
		return nil, err
	}

	// 4. Cache valid results in L1 edge cache
	if p.anycastCache != nil && res != nil && res.Valid {
		p.anycastCache.Set(cacheKey, res)
	}

	return res, nil
}

// IngestAnycastProbe records health and RTT telemetry for a target POP.
func (p *Proxy) IngestAnycastProbe(probe anycast.TelemetryProbe) {
	if p.anycastRouter != nil {
		p.anycastRouter.IngestProbe(probe)
	}
}

// GetAnycastStatus returns a consolidated diagnostic view of geo POPs, edge cache, and partition state.
func (p *Proxy) GetAnycastStatus() map[string]interface{} {
	var pops []anycast.POP
	if p.anycastRouter != nil {
		pops = p.anycastRouter.ListPOPs()
	}

	var cacheStats anycast.EdgeCacheStats
	if p.anycastCache != nil {
		cacheStats = p.anycastCache.Stats()
	}

	var partitions []anycast.PartitionState
	isPartitioned := false
	if p.partitionMitigator != nil {
		partitions = p.partitionMitigator.ListPartitionStates()
		isPartitioned = p.partitionMitigator.IsLocalPartitioned()
	}

	return map[string]interface{}{
		"pops":                 pops,
		"pop_count":            len(pops),
		"cache_stats":          cacheStats,
		"is_partitioned":       isPartitioned,
		"partition_states":     partitions,
		"edge_routing_enabled": p.anycastRouter != nil,
	}
}
