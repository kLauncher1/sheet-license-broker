package proxy

import (
	"context"
	"log"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/failover"
)

// initFailover initializes the autonomous multi-cloud edge failover & Geo-DNS health routing engine.
func (p *Proxy) initFailover(cfg ProxyConfig) {
	secret := []byte(cfg.GlobalSecret)
	if len(secret) == 0 {
		secret = []byte("default-sheet-license-broker-multicloud-secret-key-32b")
	}
	mgr := failover.NewMultiCloudManager(secret)

	// Bind real-time failover broadcast to SSE stream hub
	mgr.SetFailoverListener(func(event failover.FailoverEvent) {
		p.BroadcastStreamEvent("multicloud_failover", map[string]interface{}{
			"event_id":           event.EventID,
			"previous_provider":  event.PreviousProvider,
			"new_provider":       event.NewProvider,
			"reason":             event.Reason,
			"trigger_latency_ms": event.TriggerLatency,
			"timestamp":          event.Timestamp.Format(time.RFC3339),
		})
	})

	p.failoverManager = mgr
	log.Printf("[Proxy] Autonomous Multi-Cloud Edge Failover & Geo-DNS Health Routing engine initialized (v2.7.0)")
}

// MultiCloudManager returns the active multi-cloud orchestration manager.
func (p *Proxy) MultiCloudManager() *failover.MultiCloudManager {
	return p.failoverManager
}

// GetMultiCloudStatus returns operational telemetry and status for the multi-cloud mesh.
func (p *Proxy) GetMultiCloudStatus() failover.MultiCloudStatus {
	if p.failoverManager == nil {
		return failover.MultiCloudStatus{}
	}
	return p.failoverManager.GetStatus()
}

// RouteMultiCloud evaluates geo context and issues an optimal provider grant with signed token.
func (p *Proxy) RouteMultiCloud(clientRegion, clientIP string) (*failover.CloudProvider, *failover.MultiCloudRoutingToken, error) {
	if p.failoverManager == nil {
		return nil, nil, failover.ErrNoHealthyProviders
	}
	return p.failoverManager.RouteRequest(clientRegion, clientIP)
}

// RecordMultiCloudProbe records probe measurements and persists telemetry into Google Apps Script backend.
func (p *Proxy) RecordMultiCloudProbe(res failover.HealthProbeResult) (*failover.FailoverEvent, error) {
	if p.failoverManager == nil {
		return nil, nil
	}
	event, err := p.failoverManager.RecordProbe(res)

	// Asynchronously record probe or failover event in Google Apps Script persistent backend
	if p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "multicloud_record_probe", map[string]interface{}{
				"provider_id":   res.ProviderID,
				"success":       res.Success,
				"latency_ms":    res.LatencyMS,
				"status_code":   res.StatusCode,
				"error_message": res.ErrorMessage,
				"origin_region": res.OriginRegion,
				"timestamp":     res.Timestamp.Format(time.RFC3339),
			})

			if event != nil {
				_, _ = p.gasClient.ExecuteAction(context.Background(), "multicloud_record_failover", map[string]interface{}{
					"event_id":           event.EventID,
					"previous_provider":  event.PreviousProvider,
					"new_provider":       event.NewProvider,
					"reason":             event.Reason,
					"trigger_latency_ms": event.TriggerLatency,
					"timestamp":          event.Timestamp.Format(time.RFC3339),
				})
			}
		}()
	}

	return event, err
}

// SyncMultiCloudDelta records an atomic state delta for cross-cloud replication with zero packet loss.
func (p *Proxy) SyncMultiCloudDelta(originProvider, action string, payload []byte) (*failover.SyncDelta, error) {
	if p.failoverManager == nil {
		return nil, nil
	}
	delta, err := p.failoverManager.SubmitDelta(originProvider, action, payload)
	if err == nil && delta != nil && p.gasClient != nil {
		go func() {
			_, _ = p.gasClient.ExecuteAction(context.Background(), "multicloud_record_sync_delta", map[string]interface{}{
				"delta_id":        delta.DeltaID,
				"origin_provider": delta.OriginProvider,
				"sequence_number": delta.SequenceNumber,
				"action":          delta.Action,
				"checksum":        delta.Checksum,
				"timestamp":       delta.Timestamp,
			})
		}()
	}
	return delta, err
}

// GetMultiCloudPendingSync returns deltas queued for a partitioned or recovering cloud provider.
func (p *Proxy) GetMultiCloudPendingSync(providerID string, limit int) []*failover.SyncDelta {
	if p.failoverManager == nil {
		return []*failover.SyncDelta{}
	}
	return p.failoverManager.GetPendingSync(providerID, limit)
}

// AcknowledgeMultiCloudSync acknowledges that a delta has been committed on a peer provider.
func (p *Proxy) AcknowledgeMultiCloudSync(providerID, deltaID string, voucher *failover.SyncVoucher) error {
	if p.failoverManager == nil {
		return nil
	}
	return p.failoverManager.AcknowledgeSync(providerID, deltaID, voucher)
}

// SimulateMultiCloudOutage triggers an administrative failover drill.
func (p *Proxy) SimulateMultiCloudOutage(providerID, reason string) (*failover.FailoverEvent, error) {
	if p.failoverManager == nil {
		return nil, failover.ErrProviderNotFound
	}
	return p.failoverManager.SimulateOutage(providerID, reason)
}
