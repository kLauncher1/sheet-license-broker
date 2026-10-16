package anomaly

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// IncidentEvent captures a security incident occurrence for graph building.
type IncidentEvent struct {
	ID         string                 `json:"id"`
	EntityID   string                 `json:"entity_id"`
	LicenseKey string                 `json:"license_key"`
	HWID       string                 `json:"hwid"`
	IP         string                 `json:"ip"`
	Country    string                 `json:"country"`
	Type       string                 `json:"type"`
	Severity   int                    `json:"severity"`
	Message    string                 `json:"message"`
	Timestamp  time.Time              `json:"timestamp"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// IncidentGraphExporter coordinates security event logging and SIEM topological graph synthesis.
type IncidentGraphExporter struct {
	mu           sync.RWMutex
	incidents    []IncidentEvent
	maxIncidents int
}

// NewIncidentGraphExporter creates a new graph exporter.
func NewIncidentGraphExporter(maxIncidents int) *IncidentGraphExporter {
	if maxIncidents <= 0 {
		maxIncidents = 500
	}
	return &IncidentGraphExporter{
		incidents:    make([]IncidentEvent, 0, maxIncidents),
		maxIncidents: maxIncidents,
	}
}

// RecordIncident adds a security incident event to the real-time topology buffer.
func (ige *IncidentGraphExporter) RecordIncident(evt IncidentEvent) {
	ige.mu.Lock()
	defer ige.mu.Unlock()

	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now()
	}
	if evt.ID == "" {
		evt.ID = fmt.Sprintf("inc-%d", evt.Timestamp.UnixNano())
	}

	ige.incidents = append(ige.incidents, evt)
	if len(ige.incidents) > ige.maxIncidents {
		ige.incidents = ige.incidents[1:]
	}
}

// ExportGraph synthesizes an IncidentGraph matching the provided filter criteria.
func (ige *IncidentGraphExporter) ExportGraph(filter GraphFilter) *IncidentGraph {
	ige.mu.RLock()
	defer ige.mu.RUnlock()

	nodesMap := make(map[string]GraphNode)
	edgesList := make([]GraphEdge, 0)

	targetLicense := strings.TrimSpace(filter.LicenseKey)
	targetHWID := strings.TrimSpace(filter.HWID)
	minScore := filter.MinRiskScore
	since := filter.Since
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	count := 0
	for i := len(ige.incidents) - 1; i >= 0 && count < limit; i-- {
		inc := ige.incidents[i]

		if !since.IsZero() && inc.Timestamp.Before(since) {
			continue
		}
		if inc.Severity < minScore {
			continue
		}
		if targetLicense != "" && inc.LicenseKey != "" && !strings.EqualFold(inc.LicenseKey, targetLicense) {
			continue
		}
		if targetHWID != "" && inc.HWID != "" && !strings.EqualFold(inc.HWID, targetHWID) {
			continue
		}

		count++

		// 1. Incident Node
		incNodeID := fmt.Sprintf("incident:%s", inc.ID)
		nodesMap[incNodeID] = GraphNode{
			ID:        incNodeID,
			Type:      "incident",
			Label:     fmt.Sprintf("%s (%d)", inc.Type, inc.Severity),
			RiskScore: inc.Severity,
			Properties: map[string]interface{}{
				"message":   inc.Message,
				"timestamp": inc.Timestamp.Format(time.RFC3339),
			},
		}

		// 2. License Node
		if inc.LicenseKey != "" {
			licNodeID := fmt.Sprintf("license:%s", inc.LicenseKey)
			if _, exists := nodesMap[licNodeID]; !exists {
				nodesMap[licNodeID] = GraphNode{
					ID:        licNodeID,
					Type:      "license",
					Label:     inc.LicenseKey,
					RiskScore: inc.Severity,
				}
			}
			edgesList = append(edgesList, GraphEdge{
				Source:    licNodeID,
				Target:    incNodeID,
				Relation:  "TRIGGERED",
				Weight:    float64(inc.Severity) / 100.0,
				Timestamp: inc.Timestamp,
			})
		}

		// 3. HWID Node
		if inc.HWID != "" {
			hwidNodeID := fmt.Sprintf("hwid:%s", inc.HWID)
			if _, exists := nodesMap[hwidNodeID]; !exists {
				nodesMap[hwidNodeID] = GraphNode{
					ID:        hwidNodeID,
					Type:      "hwid",
					Label:     inc.HWID,
					RiskScore: inc.Severity,
				}
			}
			if inc.LicenseKey != "" {
				licNodeID := fmt.Sprintf("license:%s", inc.LicenseKey)
				edgesList = append(edgesList, GraphEdge{
					Source:    licNodeID,
					Target:    hwidNodeID,
					Relation:  "BOUND_TO",
					Weight:    1.0,
					Timestamp: inc.Timestamp,
				})
			}
			edgesList = append(edgesList, GraphEdge{
				Source:    hwidNodeID,
				Target:    incNodeID,
				Relation:  "ORIGINATED_AT",
				Weight:    float64(inc.Severity) / 100.0,
				Timestamp: inc.Timestamp,
			})
		}

		// 4. IP & Geo Node
		if inc.IP != "" {
			ipNodeID := fmt.Sprintf("ip:%s", inc.IP)
			if _, exists := nodesMap[ipNodeID]; !exists {
				nodesMap[ipNodeID] = GraphNode{
					ID:        ipNodeID,
					Type:      "ip",
					Label:     inc.IP,
					RiskScore: inc.Severity,
				}
			}
			if inc.HWID != "" {
				hwidNodeID := fmt.Sprintf("hwid:%s", inc.HWID)
				edgesList = append(edgesList, GraphEdge{
					Source:    hwidNodeID,
					Target:    ipNodeID,
					Relation:  "CONNECTED_FROM",
					Weight:    1.0,
					Timestamp: inc.Timestamp,
				})
			}
			if inc.Country != "" {
				geoNodeID := fmt.Sprintf("geo:%s", inc.Country)
				if _, exists := nodesMap[geoNodeID]; !exists {
					nodesMap[geoNodeID] = GraphNode{
						ID:        geoNodeID,
						Type:      "geo",
						Label:     inc.Country,
						RiskScore: 0,
					}
				}
				edgesList = append(edgesList, GraphEdge{
					Source:    ipNodeID,
					Target:    geoNodeID,
					Relation:  "LOCATED_IN",
					Weight:    1.0,
					Timestamp: inc.Timestamp,
				})
			}
		}
	}

	nodes := make([]GraphNode, 0, len(nodesMap))
	for _, node := range nodesMap {
		nodes = append(nodes, node)
	}

	return &IncidentGraph{
		Format:      "siem-topology-v1",
		GeneratedAt: time.Now().UTC(),
		TotalNodes:  len(nodes),
		TotalEdges:  len(edgesList),
		Nodes:       nodes,
		Edges:       edgesList,
	}
}

// ListIncidents returns a snapshot of recent incidents.
func (ige *IncidentGraphExporter) ListIncidents(limit int) []IncidentEvent {
	ige.mu.RLock()
	defer ige.mu.RUnlock()

	if limit <= 0 || limit > len(ige.incidents) {
		limit = len(ige.incidents)
	}
	result := make([]IncidentEvent, limit)
	start := len(ige.incidents) - limit
	copy(result, ige.incidents[start:])
	return result
}
