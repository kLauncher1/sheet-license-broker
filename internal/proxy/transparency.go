package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/kLauncher1/sheet-license-broker/internal/transparency"
)

// initTransparency initializes the verifiable Merkle tree transparency log manager.
func (p *Proxy) initTransparency(cfg ProxyConfig) {
	logID := "sheet-license-broker-transparency-v2.5.0"
	signingKey := []byte("slb-transparency-master-signing-key-fips180-4")
	p.transparencyManager = transparency.NewManager(logID, signingKey)
	log.Printf("[Proxy] Verifiable Merkle Tree Transparency Log initialized (RFC 6962, LogID: %s)", logID)
}

// TransparencyManager returns the active transparency log manager.
func (p *Proxy) TransparencyManager() *transparency.Manager {
	return p.transparencyManager
}

// GetTransparencyStatus returns the operational status and telemetry for the transparency log.
func (p *Proxy) GetTransparencyStatus() transparency.TransparencyStatus {
	if p.transparencyManager == nil {
		return transparency.TransparencyStatus{}
	}
	return *p.transparencyManager.GetStatus()
}

// AppendTransparencyAudit records an action into the verifiable Merkle transparency log.
func (p *Proxy) AppendTransparencyAudit(action, tenantID string, payload []byte) (*transparency.LogEntry, *transparency.SignedTreeHead, error) {
	if p.transparencyManager == nil {
		return nil, nil, fmt.Errorf("transparency manager not initialized")
	}

	entry, sth, err := p.transparencyManager.AppendAuditEntry(action, tenantID, payload)
	if err != nil {
		return nil, nil, err
	}

	// Dispatch asynchronous ledger audit sync to Google Apps Script backend
	if p.gasClient != nil {
		go func() {
			var payloadMap map[string]interface{}
			_ = json.Unmarshal(payload, &payloadMap)
			_, _ = p.gasClient.ExecuteAction(context.Background(), "transparency_record_entry", map[string]interface{}{
				"index":         entry.Index,
				"action":        entry.Action,
				"tenant_id":     entry.TenantID,
				"leaf_hash_hex": entry.LeafHashHex,
				"timestamp":     entry.Timestamp,
				"signature":     entry.Signature,
				"payload":       payloadMap,
				"tree_size":     sth.TreeSize,
				"root_hash_hex": sth.RootHashHex,
			})
		}()
	}

	return entry, sth, nil
}

// GetTransparencySTH returns the latest Signed Tree Head.
func (p *Proxy) GetTransparencySTH() *transparency.SignedTreeHead {
	if p.transparencyManager == nil {
		return nil
	}
	return p.transparencyManager.GetSTH()
}

// GetTransparencyEntry returns a specific log entry by index.
func (p *Proxy) GetTransparencyEntry(index int64) (*transparency.LogEntry, error) {
	if p.transparencyManager == nil {
		return nil, fmt.Errorf("transparency manager not initialized")
	}
	return p.transparencyManager.GetEntry(index)
}

// GetTransparencyEntries returns a range of log entries.
func (p *Proxy) GetTransparencyEntries(start, count int64) ([]*transparency.LogEntry, error) {
	if p.transparencyManager == nil {
		return nil, fmt.Errorf("transparency manager not initialized")
	}
	return p.transparencyManager.GetEntries(start, count)
}

// GetTransparencyInclusionProof generates an RFC 6962 inclusion proof.
func (p *Proxy) GetTransparencyInclusionProof(leafIndex, treeSize int64) (*transparency.InclusionProof, error) {
	if p.transparencyManager == nil {
		return nil, fmt.Errorf("transparency manager not initialized")
	}
	return p.transparencyManager.GetInclusionProof(leafIndex, treeSize)
}

// VerifyTransparencyInclusionProof verifies an inclusion proof payload.
func (p *Proxy) VerifyTransparencyInclusionProof(proof *transparency.InclusionProof) bool {
	if p.transparencyManager == nil {
		return false
	}
	return p.transparencyManager.VerifyInclusionProof(proof)
}

// GetTransparencyConsistencyProof generates an RFC 6962 consistency proof.
func (p *Proxy) GetTransparencyConsistencyProof(firstSize, secondSize int64) (*transparency.ConsistencyProof, error) {
	if p.transparencyManager == nil {
		return nil, fmt.Errorf("transparency manager not initialized")
	}
	return p.transparencyManager.GetConsistencyProof(firstSize, secondSize)
}

// VerifyTransparencyConsistencyProof verifies a consistency proof payload.
func (p *Proxy) VerifyTransparencyConsistencyProof(proof *transparency.ConsistencyProof) bool {
	if p.transparencyManager == nil {
		return false
	}
	return p.transparencyManager.VerifyConsistencyProof(proof)
}

// WitnessCosignTransparency allows a witness to co-sign the active tree head.
func (p *Proxy) WitnessCosignTransparency(witnessID string) (*transparency.WitnessSignature, error) {
	if p.transparencyManager == nil {
		return nil, fmt.Errorf("transparency manager not initialized")
	}
	return p.transparencyManager.WitnessCosign(witnessID)
}

// ListTransparencyWitnesses lists all registered witness node IDs.
func (p *Proxy) ListTransparencyWitnesses() []string {
	if p.transparencyManager == nil {
		return nil
	}
	return p.transparencyManager.ListWitnesses()
}
