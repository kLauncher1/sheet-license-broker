package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/consensus"
	"github.com/kLauncher1/sheet-license-broker/internal/license"
)

func (p *Proxy) initConsensus(cfg ProxyConfig) {
	nodeID := strings.TrimSpace(cfg.NodeID)
	if nodeID == "" {
		host, err := os.Hostname()
		if err == nil && host != "" {
			nodeID = "node-" + host
		} else {
			nodeID = fmt.Sprintf("node-%d", time.Now().UnixNano()%100000)
		}
	}

	region := strings.TrimSpace(cfg.ClusterRegion)
	if region == "" {
		region = "default-region"
	}

	addr := strings.TrimSpace(cfg.ClusterAddress)
	if addr == "" {
		addr = "http://localhost:9082"
	}

	p.crdtStore = consensus.NewCRDTStore(nodeID)
	p.p2pMesh = consensus.NewP2PMesh(nodeID, region, addr, p.crdtStore, 500*time.Millisecond)

	applyCb := func(entry consensus.LogEntry) error {
		switch entry.Type {
		case consensus.CmdLicenseCreate:
			var lic license.License
			if err := json.Unmarshal([]byte(entry.Value), &lic); err == nil && lic.LicenseKey != "" {
				p.cache.Set(lic.LicenseKey, lic, p.cacheTTL)
			}
		case consensus.CmdLicenseRevoke:
			_ = p.localLicense.RevokeLicense(entry.Key, entry.Value)
			p.cache.DeleteLicense(entry.Key)
		case consensus.CmdDeviceBlacklist:
			p.localLicense.Blacklist().Add(license.BlacklistTypeDevice, entry.Key, entry.Value)
		case consensus.CmdDeviceUnban:
			p.localLicense.Blacklist().Remove(license.BlacklistTypeDevice, entry.Key)
		}
		return nil
	}

	engineCfg := consensus.Config{
		NodeID:          nodeID,
		Region:          region,
		ElectionTimeout: 300 * time.Millisecond,
		HeartbeatPeriod: 100 * time.Millisecond,
		Transport:       p.p2pMesh,
		ApplyCallback:   applyCb,
	}

	p.consensusEngine = consensus.NewConsensusEngine(engineCfg, p.crdtStore)
	p.p2pMesh.BindEngine(p.consensusEngine)

	for _, peerAddr := range cfg.ClusterPeers {
		peerAddr = strings.TrimSpace(peerAddr)
		if peerAddr != "" {
			p.consensusEngine.AddPeer(consensus.PeerNode{
				ID:      peerAddr,
				Address: peerAddr,
				Active:  true,
			})
		}
	}
}

// ClusterStatus retrieves cluster quorum, role, and peer telemetry.
func (p *Proxy) ClusterStatus() consensus.ClusterStatus {
	if p.consensusEngine == nil {
		return consensus.ClusterStatus{}
	}
	return p.consensusEngine.Status()
}

// ClusterPeers returns active peer nodes in the consensus mesh.
func (p *Proxy) ClusterPeers() []consensus.PeerNode {
	if p.consensusEngine == nil {
		return nil
	}
	return p.consensusEngine.Status().Peers
}

// JoinCluster dynamically introduces a new peer into the consensus engine.
func (p *Proxy) JoinCluster(peer consensus.PeerNode) {
	if p.consensusEngine != nil {
		p.consensusEngine.AddPeer(peer)
	}
}

// HandleRaftVote processes inbound RequestVote RPCs.
func (p *Proxy) HandleRaftVote(req consensus.VoteRequest) consensus.VoteResponse {
	if p.consensusEngine == nil {
		return consensus.VoteResponse{VoteGranted: false, Reason: "consensus not enabled"}
	}
	return p.consensusEngine.HandleVoteRequest(req)
}

// HandleRaftAppend processes inbound AppendEntries RPCs.
func (p *Proxy) HandleRaftAppend(req consensus.AppendEntriesRequest) consensus.AppendEntriesResponse {
	if p.consensusEngine == nil {
		return consensus.AppendEntriesResponse{Success: false, Reason: "consensus not enabled"}
	}
	return p.consensusEngine.HandleAppendEntries(req)
}

// HandleCRDTSync merges remote state and returns local snapshot.
func (p *Proxy) HandleCRDTSync(req consensus.CRDTSyncPayload) consensus.CRDTSyncPayload {
	if p.crdtStore == nil {
		return consensus.CRDTSyncPayload{}
	}
	p.crdtStore.Merge(req)
	return p.crdtStore.ExportState()
}

// TriggerAntiEntropySync forces an anti-entropy state check and sync with a specific peer.
func (p *Proxy) TriggerAntiEntropySync(ctx context.Context, peerID string) (int, error) {
	if p.p2pMesh == nil || p.consensusEngine == nil {
		return 0, fmt.Errorf("consensus mesh inactive")
	}

	status := p.consensusEngine.Status()
	for _, peer := range status.Peers {
		if peer.ID == peerID || peer.Address == peerID {
			peerCopy := peer
			return p.p2pMesh.TriggerAntiEntropy(ctx, &peerCopy)
		}
	}
	return 0, fmt.Errorf("peer '%s' not found in cluster registry", peerID)
}

// ProposeConsensusLicense replicates license creation across quorum cluster.
func (p *Proxy) ProposeConsensusLicense(ctx context.Context, lic license.License) error {
	if p.consensusEngine == nil {
		return nil
	}
	payloadBytes, _ := json.Marshal(lic)
	_, err := p.consensusEngine.Propose(ctx, consensus.CmdLicenseCreate, lic.LicenseKey, string(payloadBytes))
	return err
}

// ProposeConsensusRevocation replicates license key revocation across quorum cluster.
func (p *Proxy) ProposeConsensusRevocation(ctx context.Context, key, reason string) error {
	if p.consensusEngine == nil {
		return nil
	}
	_, err := p.consensusEngine.Propose(ctx, consensus.CmdLicenseRevoke, key, reason)
	return err
}

// ProposeConsensusBlacklist replicates hardware ID device bans across quorum cluster.
func (p *Proxy) ProposeConsensusBlacklist(ctx context.Context, hwid, reason string) error {
	if p.consensusEngine == nil {
		return nil
	}
	_, err := p.consensusEngine.Propose(ctx, consensus.CmdDeviceBlacklist, hwid, reason)
	return err
}
