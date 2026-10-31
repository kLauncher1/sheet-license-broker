package transparency

import (
	"encoding/hex"
	"sync"
)

// Manager coordinates the transparency log Merkle tree, witness pool, and cryptographic verification pipelines.
type Manager struct {
	mu          sync.RWMutex
	logID       string
	signingKey  []byte
	tree        *TransparencyTree
	witnessPool *WitnessPool
	autoCosign  bool
}

// NewManager constructs a fully initialized transparency manager with default multi-party witness nodes.
func NewManager(logID string, signingKey []byte) *Manager {
	if logID == "" {
		logID = "sheet-license-broker-transparency-v2.5.0"
	}
	if len(signingKey) == 0 {
		signingKey = []byte("slb-transparency-master-signing-key-fips180-4")
	}

	tree := NewTransparencyTree(logID, signingKey)
	pool := NewWitnessPool()

	// Pre-seed three diverse witness participants
	pool.RegisterWitness("witness-enclave-sgx", []byte("sgx-enclave-cosigner-key-256"))
	pool.RegisterWitness("witness-node-iad", []byte("iad-pop-cosigner-key-256"))
	pool.RegisterWitness("witness-edge-fra", []byte("fra-pop-cosigner-key-256"))

	mgr := &Manager{
		logID:       logID,
		signingKey:  signingKey,
		tree:        tree,
		witnessPool: pool,
		autoCosign:  true,
	}

	return mgr
}

// SetAutoCosign enables or disables immediate witness co-signing upon each entry append.
func (m *Manager) SetAutoCosign(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.autoCosign = enabled
}

// AppendAuditEntry inserts a new verified audit record into the transparency ledger.
func (m *Manager) AppendAuditEntry(action, tenantID string, payload []byte) (*LogEntry, *SignedTreeHead, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, sth, err := m.tree.AppendEntry(action, tenantID, payload)
	if err != nil {
		return nil, nil, err
	}

	if m.autoCosign {
		var sigs []WitnessSignature
		leaves := m.tree.leafHashes
		for _, wID := range m.witnessPool.ListWitnessIDs() {
			sig, cosignErr := m.witnessPool.CoSign(sth, wID, leaves)
			if cosignErr == nil && sig != nil {
				sigs = append(sigs, *sig)
			}
		}
		m.tree.UpdateSTHWitnessSignatures(sigs)
		sth = m.tree.LatestSTH()
	}

	return entry, sth, nil
}

// GetStatus returns the operational telemetry and current Merkle tree state.
func (m *Manager) GetStatus() *TransparencyStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sth := m.tree.LatestSTH()
	rootHex := ""
	if sth != nil {
		rootHex = sth.RootHashHex
	}

	return &TransparencyStatus{
		LogID:           m.logID,
		TreeSize:        m.tree.Size(),
		RootHashHex:     rootHex,
		LatestSTH:       sth,
		ActiveWitnesses: m.witnessPool.Count(),
		TotalEntries:    m.tree.Size(),
		OperatingMode:   "active",
		ComplianceRFC:   "RFC 6962",
	}
}

// GetSTH returns the most recent Signed Tree Head.
func (m *Manager) GetSTH() *SignedTreeHead {
	return m.tree.LatestSTH()
}

// GetEntry retrieves a single log entry by index.
func (m *Manager) GetEntry(index int64) (*LogEntry, error) {
	return m.tree.GetEntry(index)
}

// GetEntries retrieves a range of log entries.
func (m *Manager) GetEntries(start, count int64) ([]*LogEntry, error) {
	return m.tree.GetEntries(start, count)
}

// GetInclusionProof generates an RFC 6962 inclusion proof for a leaf in a specific tree size.
func (m *Manager) GetInclusionProof(leafIndex, treeSize int64) (*InclusionProof, error) {
	return m.tree.GenerateInclusionProof(leafIndex, treeSize)
}

// VerifyInclusionProof verifies an inclusion proof payload.
func (m *Manager) VerifyInclusionProof(proof *InclusionProof) bool {
	if proof == nil {
		return false
	}
	leafBytes, err := hex.DecodeString(proof.LeafHashHex)
	if err != nil {
		return false
	}
	rootBytes, err := hex.DecodeString(proof.RootHashHex)
	if err != nil {
		return false
	}
	proofBytes := make([][]byte, len(proof.AuditPathHex))
	for i, h := range proof.AuditPathHex {
		b, decErr := hex.DecodeString(h)
		if decErr != nil {
			return false
		}
		proofBytes[i] = b
	}

	return VerifyInclusionProof(proof.LeafIndex, proof.TreeSize, leafBytes, rootBytes, proofBytes)
}

// GetConsistencyProof generates an RFC 6962 consistency proof between two tree heads.
func (m *Manager) GetConsistencyProof(firstSize, secondSize int64) (*ConsistencyProof, error) {
	return m.tree.GenerateConsistencyProof(firstSize, secondSize)
}

// VerifyConsistencyProof verifies a consistency proof payload.
func (m *Manager) VerifyConsistencyProof(proof *ConsistencyProof) bool {
	if proof == nil {
		return false
	}
	firstRootBytes, err := hex.DecodeString(proof.FirstRootHex)
	if err != nil {
		return false
	}
	secondRootBytes, err := hex.DecodeString(proof.SecondRootHex)
	if err != nil {
		return false
	}
	proofBytes := make([][]byte, len(proof.ProofHex))
	for i, h := range proof.ProofHex {
		b, decErr := hex.DecodeString(h)
		if decErr != nil {
			return false
		}
		proofBytes[i] = b
	}

	return VerifyConsistencyProof(proof.FirstSize, proof.SecondSize, firstRootBytes, secondRootBytes, proofBytes)
}

// WitnessCosign allows a specific witness to co-sign the active tree head.
func (m *Manager) WitnessCosign(witnessID string) (*WitnessSignature, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sth := m.tree.LatestSTH()
	leaves := m.tree.leafHashes
	sig, err := m.witnessPool.CoSign(sth, witnessID, leaves)
	if err != nil {
		return nil, err
	}

	// Attach or update in STH
	sigs := append([]WitnessSignature{}, sth.WitnessSignatures...)
	found := false
	for i, s := range sigs {
		if s.WitnessID == witnessID {
			sigs[i] = *sig
			found = true
			break
		}
	}
	if !found {
		sigs = append(sigs, *sig)
	}
	m.tree.UpdateSTHWitnessSignatures(sigs)

	return sig, nil
}

// ListWitnesses returns the list of registered witness node identifiers.
func (m *Manager) ListWitnesses() []string {
	return m.witnessPool.ListWitnessIDs()
}

// RegisterWitness adds an external witness to the pool.
func (m *Manager) RegisterWitness(id string, secret []byte) {
	m.witnessPool.RegisterWitness(id, secret)
}
