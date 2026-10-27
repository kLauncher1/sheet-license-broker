package healing

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

var (
	ErrInvalidTicketSignature = errors.New("healing ticket signature is invalid")
	ErrTicketExpired          = errors.New("healing ticket has expired")
	ErrSessionNotFound        = errors.New("healing session not found")
	ErrInvalidClientIdentity  = errors.New("client identity mismatch on healing resume")
)

// TunnelManager coordinates client connectivity resilience, ticket issuance,
// and state synchronization across network drops.
type TunnelManager struct {
	mu            sync.RWMutex
	secretKey     []byte
	defaultGrace  time.Duration
	maxBufferLen  int
	sessions      map[string]*HealingSession // Keyed by SessionID
	clientSession map[string]string          // ClientID -> SessionID
	deltaBuffer   []DeltaEvent
	nextSeq       int64
}

// NewTunnelManager creates a self-healing tunnel coordinator.
func NewTunnelManager(secretKey string, defaultGrace time.Duration) *TunnelManager {
	if defaultGrace <= 0 {
		defaultGrace = 3 * time.Minute
	}
	if secretKey == "" {
		secretKey = "default-healing-secret-key"
	}
	return &TunnelManager{
		secretKey:     []byte(secretKey),
		defaultGrace:  defaultGrace,
		maxBufferLen:  1000,
		sessions:      make(map[string]*HealingSession),
		clientSession: make(map[string]string),
		deltaBuffer:   make([]DeltaEvent, 0, 100),
		nextSeq:       1,
	}
}

// computeTicketSignature generates an HMAC-SHA256 signature for a healing ticket.
func (tm *TunnelManager) computeTicketSignature(t *HealingTicket) string {
	mac := hmac.New(sha256.New, tm.secretKey)
	mac.Write([]byte(t.SessionID))
	mac.Write([]byte("\n"))
	mac.Write([]byte(t.ClientID))
	mac.Write([]byte("\n"))
	mac.Write([]byte(t.HWID))
	mac.Write([]byte("\n"))
	mac.Write([]byte(t.TenantID))
	mac.Write([]byte("\n"))
	mac.Write([]byte(strconv.FormatInt(t.IssuedAt.Unix(), 10)))
	mac.Write([]byte("\n"))
	mac.Write([]byte(strconv.FormatInt(t.ExpiresAt.Unix(), 10)))
	mac.Write([]byte("\n"))
	mac.Write([]byte(strconv.FormatInt(t.LastAckSeq, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// IssueTicket generates a verifiable healing credential for an active or reconnecting client.
func (tm *TunnelManager) IssueTicket(sessionID, clientID, hwid, tenantID string, lastAckSeq int64, ttl time.Duration) *HealingTicket {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	if ttl <= 0 {
		ttl = tm.defaultGrace
	}

	if sessionID == "" {
		sessionID = fmt.Sprintf("heal-sess-%d-%x", now.UnixNano(), tm.nextSeq)
	}

	ticket := &HealingTicket{
		SessionID:  sessionID,
		ClientID:   clientID,
		HWID:       hwid,
		TenantID:   tenantID,
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
		LastAckSeq: lastAckSeq,
	}
	ticket.Signature = tm.computeTicketSignature(ticket)

	// Ensure session is tracked
	sess, exists := tm.sessions[sessionID]
	if !exists {
		sess = &HealingSession{
			SessionID:     sessionID,
			ClientID:      clientID,
			HWID:          hwid,
			TenantID:      tenantID,
			State:         TunnelStateConnected,
			ConnectedAt:   now,
			LastHeartbeat: now,
		}
		tm.sessions[sessionID] = sess
		tm.clientSession[clientID] = sessionID
	} else {
		sess.LastHeartbeat = now
	}

	return ticket
}

// VerifyTicket validates the authenticity and temporal validity of a healing ticket.
func (tm *TunnelManager) VerifyTicket(ticket *HealingTicket) error {
	if ticket == nil {
		return errors.New("nil ticket")
	}

	expectedSig := tm.computeTicketSignature(ticket)
	if subtle.ConstantTimeCompare([]byte(ticket.Signature), []byte(expectedSig)) != 1 {
		return ErrInvalidTicketSignature
	}

	if time.Now().After(ticket.ExpiresAt) {
		return ErrTicketExpired
	}

	return nil
}

// RecordDisconnect transitions a client session to the disconnected grace state.
func (tm *TunnelManager) RecordDisconnect(clientID string) *HealingSession {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	sessionID, ok := tm.clientSession[clientID]
	if !ok {
		return nil
	}

	sess, exists := tm.sessions[sessionID]
	if !exists {
		return nil
	}

	now := time.Now()
	sess.State = TunnelStateDisconnected
	sess.DisconnectedAt = now
	sess.GraceExpiresAt = now.Add(tm.defaultGrace)
	return sess
}

// ResumeTunnel validates the client's healing ticket, restores session state,
// and extracts all state delta events the client missed while disconnected.
func (tm *TunnelManager) ResumeTunnel(ticket *HealingTicket) (*HealingSession, []DeltaEvent, error) {
	if err := tm.VerifyTicket(ticket); err != nil {
		return nil, nil, err
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	sess, exists := tm.sessions[ticket.SessionID]
	if !exists {
		// Auto-reconstruct session from verified ticket parameters
		sess = &HealingSession{
			SessionID:   ticket.SessionID,
			ClientID:    ticket.ClientID,
			HWID:        ticket.HWID,
			TenantID:    ticket.TenantID,
			ConnectedAt: ticket.IssuedAt,
		}
		tm.sessions[ticket.SessionID] = sess
		tm.clientSession[ticket.ClientID] = ticket.SessionID
	}

	if sess.ClientID != ticket.ClientID || sess.HWID != ticket.HWID {
		return nil, nil, ErrInvalidClientIdentity
	}

	now := time.Now()
	sess.State = TunnelStateResumed
	sess.LastHeartbeat = now
	sess.DisconnectedAt = time.Time{}
	sess.GraceExpiresAt = time.Time{}

	// Retrieve missed events since ticket.LastAckSeq
	var missed []DeltaEvent
	for _, ev := range tm.deltaBuffer {
		if ev.Sequence > ticket.LastAckSeq {
			if ev.TenantID == ticket.TenantID && (ev.ClientID == "" || ev.ClientID == ticket.ClientID) {
				missed = append(missed, ev)
			}
		}
	}
	sess.MissedEventsCount = len(missed)

	return sess, missed, nil
}

// RecordDeltaEvent appends a new state update or license event to the replay buffer.
func (tm *TunnelManager) RecordDeltaEvent(tenantID, clientID, eventType, payload string) DeltaEvent {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	ev := DeltaEvent{
		Sequence:  tm.nextSeq,
		TenantID:  tenantID,
		ClientID:  clientID,
		EventType: eventType,
		Payload:   payload,
		Timestamp: time.Now(),
	}
	tm.nextSeq++

	tm.deltaBuffer = append(tm.deltaBuffer, ev)
	if len(tm.deltaBuffer) > tm.maxBufferLen {
		// Prune oldest 20%
		pruneCount := tm.maxBufferLen / 5
		tm.deltaBuffer = tm.deltaBuffer[pruneCount:]
	}

	return ev
}

// SweepExpiredTunnels terminates sessions whose grace period has lapsed.
func (tm *TunnelManager) SweepExpiredTunnels() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	closedCount := 0
	for _, sess := range tm.sessions {
		if sess.State == TunnelStateDisconnected && !sess.GraceExpiresAt.IsZero() && now.After(sess.GraceExpiresAt) {
			sess.State = TunnelStateClosed
			delete(tm.clientSession, sess.ClientID)
			closedCount++
		}
	}
	return closedCount
}

// ListSessions returns a copy of all tracked client sessions.
func (tm *TunnelManager) ListSessions() []HealingSession {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	out := make([]HealingSession, 0, len(tm.sessions))
	for _, sess := range tm.sessions {
		out = append(out, *sess)
	}
	return out
}
