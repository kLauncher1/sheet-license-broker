package marketplace

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProvisionFunc defines the callback for automated license creation.
type ProvisionFunc func(daysValid, maxDevices int, tier string, features []string) (string, error)

// RevokeFunc defines the callback for automated license deauthorization.
type RevokeFunc func(licenseKey, reason string) error

// Manager coordinates webhook verification, normalization, idempotency, and automated provisioning/revocation.
type Manager struct {
	mu           sync.RWMutex
	cfg          MarketplaceConfig
	verifier     *Verifier
	normalizer   *Normalizer
	idempotency  *IdempotencyStore
	provisionFn  ProvisionFunc
	revokeFn     RevokeFunc
	emailToKeys  map[string][]string // customer email -> list of license keys
	refToKey     map[string]string   // order/subscription ID -> license key
	transactions []TransactionRecord // recent transactions (bounded)
	maxTxRecords int

	// Atomic telemetry counters
	totalProcessed   int64
	totalProvisioned int64
	totalRevoked     int64
	totalDuplicates  int64
	totalFailed      int64
}

// NewManager initializes the marketplace manager with configurations.
func NewManager(cfg MarketplaceConfig, provisionFn ProvisionFunc, revokeFn RevokeFunc) *Manager {
	if cfg.DefaultDaysValid <= 0 {
		cfg.DefaultDaysValid = 365
	}
	if cfg.DefaultSeats <= 0 {
		cfg.DefaultSeats = 1
	}
	if cfg.DefaultTier == "" {
		cfg.DefaultTier = "pro"
	}
	if cfg.ToleranceSeconds <= 0 {
		cfg.ToleranceSeconds = 300
	}

	return &Manager{
		cfg:          cfg,
		verifier:     NewVerifier(cfg.ToleranceSeconds),
		normalizer:   NewNormalizer(cfg.DefaultTier, cfg.DefaultSeats, cfg.DefaultDaysValid),
		idempotency:  NewIdempotencyStore(10000),
		provisionFn:  provisionFn,
		revokeFn:     revokeFn,
		emailToKeys:  make(map[string][]string),
		refToKey:     make(map[string]string),
		transactions: make([]TransactionRecord, 0, 500),
		maxTxRecords: 500,
	}
}

// SetProvisioner dynamically assigns or updates the license provisioning handler.
func (m *Manager) SetProvisioner(fn ProvisionFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.provisionFn = fn
}

// SetRevoker dynamically assigns or updates the license revocation handler.
func (m *Manager) SetRevoker(fn RevokeFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeFn = fn
}

// ProcessWebhook executes the complete lifecycle: verification -> normalization -> idempotency -> provisioning/revocation.
func (m *Manager) ProcessWebhook(provider string, header http.Header, body []byte) (*NormalizedEvent, *TransactionRecord, error) {
	normProvider := strings.ToLower(strings.TrimSpace(provider))

	// 1. Resolve webhook secret
	secret := m.getSecret(normProvider)

	// 2. Cryptographic signature verification
	if err := m.verifier.Verify(normProvider, header, body, secret); err != nil {
		atomic.AddInt64(&m.totalFailed, 1)
		return nil, nil, err
	}

	// 3. Normalization
	event, err := m.normalizer.Normalize(normProvider, body)
	if err != nil {
		atomic.AddInt64(&m.totalFailed, 1)
		return nil, nil, err
	}

	atomic.AddInt64(&m.totalProcessed, 1)

	// 4. Idempotency verification with atomic in-flight lock
	record, isNew, done := m.idempotency.StartOrGet(event.EventID)
	if !isNew {
		atomic.AddInt64(&m.totalDuplicates, 1)
		tx := &TransactionRecord{
			ID:            m.generateTxID(),
			EventID:       event.EventID,
			Provider:      event.Provider,
			Action:        event.Action,
			CustomerEmail: event.CustomerEmail,
			LicenseKey:    record.LicenseKey,
			Tier:          event.Tier,
			Seats:         event.Seats,
			Status:        "DUPLICATE",
			ErrorMessage:  "Event already processed",
			ProcessedAt:   time.Now().UTC(),
		}
		m.recordTx(*tx)
		return event, tx, nil
	}

	var finalRec *IdempotencyRecord
	defer func() {
		if done != nil {
			done(finalRec)
		}
	}()

	// 5. Automated Execution
	tx, err := m.executeAction(event)
	if err != nil {
		atomic.AddInt64(&m.totalFailed, 1)
		return event, tx, err
	}

	// 6. Record idempotency
	finalRec = &IdempotencyRecord{
		EventID:       event.EventID,
		Provider:      event.Provider,
		Action:        event.Action,
		CustomerEmail: event.CustomerEmail,
		LicenseKey:    tx.LicenseKey,
		Status:        tx.Status,
		ProcessedAt:   tx.ProcessedAt,
	}

	return event, tx, nil
}

// SimulateEvent processes an event directly without signature verification (for testing and admin console).
func (m *Manager) SimulateEvent(event *NormalizedEvent) (*TransactionRecord, error) {
	if event == nil {
		return nil, ErrInvalidPayload
	}
	normProvider := strings.ToLower(strings.TrimSpace(event.Provider))
	if normProvider != ProviderStripe && normProvider != ProviderLemonSqueezy && normProvider != ProviderPaddle {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProvider, event.Provider)
	}
	event.Provider = normProvider

	if strings.TrimSpace(event.CustomerEmail) == "" {
		return nil, ErrMissingCustomer
	}

	if event.EventID == "" {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		event.EventID = fmt.Sprintf("sim_%s_%d_%s", event.Provider, time.Now().UnixNano(), hex.EncodeToString(b))
	}
	atomic.AddInt64(&m.totalProcessed, 1)

	record, isNew, done := m.idempotency.StartOrGet(event.EventID)
	if !isNew {
		atomic.AddInt64(&m.totalDuplicates, 1)
		tx := &TransactionRecord{
			ID:            m.generateTxID(),
			EventID:       event.EventID,
			Provider:      event.Provider,
			Action:        event.Action,
			CustomerEmail: event.CustomerEmail,
			LicenseKey:    record.LicenseKey,
			Tier:          event.Tier,
			Seats:         event.Seats,
			Status:        "DUPLICATE",
			ErrorMessage:  "Event already processed",
			ProcessedAt:   time.Now().UTC(),
		}
		m.recordTx(*tx)
		return tx, nil
	}

	var finalRec *IdempotencyRecord
	defer func() {
		if done != nil {
			done(finalRec)
		}
	}()

	tx, err := m.executeAction(event)
	if err != nil {
		atomic.AddInt64(&m.totalFailed, 1)
		return tx, err
	}

	finalRec = &IdempotencyRecord{
		EventID:       event.EventID,
		Provider:      event.Provider,
		Action:        event.Action,
		CustomerEmail: event.CustomerEmail,
		LicenseKey:    tx.LicenseKey,
		Status:        tx.Status,
		ProcessedAt:   tx.ProcessedAt,
	}

	return tx, nil
}

// executeAction dispatches the normalized event to provisioning or revocation handlers.
func (m *Manager) executeAction(event *NormalizedEvent) (*TransactionRecord, error) {
	tx := &TransactionRecord{
		ID:            m.generateTxID(),
		EventID:       event.EventID,
		Provider:      event.Provider,
		Action:        event.Action,
		CustomerEmail: event.CustomerEmail,
		Tier:          event.Tier,
		Seats:         event.Seats,
		ProcessedAt:   time.Now().UTC(),
	}

	switch event.Action {
	case ActionProvision:
		if m.provisionFn == nil {
			tx.Status = "FAILED"
			tx.ErrorMessage = "Provisioner callback not registered"
			m.recordTx(*tx)
			return tx, fmt.Errorf("%s", tx.ErrorMessage)
		}

		key, err := m.provisionFn(event.DaysValid, event.Seats, event.Tier, event.Features)
		if err != nil {
			tx.Status = "FAILED"
			tx.ErrorMessage = fmt.Sprintf("Provisioning failed: %v", err)
			m.recordTx(*tx)
			return tx, fmt.Errorf("provisioning failed: %w", err)
		}

		tx.LicenseKey = key
		tx.Status = "PROVISIONED"
		event.LicenseKey = key

		// Store customer bindings
		m.bindCustomerKey(event.CustomerEmail, event.OrderID, event.SubscriptionID, key)
		atomic.AddInt64(&m.totalProvisioned, 1)

	case ActionRevoke:
		targetKey := event.LicenseKey
		if targetKey == "" {
			targetKey = m.findCustomerKey(event.CustomerEmail, event.OrderID, event.SubscriptionID)
		}

		if targetKey == "" {
			tx.Status = "SKIPPED"
			tx.ErrorMessage = "No active license key found for customer to revoke"
			m.recordTx(*tx)
			return tx, nil
		}

		if m.revokeFn == nil {
			tx.Status = "FAILED"
			tx.ErrorMessage = "Revoker callback not registered"
			m.recordTx(*tx)
			return tx, fmt.Errorf("%s", tx.ErrorMessage)
		}

		reason := fmt.Sprintf("Marketplace %s deauthorization (%s event)", event.Provider, event.EventType)
		if err := m.revokeFn(targetKey, reason); err != nil {
			tx.Status = "FAILED"
			tx.ErrorMessage = fmt.Sprintf("Revocation failed: %v", err)
			m.recordTx(*tx)
			return tx, fmt.Errorf("revocation failed: %w", err)
		}

		tx.LicenseKey = targetKey
		tx.Status = "REVOKED"
		m.unbindCustomerKey(event.CustomerEmail, event.OrderID, event.SubscriptionID, targetKey)
		atomic.AddInt64(&m.totalRevoked, 1)

	case ActionUpdate:
		tx.Status = "UPDATED"
	default:
		tx.Status = "SKIPPED"
	}

	m.recordTx(*tx)
	return tx, nil
}

func (m *Manager) bindCustomerKey(email, orderID, subID, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	normEmail := strings.ToLower(strings.TrimSpace(email))
	if normEmail != "" {
		exists := false
		for _, k := range m.emailToKeys[normEmail] {
			if k == key {
				exists = true
				break
			}
		}
		if !exists {
			m.emailToKeys[normEmail] = append(m.emailToKeys[normEmail], key)
		}
	}
	if orderID != "" && orderID != "0" {
		m.refToKey[orderID] = key
	}
	if subID != "" && subID != "0" {
		m.refToKey[subID] = key
	}
}

func (m *Manager) unbindCustomerKey(email, orderID, subID, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if subID != "" && m.refToKey[subID] == key {
		delete(m.refToKey, subID)
	}
	if orderID != "" && m.refToKey[orderID] == key {
		delete(m.refToKey, orderID)
	}
	normEmail := strings.ToLower(strings.TrimSpace(email))
	if normEmail != "" {
		if keys, ok := m.emailToKeys[normEmail]; ok {
			filtered := make([]string, 0, len(keys))
			for _, k := range keys {
				if k != key {
					filtered = append(filtered, k)
				}
			}
			if len(filtered) == 0 {
				delete(m.emailToKeys, normEmail)
			} else {
				m.emailToKeys[normEmail] = filtered
			}
		}
	}
}

func (m *Manager) findCustomerKey(email, orderID, subID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if subID != "" && subID != "0" {
		if k, ok := m.refToKey[subID]; ok && k != "" {
			return k
		}
	}
	if orderID != "" && orderID != "0" {
		if k, ok := m.refToKey[orderID]; ok && k != "" {
			return k
		}
	}
	normEmail := strings.ToLower(strings.TrimSpace(email))
	if normEmail != "" {
		if keys, ok := m.emailToKeys[normEmail]; ok && len(keys) > 0 {
			// Return the most recently issued license key
			return keys[len(keys)-1]
		}
	}
	return ""
}

func (m *Manager) recordTx(tx TransactionRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.transactions) >= m.maxTxRecords {
		copy(m.transactions, m.transactions[1:])
		m.transactions[len(m.transactions)-1] = tx
		return
	}
	m.transactions = append(m.transactions, tx)
}

// ListTransactions returns recent transaction audit records (newest first).
func (m *Manager) ListTransactions() []TransactionRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]TransactionRecord, len(m.transactions))
	for i, tx := range m.transactions {
		res[len(m.transactions)-1-i] = tx
	}
	return res
}

// GetStatus returns diagnostic status summary of marketplace operations.
func (m *Manager) GetStatus() MarketplaceStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return MarketplaceStatus{
		SupportedProviders:     []string{ProviderStripe, ProviderLemonSqueezy, ProviderPaddle},
		TotalProcessedEvents:   atomic.LoadInt64(&m.totalProcessed),
		TotalProvisioned:       atomic.LoadInt64(&m.totalProvisioned),
		TotalRevoked:           atomic.LoadInt64(&m.totalRevoked),
		TotalDuplicates:        atomic.LoadInt64(&m.totalDuplicates),
		TotalFailed:            atomic.LoadInt64(&m.totalFailed),
		RecentTransactions:     len(m.transactions),
		StripeConfigured:       m.cfg.StripeWebhookSecret != "",
		LemonSqueezyConfigured: m.cfg.LemonSqueezyWebhookSecret != "",
		PaddleConfigured:       m.cfg.PaddleWebhookSecret != "",
		Timestamp:              time.Now().UTC(),
	}
}

// IdempotencyCount returns current tracked event count in the deduplicator.
func (m *Manager) IdempotencyCount() int {
	if m == nil || m.idempotency == nil {
		return 0
	}
	return m.idempotency.Count()
}

func (m *Manager) getSecret(provider string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch provider {
	case ProviderStripe:
		return m.cfg.StripeWebhookSecret
	case ProviderLemonSqueezy:
		return m.cfg.LemonSqueezyWebhookSecret
	case ProviderPaddle:
		return m.cfg.PaddleWebhookSecret
	default:
		return ""
	}
}

func (m *Manager) generateTxID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("tx_%s", hex.EncodeToString(b))
}
