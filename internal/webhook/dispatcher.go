package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// Supported webhook event types.
const (
	EventLicenseCreated  = "license.created"
	EventLicenseVerified = "license.verified"
	EventLicenseExpired  = "license.expired"
	EventLicenseRevoked  = "license.revoked"
	EventDeviceBanned    = "device.banned"
	EventTamperDetected  = "tamper.detected"
)

var (
	ErrDeliveryFailed = errors.New("webhook delivery failed after maximum retries")
	ErrDispatcherClosed = errors.New("dispatcher is closed")
)

// Event represents an immutable payload delivered to external endpoints.
type Event struct {
	ID        string      `json:"id"`
	Type      string      `json:"type"`
	TenantID  string      `json:"tenant_id,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// Config specifies operating parameters for the dispatcher.
type Config struct {
	GlobalWebhookURL string
	GlobalSecret     string
	MaxRetries       int
	BaseBackoff      time.Duration
	HTTPClient       *http.Client
	WorkerCount      int
	QueueSize        int
}

type job struct {
	event     *Event
	targetURL string
	secret    string
}

// Dispatcher manages synchronous and asynchronous webhook notification pipelines.
type Dispatcher struct {
	cfg        Config
	httpClient *http.Client
	jobs       chan job
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	closed     bool
	mu         sync.Mutex
}

// NewDispatcher initializes an asynchronous delivery worker pool.
func NewDispatcher(cfg Config) *Dispatcher {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = 50 * time.Millisecond
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 2
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	ctx, cancel := context.WithCancel(context.Background())

	d := &Dispatcher{
		cfg:        cfg,
		httpClient: client,
		jobs:       make(chan job, cfg.QueueSize),
		ctx:        ctx,
		cancel:     cancel,
	}

	for i := 0; i < cfg.WorkerCount; i++ {
		d.wg.Add(1)
		go d.worker()
	}

	return d
}

// NewEvent constructs an initialized event envelope with unique ID and current timestamp.
func NewEvent(eventType, tenantID string, data interface{}) *Event {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return &Event{
		ID:        "evt_" + hex.EncodeToString(b),
		Type:      eventType,
		TenantID:  tenantID,
		Timestamp: time.Now().UTC(),
		Data:      data,
	}
}

// SignPayload computes an HMAC-SHA256 signature formatted as sha256=<hex>.
func SignPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyPayloadSignature validates a webhook HMAC-SHA256 signature using constant-time comparison.
func VerifyPayloadSignature(secret string, body []byte, signatureHeader string) bool {
	if secret == "" || signatureHeader == "" {
		return false
	}
	expected := SignPayload(secret, body)
	return hmac.Equal([]byte(expected), []byte(signatureHeader))
}

// DispatchSync sends an event synchronously with exponential backoff retries.
func (d *Dispatcher) DispatchSync(ctx context.Context, evt *Event, targetURL, secret string) error {
	if targetURL == "" {
		return nil
	}

	body, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	backoff := d.cfg.BaseBackoff
	for attempt := 0; attempt <= d.cfg.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Broker-Event", evt.Type)
		req.Header.Set("X-Broker-Delivery", evt.ID)
		req.Header.Set("X-Broker-Timestamp", evt.Timestamp.Format(time.RFC3339))
		if secret != "" {
			req.Header.Set("X-Broker-Signature", SignPayload(secret, body))
		}

		resp, err := d.httpClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
		}

		if attempt < d.cfg.MaxRetries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}

	return ErrDeliveryFailed
}

// Dispatch queues an event for asynchronous delivery to tenant and global webhook endpoints.
func (d *Dispatcher) Dispatch(evt *Event, tenantURL, tenantSecret string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}

	// 1. Tenant webhook
	if tenantURL != "" {
		sec := tenantSecret
		if sec == "" {
			sec = d.cfg.GlobalSecret
		}
		d.enqueue(job{event: evt, targetURL: tenantURL, secret: sec})
	}

	// 2. Global webhook (if distinct from tenant URL)
	if d.cfg.GlobalWebhookURL != "" && d.cfg.GlobalWebhookURL != tenantURL {
		d.enqueue(job{event: evt, targetURL: d.cfg.GlobalWebhookURL, secret: d.cfg.GlobalSecret})
	}
}

func (d *Dispatcher) enqueue(j job) {
	select {
	case d.jobs <- j:
	default:
		log.Printf("[Webhook] Queue full, dropped event %s to %s", j.event.ID, j.targetURL)
	}
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case j, ok := <-d.jobs:
			if !ok {
				return
			}
			_ = d.DispatchSync(d.ctx, j.event, j.targetURL, j.secret)
		}
	}
}

// Close gracefully shuts down the dispatcher workers.
func (d *Dispatcher) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	d.mu.Unlock()

	d.cancel()
	close(d.jobs)
	d.wg.Wait()
}
