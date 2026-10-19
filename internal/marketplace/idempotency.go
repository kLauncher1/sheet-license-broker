package marketplace

import (
	"sync"
	"time"
)

// IdempotencyRecord stores information about a previously processed webhook event.
type IdempotencyRecord struct {
	EventID       string    `json:"event_id"`
	Provider      string    `json:"provider"`
	Action        string    `json:"action"`
	CustomerEmail string    `json:"customer_email"`
	LicenseKey    string    `json:"license_key"`
	Status        string    `json:"status"`
	ProcessedAt   time.Time `json:"processed_at"`
}

// IdempotencyStore ensures webhook events are processed at most once,
// providing atomic in-flight deduplication across concurrent requests.
type IdempotencyStore struct {
	mu         sync.Mutex
	records    map[string]*IdempotencyRecord
	inFlight   map[string]chan struct{}
	order      []string
	maxEntries int
}

// NewIdempotencyStore creates an in-memory idempotency deduplicator.
func NewIdempotencyStore(maxEntries int) *IdempotencyStore {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &IdempotencyStore{
		records:    make(map[string]*IdempotencyRecord),
		inFlight:   make(map[string]chan struct{}),
		order:      make([]string, 0, maxEntries),
		maxEntries: maxEntries,
	}
}

// StartOrGet checks if an event has already been recorded or is in flight.
// If already recorded, returns (record, false, nil).
// If in-flight by another goroutine, it blocks until that goroutine completes, then returns the record.
// If new, it registers in-flight and returns (nil, true, doneFunc) where doneFunc MUST be called
// when processing completes (passing nil if execution failed to allow retries, or passing record on success).
func (s *IdempotencyStore) StartOrGet(eventID string) (record *IdempotencyRecord, isNew bool, done func(*IdempotencyRecord)) {
	if s == nil || eventID == "" {
		return nil, true, func(*IdempotencyRecord) {}
	}

	for {
		s.mu.Lock()
		if rec, exists := s.records[eventID]; exists {
			s.mu.Unlock()
			return rec, false, nil
		}

		if waitCh, inFlight := s.inFlight[eventID]; inFlight {
			s.mu.Unlock()
			<-waitCh
			continue
		}

		// First caller: register inFlight channel
		ch := make(chan struct{})
		s.inFlight[eventID] = ch
		s.mu.Unlock()

		var once sync.Once
		done = func(rec *IdempotencyRecord) {
			once.Do(func() {
				s.mu.Lock()
				delete(s.inFlight, eventID)
				close(ch)
				if rec != nil && rec.EventID != "" {
					if _, exists := s.records[rec.EventID]; !exists {
						if len(s.order) >= s.maxEntries {
							evictCount := s.maxEntries / 10
							if evictCount == 0 {
								evictCount = 1
							}
							s.evictOldest(evictCount)
						}
						s.order = append(s.order, rec.EventID)
					}
					s.records[rec.EventID] = rec
				}
				s.mu.Unlock()
			})
		}
		return nil, true, done
	}
}

// Has checks if an event ID has already been recorded.
func (s *IdempotencyStore) Has(eventID string) (*IdempotencyRecord, bool) {
	if s == nil || eventID == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, exists := s.records[eventID]
	return rec, exists
}

// Record saves a processed event to the store, pruning older records if capacity is exceeded.
func (s *IdempotencyStore) Record(rec *IdempotencyRecord) {
	if s == nil || rec == nil || rec.EventID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[rec.EventID]; !exists {
		if len(s.order) >= s.maxEntries {
			// Evict oldest 10%
			evictCount := s.maxEntries / 10
			if evictCount == 0 {
				evictCount = 1
			}
			s.evictOldest(evictCount)
		}
		s.order = append(s.order, rec.EventID)
	}

	s.records[rec.EventID] = rec
}

func (s *IdempotencyStore) evictOldest(count int) {
	if count <= 0 || len(s.order) == 0 {
		return
	}
	if count > len(s.order) {
		count = len(s.order)
	}
	for i := 0; i < count; i++ {
		delete(s.records, s.order[i])
	}
	copy(s.order, s.order[count:])
	s.order = s.order[:len(s.order)-count]
}

// Count returns the current number of tracked event IDs.
func (s *IdempotencyStore) Count() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// Clear resets the idempotency store (useful for test suites).
func (s *IdempotencyStore) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = make(map[string]*IdempotencyRecord)
	s.inFlight = make(map[string]chan struct{})
	s.order = s.order[:0]
}
