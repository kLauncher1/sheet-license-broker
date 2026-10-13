package db

import (
	"errors"
	"sync"
	"time"
)

// Document models a NoSQL row stored in Google Sheets KV_Database tab.
type Document struct {
	Collection string    `json:"collection"`
	DocID      string    `json:"doc_id"`
	Payload    string    `json:"payload"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Storage provides an interface to query and persist documents.
type Storage struct {
	mu   sync.RWMutex
	docs map[string]*Document // key: collection:docID
}

// NewStorage initializes in-memory document store.
func NewStorage() *Storage {
	s := &Storage{
		docs: make(map[string]*Document),
	}

	// Pre-seed default configuration record
	s.Put("app_config", "global_theme", `{"theme":"dark","version":"1.0.0"}`)
	return s
}

// Put writes or updates a document in a collection.
func (s *Storage) Put(collection, docID, payload string) *Document {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := collection + ":" + docID
	doc := &Document{
		Collection: collection,
		DocID:      docID,
		Payload:    payload,
		UpdatedAt:  time.Now().UTC(),
	}

	s.docs[key] = doc
	return doc
}

// Get retrieves a document by collection and ID.
func (s *Storage) Get(collection, docID string) (*Document, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := collection + ":" + docID
	doc, exists := s.docs[key]
	if !exists {
		return nil, errors.New("document not found")
	}

	return doc, nil
}

// ListAll returns all documents in storage.
func (s *Storage) ListAll() []Document {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]Document, 0, len(s.docs))
	for _, d := range s.docs {
		res = append(res, *d)
	}
	return res
}
