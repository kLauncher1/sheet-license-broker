package stream

import (
	"encoding/json"
	"sync"
	"time"
)

const (
	writeWait      = 5 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = 25 * time.Second
	maxMessageSize = 512 * 1024
	sendBufferSize = 64
)

// Client coordinates bidirectional communication for a single WebSocket connection.
type Client struct {
	id        string
	conn      *Conn
	hub       *Hub
	info      ClientInfo
	infoMu    sync.RWMutex
	send      chan []byte
	closeOnce sync.Once
	done      chan struct{}
}

// NewClient initializes a client session bound to the provided WebSocket connection and Hub.
func NewClient(id string, conn *Conn, hub *Hub, initialInfo ClientInfo) *Client {
	if initialInfo.ConnectedAt.IsZero() {
		initialInfo.ConnectedAt = time.Now()
	}
	initialInfo.LastHeartbeat = time.Now()
	initialInfo.ID = id
	if conn != nil && conn.RemoteAddr() != nil {
		initialInfo.RemoteAddr = conn.RemoteAddr().String()
	}

	return &Client{
		id:   id,
		conn: conn,
		hub:  hub,
		info: initialInfo,
		send: make(chan []byte, sendBufferSize),
		done: make(chan struct{}),
	}
}

// ID returns the unique connection identifier.
func (c *Client) ID() string {
	return c.id
}

// GetInfo returns a thread-safe copy of the client metadata.
func (c *Client) GetInfo() ClientInfo {
	c.infoMu.RLock()
	defer c.infoMu.RUnlock()
	return c.info
}

// UpdateHeartbeat records a newly received heartbeat timestamp and telemetry.
func (c *Client) UpdateHeartbeat(payload HeartbeatPayload) {
	c.infoMu.Lock()
	defer c.infoMu.Unlock()
	now := time.Now()
	if payload.Timestamp > 0 {
		diff := now.UnixMilli() - payload.Timestamp
		if diff >= 0 && diff < 10000 {
			c.info.LatencyMs = diff
		}
	}
	c.info.LastHeartbeat = now
}

// SendChanForTest exposes the receive-only channel for testing queue delivery.
func (c *Client) SendChanForTest() <-chan []byte {
	return c.send
}

// Send sends a serialized byte payload to the client send queue.
func (c *Client) Send(data []byte) bool {
	select {
	case <-c.done:
		return false
	default:
		select {
		case c.send <- data:
			return true
		default:
			// Buffer full, drop or close slow client
			return false
		}
	}
}

// SendJSON marshals and enqueues a JSON message to the client.
func (c *Client) SendJSON(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if !c.Send(b) {
		return ErrConnectionClosed
	}
	return nil
}

// ReadPump continuously pumps messages from the WebSocket connection to the Hub.
func (c *Client) ReadPump() {
	defer func() {
		c.hub.Unregister(c)
		_ = c.Close()
	}()

	c.conn.SetReadDeadline(pongWait)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		opcode, payload, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		if opcode != OpcodeText {
			continue
		}

		var msg Message
		if err := json.Unmarshal(payload, &msg); err != nil {
			continue
		}

		switch msg.Event {
		case EventHeartbeat:
			var hb HeartbeatPayload
			if err := json.Unmarshal(msg.Payload, &hb); err == nil {
				c.UpdateHeartbeat(hb)
				c.hub.RecordHeartbeat(c.id, hb)
			}
			// Respond with ACK / Pong
			ack, _ := NewMessage(EventAcknowledge, map[string]interface{}{
				"status":    "ok",
				"timestamp": time.Now().Unix(),
			})
			_ = c.SendJSON(ack)

		case EventTelemetry:
			var hb HeartbeatPayload
			if err := json.Unmarshal(msg.Payload, &hb); err == nil {
				c.UpdateHeartbeat(hb)
				c.hub.RecordTelemetry(c.id, hb)
			}

		case EventPing:
			pong, _ := NewMessage(EventPong, map[string]int64{"timestamp": time.Now().Unix()})
			_ = c.SendJSON(pong)

		case EventSubscribe:
			// Allows dynamic binding of LicenseKey / HWID if not supplied during upgrade
			if msg.LicenseKey != "" || msg.HWID != "" || msg.TenantID != "" {
				c.infoMu.Lock()
				if msg.LicenseKey != "" {
					c.info.LicenseKey = msg.LicenseKey
				}
				if msg.HWID != "" {
					c.info.HWID = msg.HWID
				}
				if msg.TenantID != "" {
					c.info.TenantID = msg.TenantID
				}
				c.infoMu.Unlock()
				c.hub.ReindexClient(c)
			}
		}
	}
}

// WritePump continuously pumps messages from the send channel to the WebSocket connection.
func (c *Client) WritePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		_ = c.Close()
	}()

	for {
		select {
		case <-c.done:
			return
		case msg, ok := <-c.send:
			if !ok {
				_ = c.conn.WriteMessage(OpcodeClose, nil)
				return
			}
			if err := c.conn.WriteMessage(OpcodeText, msg); err != nil {
				return
			}
		case <-ticker.C:
			if err := c.conn.WriteMessage(OpcodePing, nil); err != nil {
				return
			}
		}
	}
}

// Close terminates the client session and frees resources.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		if c.conn != nil {
			err = c.conn.Close()
		}
	})
	return err
}
