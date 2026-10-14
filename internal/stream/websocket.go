package stream

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	websocketGUID    = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxPayloadLength = 1024 * 1024 // 1 MB payload limit to prevent memory exhaustion

	OpcodeContinuation = 0x0
	OpcodeText         = 0x1
	OpcodeBinary       = 0x2
	OpcodeClose        = 0x8
	OpcodePing         = 0x9
	OpcodePong         = 0xA
)

var (
	ErrNotWebSocket       = errors.New("request is not a websocket upgrade")
	ErrPayloadTooLarge    = errors.New("websocket payload exceeds 1MB limit")
	ErrConnectionClosed   = errors.New("websocket connection closed")
	ErrControlTooLong     = errors.New("control frame payload exceeds 125 bytes")
)

// Conn represents an active bidirectional RFC 6455 WebSocket connection.
type Conn struct {
	netConn   net.Conn
	reader    *bufio.Reader
	writeMu   sync.Mutex
	isClosed  bool
	closeMu   sync.Mutex
	readDead  time.Duration
	writeDead time.Duration
}

// Upgrade upgrades an incoming HTTP request to an RFC 6455 WebSocket connection.
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, ErrNotWebSocket
	}
	connHeader := strings.ToLower(r.Header.Get("Connection"))
	if !strings.Contains(connHeader, "upgrade") {
		return nil, ErrNotWebSocket
	}

	clientKey := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if clientKey == "" {
		return nil, errors.New("missing Sec-WebSocket-Key header")
	}

	// Compute Sec-WebSocket-Accept token
	h := sha1.New()
	h.Write([]byte(clientKey + websocketGUID))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("http.ResponseWriter does not support hijacking")
	}

	rawConn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijack failed: %w", err)
	}

	// Transmit HTTP 101 Switching Protocols response
	resp := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n",
		acceptKey,
	)
	if _, err := rawConn.Write([]byte(resp)); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to send handshake response: %w", err)
	}

	return &Conn{
		netConn:   rawConn,
		reader:    rw.Reader,
		readDead:  60 * time.Second,
		writeDead: 10 * time.Second,
	}, nil
}

// ReadMessage decodes the next data frame from the connection.
func (c *Conn) ReadMessage() (int, []byte, error) {
	for {
		if c.readDead > 0 {
			_ = c.netConn.SetReadDeadline(time.Now().Add(c.readDead))
		}

		head, err := c.reader.Peek(2)
		if err != nil {
			return 0, nil, err
		}

		fin := (head[0] & 0x80) != 0
		opcode := int(head[0] & 0x0F)
		masked := (head[1] & 0x80) != 0
		payloadLen := int64(head[1] & 0x7F)

		_, _ = c.reader.Discard(2)

		if payloadLen == 126 {
			var ext uint16
			if err := binary.Read(c.reader, binary.BigEndian, &ext); err != nil {
				return 0, nil, err
			}
			payloadLen = int64(ext)
		} else if payloadLen == 127 {
			var ext uint64
			if err := binary.Read(c.reader, binary.BigEndian, &ext); err != nil {
				return 0, nil, err
			}
			payloadLen = int64(ext)
		}

		if payloadLen > maxPayloadLength {
			return 0, nil, ErrPayloadTooLarge
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(c.reader, maskKey[:]); err != nil {
				return 0, nil, err
			}
		}

		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(c.reader, payload); err != nil {
				return 0, nil, err
			}
			if masked {
				for i := int64(0); i < payloadLen; i++ {
					payload[i] ^= maskKey[i%4]
				}
			}
		}

		switch opcode {
		case OpcodePing:
			_ = c.WriteMessage(OpcodePong, payload)
			continue
		case OpcodePong:
			continue
		case OpcodeClose:
			_ = c.WriteMessage(OpcodeClose, nil)
			return OpcodeClose, nil, ErrConnectionClosed
		case OpcodeText, OpcodeBinary:
			if !fin {
				// We keep simple unfragmented messages for fast streaming
				continue
			}
			return opcode, payload, nil
		default:
			return opcode, payload, nil
		}
	}
}

// WriteMessage sends an unmasked RFC 6455 frame to the client.
func (c *Conn) WriteMessage(opcode int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.closeMu.Lock()
	if c.isClosed {
		c.closeMu.Unlock()
		return ErrConnectionClosed
	}
	c.closeMu.Unlock()

	if c.writeDead > 0 {
		_ = c.netConn.SetWriteDeadline(time.Now().Add(c.writeDead))
	}

	length := len(data)
	var header []byte

	b0 := byte(0x80 | (opcode & 0x0F)) // FIN = 1
	if length <= 125 {
		header = []byte{b0, byte(length)}
	} else if length <= 65535 {
		header = make([]byte, 4)
		header[0] = b0
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:], uint16(length))
	} else {
		header = make([]byte, 10)
		header[0] = b0
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(length))
	}

	if _, err := c.netConn.Write(header); err != nil {
		return err
	}
	if length > 0 {
		if _, err := c.netConn.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// SetReadDeadline configures the read deadline on the underlying connection.
func (c *Conn) SetReadDeadline(d time.Duration) {
	c.readDead = d
}

// RemoteAddr returns the remote network address of the connection.
func (c *Conn) RemoteAddr() net.Addr {
	return c.netConn.RemoteAddr()
}

// Close gracefully closes the WebSocket connection.
func (c *Conn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.isClosed {
		return nil
	}
	c.isClosed = true
	return c.netConn.Close()
}
