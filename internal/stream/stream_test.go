package stream

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Helper to construct a client-to-server masked RFC 6455 frame
func buildMaskedFrame(opcode int, payload []byte) []byte {
	var buf bytes.Buffer
	b0 := byte(0x80 | (opcode & 0x0F))
	buf.WriteByte(b0)

	length := len(payload)
	maskKey := [4]byte{0x12, 0x34, 0x56, 0x78}

	if length <= 125 {
		buf.WriteByte(byte(0x80 | length))
	} else if length <= 65535 {
		buf.WriteByte(byte(0x80 | 126))
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(length))
		buf.Write(ext[:])
	} else {
		buf.WriteByte(byte(0x80 | 127))
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(length))
		buf.Write(ext[:])
	}

	buf.Write(maskKey[:])

	masked := make([]byte, length)
	for i := 0; i < length; i++ {
		masked[i] = payload[i] ^ maskKey[i%4]
	}
	buf.Write(masked)

	return buf.Bytes()
}

func TestWebSocketFrameReadWrite(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ws := &Conn{
		netConn:   serverConn,
		reader:    bufio.NewReader(serverConn),
		readDead:  5 * time.Second,
		writeDead: 5 * time.Second,
	}

	// Test writing from client and reading on server
	testPayload := []byte(`{"event":"test","timestamp":12345}`)
	maskedFrame := buildMaskedFrame(OpcodeText, testPayload)

	go func() {
		_, _ = clientConn.Write(maskedFrame)
	}()

	op, data, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
	if op != OpcodeText {
		t.Errorf("expected OpcodeText, got %d", op)
	}
	if string(data) != string(testPayload) {
		t.Errorf("payload mismatch: got %s, want %s", string(data), string(testPayload))
	}

	// Test server writing unmasked frame and client reading
	serverMsg := []byte("hello from server")
	go func() {
		_ = ws.WriteMessage(OpcodeText, serverMsg)
	}()

	header := make([]byte, 2)
	if _, err := clientConn.Read(header); err != nil {
		t.Fatalf("failed to read frame header from server: %v", err)
	}
	if (header[0] & 0x0F) != OpcodeText {
		t.Errorf("expected OpcodeText in server frame")
	}
	if (header[1] & 0x80) != 0 {
		t.Errorf("server frame must NOT be masked according to RFC 6455")
	}
	sLen := int(header[1] & 0x7F)
	sPayload := make([]byte, sLen)
	if _, err := clientConn.Read(sPayload); err != nil {
		t.Fatalf("failed to read server payload: %v", err)
	}
	if string(sPayload) != string(serverMsg) {
		t.Errorf("server payload mismatch: got %s, want %s", string(sPayload), string(serverMsg))
	}
}

func TestHubRegistrationAndRevocationPush(t *testing.T) {
	hub := NewHub()

	client1 := NewClient("client-1", nil, hub, ClientInfo{
		LicenseKey: "LIC-CORP-001",
		HWID:       "HWID-MAC-AAAA",
		TenantID:   "tenant-alpha",
	})
	client2 := NewClient("client-2", nil, hub, ClientInfo{
		LicenseKey: "LIC-CORP-002",
		HWID:       "HWID-MAC-BBBB",
		TenantID:   "tenant-alpha",
	})

	hub.Register(client1)
	hub.Register(client2)

	if count := hub.GetClientCount(); count != 2 {
		t.Fatalf("expected 2 clients, got %d", count)
	}

	// Push revocation for client 1's license
	signaled := hub.PushRevocation("LIC-CORP-001", "", "Fraudulent chargeback")
	if signaled != 1 {
		t.Errorf("expected 1 signaled client, got %d", signaled)
	}

	// Verify client 1 received revocation & killswitch messages in its send queue
	select {
	case msg1 := <-client1.send:
		var env Message
		_ = json.Unmarshal(msg1, &env)
		if env.Event != EventRevocation {
			t.Errorf("expected EventRevocation, got %s", env.Event)
		}
	default:
		t.Fatalf("expected revocation message in client 1 queue")
	}

	select {
	case msg2 := <-client1.send:
		var env Message
		_ = json.Unmarshal(msg2, &env)
		if env.Event != EventKillSwitch {
			t.Errorf("expected EventKillSwitch, got %s", env.Event)
		}
	default:
		t.Fatalf("expected kill switch message in client 1 queue")
	}

	// Verify client 2 queue is untouched
	select {
	case msg := <-client2.send:
		t.Fatalf("client 2 should not have received any revocation: %s", string(msg))
	default:
		// OK
	}

	// Push kill switch by HWID
	signaledHWID := hub.PushKillSwitch("HWID-MAC-BBBB", "Hardware tampering", true)
	if signaledHWID != 1 {
		t.Errorf("expected 1 signaled client by HWID, got %d", signaledHWID)
	}

	select {
	case msg := <-client2.send:
		var env Message
		_ = json.Unmarshal(msg, &env)
		if env.Event != EventKillSwitch {
			t.Errorf("expected EventKillSwitch on client 2, got %s", env.Event)
		}
	default:
		t.Fatalf("expected kill switch message on client 2")
	}

	// Unregister
	hub.Unregister(client1)
	hub.Unregister(client2)

	if count := hub.GetClientCount(); count != 0 {
		t.Errorf("expected 0 clients after unregister, got %d", count)
	}
}

func TestHubBroadcastAndTelemetry(t *testing.T) {
	hub := NewHub()

	c := NewClient("client-test", nil, hub, ClientInfo{
		LicenseKey: "LIC-TEST-BROADCAST",
		HWID:       "HWID-TEST-1234",
	})
	hub.Register(c)

	hbPayload := HeartbeatPayload{
		ClientVersion: "1.1.0",
		OS:            "windows",
		MemoryUsageMB: 128.5,
		CPUPercent:    4.2,
		Status:        "active",
		Timestamp:     time.Now().UnixMilli() - 15,
	}
	c.UpdateHeartbeat(hbPayload)
	hub.RecordHeartbeat(c.id, hbPayload)

	snapshot := hub.GetTelemetrySnapshot()
	if snapshot.ActiveConnections != 1 {
		t.Errorf("expected 1 active connection, got %d", snapshot.ActiveConnections)
	}
	if snapshot.TotalHeartbeats != 1 {
		t.Errorf("expected 1 total heartbeat, got %d", snapshot.TotalHeartbeats)
	}
	if len(snapshot.Clients) != 1 {
		t.Fatalf("expected 1 client in snapshot")
	}
	if snapshot.Clients[0].LatencyMs < 0 {
		t.Errorf("invalid latency calculation")
	}

	// Broadcast message
	msg, _ := NewMessage("test:notification", map[string]string{"alert": "maintenance"})
	sent := hub.Broadcast(msg)
	if sent != 1 {
		t.Errorf("expected 1 broadcast delivery, got %d", sent)
	}

	select {
	case received := <-c.send:
		var parsed Message
		_ = json.Unmarshal(received, &parsed)
		if parsed.Event != "test:notification" {
			t.Errorf("expected test:notification, got %s", parsed.Event)
		}
	default:
		t.Fatalf("client did not receive broadcast")
	}
}

func TestConcurrentStreamHub(t *testing.T) {
	hub := NewHub()
	var wg sync.WaitGroup

	numClients := 30
	clients := make([]*Client, numClients)

	for i := 0; i < numClients; i++ {
		clients[i] = NewClient(string(rune('a'+i)), nil, hub, ClientInfo{
			LicenseKey: "LIC-CONCURRENT",
			HWID:       "HWID-CONCURRENT",
		})
		hub.Register(clients[i])
	}

	if hub.GetClientCount() != numClients {
		t.Fatalf("expected %d clients, got %d", numClients, hub.GetClientCount())
	}

	// Concurrent heartbeats and revocation pushes
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			hb := HeartbeatPayload{
				ClientVersion: "1.1.0",
				Status:        "running",
				Timestamp:     time.Now().UnixMilli(),
			}
			hub.RecordHeartbeat(clients[idx].id, hb)
		}(i)
	}

	wg.Wait()

	// Push revocation to all concurrent clients
	signaled := hub.PushRevocation("LIC-CONCURRENT", "", "mass test")
	if signaled != numClients {
		t.Errorf("expected %d signaled clients, got %d", numClients, signaled)
	}

	// Clean unregister
	for i := 0; i < numClients; i++ {
		hub.Unregister(clients[i])
	}

	if hub.GetClientCount() != 0 {
		t.Errorf("expected 0 clients left, got %d", hub.GetClientCount())
	}
}

func TestWebSocketUpgradeHandshake(t *testing.T) {
	var capturedAccept string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := Upgrade(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(OpcodeText, []byte("handshake-ok"))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// Create raw HTTP connection to test upgrade headers
	reqKey := "dGhlIHNhbXBsZSBub25jZQ=="
	expectedAccept := func() string {
		h := sha1.New()
		h.Write([]byte(reqKey + websocketGUID))
		return base64.StdEncoding.EncodeToString(h.Sum(nil))
	}()

	tcpConn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer tcpConn.Close()

	reqStr := "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + reqKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"

	if _, err := tcpConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	reader := bufio.NewReader(tcpConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line failed: %v", err)
	}
	if !bytes.Contains([]byte(statusLine), []byte("101 Switching Protocols")) {
		t.Fatalf("expected 101 Switching Protocols, got: %s", statusLine)
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
		if bytes.HasPrefix([]byte(line), []byte("Sec-WebSocket-Accept:")) {
			parts := bytes.Split(bytes.TrimSpace([]byte(line)), []byte(": "))
			if len(parts) == 2 {
				capturedAccept = string(parts[1])
			}
		}
	}

	if capturedAccept != expectedAccept {
		t.Errorf("Sec-WebSocket-Accept mismatch: got %s, want %s", capturedAccept, expectedAccept)
	}
}
