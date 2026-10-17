package api

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kLauncher1/sheet-license-broker/internal/stream"
)

func setupTestStreamServer(t *testing.T) (*httptest.Server, *AppServer) {
	server, err := newAppServer()
	if err != nil {
		t.Fatalf("failed to create app server: %v", err)
	}

	apiMux := http.NewServeMux()
	mux := http.NewServeMux()

	server.registerStreamRoutes(apiMux, mux)
	mux.Handle("/api/", apiMux)

	ts := httptest.NewServer(mux)
	return ts, server
}

func TestStreamWebSocketUpgradeAndWelcome(t *testing.T) {
	ts, _ := setupTestStreamServer(t)
	defer ts.Close()

	// Connect raw TCP to test WebSocket upgrade handshake
	tcpConn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}
	defer tcpConn.Close()

	reqStr := "GET /api/stream/ws?license_key=LIC-STREAM-TEST&hwid=HWID-TEST-001 HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"

	if _, err := tcpConn.Write([]byte(reqStr)); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	reader := bufio.NewReader(tcpConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line failed: %v", err)
	}
	if !strings.Contains(statusLine, "101 Switching Protocols") {
		t.Fatalf("expected 101 Switching Protocols, got: %s", statusLine)
	}

	// Read headers until blank line
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	// Read initial stream:connected frame
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Fatalf("failed to read welcome frame header: %v", err)
	}
	payloadLen := int(header[1] & 0x7F)
	if payloadLen == 126 {
		var ext uint16
		if err := binary.Read(reader, binary.BigEndian, &ext); err != nil {
			t.Fatalf("failed to read extended length: %v", err)
		}
		payloadLen = int(ext)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatalf("failed to read welcome payload: %v", err)
	}

	var env stream.Message
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatalf("failed to parse welcome JSON: %v, raw: %s", err, string(payload))
	}
	if env.Event != stream.EventConnected {
		t.Errorf("expected EventConnected, got: %s", env.Event)
	}
}

func TestStreamRESTClientsAndKillSwitch(t *testing.T) {
	ts, server := setupTestStreamServer(t)
	defer ts.Close()

	// Register a mock client into the server stream hub
	mockClient := stream.NewClient("cl-rest-test", nil, server.proxy.StreamHub(), stream.ClientInfo{
		LicenseKey: "LIC-REST-KILL",
		HWID:       "HWID-REST-DEVICE",
	})
	server.proxy.RegisterStreamClient(mockClient)
	defer server.proxy.UnregisterStreamClient(mockClient)

	// Test GET /api/stream/clients
	resp, err := http.Get(ts.URL + "/api/stream/clients")
	if err != nil {
		t.Fatalf("GET /api/stream/clients failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	var clientsRes struct {
		Status string              `json:"status"`
		Count  int                 `json:"count"`
		List   []stream.ClientInfo `json:"clients"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&clientsRes)
	if clientsRes.Count != 1 {
		t.Errorf("expected 1 client in count, got %d", clientsRes.Count)
	}

	// Test POST /api/stream/kill
	killBody := []byte(`{"target":"LIC-REST-KILL","reason":"Manual test revocation","immediate":true}`)
	killResp, err := http.Post(ts.URL+"/api/stream/kill", "application/json", bytes.NewReader(killBody))
	if err != nil {
		t.Fatalf("POST /api/stream/kill failed: %v", err)
	}
	defer killResp.Body.Close()

	if killResp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 on kill, got %d", killResp.StatusCode)
	}
	var killRes struct {
		Status          string `json:"status"`
		SignaledClients int    `json:"signaled_clients"`
	}
	_ = json.NewDecoder(killResp.Body).Decode(&killRes)
	if killRes.SignaledClients != 1 {
		t.Errorf("expected 1 signaled client, got %d", killRes.SignaledClients)
	}

	// Verify kill switch frame enqueued on client
	select {
	case msg := <-mockClient.SendChanForTest():
		var env stream.Message
		_ = json.Unmarshal(msg, &env)
		if env.Event != stream.EventKillSwitch {
			t.Errorf("expected EventKillSwitch on mock client, got %s", env.Event)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected kill switch frame delivered to mock client")
	}

	// Test POST /api/stream/broadcast
	bcBody := []byte(`{"event":"stream:alert","payload":{"msg":"Broadcast test"}}`)
	bcResp, err := http.Post(ts.URL+"/api/stream/broadcast", "application/json", bytes.NewReader(bcBody))
	if err != nil {
		t.Fatalf("POST /api/stream/broadcast failed: %v", err)
	}
	defer bcResp.Body.Close()

	if bcResp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 on broadcast, got %d", bcResp.StatusCode)
	}

	// Test GET /api/stream/telemetry
	telResp, err := http.Get(ts.URL + "/api/stream/telemetry")
	if err != nil {
		t.Fatalf("GET /api/stream/telemetry failed: %v", err)
	}
	defer telResp.Body.Close()

	if telResp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 on telemetry, got %d", telResp.StatusCode)
	}
	var telRes struct {
		Status    string                  `json:"status"`
		Telemetry stream.TelemetrySummary `json:"telemetry"`
	}
	_ = json.NewDecoder(telResp.Body).Decode(&telRes)
	if telRes.Telemetry.ActiveConnections != 1 {
		t.Errorf("expected 1 active connection, got %d", telRes.Telemetry.ActiveConnections)
	}
}
