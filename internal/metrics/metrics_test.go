package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMetricsRegistryCountersAndGauges(t *testing.T) {
	reg := NewRegistry()

	reg.CounterInc("test_counter", "A test counter", map[string]string{"env": "prod", "service": "api"})
	reg.CounterAdd("test_counter", "A test counter", map[string]string{"env": "prod", "service": "api"}, 4)
	reg.GaugeSet("test_gauge", "A test gauge", map[string]string{"worker": "1"}, 42)
	reg.GaugeAdd("test_gauge", "A test gauge", map[string]string{"worker": "1"}, -10)

	var buf bytes.Buffer
	err := reg.WritePrometheus(&buf)
	if err != nil {
		t.Fatalf("WritePrometheus failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, `# HELP test_counter A test counter`) {
		t.Errorf("expected counter help comment in output")
	}
	if !strings.Contains(output, `test_counter{env="prod",service="api"} 5`) {
		t.Errorf("expected counter value 5, got:\n%s", output)
	}
	if !strings.Contains(output, `test_gauge{worker="1"} 32`) {
		t.Errorf("expected gauge value 32, got:\n%s", output)
	}
	if !strings.Contains(output, "process_uptime_seconds") {
		t.Errorf("expected process_uptime_seconds in output")
	}
	if !strings.Contains(output, "go_goroutines") {
		t.Errorf("expected go_goroutines in output")
	}
}

func TestMetricsHTTPHandler(t *testing.T) {
	reg := NewRegistry()
	reg.CounterInc("http_hits", "Hits", nil)

	handler := reg.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("unexpected content-type: %s", contentType)
	}
	if !strings.Contains(rr.Body.String(), "http_hits 1") {
		t.Errorf("expected http_hits 1 in body, got:\n%s", rr.Body.String())
	}
}

func TestMetricsConcurrency(t *testing.T) {
	reg := NewRegistry()
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				reg.CounterInc("concurrency_counter", "Concurrent test", map[string]string{"lane": "fast"})
				reg.GaugeSet("concurrency_gauge", "Concurrent test", map[string]string{"lane": "fast"}, int64(id*100+j))
			}
		}(i)
	}
	wg.Wait()

	var buf bytes.Buffer
	if err := reg.WritePrometheus(&buf); err != nil {
		t.Fatalf("WritePrometheus concurrency error: %v", err)
	}
	if !strings.Contains(buf.String(), `concurrency_counter{lane="fast"} 1000`) {
		t.Errorf("expected counter 1000, got output:\n%s", buf.String())
	}
}

func TestGlobalHelperFunctions(t *testing.T) {
	RecordRequest("POST", "/api/licenses/validate", 200, 15*time.Millisecond)
	RecordVerification("valid", "ACME")
	RecordSecurityIncident("tamper_attempt")
	RecordHAReplication("standby", "success")
	SetBackendHealth("primary", true)
	SetBackendHealth("standby", false)
	SetSpoolQueueDepth(5)
	RecordSpoolFlushed(2)

	var buf bytes.Buffer
	if err := DefaultRegistry.WritePrometheus(&buf); err != nil {
		t.Fatalf("failed to write default registry: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "sheet_license_http_requests_total") {
		t.Errorf("missing sheet_license_http_requests_total")
	}
	if !strings.Contains(out, "sheet_license_verifications_total") {
		t.Errorf("missing sheet_license_verifications_total")
	}
	if !strings.Contains(out, "sheet_license_security_incidents_total") {
		t.Errorf("missing sheet_license_security_incidents_total")
	}
	if !strings.Contains(out, "sheet_license_backend_health") {
		t.Errorf("missing sheet_license_backend_health")
	}
}
