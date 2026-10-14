package metrics

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricType represents the Prometheus metric type.
type MetricType string

const (
	TypeCounter MetricType = "counter"
	TypeGauge   MetricType = "gauge"
)

// MetricRegistry manages thread-safe Prometheus counters, gauges, and runtime telemetry.
type MetricRegistry struct {
	mu        sync.RWMutex
	startTime time.Time
	counters  map[string]*labeledCounter
	gauges    map[string]*labeledGauge
}

type labeledCounter struct {
	help   string
	values map[string]*uint64
}

type labeledGauge struct {
	help   string
	values map[string]*int64
}

// DefaultRegistry is the singleton metric registry for sheet-license-broker.
var DefaultRegistry = NewRegistry()

// NewRegistry initializes an empty metrics registry.
func NewRegistry() *MetricRegistry {
	return &MetricRegistry{
		startTime: time.Now(),
		counters:  make(map[string]*labeledCounter),
		gauges:    make(map[string]*labeledGauge),
	}
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		val := labels[k]
		val = strings.ReplaceAll(val, `\`, `\\`)
		val = strings.ReplaceAll(val, `"`, `\"`)
		val = strings.ReplaceAll(val, "\n", `\n`)
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, val))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// CounterInc increments a labeled counter by 1.
func (r *MetricRegistry) CounterInc(name, help string, labels map[string]string) {
	r.CounterAdd(name, help, labels, 1)
}

// CounterAdd adds delta to a labeled counter.
func (r *MetricRegistry) CounterAdd(name, help string, labels map[string]string, delta uint64) {
	lblStr := formatLabels(labels)
	r.mu.Lock()
	lc, exists := r.counters[name]
	if !exists {
		lc = &labeledCounter{help: help, values: make(map[string]*uint64)}
		r.counters[name] = lc
	}
	valPtr, valExists := lc.values[lblStr]
	if !valExists {
		var zero uint64
		valPtr = &zero
		lc.values[lblStr] = valPtr
	}
	r.mu.Unlock()

	atomic.AddUint64(valPtr, delta)
}

// GaugeSet sets the value of a labeled gauge.
func (r *MetricRegistry) GaugeSet(name, help string, labels map[string]string, val int64) {
	lblStr := formatLabels(labels)
	r.mu.Lock()
	lg, exists := r.gauges[name]
	if !exists {
		lg = &labeledGauge{help: help, values: make(map[string]*int64)}
		r.gauges[name] = lg
	}
	valPtr, valExists := lg.values[lblStr]
	if !valExists {
		var zero int64
		valPtr = &zero
		lg.values[lblStr] = valPtr
	}
	r.mu.Unlock()

	atomic.StoreInt64(valPtr, val)
}

// GaugeAdd adds delta to a labeled gauge.
func (r *MetricRegistry) GaugeAdd(name, help string, labels map[string]string, delta int64) {
	lblStr := formatLabels(labels)
	r.mu.Lock()
	lg, exists := r.gauges[name]
	if !exists {
		lg = &labeledGauge{help: help, values: make(map[string]*int64)}
		r.gauges[name] = lg
	}
	valPtr, valExists := lg.values[lblStr]
	if !valExists {
		var zero int64
		valPtr = &zero
		lg.values[lblStr] = valPtr
	}
	r.mu.Unlock()

	atomic.AddInt64(valPtr, delta)
}

// WritePrometheus writes exposition format (version 0.0.4) to w.
func (r *MetricRegistry) WritePrometheus(w io.Writer) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Write System / Runtime Metrics
	uptime := time.Since(r.startTime).Seconds()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	fmt.Fprintf(w, "# HELP process_uptime_seconds Total seconds since process startup.\n")
	fmt.Fprintf(w, "# TYPE process_uptime_seconds gauge\n")
	fmt.Fprintf(w, "process_uptime_seconds %.2f\n\n", uptime)

	fmt.Fprintf(w, "# HELP go_goroutines Number of goroutines that currently exist.\n")
	fmt.Fprintf(w, "# TYPE go_goroutines gauge\n")
	fmt.Fprintf(w, "go_goroutines %d\n\n", runtime.NumGoroutine())

	fmt.Fprintf(w, "# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.\n")
	fmt.Fprintf(w, "# TYPE go_memstats_alloc_bytes gauge\n")
	fmt.Fprintf(w, "go_memstats_alloc_bytes %d\n\n", memStats.Alloc)

	// Counters
	counterNames := make([]string, 0, len(r.counters))
	for name := range r.counters {
		counterNames = append(counterNames, name)
	}
	sort.Strings(counterNames)

	for _, name := range counterNames {
		lc := r.counters[name]
		fmt.Fprintf(w, "# HELP %s %s\n", name, lc.help)
		fmt.Fprintf(w, "# TYPE %s counter\n", name)

		labelKeys := make([]string, 0, len(lc.values))
		for k := range lc.values {
			labelKeys = append(labelKeys, k)
		}
		sort.Strings(labelKeys)

		for _, lk := range labelKeys {
			v := atomic.LoadUint64(lc.values[lk])
			fmt.Fprintf(w, "%s%s %d\n", name, lk, v)
		}
		fmt.Fprintln(w)
	}

	// Gauges
	gaugeNames := make([]string, 0, len(r.gauges))
	for name := range r.gauges {
		gaugeNames = append(gaugeNames, name)
	}
	sort.Strings(gaugeNames)

	for _, name := range gaugeNames {
		lg := r.gauges[name]
		fmt.Fprintf(w, "# HELP %s %s\n", name, lg.help)
		fmt.Fprintf(w, "# TYPE %s gauge\n", name)

		labelKeys := make([]string, 0, len(lg.values))
		for k := range lg.values {
			labelKeys = append(labelKeys, k)
		}
		sort.Strings(labelKeys)

		for _, lk := range labelKeys {
			v := atomic.LoadInt64(lg.values[lk])
			fmt.Fprintf(w, "%s%s %d\n", name, lk, v)
		}
		fmt.Fprintln(w)
	}

	return nil
}

// Handler returns an HTTP handler for Prometheus scraping.
func (r *MetricRegistry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.WritePrometheus(w)
	}
}

// Global metric recording shortcuts

func RecordRequest(method, path string, status int, duration time.Duration) {
	DefaultRegistry.CounterInc("sheet_license_http_requests_total", "Total incoming HTTP requests.", map[string]string{
		"method": method,
		"path":   path,
		"status": strconv.Itoa(status),
	})
	DefaultRegistry.GaugeSet("sheet_license_last_request_duration_ms", "Duration of the last handled HTTP request in milliseconds.", map[string]string{
		"path": path,
	}, duration.Milliseconds())
}

func RecordVerification(result, tenant string) {
	DefaultRegistry.CounterInc("sheet_license_verifications_total", "Total license verification attempts and results.", map[string]string{
		"result": result,
		"tenant": tenant,
	})
}

func RecordSecurityIncident(incidentType string) {
	DefaultRegistry.CounterInc("sheet_license_security_incidents_total", "Total anti-tamper security incidents detected.", map[string]string{
		"type": incidentType,
	})
}

func RecordHAReplication(target, status string) {
	DefaultRegistry.CounterInc("sheet_license_ha_replication_ops_total", "Total high-availability replication operations.", map[string]string{
		"target": target,
		"status": status,
	})
}

func SetBackendHealth(backend string, isUp bool) {
	val := int64(0)
	if isUp {
		val = 1
	}
	DefaultRegistry.GaugeSet("sheet_license_backend_health", "Health status of backend sheets (1=healthy, 0=unreachable).", map[string]string{
		"backend": backend,
	}, val)
}

func SetSpoolQueueDepth(depth int) {
	DefaultRegistry.GaugeSet("sheet_license_spool_queue_depth", "Current number of events waiting in local encrypted disk spool.", nil, int64(depth))
}

func RecordSpoolFlushed(count int) {
	DefaultRegistry.CounterAdd("sheet_license_spool_flushed_total", "Total spooled events flushed to remote sheet backend.", nil, uint64(count))
}
