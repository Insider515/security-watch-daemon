// The service's own counters: how many events went through it and what became of
// them.
package watch

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metrics counts the work of the service itself: how many events arrived from
// the watchers, how many were suppressed by rules, merged as repeats, delivered,
// and how many deliveries failed. The counters go out with the heartbeat and are
// printed by the -stats flag. A zero count of arrivals on a running service
// means it sees nothing.
type Metrics struct {
	mu        sync.Mutex
	statePath string
	startedAt time.Time
	counts    metricCounts
}

// metricCounts - what survives a restart and is printed by -stats.
type metricCounts struct {
	// Arrived from the watchers before any processing.
	Seen uint64 `json:"seen"`
	// Dropped by suppression rules.
	Ignored uint64 `json:"ignored"`
	// Merged with a previous identical event.
	Merged uint64 `json:"merged"`
	// Delivered to the sinks.
	Sent uint64 `json:"sent"`
	// Deliveries that failed in at least one sink.
	SinkErrors uint64            `json:"sink_errors"`
	BySeverity map[string]uint64 `json:"by_severity"`
	BySource   map[string]uint64 `json:"by_source"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// NewMetrics starts the counters, continuing the previous count if it was saved.
func NewMetrics(stateDir string) *Metrics {
	metrics := &Metrics{
		statePath: filepath.Join(stateDir, "metrics.state.json"),
		startedAt: time.Now(),
		counts:    metricCounts{BySeverity: map[string]uint64{}, BySource: map[string]uint64{}},
	}
	saved := metricCounts{}
	if loadJSONState(metrics.statePath, &saved) {
		if saved.BySeverity == nil {
			saved.BySeverity = map[string]uint64{}
		}
		if saved.BySource == nil {
			saved.BySource = map[string]uint64{}
		}
		metrics.counts = saved
	}
	return metrics
}

// Seen records an event that arrived from a watcher.
func (m *Metrics) Seen() { m.add(func(c *metricCounts) { c.Seen++ }) }

// Ignored records an event dropped by the suppression rules.
func (m *Metrics) Ignored() { m.add(func(c *metricCounts) { c.Ignored++ }) }

// Merged records an event merged with a previous identical one.
func (m *Metrics) Merged() { m.add(func(c *metricCounts) { c.Merged++ }) }

// Sent records a delivered event, broken down by source and severity.
func (m *Metrics) Sent(event Event) {
	m.add(func(c *metricCounts) {
		c.Sent++
		c.BySeverity[string(event.Severity)]++
		c.BySource[event.Source]++
	})
}

// SinkError records a failed delivery.
func (m *Metrics) SinkError() { m.add(func(c *metricCounts) { c.SinkErrors++ }) }

// add changes the counters under the lock.
func (m *Metrics) add(change func(*metricCounts)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	change(&m.counts)
	m.counts.UpdatedAt = time.Now()
}

// Snapshot returns a copy of the counters.
func (m *Metrics) Snapshot() metricCounts {
	m.mu.Lock()
	defer m.mu.Unlock()
	copyOf := m.counts
	copyOf.BySeverity = map[string]uint64{}
	copyOf.BySource = map[string]uint64{}
	for name, value := range m.counts.BySeverity {
		copyOf.BySeverity[name] = value
	}
	for name, value := range m.counts.BySource {
		copyOf.BySource[name] = value
	}
	return copyOf
}

// Save writes the counters so they are visible to the -stats command and survive
// a restart.
func (m *Metrics) Save() {
	saveJSONState(m.statePath, m.Snapshot(), 0o640)
}

// formatMetrics renders the counters as readable lines. Used by the bot's
// /status reply.
func formatMetrics(counts metricCounts) string {
	lines := []string{
		fmt.Sprintf("events seen: %d", counts.Seen),
		fmt.Sprintf("sent on: %d", counts.Sent),
		fmt.Sprintf("suppressed by rules: %d", counts.Ignored),
		fmt.Sprintf("merged as repeats: %d", counts.Merged),
	}
	if counts.SinkErrors > 0 {
		lines = append(lines, fmt.Sprintf("delivery failures: %d", counts.SinkErrors))
	}
	if len(counts.BySource) > 0 {
		sources := make([]string, 0, len(counts.BySource))
		for name := range counts.BySource {
			sources = append(sources, name)
		}
		sort.Slice(sources, func(i, j int) bool {
			return counts.BySource[sources[i]] > counts.BySource[sources[j]]
		})
		parts := make([]string, 0, len(sources))
		for _, name := range sources {
			parts = append(parts, fmt.Sprintf("%s %d", name, counts.BySource[name]))
		}
		lines = append(lines, "by source: "+strings.Join(parts, ", "))
	}
	return strings.Join(lines, "\n")
}

// Details returns the counters to be attached to the heartbeat.
func (m *Metrics) Details() map[string]string {
	snapshot := m.Snapshot()
	return map[string]string{
		"seen":        strconv.FormatUint(snapshot.Seen, 10),
		"sent":        strconv.FormatUint(snapshot.Sent, 10),
		"ignored":     strconv.FormatUint(snapshot.Ignored, 10),
		"merged":      strconv.FormatUint(snapshot.Merged, 10),
		"sink_errors": strconv.FormatUint(snapshot.SinkErrors, 10),
		"uptime":      time.Since(m.startedAt).Round(time.Second).String(),
	}
}

// PrintMetrics prints the saved counters. The service is not started for this,
// so the last written snapshot is used.
func PrintMetrics(stateDir string) error {
	counts := metricCounts{}
	path := filepath.Join(stateDir, "metrics.state.json")
	if !loadJSONState(path, &counts) {
		return fmt.Errorf("no counters yet: %s", path)
	}
	// A zero time means the counters have never changed: there were no events.
	// Printing "snapshot from year 0001" would be pointless.
	if counts.UpdatedAt.IsZero() {
		fmt.Println("counters have never changed: there were no events")
	} else {
		fmt.Printf("last change %s\n", counts.UpdatedAt.Format("2006-01-02 15:04:05"))
	}
	fmt.Printf("arrived %d, delivered %d, suppressed %d, merged %d, failed deliveries %d\n",
		counts.Seen, counts.Sent, counts.Ignored, counts.Merged, counts.SinkErrors)
	printCountMap("by severity", counts.BySeverity)
	printCountMap("by source", counts.BySource)
	return nil
}

// printCountMap prints a breakdown in a stable order.
func printCountMap(title string, values map[string]uint64) {
	if len(values) == 0 {
		return
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Println(title + ":")
	for _, name := range names {
		fmt.Printf("  %-12s %d\n", name, values[name])
	}
}
