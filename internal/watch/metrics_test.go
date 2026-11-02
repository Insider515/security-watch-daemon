package watch

import (
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The counters tell three fates of an event apart: suppressed by a rule, merged
// as a repeat, delivered.
func TestMetricsCounts(t *testing.T) {
	metrics := NewMetrics(t.TempDir())

	metrics.Seen()
	metrics.Ignored()
	metrics.Seen()
	metrics.Merged()
	metrics.Seen()
	metrics.Sent(Event{Source: "access", Severity: SevAlert})
	metrics.Sent(Event{Source: "access", Severity: SevInfo})
	metrics.SinkError()

	got := metrics.Snapshot()
	if got.Seen != 3 || got.Ignored != 1 || got.Merged != 1 || got.Sent != 2 || got.SinkErrors != 1 {
		t.Fatalf("counters: %+v", got)
	}
	if got.BySource["access"] != 2 {
		t.Errorf("by source: %+v", got.BySource)
	}
	if got.BySeverity[string(SevAlert)] != 1 || got.BySeverity[string(SevInfo)] != 1 {
		t.Errorf("by severity: %+v", got.BySeverity)
	}
}

// The snapshot does not share its maps with the live counters.
func TestMetricsSnapshotIsCopy(t *testing.T) {
	metrics := NewMetrics(t.TempDir())
	metrics.Sent(Event{Source: "auth", Severity: SevWarn})

	snapshot := metrics.Snapshot()
	snapshot.BySource["auth"] = 999
	metrics.Sent(Event{Source: "auth", Severity: SevWarn})

	if again := metrics.Snapshot(); again.BySource["auth"] != 2 {
		t.Fatalf("the snapshot is tied to the live counters: %+v", again.BySource)
	}
}

// The count continues after a restart: otherwise "before" and "after" cannot be
// compared.
func TestMetricsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	first := NewMetrics(dir)
	first.Seen()
	first.Sent(Event{Source: "files", Severity: SevWarn})
	first.Save()

	second := NewMetrics(dir)
	got := second.Snapshot()
	if got.Seen != 1 || got.Sent != 1 || got.BySource["files"] != 1 {
		t.Fatalf("the counters were not restored: %+v", got)
	}
}

// The heartbeat carries the counters: on the receiving side they show whether
// the service notices anything or merely reports that it is alive.
func TestMetricsDetails(t *testing.T) {
	metrics := NewMetrics(t.TempDir())
	metrics.Seen()
	metrics.Sent(Event{Source: "ports", Severity: SevAlert})

	details := metrics.Details()
	if details["seen"] != "1" || details["sent"] != "1" {
		t.Fatalf("counters in the heartbeat: %+v", details)
	}
	if details["uptime"] == "" {
		t.Errorf("the uptime is empty: %+v", details)
	}
}

// Different watchers change the counters at the same time, so they must hold up
// under concurrent counting (checked by running with -race).
func TestMetricsConcurrent(t *testing.T) {
	metrics := NewMetrics(t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				metrics.Seen()
				metrics.Sent(Event{Source: "db", Severity: SevWarn})
				_ = metrics.Snapshot()
			}
		}()
	}
	wg.Wait()

	if got := metrics.Snapshot(); got.Seen != 1000 || got.Sent != 1000 {
		t.Fatalf("counts were lost under concurrent work: %+v", got)
	}
}

// Without a snapshot the command must honestly say there is nothing to show
// instead of printing zeros.
func TestPrintMetricsWithoutState(t *testing.T) {
	if err := PrintMetrics(t.TempDir()); err == nil {
		t.Fatal("an error was expected: there are no counters yet")
	}
}

// The time of the last change is needed to tell a live snapshot from an old one.
func TestMetricsUpdatedAt(t *testing.T) {
	metrics := NewMetrics(t.TempDir())
	before := time.Now().Add(-time.Second)
	metrics.Seen()
	if got := metrics.Snapshot(); !got.UpdatedAt.After(before) {
		t.Fatalf("the change time was not set: %v", got.UpdatedAt)
	}
}

// Printing a breakdown must not depend on the random map iteration order.
func TestPrintCountMapOrder(t *testing.T) {
	out := captureStdout(t, func() {
		printCountMap("by source", map[string]uint64{"ports": 1, "access": 2, "db": 3})
	})
	if strings.Index(out, "access") > strings.Index(out, "db") {
		t.Fatalf("the order is not alphabetical: %q", out)
	}
}

// captureStdout collects what the code under test printed: the control commands
// print for people, and it is the printing that has to be checked.
func captureStdout(t *testing.T, action func()) string {
	t.Helper()
	saved := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = writer
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		done <- string(data)
	}()
	action()
	_ = writer.Close()
	os.Stdout = saved
	return <-done
}

// A short run must leave the counters behind as well: otherwise after -once the
// -stats command would say there are no counters, although a pass did happen.
func TestServiceSavesMetricsOnClose(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{StateDir: dir}
	cfg.applyDefaults()
	cfg.StateDir = dir

	service, err := NewService(cfg, "")
	if err != nil {
		t.Fatalf("assembling the service: %v", err)
	}
	service.emit(Event{Source: "test", Kind: "probe", Severity: SevInfo, Subject: "x", Count: 1})
	service.Close()

	if err := PrintMetrics(dir); err != nil {
		t.Fatalf("the counters were not written on shutdown: %v", err)
	}
}

// The printout must not invent a time that never was: with an empty count it
// says so instead of printing "snapshot from year 0001".
func TestPrintMetricsWithoutChanges(t *testing.T) {
	dir := t.TempDir()
	NewMetrics(dir).Save()

	out := captureStdout(t, func() {
		if err := PrintMetrics(dir); err != nil {
			t.Fatalf("printing the counters: %v", err)
		}
	})
	if strings.Contains(out, "0001") {
		t.Errorf("a zero time was printed: %q", out)
	}
	if !strings.Contains(out, "never changed") {
		t.Errorf("it does not say that there were no events: %q", out)
	}
}
