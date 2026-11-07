package watch

import (
	"strings"
	"testing"
	"time"
)

// resourcesForTest returns the watcher and the events it emitted.
func resourcesForTest(cfg ResourcesConfig) (*ResourcesWatcher, *[]Event) {
	got := []Event{}
	watcher := NewResourcesWatcher(cfg, func(e Event) { got = append(got, e) })
	return watcher, &got
}

// Memory running out is the server's own trouble: it gets the system grade, so
// it can be reported without reporting every scanner.
func TestResourcesMemoryLow(t *testing.T) {
	watcher, got := resourcesForTest(ResourcesConfig{MemoryFreePercent: 10})
	watcher.check(resourceState{MemoryTotalKB: 1000000, MemoryAvailableKB: 50000})

	if len(*got) != 1 {
		t.Fatalf("expected one event, got %d", len(*got))
	}
	event := (*got)[0]
	if event.Kind != "memory_low" || event.Grade != GradeSystem || event.Source != "resources" {
		t.Fatalf("the event does not look like system trouble: %+v", event)
	}
	if event.Details["free_percent"] != "5" {
		t.Errorf("the share of free memory: %q", event.Details["free_percent"])
	}
}

// Above the threshold nothing is reported: a healthy server must stay silent.
func TestResourcesQuietWhenHealthy(t *testing.T) {
	watcher, got := resourcesForTest(ResourcesConfig{MemoryFreePercent: 10})
	watcher.check(resourceState{MemoryTotalKB: 1000000, MemoryAvailableKB: 800000})
	if len(*got) != 0 {
		t.Fatalf("a healthy server produced events: %+v", *got)
	}
}

// Trouble that has not gone away is not repeated at every pass: a full disk
// stays full, and the message about it must not fill the chat.
func TestResourcesDoesNotRepeat(t *testing.T) {
	watcher, got := resourcesForTest(ResourcesConfig{
		MemoryFreePercent: 10, Repeat: Duration{Duration: time.Hour},
	})
	moment := time.Now()
	watcher.now = func() time.Time { return moment }

	low := resourceState{MemoryTotalKB: 1000000, MemoryAvailableKB: 50000}
	watcher.check(low)
	watcher.check(low)
	watcher.check(low)
	if len(*got) != 1 {
		t.Fatalf("the report repeated %d times inside the window", len(*got))
	}

	moment = moment.Add(time.Hour + time.Minute)
	watcher.check(low)
	if len(*got) != 2 {
		t.Fatalf("after the window the report must come again, got %d", len(*got))
	}
}

// Once the trouble is over it is said so: otherwise the operator cannot tell
// whether the server pulled through without going to look.
func TestResourcesReportsRecovery(t *testing.T) {
	watcher, got := resourcesForTest(ResourcesConfig{MemoryFreePercent: 10})
	watcher.check(resourceState{MemoryTotalKB: 1000000, MemoryAvailableKB: 50000})
	watcher.check(resourceState{MemoryTotalKB: 1000000, MemoryAvailableKB: 900000})

	if len(*got) != 2 {
		t.Fatalf("expected trouble and recovery, got %d events", len(*got))
	}
	recovery := (*got)[1]
	if recovery.Kind != "resource_recovered" || recovery.Details["was"] != "memory_low" {
		t.Fatalf("the recovery event: %+v", recovery)
	}
}

// Free space and free file slots are watched separately: a disk with no slots
// left refuses to create files although the space is there.
func TestResourcesDiskAndInodes(t *testing.T) {
	watcher, got := resourcesForTest(ResourcesConfig{DiskFreePercent: 10, InodesFreePercent: 10})
	watcher.check(resourceState{Disks: []diskState{{
		Path: "/", TotalBlocks: 1000, FreeBlocks: 500, FreeBytes: 500 * 4096,
		TotalInodes: 1000, FreeInodes: 20,
	}}})

	if len(*got) != 1 {
		t.Fatalf("expected one event, got %+v", *got)
	}
	event := (*got)[0]
	if event.Kind != "inodes_low" {
		t.Fatalf("the slots running out were not noticed: %+v", event)
	}
	if !strings.Contains(event.Details["hint"], "refuses to create files") {
		t.Errorf("the event does not explain what this means: %q", event.Details["hint"])
	}
}

// Load is measured per processor: the same figure means different things on a
// machine with two cores and on one with thirty-two.
func TestResourcesLoadPerProcessor(t *testing.T) {
	watcher, got := resourcesForTest(ResourcesConfig{LoadPerCPU: 4})
	watcher.check(resourceState{Load1: 16, CPUs: 8})
	if len(*got) != 0 {
		t.Fatalf("two per processor is not high: %+v", *got)
	}
	watcher.check(resourceState{Load1: 40, CPUs: 8})
	if len(*got) != 1 || (*got)[0].Kind != "load_high" {
		t.Fatalf("five per processor must be reported: %+v", *got)
	}
}

// Nothing to run out of means nothing to report: figures of zero must not come
// out as a hundred percent used.
func TestResourcesZeroTotals(t *testing.T) {
	watcher, got := resourcesForTest(ResourcesConfig{})
	watcher.check(resourceState{})
	if len(*got) != 0 {
		t.Fatalf("empty figures produced events: %+v", *got)
	}
}

// A pass that cannot read the figures is not a failure of the service: the
// watcher says so in the log and the next pass tries again. Outside Linux there
// is nothing to read at all, and that is the case under test here.
func TestResourcesScanSurvivesUnreadableFigures(t *testing.T) {
	watcher, got := resourcesForTest(ResourcesConfig{Enabled: true})
	watcher.Scan()
	if len(*got) != 0 {
		t.Fatalf("events appeared where there was nothing to read: %+v", *got)
	}
}

// The defaults are put in when the watcher is created, so one built directly -
// by a test, or by a caller that assembled the configuration itself - behaves
// like one built from a loaded configuration file.
func TestResourcesAppliesDefaults(t *testing.T) {
	watcher, got := resourcesForTest(ResourcesConfig{})
	if watcher.cfg.MemoryFreePercent != 10 || watcher.cfg.LoadPerCPU != 4 {
		t.Fatalf("the thresholds were not filled in: %+v", watcher.cfg)
	}
	if watcher.cfg.Repeat.Duration != time.Hour || len(watcher.cfg.Paths) != 1 {
		t.Fatalf("the repeat period or the mount points were not filled in: %+v", watcher.cfg)
	}

	// The filled-in threshold is the one that works: nine percent left is below
	// the default ten and must be reported.
	watcher.check(resourceState{MemoryTotalKB: 100000, MemoryAvailableKB: 9000})
	if len(*got) != 1 {
		t.Fatalf("the default threshold did not work: %+v", *got)
	}
}

// Nothing to run out of gives a full share rather than an empty one: a figure
// of zero must not read as "nothing left" and raise an alarm about a mount
// point that was not measured.
func TestResourcesPercentOfNothing(t *testing.T) {
	if got := percent(0, 0); got != 100 {
		t.Errorf("percent(0, 0) = %d, expected 100", got)
	}
	if got := percent(1, 4); got != 25 {
		t.Errorf("percent(1, 4) = %d, expected 25", got)
	}
}

// A mount point that was measured and is healthy says nothing, and one that is
// full says it once per repeat period - both at the same pass.
func TestResourcesDiskSeparateFromMemory(t *testing.T) {
	watcher, got := resourcesForTest(ResourcesConfig{DiskFreePercent: 10, InodesFreePercent: 10})
	watcher.check(resourceState{Disks: []diskState{
		{Path: "/", TotalBlocks: 1000, FreeBlocks: 50, FreeBytes: 50 * 4096, TotalInodes: 1000, FreeInodes: 900},
		{Path: "/var", TotalBlocks: 1000, FreeBlocks: 900, FreeBytes: 900 * 4096, TotalInodes: 1000, FreeInodes: 950},
	}})

	if len(*got) != 1 {
		t.Fatalf("expected one event about one mount point, got %+v", *got)
	}
	if (*got)[0].Kind != "disk_low" || (*got)[0].Subject != "/" {
		t.Fatalf("the wrong mount point was reported: %+v", (*got)[0])
	}
}
