// Watching the machine's own resources: memory, disk space, load.
//
// This is the only watcher with nobody on the other side. Everything else
// reports what somebody did to the server; this one reports that the server is
// running out of something. Such trouble gets its own grade - system - so that
// it can be switched on and off apart from the reports about attacks: the
// operator may want to know about a full disk without wanting to know about
// every scanner, or the other way round.
package watch

import (
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"
)

// ResourcesConfig - what to watch and at which point to report.
type ResourcesConfig struct {
	Enabled  bool     `json:"enabled"`
	Interval Duration `json:"interval"`
	// Report when less than this share of memory is left, in percent. Zero
	// means ten percent.
	MemoryFreePercent int `json:"memory_free_percent"`
	// Mount points to watch for free space. Empty means the root one.
	Paths []string `json:"paths"`
	// Report when less than this share of space or of inodes is left. A disk
	// with no inodes left refuses to create files although the space is there,
	// which looks like an unexplained failure of everything at once.
	DiskFreePercent   int `json:"disk_free_percent"`
	InodesFreePercent int `json:"inodes_free_percent"`
	// Report when the load per processor is above this. Zero means four, which
	// is high enough that an ordinary busy hour does not reach it.
	LoadPerCPU float64 `json:"load_per_cpu"`
	// How often to repeat a report about trouble that has not gone away. Zero
	// means once an hour: a full disk stays full, and the message about it
	// should not repeat at every pass.
	Repeat Duration `json:"repeat"`
}

// ResourcesWatcher watches the machine's own resources.
type ResourcesWatcher struct {
	cfg  ResourcesConfig
	emit func(Event)

	mu sync.Mutex
	// When each kind of trouble was last reported: a disk that stays full must
	// not fill the chat as well.
	reported map[string]time.Time
	now      func() time.Time // replaced in tests
}

// NewResourcesWatcher creates the watcher.
//
// The defaults are put in here rather than read at every pass: the service
// fills them in when it loads the configuration, and a watcher created directly
// - in a test, or by a caller that built the configuration itself - must behave
// the same way.
func NewResourcesWatcher(cfg ResourcesConfig, emit func(Event)) *ResourcesWatcher {
	for _, item := range []struct {
		target *int
		value  int
	}{
		{&cfg.MemoryFreePercent, 10},
		{&cfg.DiskFreePercent, 10},
		{&cfg.InodesFreePercent, 10},
	} {
		if *item.target == 0 {
			*item.target = item.value
		}
	}
	if cfg.LoadPerCPU == 0 {
		cfg.LoadPerCPU = 4
	}
	if cfg.Repeat.Duration == 0 {
		cfg.Repeat.Duration = time.Hour
	}
	if len(cfg.Paths) == 0 {
		cfg.Paths = []string{"/"}
	}
	return &ResourcesWatcher{cfg: cfg, emit: emit, reported: map[string]time.Time{}, now: time.Now}
}

// Scan takes one look at the machine and reports what is running out.
func (w *ResourcesWatcher) Scan() {
	state, err := readResources(w.cfg.Paths)
	if err != nil {
		slog.Warn("could not read the machine's resources", slog.Any("error", err))
		return
	}
	w.check(state)
}

// check compares what was read against the thresholds. Kept apart from reading
// so that the decision can be tested on figures of our own, on any system: the
// reading itself only works on Linux.
func (w *ResourcesWatcher) check(state resourceState) {
	if state.MemoryTotalKB > 0 {
		free := percent(state.MemoryAvailableKB, state.MemoryTotalKB)
		if free < w.cfg.MemoryFreePercent {
			w.report("memory_low", "memory", fmt.Sprintf("%d%% of memory left", free), map[string]string{
				"free_percent": strconv.Itoa(free),
				"available_mb": strconv.FormatUint(state.MemoryAvailableKB/1024, 10),
				"total_mb":     strconv.FormatUint(state.MemoryTotalKB/1024, 10),
				"swap_free_mb": strconv.FormatUint(state.SwapFreeKB/1024, 10),
			})
		} else {
			w.recovered("memory_low", "memory", fmt.Sprintf("%d%% of memory left again", free))
		}
	}

	for _, disk := range state.Disks {
		freeSpace := percent(disk.FreeBlocks, disk.TotalBlocks)
		if disk.TotalBlocks > 0 && freeSpace < w.cfg.DiskFreePercent {
			w.report("disk_low", disk.Path, fmt.Sprintf("%d%% of space left on %s", freeSpace, disk.Path),
				map[string]string{
					"free_percent": strconv.Itoa(freeSpace),
					"free_mb":      strconv.FormatUint(disk.FreeBytes/1024/1024, 10),
					"path":         disk.Path,
				})
		} else if disk.TotalBlocks > 0 {
			w.recovered("disk_low", disk.Path, fmt.Sprintf("%d%% of space left on %s again", freeSpace, disk.Path))
		}

		freeInodes := percent(disk.FreeInodes, disk.TotalInodes)
		if disk.TotalInodes > 0 && freeInodes < w.cfg.InodesFreePercent {
			w.report("inodes_low", disk.Path,
				fmt.Sprintf("%d%% of file slots left on %s", freeInodes, disk.Path),
				map[string]string{
					"free_percent": strconv.Itoa(freeInodes),
					"free_inodes":  strconv.FormatUint(disk.FreeInodes, 10),
					"path":         disk.Path,
					"hint":         "with no file slots left the disk refuses to create files although the space is there",
				})
		} else if disk.TotalInodes > 0 {
			w.recovered("inodes_low", disk.Path, fmt.Sprintf("file slots on %s are back to %d%%", disk.Path, freeInodes))
		}
	}

	if state.CPUs > 0 && state.Load1 > 0 {
		perCPU := state.Load1 / float64(state.CPUs)
		if perCPU > w.cfg.LoadPerCPU {
			w.report("load_high", "load", fmt.Sprintf("load %.2f per processor", perCPU), map[string]string{
				"load1":      fmt.Sprintf("%.2f", state.Load1),
				"per_cpu":    fmt.Sprintf("%.2f", perCPU),
				"processors": strconv.Itoa(state.CPUs),
			})
		} else {
			w.recovered("load_high", "load", fmt.Sprintf("load is back to %.2f per processor", perCPU))
		}
	}
}

// report emits the event about trouble, no more often than the repeat setting
// allows.
func (w *ResourcesWatcher) report(kind, subject, description string, details map[string]string) {
	key := kind + "|" + subject
	w.mu.Lock()
	last, seen := w.reported[key]
	if seen && w.now().Sub(last) < w.cfg.Repeat.Duration {
		w.mu.Unlock()
		return
	}
	w.reported[key] = w.now()
	w.mu.Unlock()

	if details == nil {
		details = map[string]string{}
	}
	details["description"] = description
	w.emit(Event{
		At: w.now(), Source: "resources", Kind: kind, Severity: SevAlert,
		Subject: subject, Count: 1, Details: details, Grade: GradeSystem,
	})
}

// recovered clears the mark once the trouble is over and says so, so that the
// operator knows the server pulled through without having to ask.
func (w *ResourcesWatcher) recovered(kind, subject, description string) {
	key := kind + "|" + subject
	w.mu.Lock()
	_, seen := w.reported[key]
	if !seen {
		w.mu.Unlock()
		return
	}
	delete(w.reported, key)
	w.mu.Unlock()

	w.emit(Event{
		At: w.now(), Source: "resources", Kind: "resource_recovered", Severity: SevInfo,
		Subject: subject, Count: 1, Grade: GradeNotice,
		Details: map[string]string{"description": description, "was": kind},
	})
}

// percent is the share of part in whole, rounded down. A whole of zero gives a
// hundred: nothing to run out of means nothing to report.
func percent(part, whole uint64) int {
	if whole == 0 {
		return 100
	}
	return int(part * 100 / whole)
}

// resourceState is what one look at the machine shows.
type resourceState struct {
	MemoryTotalKB     uint64
	MemoryAvailableKB uint64
	SwapTotalKB       uint64
	SwapFreeKB        uint64
	Load1             float64
	CPUs              int
	Disks             []diskState
}

// diskState is the free space and free file slots of one mount point.
type diskState struct {
	Path        string
	TotalBlocks uint64
	FreeBlocks  uint64
	FreeBytes   uint64
	TotalInodes uint64
	FreeInodes  uint64
}
