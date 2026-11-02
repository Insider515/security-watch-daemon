// Protecting the watcher itself: it checks its own files, reports start and stop
// and emits a heartbeat on schedule.
package watch

import (
	"os"
	"strconv"
	"time"
)

// SelfGuardConfig - self-protection settings.
type SelfGuardConfig struct {
	Enabled bool `json:"enabled"`
	// How often to emit the heartbeat. On the receiving side a missing heartbeat
	// is an alarm: the service was stopped or the server was cut off.
	HeartbeatInterval Duration `json:"heartbeat_interval"`
	// How often to re-check its own files.
	CheckInterval Duration `json:"check_interval"`
	// Additional files of its own (the systemd unit and anything else).
	WatchPaths []string `json:"watch_paths"`
}

// SelfGuard watches the files of the service itself (the executable, the
// configuration, the systemd unit) and emits the heartbeat. A missing heartbeat
// on the receiving side means the service was stopped or the server was cut off.
type SelfGuard struct {
	cfg   SelfGuardConfig
	paths []string
	sums  map[string]string
	emit  func(Event)
}

// NewSelfGuard assembles the guard: its own executable, its own configuration
// file and everything listed additionally.
func NewSelfGuard(cfg SelfGuardConfig, configPath string, emit func(Event)) *SelfGuard {
	paths := []string{}
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, exe)
	}
	if configPath != "" {
		paths = append(paths, configPath)
	}
	paths = append(paths, cfg.WatchPaths...)

	guard := &SelfGuard{cfg: cfg, paths: paths, sums: map[string]string{}, emit: emit}
	for _, path := range paths {
		if sum, err := hashFile(path); err == nil {
			guard.sums[path] = sum
		}
	}
	return guard
}

// Started reports that the service has started. A restart you did not perform is
// an event in itself.
func (s *SelfGuard) Started(host string, sinks string) {
	s.emit(Event{
		At: time.Now(), Source: "self", Kind: "watch_started", Severity: SevInfo,
		Subject: host, Count: 1,
		Details: map[string]string{"sinks": sinks, "pid": strconv.Itoa(os.Getpid())},
	})
}

// Stopped reports the shutdown. If it was not you who stopped it, this is the
// most important event of the day.
func (s *SelfGuard) Stopped(reason string) {
	s.emit(Event{
		At: time.Now(), Source: "self", Kind: "watch_stopped", Severity: SevAlert,
		Subject: reason, Count: 1,
	})
}

// Heartbeat emits the sign of life with the head of the chain (the number of the
// last event and its hash) and the service counters. A number that went down or
// a hash that does not match means the state was tampered with; a zero count of
// received events means the service sees nothing.
func (s *SelfGuard) Heartbeat(seq uint64, head string, counters map[string]string) {
	details := map[string]string{
		"uptime_check": time.Now().Format(time.RFC3339),
		"chain_seq":    strconv.FormatUint(seq, 10),
		"chain_head":   head,
	}
	for name, value := range counters {
		details[name] = value
	}
	s.emit(Event{
		At: time.Now(), Source: "self", Kind: "heartbeat", Severity: SevInfo,
		Subject: "", Count: 1, Details: details,
	})
}

// Check compares its own files against the remembered hashes.
func (s *SelfGuard) Check() {
	for _, path := range s.paths {
		sum, err := hashFile(path)
		if err != nil {
			if _, had := s.sums[path]; had {
				s.emit(Event{
					At: time.Now(), Source: "self", Kind: "own_file_missing", Severity: SevAlert,
					Subject: path, Count: 1,
					Details: map[string]string{"error": err.Error()},
				})
				delete(s.sums, path)
			}
			continue
		}
		before, known := s.sums[path]
		if !known {
			s.sums[path] = sum
			continue
		}
		if before != sum {
			s.sums[path] = sum
			s.emit(Event{
				At: time.Now(), Source: "self", Kind: "own_file_changed", Severity: SevAlert,
				Subject: path, Count: 1,
				Details: map[string]string{"hint": "the watcher's own files were replaced"},
			})
		}
	}
}
