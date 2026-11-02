// Watching processes and outbound connections: this is what tells "they are
// knocking from outside" apart from "they are already working inside".
package watch

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// processInfo - what is known about a running process.
type processInfo struct {
	PID     int
	Exe     string // the real path to the program file
	Cmdline string
	Deleted bool // the program file was deleted from disk
}

// ProcessWatcher watches the set of processes and the outbound connections.
// It looks for:
//   - a program started from a temporary directory;
//   - a program whose file was deleted while the process keeps running;
//   - an outbound connection to an undeclared port.
type ProcessWatcher struct {
	cfg          ProcessConfig
	known        map[int]string // pid -> program path, to avoid repeating
	knownOutflow map[string]bool
	emit         func(Event)
	procRoot     string // replaced in tests
	netFiles     []string
}

// NewProcessWatcher creates the process watcher.
func NewProcessWatcher(cfg ProcessConfig, emit func(Event)) *ProcessWatcher {
	return &ProcessWatcher{
		cfg:          cfg,
		known:        map[int]string{},
		knownOutflow: map[string]bool{},
		emit:         emit,
		procRoot:     "/proc",
		netFiles:     []string{"/proc/net/tcp", "/proc/net/tcp6"},
	}
}

// Scan walks the processes and connections and emits events for what is new.
func (p *ProcessWatcher) Scan() {
	processes := p.readProcesses()
	if len(processes) == 0 {
		return // not Linux, or no access - stay silent
	}

	alive := map[int]bool{}
	for _, proc := range processes {
		alive[proc.PID] = true
		if previous, seen := p.known[proc.PID]; seen && previous == proc.Exe {
			continue
		}
		p.known[proc.PID] = proc.Exe

		if proc.Deleted {
			p.emit(Event{
				At: time.Now(), Source: "process", Kind: "deleted_binary", Severity: SevAlert,
				Subject: proc.Exe, Count: 1,
				Details: map[string]string{"pid": strconv.Itoa(proc.PID), "cmdline": sampleOf(proc.Cmdline, 200)},
			})
			continue
		}
		for _, dir := range p.cfg.SuspiciousDirs {
			if dir != "" && strings.HasPrefix(proc.Exe, dir) {
				p.emit(Event{
					At: time.Now(), Source: "process", Kind: "process_from_temp", Severity: SevAlert,
					Subject: proc.Exe, Count: 1,
					Details: map[string]string{"pid": strconv.Itoa(proc.PID), "cmdline": sampleOf(proc.Cmdline, 200)},
				})
				break
			}
		}
	}
	for pid := range p.known {
		if !alive[pid] {
			delete(p.known, pid)
		}
	}

	p.scanOutbound()
}

// scanOutbound looks for outbound connections to undeclared ports.
func (p *ProcessWatcher) scanOutbound() {
	if len(p.cfg.AllowedOutboundPorts) == 0 {
		return // without a list of allowed ports everything would be reported
	}
	allowed := map[int]bool{}
	for _, port := range p.cfg.AllowedOutboundPorts {
		allowed[port] = true
	}

	for _, path := range p.netFiles {
		for _, conn := range establishedConnections(path) {
			if allowed[conn.RemotePort] || isPrivateIP(conn.RemoteIP) {
				continue
			}
			key := conn.RemoteIP + ":" + strconv.Itoa(conn.RemotePort)
			if p.knownOutflow[key] {
				continue
			}
			p.knownOutflow[key] = true
			p.emit(Event{
				At: time.Now(), Source: "process", Kind: "outbound_connection", Severity: SevWarn,
				IP: conn.RemoteIP, Subject: key, Count: 1,
				Details: map[string]string{"local_port": strconv.Itoa(conn.LocalPort)},
			})
		}
	}
}

// readProcesses collects process information from /proc.
func (p *ProcessWatcher) readProcesses() []processInfo {
	entries, err := os.ReadDir(p.procRoot)
	if err != nil {
		return nil
	}
	out := []processInfo{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join(p.procRoot, entry.Name(), "exe"))
		if err != nil {
			continue // the process has already exited, or it belongs to someone else
		}
		info := processInfo{PID: pid, Exe: exe}
		// The kernel marks a deleted program file with a " (deleted)" suffix.
		if strings.HasSuffix(exe, " (deleted)") {
			info.Deleted = true
			info.Exe = strings.TrimSuffix(exe, " (deleted)")
		}
		if raw, err := os.ReadFile(filepath.Join(p.procRoot, entry.Name(), "cmdline")); err == nil {
			info.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
		}
		out = append(out, info)
	}
	return out
}
