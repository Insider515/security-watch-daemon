// Reading the auditd log: program starts with their command lines and access to
// canary files. Neither walking /proc nor subscribing to file changes shows
// this.
package watch

import (
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AuditConfig - watching the auditd log.
type AuditConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
	// Keys of the auditd rules that cover program execution.
	ExecKeys []string `json:"exec_keys"`
	// Keys of the rules that cover reading canary files.
	CanaryKeys []string `json:"canary_keys"`
}

var (
	reAuditEventID = regexp.MustCompile(`msg=audit\([\d.]+:(\d+)\)`)
	reAuditTime    = regexp.MustCompile(`msg=audit\(([\d.]+):\d+\)`)
	reAuditKey     = regexp.MustCompile(`key="?([\w-]+)"?`)
	reAuditType    = regexp.MustCompile(`type=(\w+)`)
	reAuditExe     = regexp.MustCompile(`exe="([^"]+)"`)
	reAuditComm    = regexp.MustCompile(`comm="([^"]+)"`)
	reAuditName    = regexp.MustCompile(`name="([^"]+)"`)
	reAuditCwd     = regexp.MustCompile(`cwd="([^"]+)"`)
	reAuditTTY     = regexp.MustCompile(`tty=(\S+)`)
	reAuditSuccess = regexp.MustCompile(`success=(\w+)`)
	reAuditUID     = regexp.MustCompile(`\buid=(\d+)`)
	reAuditAUID    = regexp.MustCompile(`\bauid=(\d+)`)
	reAuditPID     = regexp.MustCompile(`\bpid=(\d+)`)
	reAuditPPID    = regexp.MustCompile(`\bppid=(\d+)`)
	reAuditArgs    = regexp.MustCompile(`a\d+="([^"]*)"`)
	reAuditHexArg  = regexp.MustCompile(`a\d+=([0-9A-F]{4,})`)
)

// AuditWatcher parses auditd log lines. The auditd rules are installed
// separately (see docs-auditd.md): one for program execution, one for reading
// the canary file. The service does not install rules.
type AuditWatcher struct {
	cfg        AuditConfig
	execKeys   map[string]bool
	canaryKeys map[string]bool
	emit       func(Event)

	// The kernel writes the records of one event as several lines sharing an id:
	// SYSCALL has the user and the program, EXECVE the command line, PATH the
	// file. Lines pile up by id and are parsed together.
	mu      sync.Mutex
	pending map[string]*auditGroup
}

// auditGroup holds the lines of one kernel event, collected by their shared id.
type auditGroup struct {
	id        string
	at        time.Time
	key       string
	exe       string
	comm      string
	uid       string
	auid      string
	pid       string
	ppid      string
	cwd       string
	tty       string
	success   string
	args      []string
	paths     []string
	types     map[string]bool
	collected time.Time
}

// NewAuditWatcher creates the auditd log watcher.
func NewAuditWatcher(cfg AuditConfig, emit func(Event)) *AuditWatcher {
	toSet := func(values []string) map[string]bool {
		out := map[string]bool{}
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value != "" {
				out[value] = true
			}
		}
		return out
	}
	execKeys := toSet(cfg.ExecKeys)
	if len(execKeys) == 0 {
		execKeys["sw_exec"] = true
	}
	canaryKeys := toSet(cfg.CanaryKeys)
	if len(canaryKeys) == 0 {
		canaryKeys["sw_canary"] = true
	}
	return &AuditWatcher{
		cfg: cfg, execKeys: execKeys, canaryKeys: canaryKeys, emit: emit,
		pending: map[string]*auditGroup{},
	}
}

// Handle parses a log line and adds it to the group of its event.
func (a *AuditWatcher) Handle(line string) {
	if line == "" {
		return
	}
	id := firstGroup(reAuditEventID, line)
	if id == "" {
		return
	}

	a.mu.Lock()
	group, known := a.pending[id]
	if !known {
		group = &auditGroup{id: id, collected: time.Now(), types: map[string]bool{}}
		if seconds := firstGroup(reAuditTime, line); seconds != "" {
			if value, err := strconv.ParseFloat(seconds, 64); err == nil {
				group.at = time.Unix(int64(value), 0)
			}
		}
		a.pending[id] = group
	}
	group.absorb(line)
	// The kernel does not always close an event with an EOE record, so groups
	// also mature by time (see Flush), and the group limit protects memory.
	ready := group.types["EOE"] || len(a.pending) > 500
	a.mu.Unlock()

	if ready {
		a.flushOne(id)
	}
}

// absorb takes the facts from the next line into the group.
func (g *auditGroup) absorb(line string) {
	recordType := firstGroup(reAuditType, line)
	if recordType != "" {
		g.types[recordType] = true
	}
	set := func(target *string, value string) {
		if value != "" && *target == "" {
			*target = value
		}
	}
	if key := firstGroup(reAuditKey, line); key != "" {
		g.key = key
	}
	set(&g.exe, firstGroup(reAuditExe, line))
	set(&g.comm, firstGroup(reAuditComm, line))
	set(&g.uid, firstGroup(reAuditUID, line))
	set(&g.auid, firstGroup(reAuditAUID, line))
	set(&g.pid, firstGroup(reAuditPID, line))
	set(&g.ppid, firstGroup(reAuditPPID, line))
	set(&g.cwd, firstGroup(reAuditCwd, line))
	set(&g.tty, firstGroup(reAuditTTY, line))
	set(&g.success, firstGroup(reAuditSuccess, line))

	if recordType == "EXECVE" {
		if command := auditCommand(line); command != "" {
			g.args = append(g.args, command)
		}
	}
	if recordType == "PATH" || recordType == "CWD" {
		if name := firstGroup(reAuditName, line); name != "" {
			g.paths = appendUnique(g.paths, name, 10)
		}
	}
}

// Flush releases the groups the kernel writes nothing more about.
func (a *AuditWatcher) Flush(olderThan time.Duration) {
	a.mu.Lock()
	ready := []string{}
	cutoff := time.Now().Add(-olderThan)
	for id, group := range a.pending {
		if group.collected.Before(cutoff) {
			ready = append(ready, id)
		}
	}
	a.mu.Unlock()
	for _, id := range ready {
		a.flushOne(id)
	}
}

// flushOne releases one collected group as an event.
func (a *AuditWatcher) flushOne(id string) {
	a.mu.Lock()
	group, known := a.pending[id]
	if known {
		delete(a.pending, id)
	}
	a.mu.Unlock()
	if !known || group.key == "" {
		return
	}

	at := group.at
	if at.IsZero() {
		at = time.Now()
	}
	details := map[string]string{
		"pid": group.pid, "ppid": group.ppid, "uid": group.uid, "auid": group.auid,
		"cwd": group.cwd, "tty": group.tty, "comm": group.comm, "success": group.success,
	}
	if len(group.paths) > 0 {
		details["paths"] = strings.Join(group.paths, " ")
	}
	if len(group.args) > 0 {
		details["cmdline"] = sampleOf(strings.Join(group.args, " "), 300)
	}
	for name, value := range details {
		if value == "" {
			delete(details, name)
		}
	}

	switch {
	case a.canaryKeys[group.key]:
		subject := group.exe
		if len(group.paths) > 0 {
			subject = group.paths[0]
		}
		a.emit(Event{
			At: at, Source: "audit", Kind: "canary_file_read", Severity: SevAlert,
			Subject: subject, Count: 1, Details: details,
		})
	case a.execKeys[group.key]:
		severity, kind := SevInfo, "process_exec"
		if strings.HasPrefix(group.exe, "/tmp/") || strings.HasPrefix(group.exe, "/dev/shm/") ||
			strings.HasPrefix(group.exe, "/var/tmp/") {
			severity, kind = SevAlert, "process_exec_from_temp"
		}
		a.emit(Event{
			At: at, Source: "audit", Kind: kind, Severity: severity,
			Subject: group.exe, Count: 1, Details: details,
		})
	}
}

// auditCommand assembles the command line from an EXECVE record. auditd writes
// the arguments one by one (a0, a1, ...) and non-printable ones as hex.
func auditCommand(line string) string {
	if typeMatch := reAuditType.FindStringSubmatch(line); typeMatch != nil && typeMatch[1] != "EXECVE" {
		// Other records have no command line, so return what there is.
		if name := firstGroup(reAuditName, line); name != "" {
			return name
		}
	}
	parts := []string{}
	for _, match := range reAuditArgs.FindAllStringSubmatch(line, -1) {
		parts = append(parts, match[1])
	}
	for _, match := range reAuditHexArg.FindAllStringSubmatch(line, -1) {
		if decoded, err := hex.DecodeString(match[1]); err == nil {
			parts = append(parts, string(decoded))
		}
	}
	return strings.Join(parts, " ")
}

// firstGroup returns the first capture group of the pattern, or an empty
// string.
func firstGroup(expression *regexp.Regexp, line string) string {
	if match := expression.FindStringSubmatch(line); match != nil {
		return match[1]
	}
	return ""
}
