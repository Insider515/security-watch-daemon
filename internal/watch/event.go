// A watcher event: what was noticed, where, and how important it is.
package watch

import (
	"encoding/json"
	"fmt"
	"time"
)

// Severity level. A separate type so that an arbitrary string cannot be used.
type Severity string

const (
	// SevInfo - noticed, but not an alarm by itself (key-based login, restart).
	SevInfo Severity = "info"
	// SevWarn - looks like an attempt, with no sign of success (brute force, scan).
	SevWarn Severity = "warn"
	// SevAlert - a sign that someone is already inside (new access key, changed
	// application file, password login from an unknown network).
	SevAlert Severity = "alert"
)

// Event is one observation record. The fields are the same for every source, so
// that a dashboard page and the emails do not have to parse each source its own
// way.
type Event struct {
	At       time.Time `json:"at"`
	Source   string    `json:"source"` // nginx, auth, files, db
	Kind     string    `json:"kind"`   // path_scan, ssh_failed, ...
	Severity Severity  `json:"severity"`
	// How bad this is for the server, as opposed to how sure the watcher is.
	// Filled in by the service once the event is enriched; it stays out of the
	// chain hash, so older event files still verify.
	Grade   Grade             `json:"grade,omitempty"`
	IP      string            `json:"ip"`      // the real address, when known
	Subject string            `json:"subject"` // path, user name, file
	Count   int               `json:"count"`   // how many times within the window
	Details map[string]string `json:"details"` // everything else, unparsed

	// Sequence number and hashes form the chain that shows whether something was
	// cut out of the log or replaced (see chain.go).
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Fingerprint is the key for merging repeats: the same source, kind, address and
// subject within the window count as one event.
func (e Event) Fingerprint() string {
	return fmt.Sprintf("%s|%s|%s|%s", e.Source, e.Kind, e.IP, e.Subject)
}

// String is the short form for the service log.
func (e Event) String() string {
	raw, _ := json.Marshal(e.Details)
	return fmt.Sprintf("[%s] %s/%s ip=%s subject=%q count=%d %s",
		e.Severity, e.Source, e.Kind, e.IP, e.Subject, e.Count, string(raw))
}
