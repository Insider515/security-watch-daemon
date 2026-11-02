// Merging repeats: a stream of identical events becomes one message carrying the
// number of repeats.
package watch

import (
	"strings"
	"sync"
	"time"
)

// Deduper remembers when an event with a given fingerprint was last sent and how
// many repeats have piled up since.
type Deduper struct {
	window time.Duration
	mu     sync.Mutex
	seen   map[string]*dedupState
	now    func() time.Time // replaced in tests
	// Sources and kinds whose subject is left out of the merge key. During path
	// scanning the subject (the request path) is different every time, so with
	// the subject in the key a scanner that walked 500 paths would produce 500
	// events instead of one with a repeat count.
	ignoreSubject map[string]bool
}

// dedupState is the state of one fingerprint.
type dedupState struct {
	lastSent   time.Time
	suppressed int
}

// NewDeduper creates the merger with the given window. ignoreSubject holds the
// entries whose subject is left out of the merge key: either a source
// ("access") or a source and kind ("access/path_scan").
func NewDeduper(window time.Duration, ignoreSubject []string) *Deduper {
	set := map[string]bool{}
	for _, entry := range ignoreSubject {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry != "" {
			set[entry] = true
		}
	}
	return &Deduper{window: window, seen: map[string]*dedupState{}, now: time.Now, ignoreSubject: set}
}

// key builds the merge key for an event. The subject is dropped when the event
// source or the source and kind pair is listed in ignoreSubject.
func (d *Deduper) key(e Event) string {
	if d.ignoreSubject[strings.ToLower(e.Source)] ||
		d.ignoreSubject[strings.ToLower(e.Source+"/"+e.Kind)] {
		return e.Source + "|" + e.Kind + "|" + e.IP
	}
	return e.Fingerprint()
}

// Offer decides whether to send the event now. The first event with a given
// fingerprint passes immediately, the following ones inside the window pile up;
// once the window has passed, one event goes out with the number of accumulated
// repeats in Count.
func (d *Deduper) Offer(e Event) (Event, bool) {
	key := d.key(e)
	now := d.now()

	d.mu.Lock()
	defer d.mu.Unlock()

	state, known := d.seen[key]
	if !known {
		d.seen[key] = &dedupState{lastSent: now}
		if e.Count == 0 {
			e.Count = 1
		}
		return e, true
	}
	if now.Sub(state.lastSent) < d.window {
		state.suppressed++
		return Event{}, false
	}
	repeats := state.suppressed + 1
	state.suppressed = 0
	state.lastSent = now
	if e.Count <= 1 {
		e.Count = repeats
	}
	if e.Details == nil {
		e.Details = map[string]string{}
	}
	e.Details["repeats_in_window"] = d.window.String()
	return e, true
}

// Forget drops fingerprints nothing has been heard about for a while: otherwise
// memory grows with every new scanner address.
func (d *Deduper) Forget(olderThan time.Duration) int {
	cutoff := d.now().Add(-olderThan)
	d.mu.Lock()
	defer d.mu.Unlock()
	removed := 0
	for key, state := range d.seen {
		if state.lastSent.Before(cutoff) {
			delete(d.seen, key)
			removed++
		}
	}
	return removed
}
