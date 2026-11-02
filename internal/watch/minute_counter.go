// Per-minute event counting, shared by every watcher that needs thresholds.
package watch

import "time"

// minuteCounters holds the counters of one key (usually an address) for one
// minute. Shared by the web server log and the auth log.
type minuteCounters struct {
	minute int64
	values map[string]int
}

// minuteTracker keeps counters per key and clears stale ones.
type minuteTracker struct {
	buckets map[string]*minuteCounters
}

// newMinuteTracker creates the tracker.
func newMinuteTracker() *minuteTracker {
	return &minuteTracker{buckets: map[string]*minuteCounters{}}
}

// Add increments the named counter for the key and returns the new value. The
// count restarts when the minute changes.
func (m *minuteTracker) Add(key string, at time.Time, name string) int {
	minute := at.Unix() / 60
	bucket, known := m.buckets[key]
	if !known || bucket.minute != minute {
		bucket = &minuteCounters{minute: minute, values: map[string]int{}}
		m.buckets[key] = bucket
	}
	bucket.values[name]++
	return bucket.values[name]
}

// Sweep drops counters of past minutes: without it memory grows with every new
// address, and scanners bring thousands of them.
func (m *minuteTracker) Sweep(now time.Time) {
	minute := now.Unix() / 60
	for key, bucket := range m.buckets {
		if bucket.minute < minute-1 {
			delete(m.buckets, key)
		}
	}
}
