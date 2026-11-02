// Learning normal behaviour: what always happens on this server and what
// happened for the first time.
package watch

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

// BaselineConfig - learning settings.
type BaselineConfig struct {
	Enabled bool `json:"enabled"`
	// How many days to learn without reporting anything. During that time the
	// service finds out what is normal on this server.
	LearnDays int `json:"learn_days"`
	// Which features to track. They are taken from the event details -
	// country, agent, ptr, owner, tls_fingerprint - and from the event itself:
	// ip, subject.
	Features []string `json:"features"`
	// Event kinds to learn from. Empty means all of them.
	Kinds []string `json:"kinds"`
	// Severity of the report about a value seen for the first time.
	Severity Severity `json:"severity"`
}

// baselineEntry - one remembered feature value.
type baselineEntry struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

// Baseline remembers the feature values that are normal for this server and
// reports new ones. Learning runs for the configured number of days without
// events, after which the service reports values it has not seen before.
type Baseline struct {
	cfg     BaselineConfig
	mu      sync.Mutex
	path    string
	Started time.Time                            `json:"started"`
	Known   map[string]map[string]*baselineEntry `json:"known"`
	emit    func(Event)
}

// NewBaseline reads what has been accumulated.
func NewBaseline(cfg BaselineConfig, stateDir string, emit func(Event)) *Baseline {
	base := &Baseline{
		cfg:   cfg,
		path:  filepath.Join(stateDir, "baseline.json"),
		Known: map[string]map[string]*baselineEntry{},
		emit:  emit,
	}
	loadJSONState(base.path, base)
	if base.Started.IsZero() {
		base.Started = time.Now()
	}
	return base
}

// Observe takes the event into account and, once learning is over, reports what
// is new.
func (b *Baseline) Observe(event Event) {
	if !b.cfg.Enabled || len(b.cfg.Features) == 0 {
		return
	}
	if len(b.cfg.Kinds) > 0 {
		match := false
		for _, kind := range b.cfg.Kinds {
			if kind == event.Kind {
				match = true
				break
			}
		}
		if !match {
			return
		}
	}

	learnDays := b.cfg.LearnDays
	if learnDays <= 0 {
		learnDays = 14
	}
	learning := time.Since(b.Started) < time.Duration(learnDays)*24*time.Hour

	b.mu.Lock()
	newValues := map[string]string{}
	for _, feature := range b.cfg.Features {
		value := featureValue(event, feature)
		if value == "" {
			continue
		}
		bucket, has := b.Known[feature]
		if !has {
			bucket = map[string]*baselineEntry{}
			b.Known[feature] = bucket
		}
		entry, seen := bucket[value]
		if !seen {
			bucket[value] = &baselineEntry{FirstSeen: time.Now(), LastSeen: time.Now(), Count: 1}
			if !learning {
				newValues[feature] = value
			}
			continue
		}
		entry.Count++
		entry.LastSeen = time.Now()
	}
	b.save()
	b.mu.Unlock()

	severity := b.cfg.Severity
	if severity == "" {
		severity = SevWarn
	}
	for feature, value := range newValues {
		b.emit(Event{
			At: time.Now(), Source: "baseline", Kind: "first_time_" + feature, Severity: severity,
			IP: event.IP, Subject: sampleOf(value, 120), Count: 1,
			Details: map[string]string{
				"feature":     feature,
				"event_kind":  event.Kind,
				"learned_for": fmt.Sprintf("%d days", learnDays),
				"hint":        "this value has not been seen on this server before",
			},
		})
	}
}

// Learning reports whether learning is still going on (for the startup notice).
func (b *Baseline) Learning() (bool, time.Duration) {
	learnDays := b.cfg.LearnDays
	if learnDays <= 0 {
		learnDays = 14
	}
	passed := time.Since(b.Started)
	total := time.Duration(learnDays) * 24 * time.Hour
	return passed < total, total - passed
}

// featureValue pulls a feature value out of the event.
func featureValue(event Event, feature string) string {
	switch feature {
	case "ip":
		return event.IP
	case "subject":
		return event.Subject
	case "kind":
		return event.Kind
	default:
		return event.Details[feature]
	}
}

// save writes what has been accumulated.
func (b *Baseline) save() {
	saveJSONState(b.path, b, 0o600)
}
