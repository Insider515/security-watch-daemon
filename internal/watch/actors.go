// Actors: events are grouped by whoever caused them and given a score.
package watch

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ActorsConfig - settings for grouping events into actors.
type ActorsConfig struct {
	Enabled bool `json:"enabled"`
	// Weight of an event kind in the score. Anything not listed weighs 1.
	Weights map[string]int `json:"weights"`
	// The score at which a separate report about the actor is emitted.
	AlertScore int `json:"alert_score"`
	// How often to send the digest of what has accumulated.
	DigestInterval Duration `json:"digest_interval"`
	// How long to remember an actor with no new events.
	Forget Duration `json:"forget"`
}

// Actor holds what is known about one address: event kinds, event count, score,
// country, network owner, clients and fingerprints. The score makes addresses
// comparable with each other.
type Actor struct {
	IP          string         `json:"ip"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	Score       int            `json:"score"`
	Events      int            `json:"events"`
	Kinds       map[string]int `json:"kinds"`
	Subjects    []string       `json:"subjects"`
	Agents      []string       `json:"agents"`
	Fingerprint string         `json:"fingerprint"`
	Country     string         `json:"country"`
	Owner       string         `json:"owner"`
	Notified    bool           `json:"notified"`
}

// ActorStore accumulates actors and keeps them across restarts.
type ActorStore struct {
	cfg   ActorsConfig
	mu    sync.Mutex
	path  string
	items map[string]*Actor
	emit  func(Event)
}

// NewActorStore reads what has accumulated from disk.
func NewActorStore(cfg ActorsConfig, stateDir string, emit func(Event)) *ActorStore {
	store := &ActorStore{
		cfg:   cfg,
		path:  filepath.Join(stateDir, "actors.json"),
		items: map[string]*Actor{},
		emit:  emit,
	}
	loadJSONState(store.path, &store.items)
	return store
}

// Observe takes an event into account and reports the actor when it has just
// crossed the score threshold.
func (a *ActorStore) Observe(event Event) {
	if !a.cfg.Enabled || event.IP == "" || isPrivateIP(event.IP) {
		return
	}
	// The service's own actions (blocks, actor reports, the heartbeat) do not
	// belong to an actor: otherwise the score would inflate itself.
	if event.Source == "action" || event.Source == "self" || event.Source == "actor" {
		return
	}

	a.mu.Lock()
	actor, known := a.items[event.IP]
	if !known {
		actor = &Actor{IP: event.IP, FirstSeen: event.At, Kinds: map[string]int{}}
		a.items[event.IP] = actor
	}
	weight := 1
	if value, has := a.cfg.Weights[event.Kind]; has {
		weight = value
	}
	actor.LastSeen = event.At
	actor.Events++
	actor.Score += weight
	actor.Kinds[event.Kind]++
	actor.Subjects = appendUnique(actor.Subjects, sampleOf(event.Subject, 80), 15)
	actor.Agents = appendUnique(actor.Agents, event.Details["agent"], 5)
	if value := event.Details["tls_fingerprint"]; value != "" {
		actor.Fingerprint = value
	}
	if value := event.Details["country"]; value != "" {
		actor.Country = value
	}
	if value := event.Details["owner"]; value != "" {
		actor.Owner = value
	}

	threshold := a.cfg.AlertScore
	if threshold <= 0 {
		threshold = 50
	}
	notify := !actor.Notified && actor.Score >= threshold
	if notify {
		actor.Notified = true
	}
	snapshot := *actor
	a.save()
	a.mu.Unlock()

	if notify {
		a.emit(Event{
			At: time.Now(), Source: "actor", Kind: "actor_threshold", Severity: SevAlert,
			IP: snapshot.IP, Subject: describeActor(&snapshot), Count: snapshot.Events,
			Details: actorDetails(&snapshot),
		})
	}
}

// Digest sends the summary of what accumulated: who did what over the period.
func (a *ActorStore) Digest() {
	if !a.cfg.Enabled {
		return
	}
	a.mu.Lock()
	window := a.cfg.DigestInterval.Duration
	if window == 0 {
		window = time.Hour
	}
	cutoff := time.Now().Add(-window)
	active := []*Actor{}
	for _, actor := range a.items {
		if actor.LastSeen.After(cutoff) {
			copied := *actor
			active = append(active, &copied)
		}
	}
	a.mu.Unlock()

	if len(active) == 0 {
		return
	}
	sort.Slice(active, func(i, j int) bool { return active[i].Score > active[j].Score })

	lines := []string{}
	total := 0
	for i, actor := range active {
		total += actor.Events
		if i < 5 { // the five most prominent make it into the digest
			lines = append(lines, describeActor(actor))
		}
	}
	a.emit(Event{
		At: time.Now(), Source: "actor", Kind: "digest", Severity: SevInfo,
		Subject: fmt.Sprintf("over %s: %d actors, %d events", window, len(active), total),
		Count:   len(active),
		Details: map[string]string{"top": strings.Join(lines, " | ")},
	})
}

// Forget drops actors nothing has been heard about for a while.
func (a *ActorStore) Forget() {
	a.mu.Lock()
	defer a.mu.Unlock()
	keep := a.cfg.Forget.Duration
	if keep == 0 {
		keep = 7 * 24 * time.Hour
	}
	cutoff := time.Now().Add(-keep)
	for ip, actor := range a.items {
		if actor.LastSeen.Before(cutoff) {
			delete(a.items, ip)
		}
	}
	a.save()
}

// Top returns the prominent actors, highest score first.
func (a *ActorStore) Top(limit int) []*Actor {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*Actor, 0, len(a.items))
	for _, actor := range a.items {
		copied := *actor
		out = append(out, &copied)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// describeActor is the short line about an actor for the digest.
func describeActor(actor *Actor) string {
	kinds := make([]string, 0, len(actor.Kinds))
	for kind, count := range actor.Kinds {
		kinds = append(kinds, fmt.Sprintf("%s×%d", kind, count))
	}
	sort.Strings(kinds)
	place := actor.Country
	if actor.Owner != "" {
		place = strings.TrimSpace(place + " " + actor.Owner)
	}
	if place != "" {
		place = " (" + sampleOf(place, 40) + ")"
	}
	return fmt.Sprintf("%s%s score %d: %s", actor.IP, place, actor.Score, strings.Join(kinds, ", "))
}

// actorDetails builds the actor details for an event.
func actorDetails(actor *Actor) map[string]string {
	kinds := make([]string, 0, len(actor.Kinds))
	for kind, count := range actor.Kinds {
		kinds = append(kinds, fmt.Sprintf("%s×%d", kind, count))
	}
	sort.Strings(kinds)
	return map[string]string{
		"score":       strconv.Itoa(actor.Score),
		"events":      strconv.Itoa(actor.Events),
		"kinds":       strings.Join(kinds, ", "),
		"subjects":    sampleOf(strings.Join(actor.Subjects, " "), 300),
		"agents":      sampleOf(strings.Join(actor.Agents, " | "), 200),
		"fingerprint": actor.Fingerprint,
		"country":     actor.Country,
		"owner":       actor.Owner,
		"since":       actor.FirstSeen.Format(time.RFC3339),
	}
}

// save writes the actors to disk.
func (a *ActorStore) save() {
	saveJSONState(a.path, a.items, 0o600)
}
