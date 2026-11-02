package watch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Events are grouped into one actor: instead of twenty separate records there is
// one score and one report when the score crosses the threshold.
func TestActorScoreAndThreshold(t *testing.T) {
	events := []Event{}
	store := NewActorStore(ActorsConfig{
		Enabled: true, AlertScore: 10,
		Weights: map[string]int{"trap_hit": 5, "path_scan": 2},
	}, t.TempDir(), func(e Event) { events = append(events, e) })

	for i := 0; i < 2; i++ {
		store.Observe(Event{At: time.Now(), IP: "203.0.113.4", Source: "access", Kind: "path_scan", Subject: "/x"})
	}
	if len(events) != 0 {
		t.Fatalf("below the threshold there is nothing to report: %+v", events)
	}

	store.Observe(Event{At: time.Now(), IP: "203.0.113.4", Source: "trap", Kind: "trap_hit", Subject: "/.env"})
	store.Observe(Event{At: time.Now(), IP: "203.0.113.4", Source: "access", Kind: "sqli_union", Subject: "/p?id=1"})

	if len(events) != 1 || events[0].Kind != "actor_threshold" {
		t.Fatalf("expected one actor report, got %+v", events)
	}
	if !strings.Contains(events[0].Details["kinds"], "trap_hit×1") {
		t.Errorf("the report lacks the breakdown by kind: %+v", events[0].Details)
	}
	// Further events do not raise the threshold report again.
	store.Observe(Event{At: time.Now(), IP: "203.0.113.4", Source: "trap", Kind: "trap_hit"})
	if len(events) != 1 {
		t.Errorf("an actor is reported once, not on every event: %+v", events)
	}
}

// The digest: who did how much over the period, most prominent first.
func TestActorDigest(t *testing.T) {
	events := []Event{}
	store := NewActorStore(ActorsConfig{Enabled: true, AlertScore: 1000, DigestInterval: Duration{time.Hour}},
		t.TempDir(), func(e Event) { events = append(events, e) })

	store.Observe(Event{At: time.Now(), IP: "203.0.113.1", Source: "access", Kind: "path_scan"})
	for i := 0; i < 5; i++ {
		store.Observe(Event{At: time.Now(), IP: "203.0.113.2", Source: "access", Kind: "path_scan"})
	}
	store.Digest()

	if len(events) != 1 || events[0].Kind != "digest" {
		t.Fatalf("no digest was emitted: %+v", events)
	}
	top := events[0].Details["top"]
	if !strings.HasPrefix(top, "203.0.113.2") {
		t.Errorf("the most prominent one must come first: %q", top)
	}
}

// The service's own actions do not belong to actors: otherwise blocks would
// raise their own score.
func TestActorIgnoresOwnActions(t *testing.T) {
	store := NewActorStore(ActorsConfig{Enabled: true, AlertScore: 1}, t.TempDir(), func(Event) {})
	store.Observe(Event{At: time.Now(), IP: "203.0.113.3", Source: "action", Kind: "ip_blocked"})
	store.Observe(Event{At: time.Now(), IP: "203.0.113.3", Source: "self", Kind: "heartbeat"})

	if len(store.Top(10)) != 0 {
		t.Fatalf("the service's own actions must not create an actor: %+v", store.Top(10))
	}
}

// Learning: while the learning period lasts the service stays silent and
// remembers; afterwards it reports a value that was not there before.
func TestBaselineLearnThenAlert(t *testing.T) {
	dir := t.TempDir()
	events := []Event{}
	base := NewBaseline(BaselineConfig{
		Enabled: true, LearnDays: 14, Features: []string{"country"}, Kinds: []string{"ssh_login"},
	}, dir, func(e Event) { events = append(events, e) })

	base.Observe(Event{Kind: "ssh_login", IP: "1.1.1.1", Details: map[string]string{"country": "UA"}})
	if len(events) != 0 {
		t.Fatalf("during learning there is nothing to report: %+v", events)
	}

	// Learning is over: wind the start time back.
	base.Started = time.Now().Add(-15 * 24 * time.Hour)
	base.Observe(Event{Kind: "ssh_login", IP: "1.1.1.1", Details: map[string]string{"country": "UA"}})
	if len(events) != 0 {
		t.Fatalf("a familiar value raises no alarm: %+v", events)
	}

	base.Observe(Event{Kind: "ssh_login", IP: "2.2.2.2", Details: map[string]string{"country": "CN"}})
	if len(events) != 1 || events[0].Kind != "first_time_country" {
		t.Fatalf("a new value must be reported: %+v", events)
	}
	if events[0].Subject != "CN" {
		t.Errorf("the wrong value: %+v", events[0])
	}
}

// What was learned survives a restart: otherwise every reboot would produce a
// stream of false "seen for the first time" reports.
func TestBaselineSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := BaselineConfig{Enabled: true, LearnDays: 0, Features: []string{"agent"}}
	first := NewBaseline(cfg, dir, func(Event) {})
	first.Started = time.Now().Add(-30 * 24 * time.Hour)
	first.Observe(Event{Kind: "x", Details: map[string]string{"agent": "curl/8.4"}})

	events := []Event{}
	second := NewBaseline(cfg, dir, func(e Event) { events = append(events, e) })
	second.Started = time.Now().Add(-30 * 24 * time.Hour)
	second.Observe(Event{Kind: "x", Details: map[string]string{"agent": "curl/8.4"}})

	if len(events) != 0 {
		t.Fatalf("after a restart a familiar value must not count as new: %+v", events)
	}
}

// Chain verification: an intact file is accepted, a file with a line cut out is
// rejected with the number of the record.
func TestVerifyFile(t *testing.T) {
	dir := t.TempDir()
	chain := NewChain(dir)
	path := filepath.Join(dir, "events.jsonl")
	sink := &FileSink{path: path}

	for i := 0; i < 5; i++ {
		event := chain.Stamp(Event{At: time.Now(), Source: "access", Kind: "path_scan", IP: "9.9.9.9", Count: 1})
		if err := sink.Send([]Event{event}); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyFile(path); err != nil {
		t.Fatalf("an intact file must pass verification: %v", err)
	}

	// Cut a line out, the way someone covering their tracks would.
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	cut := append(append([]string{}, lines[:2]...), lines[3:]...)
	os.WriteFile(path, []byte(strings.Join(cut, "\n")+"\n"), 0o640)

	if err := VerifyFile(path); err == nil {
		t.Fatalf("a cut-out line must be detected")
	}
}

// A response action runs only on command and only with a validated value.
func TestRunAction(t *testing.T) {
	events := []Event{}
	cfg := ActionsConfig{Enabled: true, Commands: map[string]string{"revoke-tokens": "echo revoked keys of %s"}}

	if err := RunAction(cfg, "revoke-tokens", "2648", func(e Event) { events = append(events, e) }); err != nil {
		t.Fatalf("the action must run: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "action_done" {
		t.Errorf("the action must be recorded as an event: %+v", events)
	}
	if err := RunAction(cfg, "unknown", "1", func(Event) {}); err == nil {
		t.Errorf("an undefined action must be rejected")
	}
	if err := RunAction(cfg, "revoke-tokens", "1; rm -rf /", func(Event) {}); err == nil {
		t.Errorf("a dangerous value must be rejected")
	}
	if err := RunAction(ActionsConfig{Enabled: false}, "revoke-tokens", "1", func(Event) {}); err == nil {
		t.Errorf("with actions disabled the command must not run")
	}
}

// An actor report must not feed back into that actor's score: otherwise the
// score would inflate itself.
func TestActorIgnoresOwnSummary(t *testing.T) {
	store := NewActorStore(ActorsConfig{Enabled: true, AlertScore: 1}, t.TempDir(), func(Event) {})
	store.Observe(Event{At: time.Now(), IP: "203.0.113.8", Source: "actor", Kind: "actor_threshold"})

	if len(store.Top(10)) != 0 {
		t.Fatalf("an actor report must not create an actor: %+v", store.Top(10))
	}
}
