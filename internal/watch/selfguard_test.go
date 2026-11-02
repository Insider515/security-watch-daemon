package watch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Replacement of the service's own file is noticed: this is the first thing
// whoever broke in with root privileges does.
func TestSelfGuardDetectsOwnFileChange(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	os.WriteFile(configPath, []byte(`{"host":"srv"}`), 0o640)

	events := []Event{}
	guard := NewSelfGuard(SelfGuardConfig{}, configPath, func(e Event) { events = append(events, e) })

	guard.Check()
	if len(events) != 0 {
		t.Fatalf("with no changes there must be no events: %+v", events)
	}

	os.WriteFile(configPath, []byte(`{"host":"replaced"}`), 0o640)
	guard.Check()

	if len(events) != 1 || events[0].Kind != "own_file_changed" || events[0].Severity != SevAlert {
		t.Fatalf("the configuration replacement was not noticed: %+v", events)
	}
}

// The disappearance of its own file is an event of the highest severity too.
func TestSelfGuardDetectsOwnFileMissing(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	os.WriteFile(configPath, []byte(`{}`), 0o640)

	events := []Event{}
	guard := NewSelfGuard(SelfGuardConfig{}, configPath, func(e Event) { events = append(events, e) })
	os.Remove(configPath)
	guard.Check()

	if len(events) != 1 || events[0].Kind != "own_file_missing" {
		t.Fatalf("the missing configuration was not noticed: %+v", events)
	}
}

// The shutdown is reported with the highest severity: if it was not you who
// stopped it, this is the event of the day.
func TestSelfGuardStartStop(t *testing.T) {
	events := []Event{}
	guard := NewSelfGuard(SelfGuardConfig{}, "", func(e Event) { events = append(events, e) })

	guard.Started("srv", "telegram+file")
	guard.Heartbeat(42, "abc123", map[string]string{"sent": "7"})
	guard.Stopped("terminated")

	if len(events) != 3 {
		t.Fatalf("expected three events, got %d", len(events))
	}
	if events[0].Kind != "watch_started" || events[1].Kind != "heartbeat" {
		t.Errorf("unexpected events: %+v", events)
	}
	// The head of the chain goes off the host: by it the receiving side sees
	// whether the log on the server was rewritten after the fact.
	if events[1].Details["chain_seq"] != "42" || events[1].Details["chain_head"] != "abc123" {
		t.Errorf("the chain head did not go out with the heartbeat: %+v", events[1].Details)
	}
	if events[2].Kind != "watch_stopped" || events[2].Severity != SevAlert {
		t.Errorf("the shutdown must be an alarm: %+v", events[2])
	}
}

// failingSink is a sink that refuses a given number of times. It is guarded by a
// mutex: in the retry test a separate goroutine talks to it.
type failingSink struct {
	mu       sync.Mutex
	failures int
	got      []Event
}

func (f *failingSink) Send(events []Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures > 0 {
		f.failures--
		return errors.New("network unavailable")
	}
	f.got = append(f.got, events...)
	return nil
}

// delivered reports how many events arrived (for checks from another goroutine).
func (f *failingSink) delivered() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func (f *failingSink) Name() string { return "test" }

// An event that could not go out because the link was down is not lost and goes
// out later: that is what the queue is for - the link gets cut exactly at the
// wrong minute.
func TestOutboxKeepsEventsUntilDelivered(t *testing.T) {
	dir := t.TempDir()
	inner := &failingSink{failures: 1}
	outbox := NewOutbox(inner, dir, 100)

	event := Event{At: time.Now(), Source: "self", Kind: "watch_stopped", Severity: SevAlert}
	if err := outbox.Send([]Event{event}); err == nil {
		t.Fatalf("the first delivery should have failed")
	}
	if len(inner.got) != 0 {
		t.Fatalf("on a refusal the sink receives nothing")
	}

	// The link is back: what was deferred goes out.
	outbox.flush()
	if len(inner.got) != 1 || inner.got[0].Kind != "watch_stopped" {
		t.Fatalf("the deferred event was not delivered: %+v", inner.got)
	}
	if _, err := os.Stat(outbox.path); !os.IsNotExist(err) {
		t.Errorf("the queue must be cleared after delivery")
	}
}

// The chain: the numbers run consecutively, and replacing or cutting out a line
// breaks it.
func TestChainDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	chain := NewChain(dir)

	events := []Event{}
	for i := 0; i < 4; i++ {
		events = append(events, chain.Stamp(Event{
			At: time.Now(), Source: "access", Kind: "path_scan", IP: "9.9.9.9", Count: 1,
		}))
	}
	if broken := VerifyChain(events); broken != 0 {
		t.Fatalf("an intact chain must not count as corrupted (number %d)", broken)
	}

	// A line was cut out of the middle.
	cut := []Event{events[0], events[2], events[3]}
	if VerifyChain(cut) == 0 {
		t.Errorf("a cut-out event must be detected")
	}

	// The contents of an event were replaced.
	events[2].Subject = "replaced"
	if VerifyChain(events) == 0 {
		t.Errorf("a replaced event must be detected")
	}
}

// The chain continues after a service restart: the numbers do not start over.
func TestChainSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	first := NewChain(dir)
	one := first.Stamp(Event{At: time.Now(), Source: "self", Kind: "heartbeat"})

	second := NewChain(dir)
	two := second.Stamp(Event{At: time.Now(), Source: "self", Kind: "heartbeat"})

	if two.Seq != one.Seq+1 {
		t.Errorf("after a restart the number must continue: was %d, became %d", one.Seq, two.Seq)
	}
	if two.PrevHash != one.Hash {
		t.Errorf("the hash of the previous event was not kept")
	}
}

// The event log is rotated by the service itself: an external logrotate is not
// installed everywhere, and an unrotated log eventually fills the disk.
func TestFileSinkRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	sink := &FileSink{path: path, maxSize: 1024, keep: 2}

	long := strings.Repeat("x", 200)
	for i := 0; i < 40; i++ {
		if err := sink.Send([]Event{{At: time.Now(), Source: "access", Kind: "path_scan", Subject: long}}); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("the log should have been rotated: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 4096 {
		t.Errorf("the active piece of the log is too large: %d bytes", info.Size())
	}
	// Only the configured number of pieces is kept, no more.
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Errorf("surplus pieces must be removed")
	}
}
