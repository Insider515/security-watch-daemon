package watch

import (
	"fmt"
	"testing"
	"time"
)

// Merging repeats: the first event passes immediately, the following ones inside
// the window pile up, and after the window one event goes out with the repeat
// count.
func TestDeduperWindow(t *testing.T) {
	clock := time.Date(2026, 10, 30, 22, 0, 0, 0, time.UTC)
	deduper := NewDeduper(10*time.Minute, nil)
	deduper.now = func() time.Time { return clock }

	event := Event{Source: "access", Kind: "path_scan", IP: "9.9.9.9", Subject: "/x"}

	if _, send := deduper.Offer(event); !send {
		t.Fatalf("the first event must pass")
	}
	for i := 0; i < 5; i++ {
		clock = clock.Add(time.Minute)
		if _, send := deduper.Offer(event); send {
			t.Fatalf("a repeat inside the window must not pass")
		}
	}
	clock = clock.Add(10 * time.Minute)
	got, send := deduper.Offer(event)
	if !send {
		t.Fatalf("after the window the event must pass")
	}
	if got.Count != 6 {
		t.Errorf("expected 6 accumulated repeats, got %d", got.Count)
	}
}

// Different addresses are counted separately: a stream from one host must not
// hide another.
func TestDeduperDifferentKeys(t *testing.T) {
	deduper := NewDeduper(time.Hour, nil)
	first := Event{Source: "access", Kind: "path_scan", IP: "1.1.1.1"}
	second := Event{Source: "access", Kind: "path_scan", IP: "2.2.2.2"}

	if _, send := deduper.Offer(first); !send {
		t.Fatalf("the first event must pass")
	}
	if _, send := deduper.Offer(second); !send {
		t.Fatalf("an event from another address must pass")
	}
}

// Forgetting old fingerprints: otherwise memory grows with every new address.
func TestDeduperForget(t *testing.T) {
	clock := time.Date(2026, 10, 30, 22, 0, 0, 0, time.UTC)
	deduper := NewDeduper(time.Minute, nil)
	deduper.now = func() time.Time { return clock }

	deduper.Offer(Event{Source: "access", Kind: "path_scan", IP: "3.3.3.3"})
	clock = clock.Add(48 * time.Hour)

	if removed := deduper.Forget(24 * time.Hour); removed != 1 {
		t.Errorf("expected one forgotten entry, got %d", removed)
	}
}

// The defect this fixes: during path scanning the subject is different every
// time, so with the subject in the merge key one scanner produced an event per
// path. For the sources listed in dedup_ignore_subject the subject is left out
// of the key, and a scan becomes one event with a repeat count.
func TestDeduperIgnoresSubjectForScans(t *testing.T) {
	clock := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	deduper := NewDeduper(10*time.Minute, []string{"access", "trap"})
	deduper.now = func() time.Time { return clock }

	passed := 0
	for i := 0; i < 50; i++ {
		event := Event{
			Source: "access", Kind: "suspicious_path", IP: "203.0.113.77",
			Subject: fmt.Sprintf("/wp-admin/%d.php", i),
		}
		if _, send := deduper.Offer(event); send {
			passed++
		}
		clock = clock.Add(time.Second)
	}

	if passed != 1 {
		t.Fatalf("a scan of 50 paths must produce one event, got %d", passed)
	}

	// After the window one event goes out carrying the number of repeats.
	clock = clock.Add(10 * time.Minute)
	got, send := deduper.Offer(Event{
		Source: "access", Kind: "suspicious_path", IP: "203.0.113.77", Subject: "/wp-admin/51.php",
	})
	if !send {
		t.Fatal("after the window the event must pass")
	}
	if got.Count != 50 {
		t.Errorf("expected 50 accumulated repeats, got %d", got.Count)
	}
}

// The subject must stay in the key where it identifies the thing itself: two
// changed files are two different events, not a repeat.
func TestDeduperKeepsSubjectForFiles(t *testing.T) {
	deduper := NewDeduper(time.Hour, []string{"access", "trap", "mirror"})

	first := Event{Source: "files", Kind: "file_changed", Subject: "/etc/nginx/nginx.conf"}
	second := Event{Source: "files", Kind: "file_changed", Subject: "/root/.ssh/authorized_keys"}

	if _, send := deduper.Offer(first); !send {
		t.Fatal("the first changed file must pass")
	}
	if _, send := deduper.Offer(second); !send {
		t.Fatal("a change of another file must pass as a separate event")
	}
}

// A single kind can be listed as "source/kind" when the rest of the source must
// keep its subject in the key.
func TestDeduperIgnoresSubjectForOneKind(t *testing.T) {
	deduper := NewDeduper(time.Hour, []string{"db/row_added"})

	added := func(subject string) Event {
		return Event{Source: "db", Kind: "row_added", Subject: subject}
	}
	if _, send := deduper.Offer(added("users id=1")); !send {
		t.Fatal("the first event must pass")
	}
	if _, send := deduper.Offer(added("users id=2")); send {
		t.Error("for the listed kind the subject must be out of the key")
	}
	if _, send := deduper.Offer(Event{Source: "db", Kind: "column_changed", Subject: "users id=1"}); !send {
		t.Error("another kind of the same source must keep its subject in the key")
	}
	if _, send := deduper.Offer(Event{Source: "db", Kind: "column_changed", Subject: "users id=2"}); !send {
		t.Error("a different subject of that kind must pass as a separate event")
	}
}

// The defaults cover the sources whose subject is a request path.
func TestDedupIgnoreSubjectDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()

	want := map[string]bool{"access": true, "trap": true, "mirror": true}
	if len(cfg.DedupIgnoreSubject) != len(want) {
		t.Fatalf("defaults: %v", cfg.DedupIgnoreSubject)
	}
	for _, entry := range cfg.DedupIgnoreSubject {
		if !want[entry] {
			t.Errorf("unexpected entry in the defaults: %q", entry)
		}
	}
}
