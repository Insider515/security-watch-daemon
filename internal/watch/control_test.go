package watch

import (
	"os"
	"strings"
	"testing"
	"time"
)

// An empty listing must be printed in words rather than as an empty table:
// otherwise it is unclear whether there is nothing to show or the command
// failed.
func TestControlEmptyListings(t *testing.T) {
	for name, action := range map[string]func(){
		"actors":    func() { printActors(nil) },
		"proposals": func() { printCandidates(nil) },
		"dossiers":  func() { printDossiers(nil) },
	} {
		if out := captureStdout(t, action); strings.TrimSpace(out) == "" {
			t.Errorf("%s: an empty listing was printed silently", name)
		}
	}
}

// The score, the event count and the time of the last sighting are what a
// blocking decision is based on, so they must appear in the printout.
func TestPrintActorsShowsScore(t *testing.T) {
	out := captureStdout(t, func() {
		printActors([]*Actor{{
			IP: "203.0.113.9", Score: 77, Events: 12,
			LastSeen: time.Date(2026, 11, 1, 12, 30, 0, 0, time.UTC),
			Kinds:    map[string]int{"path_scan": 12},
		}})
	})
	for _, want := range []string{"203.0.113.9", "77", "12", "2026-11-01"} {
		if !strings.Contains(out, want) {
			t.Errorf("the printout lacks %q: %s", want, out)
		}
	}
}

// A blocked address must be marked: otherwise the operator blocks it a second
// time.
func TestPrintCandidatesMarksBlocked(t *testing.T) {
	out := captureStdout(t, func() {
		printCandidates([]*BlockCandidate{
			{IP: "198.51.100.7", Count: 4, LastSeen: time.Now(), Reasons: []string{"ssh_bruteforce"}, Blocked: true},
			{IP: "198.51.100.8", Count: 1, LastSeen: time.Now(), Reasons: []string{"path_scan"}},
		})
	})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var blocked, plain string
	for _, line := range lines {
		if strings.Contains(line, "198.51.100.7") {
			blocked = line
		}
		if strings.Contains(line, "198.51.100.8") {
			plain = line
		}
	}
	if !strings.Contains(blocked, "blocked") {
		t.Errorf("the blocked mark was lost: %q", blocked)
	}
	if strings.Contains(plain, "blocked") {
		t.Errorf("an address that is not blocked was marked: %q", plain)
	}
}

// Asking for a dossier on an unknown address is not an error: the command must
// say there is no dossier and exit without failing.
func TestControlUnknownDossier(t *testing.T) {
	cfg := &Config{StateDir: t.TempDir()}
	cfg.applyDefaults()
	cfg.StateDir = t.TempDir()

	out := captureStdout(t, func() {
		if err := RunControlCommand(cfg, ControlRequest{Dossier: "203.0.113.1"}); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "203.0.113.1") {
		t.Errorf("the answer does not contain the requested address: %q", out)
	}
}

// Blocking while the setting is off must refuse with a clear reason instead of
// silently doing nothing.
func TestControlBlockDisabled(t *testing.T) {
	cfg := &Config{StateDir: t.TempDir()}
	cfg.applyDefaults()
	cfg.StateDir = t.TempDir()

	err := RunControlCommand(cfg, ControlRequest{Block: "203.0.113.9"})
	if err == nil {
		t.Fatal("a refusal was expected: blocking is disabled")
	}
	if !strings.Contains(err.Error(), "blocking.enabled") {
		t.Errorf("the reason for the refusal is unclear: %v", err)
	}
}

// The blocking command must run with the address substituted in and be
// remembered in the list, otherwise the next run shows the address as unblocked.
func TestControlBlockRunsCommand(t *testing.T) {
	dir := t.TempDir()
	mark := dir + "/blocked.txt"
	script := dir + "/blocker.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"$1\" >> "+mark+"\n"), 0o700); err != nil {
		t.Fatalf("preparing the command: %v", err)
	}
	cfg := &Config{
		StateDir: dir,
		Blocking: BlockingConfig{Enabled: true, Command: script + " %s"},
	}
	cfg.applyDefaults()

	out := captureStdout(t, func() {
		if err := RunControlCommand(cfg, ControlRequest{Block: "203.0.113.9"}); err != nil {
			t.Fatalf("blocking failed: %v", err)
		}
	})
	if !strings.Contains(out, "203.0.113.9") {
		t.Errorf("the block was not reported: %q", out)
	}
	if got := readFileString(t, mark); !strings.Contains(got, "203.0.113.9") {
		t.Errorf("the blocking command did not receive the address: %q", got)
	}

	listed := captureStdout(t, func() {
		if err := RunControlCommand(cfg, ControlRequest{Candidates: true}); err != nil {
			t.Fatalf("listing the proposals: %v", err)
		}
	})
	if !strings.Contains(listed, "blocked") {
		t.Errorf("the block was not remembered: %q", listed)
	}
}

// An unknown action must be refused by name: the response actions are defined by
// the operator, and a typo must not run a different one.
func TestControlUnknownAction(t *testing.T) {
	cfg := &Config{StateDir: t.TempDir()}
	cfg.applyDefaults()
	cfg.StateDir = t.TempDir()

	if err := RunControlCommand(cfg, ControlRequest{Action: "no-such-thing"}); err == nil {
		t.Fatal("a refusal was expected for an unknown action")
	}
}

// readFileString reads a file for a check or fails the test.
func readFileString(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(raw)
}
