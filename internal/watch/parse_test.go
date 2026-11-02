package watch

import (
	"testing"
	"time"
)

// Parsing a web server log line: the address, path and status code come from it,
// and without them there is nothing to count thresholds from.
func TestParseCombined(t *testing.T) {
	line := `172.68.75.160 - - [30/Oct/2026:22:13:00 +0100] "POST /api/payments HTTP/2.0" 404 153 "-" "Mozilla/5.0 (Windows NT 10.0)"`
	got := parseCombined(line)

	if !got.Valid {
		t.Fatalf("the line must parse: %+v", got)
	}
	if got.IP != "172.68.75.160" {
		t.Errorf("address: got %q", got.IP)
	}
	if got.Method != "POST" || got.Path != "/api/payments" {
		t.Errorf("request: got %q %q", got.Method, got.Path)
	}
	if got.Status != 404 {
		t.Errorf("status code: got %d", got.Status)
	}
	if got.Agent != "Mozilla/5.0 (Windows NT 10.0)" {
		t.Errorf("client: got %q", got.Agent)
	}
	if got.At.IsZero() {
		t.Errorf("the time was not parsed")
	}
}

// A foreign format must not bring the watcher down: the line is simply marked as
// unparsed.
func TestParseCombinedGarbage(t *testing.T) {
	for _, line := range []string{"", "garbage", `1.2.3.4 - -`} {
		if parseCombined(line).Valid {
			t.Errorf("the line %q must not count as parsed", line)
		}
	}
}

// Path scanning: the event is emitted exactly at the threshold and is not
// repeated for every following request.
func TestAccessWatcherPathScan(t *testing.T) {
	events := []Event{}
	watcher := NewAccessWatcher(AccessConfig{NotFoundPerMinute: 3, DeniedPerMinute: 99, RequestsPerMinute: 99},
		nil, func(e Event) { events = append(events, e) })

	at := time.Date(2026, 10, 30, 22, 13, 0, 0, time.UTC).Format("02/Jan/2006:15:04:05 -0700")
	for i := 0; i < 5; i++ {
		watcher.Handle(`9.9.9.9 - - [` + at + `] "POST /api/pay HTTP/1.1" 404 10 "-" "bot"`)
	}

	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].Kind != "path_scan" || events[0].Count != 3 || events[0].IP != "9.9.9.9" {
		t.Errorf("unexpected event: %+v", events[0])
	}
}

// A suspicious path is reported on its own, without any threshold.
func TestAccessWatcherSuspiciousPath(t *testing.T) {
	events := []Event{}
	watcher := NewAccessWatcher(AccessConfig{
		NotFoundPerMinute: 99, DeniedPerMinute: 99, RequestsPerMinute: 99,
		SuspiciousPaths: []string{"/.env", "/wp-login.php"},
	}, nil, func(e Event) { events = append(events, e) })

	watcher.Handle(`5.5.5.5 - - [30/Oct/2026:22:13:00 +0100] "GET /.env HTTP/1.1" 404 0 "-" "curl"`)

	if len(events) != 1 || events[0].Kind != "suspicious_path" {
		t.Fatalf("expected a suspicious path event, got: %+v", events)
	}
	if events[0].Subject != "/.env" {
		t.Errorf("event subject: %q", events[0].Subject)
	}
}

// A successful login from an unknown address gets the highest severity: this is
// what tells "they are knocking" apart from "they are already in".
func TestAuthWatcherLogin(t *testing.T) {
	events := []Event{}
	watcher := NewAuthWatcher(AuthConfig{FailuresPerMinute: 3, KnownIPs: []string{"10.0.0.1"}},
		func(e Event) { events = append(events, e) })

	watcher.Handle("Oct 30 22:00:01 srv sshd[1]: Accepted publickey for root from 203.0.113.9 port 5 ssh2: RSA SHA256:abc")
	watcher.Handle("Oct 30 22:00:02 srv sshd[1]: Accepted password for root from 10.0.0.1 port 5 ssh2")

	if len(events) != 2 {
		t.Fatalf("expected two events, got %d", len(events))
	}
	if events[0].Severity != SevAlert || events[0].IP != "203.0.113.9" {
		t.Errorf("login from an unknown address: %+v", events[0])
	}
	if events[1].Severity != SevInfo {
		t.Errorf("a login from a known address must be informational: %+v", events[1])
	}
}

// Password guessing: the event fires at the threshold and carries the number of
// attempts.
func TestAuthWatcherBruteforce(t *testing.T) {
	events := []Event{}
	watcher := NewAuthWatcher(AuthConfig{FailuresPerMinute: 2}, func(e Event) { events = append(events, e) })

	watcher.Handle("Oct 30 22:00:01 srv sshd[1]: Failed password for root from 198.51.100.7 port 5 ssh2")
	watcher.Handle("Oct 30 22:00:02 srv sshd[1]: Invalid user admin from 198.51.100.7")
	watcher.Handle("Oct 30 22:00:03 srv sshd[1]: Failed password for root from 198.51.100.7 port 5 ssh2")

	if len(events) != 1 {
		t.Fatalf("expected one event, got %d: %+v", len(events), events)
	}
	if events[0].Kind != "ssh_bruteforce" || events[0].Count != 2 {
		t.Errorf("unexpected event: %+v", events[0])
	}
}
