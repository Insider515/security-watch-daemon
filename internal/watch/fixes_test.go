package watch

import (
	"errors"
	"fmt"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The defect this fixes: an event born while another one was being processed
// (an actor report, for example) landed in the file before the one that caused
// it, and -verify then reported a break in the chain numbering. Events now go
// through a queue and are processed one at a time, so the numbers in the file
// run in order.
func TestChainOrderWithNestedEvents(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{StateDir: dir}
	cfg.Sinks.File = filepath.Join(dir, "events.jsonl")
	cfg.Actors.Enabled = true
	cfg.Actors.AlertScore = 2
	cfg.applyDefaults()
	cfg.StateDir = dir

	service, err := NewService(cfg, "")
	if err != nil {
		t.Fatalf("assembling the service: %v", err)
	}

	// Two events from one address are enough to cross the actor threshold, so
	// the actor report is born while the second event is being processed. The
	// kinds differ on purpose: two identical ones would be merged as repeats.
	service.emit(Event{
		At: time.Now(), Source: "trap", Kind: "trap_hit", Severity: SevAlert,
		IP: "203.0.113.77", Subject: "/.env.bak", Count: 1,
	})
	service.emit(Event{
		At: time.Now(), Source: "access", Kind: "sqli_union", Severity: SevAlert,
		IP: "203.0.113.77", Subject: "/news?id=1 union select 1", Count: 1,
	})
	service.Close()

	if err := VerifyFile(cfg.Sinks.File); err != nil {
		t.Fatalf("the chain in the file must be intact: %v", err)
	}
	raw, err := os.ReadFile(cfg.Sinks.File)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "actor_threshold") {
		t.Fatalf("the nested event did not reach the file: %q", string(raw))
	}
}

// The queue must not lose events: everything emitted is processed, including
// what was emitted while processing.
func TestQueueDeliversEveryEvent(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{StateDir: dir}
	cfg.Sinks.File = filepath.Join(dir, "events.jsonl")
	cfg.applyDefaults()
	cfg.StateDir = dir

	service, err := NewService(cfg, "")
	if err != nil {
		t.Fatalf("assembling the service: %v", err)
	}
	for i := 0; i < 20; i++ {
		service.emit(Event{
			Source: "files", Kind: "file_changed", Severity: SevAlert,
			Subject: filepath.Join("/opt/app", string(rune('a'+i))), Count: 1,
		})
	}
	service.Close()

	raw, err := os.ReadFile(cfg.Sinks.File)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(strings.TrimSpace(string(raw)), "\n") + 1; got != 20 {
		t.Fatalf("expected 20 events in the file, got %d", got)
	}
}

// A watcher may emit more events than the queue holds: the first pass over a
// directory after a mass update gives thousands of them. The processing
// goroutine runs for the whole lifetime of the service, so the watcher waits for
// the reader instead of deadlocking.
func TestQueueOverflowDoesNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{StateDir: dir}
	cfg.Sinks.File = filepath.Join(dir, "events.jsonl")
	cfg.applyDefaults()
	cfg.StateDir = dir

	service, err := NewService(cfg, "")
	if err != nil {
		t.Fatalf("assembling the service: %v", err)
	}

	const total = 10050 // more than the queue holds
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < total; i++ {
			service.emit(Event{
				Source: "files", Kind: "file_changed", Severity: SevAlert,
				Subject: fmt.Sprintf("/opt/app/file-%d.js", i), Count: 1,
			})
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the watcher is stuck: the queue is full and nobody reads it")
	}
	service.Close()

	raw, err := os.ReadFile(cfg.Sinks.File)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "\n"); got != total {
		t.Fatalf("every event must reach the file: %d of %d", got, total)
	}
}

// The shutdown event must reach the sinks: it is emitted after the context is
// cancelled, when the processing goroutine is already winding down.
func TestStoppedEventReachesSink(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{StateDir: dir}
	cfg.Sinks.File = filepath.Join(dir, "events.jsonl")
	cfg.Self.Enabled = true
	cfg.applyDefaults()
	cfg.StateDir = dir

	service, err := NewService(cfg, "")
	if err != nil {
		t.Fatalf("assembling the service: %v", err)
	}
	service.Stopped("received a stop signal")
	service.Close()

	raw, err := os.ReadFile(cfg.Sinks.File)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "watch_stopped") {
		t.Fatalf("the shutdown event did not reach the file: %q", string(raw))
	}
}

// The defect this fixes: a column named like a reserved word of the DBMS (key,
// order, group) made the query fail with a syntax error. The identifiers are
// now quoted, differently for MySQL and PostgreSQL.
func TestColumnWatcherQuotesIdentifiers(t *testing.T) {
	mysql := NewColumnWatcher(nil, nil, t.TempDir(), "mysql", func(Event) {})
	if got := mysql.quoted("key"); got != "`key`" {
		t.Errorf("MySQL quoting: %q", got)
	}
	postgres := NewColumnWatcher(nil, nil, t.TempDir(), "postgres", func(Event) {})
	if got := postgres.quoted("order"); got != `"order"` {
		t.Errorf("PostgreSQL quoting: %q", got)
	}
	// An empty driver means MySQL, as in the rest of the service.
	byDefault := NewColumnWatcher(nil, nil, t.TempDir(), "", func(Event) {})
	if got := byDefault.quoted("group"); got != "`group`" {
		t.Errorf("default quoting: %q", got)
	}
}

// The defect this fixes: known_ips only understood exact addresses, so with a
// provider address that changes your own login kept raising an alarm. Networks
// in CIDR form are now understood.
func TestAuthWatcherKnownNetworks(t *testing.T) {
	events := []Event{}
	watcher := NewAuthWatcher(AuthConfig{
		FailuresPerMinute: 5,
		KnownIPs:          []string{"203.0.113.9", "188.129.64.0/18", "2001:db8::/32"},
	}, func(e Event) { events = append(events, e) })

	for _, line := range []string{
		"Nov  2 10:00:01 srv sshd[1]: Accepted publickey for root from 203.0.113.9 port 5 ssh2",
		"Nov  2 10:00:02 srv sshd[1]: Accepted publickey for root from 188.129.78.23 port 5 ssh2",
		"Nov  2 10:00:03 srv sshd[1]: Accepted publickey for root from 2001:db8::1234 port 5 ssh2",
		"Nov  2 10:00:04 srv sshd[1]: Accepted publickey for root from 45.198.224.51 port 5 ssh2",
	} {
		watcher.Handle(line)
	}

	if len(events) != 4 {
		t.Fatalf("expected four logins, got %d", len(events))
	}
	for i, event := range events[:3] {
		if event.Severity != SevInfo || event.Details["known_ip"] != "yes" {
			t.Errorf("login %d from a known address or network must be informational: %+v", i, event)
		}
	}
	if events[3].Severity != SevAlert || events[3].Details["known_ip"] != "no" {
		t.Errorf("a login from outside the networks must be an alarm: %+v", events[3])
	}
}

// An unparsable entry in known_ips must not be mistaken for a network: it is
// compared exactly and matches nothing else.
func TestAuthWatcherBrokenKnownEntry(t *testing.T) {
	events := []Event{}
	watcher := NewAuthWatcher(AuthConfig{KnownIPs: []string{"not-an-address", ""}},
		func(e Event) { events = append(events, e) })

	watcher.Handle("Nov  2 10:00:01 srv sshd[1]: Accepted publickey for root from 203.0.113.9 port 5 ssh2")

	if len(events) != 1 || events[0].Severity != SevAlert {
		t.Fatalf("with no usable known addresses a login must be an alarm: %+v", events)
	}
}

// The defect this fixes: behind a reverse proxy the first field of the log line
// is the proxy address. With real_ip_field the event carries the client address
// taken from the extra field.
func TestAccessWatcherRealIPField(t *testing.T) {
	events := []Event{}
	watcher := NewAccessWatcher(AccessConfig{
		NotFoundPerMinute: 99, DeniedPerMinute: 99, RequestsPerMinute: 99, ErrorsPerMinute: 99,
		HoneypotPaths: []string{"/.env"},
		ExtraFields:   []string{"ja3", "cf_ip"},
		RealIPField:   "cf_ip",
	}, nil, func(e Event) { events = append(events, e) })

	watcher.Handle(`172.68.75.160 - - [02/Nov/2026:10:00:00 +0100] "GET /.env HTTP/1.1" 404 0 "-" "bot" "771,4866" "203.0.113.77"`)

	if len(events) == 0 {
		t.Fatal("the trap path must produce an event")
	}
	if events[0].IP != "203.0.113.77" {
		t.Errorf("the event must carry the client address, got %q", events[0].IP)
	}
}

// Without real_ip_field nothing changes, and a garbage value in the field is
// ignored in favour of the address from the line.
func TestAccessWatcherRealIPFallback(t *testing.T) {
	line := `172.68.75.160 - - [02/Nov/2026:10:00:00 +0100] "GET /.env HTTP/1.1" 404 0 "-" "bot" "771,4866" "-"`

	plain := []Event{}
	watcher := NewAccessWatcher(AccessConfig{
		NotFoundPerMinute: 99, DeniedPerMinute: 99, RequestsPerMinute: 99, ErrorsPerMinute: 99,
		HoneypotPaths: []string{"/.env"}, ExtraFields: []string{"ja3", "cf_ip"},
	}, nil, func(e Event) { plain = append(plain, e) })
	watcher.Handle(line)
	if len(plain) == 0 || plain[0].IP != "172.68.75.160" {
		t.Fatalf("without the setting the address from the line is used: %+v", plain)
	}

	garbage := []Event{}
	watcher = NewAccessWatcher(AccessConfig{
		NotFoundPerMinute: 99, DeniedPerMinute: 99, RequestsPerMinute: 99, ErrorsPerMinute: 99,
		HoneypotPaths: []string{"/.env"}, ExtraFields: []string{"ja3", "cf_ip"}, RealIPField: "cf_ip",
	}, nil, func(e Event) { garbage = append(garbage, e) })
	watcher.Handle(line)
	if len(garbage) == 0 || garbage[0].IP != "172.68.75.160" {
		t.Fatalf("an unparsable field value must be ignored: %+v", garbage)
	}
}

// A proxy may write a list of addresses; the first one is the client.
func TestAccessWatcherRealIPList(t *testing.T) {
	events := []Event{}
	watcher := NewAccessWatcher(AccessConfig{
		NotFoundPerMinute: 99, DeniedPerMinute: 99, RequestsPerMinute: 99, ErrorsPerMinute: 99,
		HoneypotPaths: []string{"/.env"}, ExtraFields: []string{"cf_ip"}, RealIPField: "cf_ip",
	}, nil, func(e Event) { events = append(events, e) })

	watcher.Handle(`172.68.75.160 - - [02/Nov/2026:10:00:00 +0100] "GET /.env HTTP/1.1" 404 0 "-" "bot" "203.0.113.77, 172.68.75.160"`)

	if len(events) == 0 || events[0].IP != "203.0.113.77" {
		t.Fatalf("the first address of the list must be taken: %+v", events)
	}
}

// The defect this fixes: a failure of the email sink did not reach the
// sink_errors counter, because MultiSink.Send always returned nil. The error is
// now returned and counted.
func TestMultiSinkReturnsFailure(t *testing.T) {
	dir := t.TempDir()
	failing := &failingSink{failures: 1}
	multi := &MultiSink{sinks: []Sink{failing, &FileSink{path: filepath.Join(dir, "events.jsonl")}}}

	err := multi.Send([]Event{{At: time.Now(), Source: "trap", Kind: "trap_hit"}})

	if err == nil {
		t.Fatal("a sink failure must be returned to the caller")
	}
	if !strings.Contains(err.Error(), "test") {
		t.Errorf("the error must name the sink: %v", err)
	}
	// The other sink still received the event.
	raw, readErr := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if readErr != nil || !strings.Contains(string(raw), "trap_hit") {
		t.Errorf("the second sink must have worked: %v %q", readErr, string(raw))
	}
}

// The counter must grow on a failed delivery: without it "quiet" and "nothing
// is being delivered" look the same in -stats.
func TestServiceCountsSinkFailure(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{StateDir: dir}
	cfg.applyDefaults()
	cfg.StateDir = dir

	service, err := NewService(cfg, "")
	if err != nil {
		t.Fatalf("assembling the service: %v", err)
	}
	service.sinks = &MultiSink{sinks: []Sink{&failingSink{failures: 5}}}

	service.emit(Event{Source: "trap", Kind: "trap_hit", Severity: SevAlert, IP: "203.0.113.1"})
	service.Close()

	if got := service.metrics.Snapshot(); got.SinkErrors != 1 {
		t.Fatalf("a failed delivery must be counted: %+v", got)
	}
}

// The email sink holds events back until its throttle period has passed. The
// waiting happens in the on-disk queue, not in memory, so a restart does not
// lose them; on shutdown Flush sends what the queue holds.
func TestEmailQueueHoldsAndFlushes(t *testing.T) {
	dir := t.TempDir()
	sent := [][]byte{}
	email := NewEmailSink(EmailConfig{
		From: "watch@example.com", To: []string{"admin@example.com"},
		MinSeverity: SevAlert, Throttle: Duration{time.Hour},
	}, "srv")
	email.send = func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		sent = append(sent, msg)
		return nil
	}
	outbox := NewOutbox(email, dir, 100)

	// The first event goes out at once, the second is held back by the throttle
	// period - and must land on disk rather than in memory.
	if err := outbox.Send([]Event{{At: time.Now(), Kind: "trap_hit", Severity: SevAlert}}); err != nil {
		t.Fatalf("the first delivery must succeed: %v", err)
	}
	if err := outbox.Send([]Event{{At: time.Now(), Kind: "canary_used", Severity: SevAlert}}); err != nil {
		t.Fatalf("a deliberate deferral must not count as a failure: %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("the throttle period must hold the second event back: %d messages", len(sent))
	}
	queue := filepath.Join(dir, "outbox.email.jsonl")
	raw, err := os.ReadFile(queue)
	if err != nil || !strings.Contains(string(raw), "canary_used") {
		t.Fatalf("the held event must be on disk: %v %q", err, string(raw))
	}

	// On shutdown the queue is sent regardless of the throttle period and the
	// file is removed.
	if err := outbox.Flush(); err != nil {
		t.Fatalf("the flush must succeed: %v", err)
	}
	if len(sent) != 2 || !strings.Contains(string(sent[1]), "canary_used") {
		t.Fatalf("the held event must be sent on shutdown: %d messages", len(sent))
	}
	if _, err := os.Stat(queue); !os.IsNotExist(err) {
		t.Errorf("the queue file must be removed after a successful send")
	}
}

// A real failure (a mail server refusing to authenticate, as happened on the
// server) stays a failure: it is counted and the events stay in the queue.
func TestEmailFailureIsCountedAndQueued(t *testing.T) {
	dir := t.TempDir()
	email := NewEmailSink(EmailConfig{
		From: "watch@example.com", To: []string{"admin@example.com"},
		MinSeverity: SevAlert,
	}, "srv")
	email.send = func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		return errors.New("535 5.7.8 Authentication Failed")
	}
	outbox := NewOutbox(email, dir, 100)

	err := outbox.Send([]Event{{At: time.Now(), Kind: "trap_hit", Severity: SevAlert}})
	if err == nil {
		t.Fatal("a refusal from the mail server must be returned as an error")
	}
	raw, readErr := os.ReadFile(filepath.Join(dir, "outbox.email.jsonl"))
	if readErr != nil || !strings.Contains(string(raw), "trap_hit") {
		t.Fatalf("the undelivered event must stay in the queue: %v %q", readErr, string(raw))
	}
}

// The old test of the sink itself: deferral is reported by errDeferred and
// SendNow ignores the throttle period.
func TestEmailSinkDeferAndSendNow(t *testing.T) {
	sent := [][]byte{}
	sink := NewEmailSink(EmailConfig{
		From: "watch@example.com", To: []string{"admin@example.com"},
		MinSeverity: SevAlert, Throttle: Duration{time.Hour},
	}, "srv")
	sink.send = func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		sent = append(sent, msg)
		return nil
	}

	if err := sink.Send([]Event{{At: time.Now(), Kind: "trap_hit", Severity: SevAlert}}); err != nil {
		t.Fatalf("the first event must go out: %v", err)
	}
	err := sink.Send([]Event{{At: time.Now(), Kind: "canary_used", Severity: SevAlert}})
	if !errors.Is(err, errDeferred) {
		t.Fatalf("inside the throttle period the sink must report a deferral, got %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("the throttle period must hold the second event back: %d messages", len(sent))
	}

	if err := sink.SendNow([]Event{{At: time.Now(), Kind: "canary_used", Severity: SevAlert}}); err != nil {
		t.Fatalf("SendNow must ignore the throttle period: %v", err)
	}
	if len(sent) != 2 || !strings.Contains(string(sent[1]), "canary_used") {
		t.Fatalf("the message must contain the held event: %d messages", len(sent))
	}
	// Events below the severity threshold are not a reason for a message.
	if err := sink.SendNow([]Event{{Kind: "heartbeat", Severity: SevInfo}}); err != nil || len(sent) != 2 {
		t.Errorf("an event below the threshold must not be sent: %v %d", err, len(sent))
	}
}

// Flush on the whole set passes the request to the sinks that hold events back
// and leaves the others alone.
func TestMultiSinkFlush(t *testing.T) {
	dir := t.TempDir()
	email := NewEmailSink(EmailConfig{
		From: "watch@example.com", To: []string{"admin@example.com"},
		MinSeverity: SevAlert, Throttle: Duration{time.Hour},
	}, "srv")
	delivered := 0
	email.send = func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		delivered++
		return nil
	}
	boxed := NewOutbox(email, dir, 100)
	multi := &MultiSink{sinks: []Sink{&FileSink{path: filepath.Join(dir, "events.jsonl")}, boxed}}

	_ = multi.Send([]Event{{At: time.Now(), Kind: "trap_hit", Severity: SevAlert}})
	_ = multi.Send([]Event{{At: time.Now(), Kind: "canary_used", Severity: SevAlert}})
	if delivered != 1 {
		t.Fatalf("the throttle period must hold the second event back: %d messages", delivered)
	}

	multi.Flush()
	if delivered != 2 {
		t.Fatalf("the flush must send the held events: %d messages", delivered)
	}
	// The file sink holds nothing back, so the flush must not disturb it.
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil || strings.Count(strings.TrimSpace(string(raw)), "\n")+1 != 2 {
		t.Errorf("the file sink must hold both events: %v %q", err, string(raw))
	}
}
