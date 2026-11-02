package watch

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A trap hit: the facts the attacker sent themselves are collected and a dossier
// is opened.
func TestTrapCollectsDossier(t *testing.T) {
	dir := t.TempDir()
	store := NewDossierStore(dir)
	canary := NewRuntimeCanary(nil)
	events := []Event{}
	trap := NewTrapServer(TrapConfig{ServeBait: false}, store, canary, func(e Event) { events = append(events, e) })

	request := httptest.NewRequest(http.MethodGet, "/.env.bak", nil)
	request.Header.Set("CF-Connecting-IP", "203.0.113.55")
	request.Header.Set("User-Agent", "python-requests/2.31")
	request.Header.Set("X-Original-URI", "/.env.bak")
	request.Header.Set("X-JA3", "771,4866-4867-4865")
	request.Header.Set("Cookie", "secret=value")
	recorder := httptest.NewRecorder()

	trap.handle(recorder, request)

	if len(events) != 1 || events[0].Kind != "trap_hit" || events[0].Severity != SevAlert {
		t.Fatalf("no trap event was emitted: %+v", events)
	}
	item := store.Get("203.0.113.55")
	if item == nil {
		t.Fatal("no dossier was opened")
	}
	if item.Fingerprint != "771,4866-4867-4865" {
		t.Errorf("the fingerprint was not recorded: %+v", item)
	}
	if len(item.Paths) != 1 || item.Paths[0] != "/.env.bak" {
		t.Errorf("the path was not recorded: %+v", item.Paths)
	}
	// Someone else's secrets are not kept: only the fact that they were
	// presented is recorded.
	if item.Headers["Cookie"] != "presented" {
		t.Errorf("the cookie contents must not be kept: %q", item.Headers["Cookie"])
	}
	// Without the bait the trap answers like an ordinary missing page and gives
	// nothing away.
	if recorder.Code != http.StatusNotFound {
		t.Errorf("the trap must not stand out by its answer, got %d", recorder.Code)
	}
}

// The bait content: every visitor gets their own fake key, and it is taken under
// watch immediately.
func TestTrapIssuesUniqueBait(t *testing.T) {
	dir := t.TempDir()
	store := NewDossierStore(dir)
	canary := NewRuntimeCanary(nil)
	trap := NewTrapServer(TrapConfig{ServeBait: true}, store, canary, func(Event) {})

	call := func(ip string) string {
		request := httptest.NewRequest(http.MethodGet, "/.env.bak", nil)
		request.Header.Set("CF-Connecting-IP", ip)
		recorder := httptest.NewRecorder()
		trap.handle(recorder, request)
		return recorder.Body.String()
	}

	first := call("203.0.113.1")
	second := call("203.0.113.2")
	again := call("203.0.113.1")

	if !strings.Contains(first, "SWBAIT_") || !strings.Contains(second, "SWBAIT_") {
		t.Fatalf("the bait was not served: %q / %q", first, second)
	}
	if first == second {
		t.Errorf("different addresses must get different tokens")
	}
	if first != again {
		t.Errorf("the same address must get the same token")
	}

	// An issued token is matched alongside the ones from the configuration: if
	// someone tries to use it, that will be noticed.
	token := strings.TrimSpace(strings.Split(strings.Split(first, "DB_PASSWORD=")[1], "\n")[0])
	if _, found := canary.Match("POST /api/login key=" + token); !found {
		t.Errorf("the issued token was not taken under watch")
	}
	if item := store.MarkBaitUsed(token); item == nil || item.IP != "203.0.113.1" {
		t.Errorf("the token use was not linked to whoever it was issued to")
	}
}

// Proposals accumulate, but the service itself blocks nobody.
func TestBlocklistProposesButDoesNotAct(t *testing.T) {
	dir := t.TempDir()
	list := NewBlocklist(BlockingConfig{ProposeOn: []string{"trap_hit", "sqli_union"}}, dir, func(Event) {})

	list.Consider(Event{IP: "203.0.113.9", Source: "trap", Kind: "trap_hit", Subject: "/.env.bak"})
	list.Consider(Event{IP: "203.0.113.9", Source: "access", Kind: "sqli_union", Subject: "/news?id=1"})
	list.Consider(Event{IP: "198.51.100.2", Source: "access", Kind: "path_scan", Subject: "/x"})

	items := list.Candidates()
	if len(items) != 1 {
		t.Fatalf("expected one proposal, got %d: %+v", len(items), items)
	}
	if items[0].IP != "203.0.113.9" || items[0].Count != 2 || len(items[0].Reasons) != 2 {
		t.Errorf("the proposal was assembled incorrectly: %+v", items[0])
	}
	if items[0].Blocked {
		t.Errorf("the service must not block on its own")
	}
}

// Blocking is not performed without being enabled in the configuration.
func TestBlockRequiresEnabled(t *testing.T) {
	list := NewBlocklist(BlockingConfig{Enabled: false, Command: "echo %s"}, t.TempDir(), func(Event) {})
	if err := list.Block("203.0.113.9"); err == nil {
		t.Fatalf("with blocking disabled the command must not run")
	}
}

// Blocking on the operator's decision runs the configured command.
func TestBlockRunsConfiguredCommand(t *testing.T) {
	events := []Event{}
	list := NewBlocklist(BlockingConfig{Enabled: true, Command: "echo blocked %s", UnblockCommand: "echo unblocked %s"},
		t.TempDir(), func(e Event) { events = append(events, e) })

	if err := list.Block("203.0.113.9"); err != nil {
		t.Fatalf("blocking failed: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "ip_blocked" {
		t.Fatalf("the action was not recorded as an event: %+v", events)
	}
	if !list.Candidates()[0].Blocked {
		t.Errorf("the blocked mark was not set")
	}

	if err := list.Unblock("203.0.113.9"); err != nil {
		t.Fatalf("unblocking failed: %v", err)
	}
	if list.Candidates()[0].Blocked {
		t.Errorf("the blocked mark was not cleared")
	}
}

// The address is substituted into a shell command, so it is validated strictly:
// otherwise a corrupted entry could run anything on the server.
func TestValidateIP(t *testing.T) {
	good := []string{"203.0.113.9", "2001:db8::1", "10.0.0.1"}
	for _, ip := range good {
		if err := validateIP(ip); err != nil {
			t.Errorf("%s must be accepted: %v", ip, err)
		}
	}
	bad := []string{"", "1.2.3.4; rm -rf /", "$(whoami)", "1.2.3.4 && reboot", "`id`"}
	for _, ip := range bad {
		if err := validateIP(ip); err == nil {
			t.Errorf("%q must be rejected", ip)
		}
	}
}

// Self-directed blocking fires only when every condition is met.
func TestAutoBlockRequiresConditions(t *testing.T) {
	events := []Event{}
	list := NewBlocklist(BlockingConfig{
		Enabled: true, Command: "echo %s",
		ProposeOn: []string{"trap_hit", "path_scan"},
		Auto: AutoBlockConfig{
			Enabled: true, MinHits: 3, MinReasons: 2,
			RequireKinds: []string{"trap_hit"}, MaxPerHour: 10,
		},
	}, t.TempDir(), func(e Event) { events = append(events, e) })

	// One hit could be a browser that loaded someone else's image linking to our
	// trap path. Blocking is out of the question.
	list.Consider(Event{IP: "203.0.113.5", Source: "trap", Kind: "trap_hit", Subject: "/.env.bak"})
	if blocked(list, "203.0.113.5") {
		t.Fatalf("one hit is not enough for self-directed blocking")
	}

	// The third hit and the second reason: the conditions are met.
	list.Consider(Event{IP: "203.0.113.5", Source: "access", Kind: "path_scan", Subject: "/admin"})
	list.Consider(Event{IP: "203.0.113.5", Source: "trap", Kind: "trap_hit", Subject: "/backup.sql"})

	if !blocked(list, "203.0.113.5") {
		t.Fatalf("with the conditions met the address must be shut out: %+v", list.Candidates())
	}
	if !hasKind(events, "ip_auto_blocked") {
		t.Errorf("self-directed blocking must be recorded as an event: %+v", events)
	}
}

// A required event kind: without it there is no blocking, no matter how many
// hits there are.
func TestAutoBlockRequiredKindMissing(t *testing.T) {
	list := NewBlocklist(BlockingConfig{
		Enabled: true, Command: "echo %s", ProposeOn: []string{"path_scan"},
		Auto: AutoBlockConfig{Enabled: true, MinHits: 2, RequireKinds: []string{"trap_hit"}},
	}, t.TempDir(), func(Event) {})

	for i := 0; i < 5; i++ {
		list.Consider(Event{IP: "198.51.100.9", Source: "access", Kind: "path_scan", Subject: "/x"})
	}
	if blocked(list, "198.51.100.9") {
		t.Fatalf("without the required event kind blocking is not allowed")
	}
}

// Your own addresses are never blocked, including whole networks.
func TestAutoBlockAllowlist(t *testing.T) {
	list := NewBlocklist(BlockingConfig{
		Enabled: true, Command: "echo %s", ProposeOn: []string{"trap_hit"},
		Auto: AutoBlockConfig{Enabled: true, MinHits: 1, Allowlist: []string{"203.0.113.7", "95.87."}},
	}, t.TempDir(), func(Event) {})

	list.Consider(Event{IP: "203.0.113.7", Source: "trap", Kind: "trap_hit"})
	list.Consider(Event{IP: "95.87.64.205", Source: "trap", Kind: "trap_hit"})

	if blocked(list, "203.0.113.7") || blocked(list, "95.87.64.205") {
		t.Fatalf("addresses from the allowlist must not be blocked")
	}
}

// The hourly limit: if someone floods the trap from other people's addresses,
// the service will not shut out half the internet.
func TestAutoBlockHourlyLimit(t *testing.T) {
	list := NewBlocklist(BlockingConfig{
		Enabled: true, Command: "echo %s", ProposeOn: []string{"trap_hit"},
		Auto: AutoBlockConfig{Enabled: true, MinHits: 1, MaxPerHour: 2},
	}, t.TempDir(), func(Event) {})

	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		list.Consider(Event{IP: ip, Source: "trap", Kind: "trap_hit"})
	}

	count := 0
	for _, item := range list.Candidates() {
		if item.Blocked {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("no more than two addresses may be shut out per hour, got %d", count)
	}
}

// The report-only mode performs nothing and merely reports.
func TestAutoBlockDryRun(t *testing.T) {
	events := []Event{}
	list := NewBlocklist(BlockingConfig{
		Enabled: true, Command: "echo %s", ProposeOn: []string{"trap_hit"},
		Auto: AutoBlockConfig{Enabled: true, MinHits: 1, DryRun: true},
	}, t.TempDir(), func(e Event) { events = append(events, e) })

	list.Consider(Event{IP: "203.0.113.11", Source: "trap", Kind: "trap_hit"})

	if blocked(list, "203.0.113.11") {
		t.Fatalf("in report-only mode there must be no block")
	}
	if !hasKind(events, "auto_block_proposed") {
		t.Errorf("there must be a report about what the service would have blocked: %+v", events)
	}
}

// blocked reports whether the address is shut out according to the proposal
// list.
func blocked(list *Blocklist, ip string) bool {
	for _, item := range list.Candidates() {
		if item.IP == ip {
			return item.Blocked
		}
	}
	return false
}

// hasKind reports whether the events contain this kind.
func hasKind(events []Event, kind string) bool {
	for _, event := range events {
		if event.Kind == kind {
			return true
		}
	}
	return false
}
