package watch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The grade of an event follows what it means for the server, not how loud the
// watcher was: a used bait key is critical, a scan from outside is minor.
func TestGradeOfKnownKinds(t *testing.T) {
	for _, item := range []struct {
		kind string
		want Grade
	}{
		{"canary_used", GradeCritical},
		{"file_changed_realtime", GradeCritical},
		{"listening_port", GradeCritical},
		{"sqli_union", GradeMajor},
		{"mass_assignment_attempt", GradeMajor},
		{"ssh_bruteforce", GradeMinor},
		{"file_added_realtime", GradeMinor},
		{"heartbeat", GradeNotice},
		{"ip_blocked", GradeNotice},
		{"db_error", GradeSystem},
		{"memory_low", GradeSystem},
		{"first_time_country", GradeMinor},
	} {
		got := GradeOf(Event{Kind: item.kind, IP: "203.0.113.1"}, nil)
		if got != item.want {
			t.Errorf("%s: grade %q, expected %q", item.kind, got, item.want)
		}
	}
}

// An unknown kind with an address behind it is reconnaissance; with no address
// it comes from our own machinery and is system trouble.
func TestGradeOfUnknownKind(t *testing.T) {
	if got := GradeOf(Event{Kind: "something_new", IP: "203.0.113.1"}, nil); got != GradeMinor {
		t.Errorf("an unknown kind from an address: %q", got)
	}
	if got := GradeOf(Event{Kind: "something_new"}, nil); got != GradeSystem {
		t.Errorf("an unknown kind with no address: %q", got)
	}
}

// The configuration has the last word: what counts as serious differs from
// server to server.
func TestGradeOverride(t *testing.T) {
	overrides := map[string]Grade{"file_changed_realtime": GradeMinor}
	if got := GradeOf(Event{Kind: "file_changed_realtime"}, overrides); got != GradeMinor {
		t.Errorf("the override was not applied: %q", got)
	}
}

// A lot piled up from one address raises the grade: each separate scan means
// nothing, the same address at fifty is working on us on purpose.
func TestEscalateByScore(t *testing.T) {
	if got := EscalateByScore(GradeMinor, 10, 50); got != GradeMinor {
		t.Errorf("below the threshold the grade must not change: %q", got)
	}
	if got := EscalateByScore(GradeMinor, 50, 50); got != GradeMajor {
		t.Errorf("at the threshold reconnaissance becomes an attempt: %q", got)
	}
	if got := EscalateByScore(GradeMajor, 120, 50); got != GradeCritical {
		t.Errorf("twice the threshold is a break-in in progress: %q", got)
	}
	if got := EscalateByScore(GradeSystem, 500, 50); got != GradeSystem {
		t.Errorf("the machine's own trouble has no address behind it: %q", got)
	}
}

// What the bot sends is decided by grade. By default reconnaissance stays out
// and a deliberate attempt goes through.
func TestTelegramGradeFilter(t *testing.T) {
	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1", MinSeverity: SevInfo}, "srv", t.TempDir())
	batch := sink.wanted([]Event{
		{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor},
		{Kind: "sqli_union", Severity: SevWarn, IP: "2.2.2.2", Grade: GradeMajor},
		{Kind: "memory_low", Severity: SevAlert, Grade: GradeSystem},
	})
	if len(batch) != 1 || batch[0].Kind != "sqli_union" {
		t.Fatalf("the default filter let through: %+v", kindsOf(batch))
	}
}

// The machine's own trouble is a separate switch: it is wanted without wanting
// every scanner, or the other way round.
func TestTelegramSystemErrorsSwitch(t *testing.T) {
	cfg := TelegramConfig{Token: "t", ChatID: "1", MinSeverity: SevInfo, SystemErrors: true}
	sink := NewTelegramSink(cfg, "srv", t.TempDir())
	batch := sink.wanted([]Event{
		{Kind: "memory_low", Severity: SevAlert, Grade: GradeSystem},
		{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor},
	})
	if len(batch) != 1 || batch[0].Kind != "memory_low" {
		t.Fatalf("system trouble with the switch on: %+v", kindsOf(batch))
	}
}

// With "attacks only" the service's own doings stay out even when their grade
// would pass.
func TestTelegramIntrusionsOnly(t *testing.T) {
	cfg := TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo,
		MinGrade: GradeNotice, IntrusionsOnly: true,
	}
	sink := NewTelegramSink(cfg, "srv", t.TempDir())
	batch := sink.wanted([]Event{
		{Source: "action", Kind: "ip_blocked", Severity: SevInfo, Grade: GradeNotice},
		{Source: "actor", Kind: "actor_threshold", Severity: SevAlert, IP: "1.1.1.1", Grade: GradeMajor},
		{Source: "access", Kind: "sqli_union", Severity: SevWarn, IP: "2.2.2.2", Grade: GradeMajor},
	})
	got := kindsOf(batch)
	if len(batch) != 2 || !strings.Contains(got, "actor_threshold") || !strings.Contains(got, "sqli_union") {
		t.Fatalf("attacks only let through: %s", got)
	}
}

// Same-kind events are held together: a deploy touches thousands of files, and
// a message for each would bury the one that matters.
func TestTelegramHoldsEventsTogether(t *testing.T) {
	sink, _ := telegramTestSink(t, TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo,
		MinGrade: GradeMinor, GroupWindow: Duration{Duration: time.Minute},
	})
	moment := time.Now()
	sink.now = func() time.Time { return moment }

	if err := sink.Send([]Event{{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}}); err != nil {
		t.Fatalf("the first message must go out: %v", err)
	}
	err := sink.Send([]Event{{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}})
	if err != errDeferred {
		t.Fatalf("inside the window the event must be deferred, got %v", err)
	}
}

// Nothing holds back a critical event: the holding window is there to quiet
// the noise, not to delay a break-in.
func TestTelegramCriticalIgnoresWindow(t *testing.T) {
	sink, body := telegramTestSink(t, TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo,
		MinGrade: GradeMinor, GroupWindow: Duration{Duration: time.Hour},
	})
	moment := time.Now()
	sink.now = func() time.Time { return moment }

	_ = sink.Send([]Event{{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}})
	err := sink.Send([]Event{{Kind: "canary_used", Severity: SevAlert, IP: "2.2.2.2", Grade: GradeCritical}})
	if err != nil {
		t.Fatalf("a critical event must not be deferred: %v", err)
	}
	if !strings.Contains(body().text(), "canary_used") {
		t.Errorf("the critical event did not reach the chat: %q", body().text())
	}
}

// The hourly cap: what does not fit is deferred and comes back through the
// on-disk queue, so nothing is lost and the chat stays readable.
func TestTelegramHourlyCap(t *testing.T) {
	sink, _ := telegramTestSink(t, TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo,
		MinGrade: GradeMinor, MaxPerHour: 1,
	})
	moment := time.Now()
	sink.now = func() time.Time { return moment }

	_ = sink.Send([]Event{{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}})
	if err := sink.Send([]Event{{Kind: "path_scan", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}}); err != errDeferred {
		t.Fatalf("over the cap the event must be deferred, got %v", err)
	}

	// An hour later the counter starts over.
	moment = moment.Add(time.Hour + time.Minute)
	if err := sink.Send([]Event{{Kind: "path_scan", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}}); err != nil {
		t.Fatalf("after the hour the message must go out: %v", err)
	}
}

// Silence asked for in the chat holds back the noise but not a break-in.
func TestTelegramMute(t *testing.T) {
	sink, body := telegramTestSink(t, TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo, MinGrade: GradeMinor,
	})
	moment := time.Now()
	sink.now = func() time.Time { return moment }
	sink.Mute(moment.Add(time.Hour))

	if err := sink.Send([]Event{{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}}); err != errDeferred {
		t.Fatalf("during silence the event must be deferred, got %v", err)
	}
	if err := sink.Send([]Event{{Kind: "trap_hit", Severity: SevAlert, IP: "2.2.2.2", Grade: GradeCritical}}); err != nil {
		t.Fatalf("a critical event must go out during silence: %v", err)
	}
	if !strings.Contains(body().text(), "trap_hit") {
		t.Errorf("the break-in did not reach the chat: %q", body().text())
	}
}

// A long batch becomes the worst events in full plus a count by kind: the
// operator needs the worst of them, not the thousandth repetition.
func TestTelegramComposeCounts(t *testing.T) {
	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1"}, "srv", t.TempDir())
	events := []Event{{Kind: "canary_used", IP: "9.9.9.9", Grade: GradeCritical}}
	for i := 0; i < 40; i++ {
		events = append(events, Event{Kind: "file_added_realtime", Grade: GradeMinor})
	}
	text := sink.compose(events)
	if !strings.Contains(text, "canary_used") {
		t.Errorf("the worst event must be shown in full: %q", text)
	}
	if !strings.Contains(text, "and 40 more events") || !strings.Contains(text, "file_added_realtime 40") {
		t.Errorf("the rest must be counted by kind: %q", text)
	}
	if strings.Count(text, "file_added_realtime") != 1 {
		t.Errorf("a thousand identical events must be counted, not listed: %q", text)
	}
	if !strings.Contains(text, "srv: critical") {
		t.Errorf("the header must carry the grade: %q", text)
	}
}

// With no chat named, messages go to the allowed people in private: there is
// then no group whose membership has to be watched.
func TestTelegramWritesToAllowedPeople(t *testing.T) {
	cfg := TelegramConfig{Token: "t", AllowedUserIDs: []string{"111", "222"}}
	got := cfg.Recipients()
	if len(got) != 2 || got[0] != "111" || got[1] != "222" {
		t.Fatalf("recipients: %v", got)
	}
	cfg.ChatID = "-100500"
	if got := cfg.Recipients(); len(got) != 1 || got[0] != "-100500" {
		t.Fatalf("a named chat has the last word: %v", got)
	}
}

// kindsOf lists the kinds of a batch for failure messages.
func kindsOf(events []Event) string {
	names := make([]string, 0, len(events))
	for _, event := range events {
		names = append(names, event.Kind)
	}
	return strings.Join(names, ", ")
}

// sentMessage is what the test server received.
type sentMessage map[string]string

// text is the message body.
func (m sentMessage) text() string { return m["text"] }

// telegramTestSink starts a server standing in for Telegram and returns the
// sink and a way to look at the last message.
func telegramTestSink(t *testing.T, cfg TelegramConfig) (*TelegramSink, func() sentMessage) {
	t.Helper()
	last := sentMessage{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got := sentMessage{}
		_ = json.Unmarshal(body, &got)
		for key, value := range got {
			last[key] = value
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	sink := NewTelegramSink(cfg, "srv", t.TempDir())
	sink.apiBase = server.URL
	return sink, func() sentMessage { return last }
}

// A mistake in the bot's settings is quiet in a bad way: the service keeps
// running and says nothing. So each case is reported when the configuration is
// checked, before it is put to work.
func TestCheckTelegramSettings(t *testing.T) {
	for _, item := range []struct {
		name string
		cfg  TelegramConfig
		want string
	}{
		{
			"no token",
			TelegramConfig{Enabled: true, ChatID: "1"},
			"no token is set",
		},
		{
			"nobody to write to",
			TelegramConfig{Enabled: true, Token: "t"},
			"nobody to write to",
		},
		{
			"an identifier that is not a number",
			TelegramConfig{Enabled: true, Token: "t", AllowedUserIDs: []string{"@someone"}},
			"not a numeric identifier",
		},
		{
			"system as a level of the scale",
			TelegramConfig{Enabled: true, Token: "t", ChatID: "1", MinGrade: GradeSystem},
			"not a level of the scale",
		},
		{
			"an unknown grade",
			TelegramConfig{Enabled: true, Token: "t", ChatID: "1", MinGrade: Grade("huge")},
			"is unknown",
		},
		{
			"commands with nobody allowed",
			TelegramConfig{Enabled: true, Token: "t", ChatID: "1", Commands: true},
			"nobody could use them",
		},
	} {
		report := &configReport{}
		checkTelegram(&Config{Sinks: SinksConfig{Telegram: item.cfg}}, report)
		if len(report.problems) == 0 {
			t.Errorf("%s: no problem reported", item.name)
			continue
		}
		if !strings.Contains(strings.Join(report.problems, " "), item.want) {
			t.Errorf("%s: problems %v, expected a mention of %q", item.name, report.problems, item.want)
		}
	}
}

// A sane setup passes without complaints.
func TestCheckTelegramAcceptsSaneSetup(t *testing.T) {
	report := &configReport{}
	checkTelegram(&Config{Sinks: SinksConfig{Telegram: TelegramConfig{
		Enabled: true, Token: "t", AllowedUserIDs: []string{"111", "222"},
		MinGrade: GradeMajor, Commands: true, SystemErrors: true,
	}}}, report)
	if len(report.problems) != 0 {
		t.Fatalf("a sane setup was refused: %v", report.problems)
	}
}

// An unknown grade in the overrides is caught as well: a typo there would
// quietly change what the bot reports.
func TestCheckGradeOverrides(t *testing.T) {
	report := &configReport{}
	checkTelegram(&Config{
		Sinks:          SinksConfig{Telegram: TelegramConfig{Enabled: true, Token: "t", ChatID: "1"}},
		GradeOverrides: map[string]Grade{"sqli_union": Grade("very bad")},
	}, report)
	if len(report.problems) == 0 || !strings.Contains(strings.Join(report.problems, " "), "is unknown") {
		t.Fatalf("a typo in the overrides was not caught: %v", report.problems)
	}
}

// A break-in inside the noise of a deploy stays visible: one example of each
// kind that matters is shown, the thousand identical file events are counted.
func TestTelegramShowsAttackInsideNoise(t *testing.T) {
	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1", MinGrade: GradeMajor}, "srv", t.TempDir())
	events := []Event{
		{Kind: "trap_hit", Source: "trap", Grade: GradeCritical, IP: "1.1.1.1", Subject: "/admin/.env"},
		{Kind: "sqli_union", Source: "access", Grade: GradeMajor, IP: "1.1.1.1", Subject: "/api?id=1"},
	}
	for i := 0; i < 1200; i++ {
		events = append(events, Event{Kind: "file_added_realtime", Source: "files", Grade: GradeMinor})
	}
	text := sink.compose(events)

	for _, want := range []string{"trap_hit", "sqli_union", "/admin/.env", "and 1200 more events"} {
		if !strings.Contains(text, want) {
			t.Errorf("the message lacks %q: %q", want, text)
		}
	}
	if strings.Count(text, "file_added_realtime") != 1 {
		t.Errorf("the identical file events must only be counted: %q", text)
	}
}

// With nothing serious in the batch the message is still not a bare count: a
// couple of kinds are shown, so a quiet night with one scanner reads as such.
func TestTelegramQuietBatchStillShowsSomething(t *testing.T) {
	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1", MinGrade: GradeMinor}, "srv", t.TempDir())
	text := sink.compose([]Event{
		{Kind: "ssh_bruteforce", Source: "auth", Grade: GradeMinor, IP: "1.1.1.1", Subject: "root", Count: 40},
		{Kind: "path_scan", Source: "access", Grade: GradeMinor, IP: "1.1.1.1", Subject: "/wp-login.php"},
	})
	if !strings.Contains(text, "ssh_bruteforce") || !strings.Contains(text, "path_scan") {
		t.Errorf("a quiet batch must still show what was tried: %q", text)
	}
	if !strings.Contains(text, "srv: minor") {
		t.Errorf("the header must carry the grade: %q", text)
	}
}

// On shutdown what was held back goes out regardless of the window, the hourly
// cap and the silence: otherwise the last batch would die with the service.
func TestTelegramSendNowIgnoresHolding(t *testing.T) {
	sink, body := telegramTestSink(t, TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo, MinGrade: GradeMinor,
		MaxPerHour: 1, GroupWindow: Duration{Duration: time.Hour},
	})
	moment := time.Now()
	sink.now = func() time.Time { return moment }
	sink.Mute(moment.Add(time.Hour))

	_ = sink.Send([]Event{{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}})
	if err := sink.SendNow([]Event{{Kind: "path_scan", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}}); err != nil {
		t.Fatalf("what was held back must go out on shutdown: %v", err)
	}
	if !strings.Contains(body().text(), "path_scan") {
		t.Errorf("the held events did not reach the chat: %q", body().text())
	}
}

// Nothing worth a message means no request to Telegram at all.
func TestTelegramSendNowSkipsEmptyBatch(t *testing.T) {
	sink, body := telegramTestSink(t, TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo, MinGrade: GradeCritical,
	})
	if err := sink.SendNow([]Event{{Kind: "heartbeat", Severity: SevInfo, Grade: GradeNotice}}); err != nil {
		t.Fatalf("an empty batch is not a failure: %v", err)
	}
	if body().text() != "" {
		t.Errorf("a message was sent for nothing: %q", body().text())
	}
}

// An event that reached the sink without a grade - written to the on-disk queue
// by an earlier version - is judged by its kind, and by the same rule
// everywhere: it must not be filtered as minor and then held back as if it were
// not critical.
func TestTelegramDerivesMissingGrade(t *testing.T) {
	sink, body := telegramTestSink(t, TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo,
		MinGrade: GradeMajor, GroupWindow: Duration{Duration: time.Hour},
	})
	moment := time.Now()
	sink.now = func() time.Time { return moment }

	_ = sink.Send([]Event{{Kind: "sqli_union", Severity: SevWarn, IP: "1.1.1.1"}})
	err := sink.Send([]Event{{Kind: "trap_hit", Severity: SevAlert, IP: "2.2.2.2", Subject: "/.env"}})
	if err != nil {
		t.Fatalf("a critical event with no grade must not be held: %v", err)
	}
	if !strings.Contains(body().text(), "trap_hit") || !strings.Contains(body().text(), "srv: critical") {
		t.Errorf("the grade was not worked out from the kind: %q", body().text())
	}
}

// Silence lifted in the chat reaches the sink.
func TestTelegramUnmute(t *testing.T) {
	sink, _ := telegramTestSink(t, TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo, MinGrade: GradeMinor,
	})
	moment := time.Now()
	sink.now = func() time.Time { return moment }
	sink.Mute(moment.Add(time.Hour))
	sink.Mute(time.Time{})

	if err := sink.Send([]Event{{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}}); err != nil {
		t.Fatalf("after the silence is lifted the message must go out: %v", err)
	}
}

// What is known about an address is handed out as a copy: a caller holding it
// must not be able to change the store while events keep arriving.
func TestActorStoreGetReturnsCopy(t *testing.T) {
	store := NewActorStore(ActorsConfig{Enabled: true}, t.TempDir(), func(Event) {})
	store.Observe(Event{At: time.Now(), Source: "access", Kind: "path_scan", IP: "203.0.113.4"})

	if store.Get("203.0.113.9") != nil {
		t.Error("an unknown address must give nothing")
	}
	if store.Get("") != nil {
		t.Error("an empty address must give nothing")
	}

	actor := store.Get("203.0.113.4")
	if actor == nil {
		t.Fatal("the known address was not found")
	}
	actor.Score = 9999
	actor.Kinds["made_up"] = 7
	again := store.Get("203.0.113.4")
	if again.Score == 9999 || again.Kinds["made_up"] != 0 {
		t.Error("the store was changed through the copy handed out")
	}
}

// A grade that is not on the scale - set in the configuration and not caught
// because the service was started without -check - must not crash the message
// or hide the event: it is shown as it was written.
func TestTelegramUnknownGradeInMessage(t *testing.T) {
	sink := NewTelegramSink(TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo, MinGrade: GradeNotice,
	}, "srv", t.TempDir())
	text := sink.compose([]Event{{Kind: "sqli_union", Source: "access", Grade: Grade("huge"), IP: "1.1.1.1"}})
	if !strings.Contains(text, "sqli_union") {
		t.Errorf("the event was lost: %q", text)
	}
	if !strings.Contains(text, "huge") {
		t.Errorf("an unknown grade must be shown as it was written: %q", text)
	}
}

// The name of the sink is part of the name of its on-disk queue
// (outbox.telegram.jsonl), so it is not free to change.
func TestTelegramSinkName(t *testing.T) {
	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1"}, "srv", t.TempDir())
	if sink.Name() != "telegram" {
		t.Errorf("the sink is named %q; the queue file on disk is named after it", sink.Name())
	}
}

// A delivery failure is reported, so that the service counts it in
// sink_errors instead of believing the message went out.
func TestTelegramReportsDeliveryFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	sink := NewTelegramSink(TelegramConfig{
		Token: "t", AllowedUserIDs: []string{"111", "222"}, MinSeverity: SevInfo, MinGrade: GradeMinor,
	}, "srv", t.TempDir())
	sink.apiBase = server.URL

	err := sink.Send([]Event{{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}})
	if err == nil {
		t.Fatal("a refusal from Telegram must be reported")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("the failure does not name what happened: %v", err)
	}
}

// Telegram refuses messages longer than 4096 characters, so a long batch is cut
// short rather than lost.
func TestTelegramTrimsLongMessage(t *testing.T) {
	sink := NewTelegramSink(TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo, MinGrade: GradeMinor,
	}, "srv", t.TempDir())

	events := []Event{}
	for i := 0; i < 5; i++ {
		events = append(events, Event{
			Kind: fmt.Sprintf("sqli_union_%d", i), Source: "access", Grade: GradeMajor,
			IP: "1.1.1.1", Subject: strings.Repeat("/very-long-path-segment", 60),
			Details: map[string]string{"agent": strings.Repeat("agent", 40)},
		})
	}
	text := sink.compose(events)
	if len([]rune(text)) > 3904 {
		t.Fatalf("the message was not cut short: %d characters", len([]rune(text)))
	}
	if !strings.HasSuffix(text, "...") {
		t.Errorf("a cut message must say so: %q", text[len(text)-20:])
	}
}

// The count is ordered by how much of each kind there was, and kinds with the
// same count go in alphabetical order, so the same batch always reads the same.
func TestTelegramCountRestOrder(t *testing.T) {
	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1"}, "srv", t.TempDir())
	events := []Event{{Kind: "trap_hit", Source: "trap", Grade: GradeCritical, IP: "1.1.1.1"}}
	for _, kind := range []string{"path_scan", "honeypot_hit"} {
		for i := 0; i < 3; i++ {
			events = append(events, Event{Kind: kind, Source: "access", Grade: GradeMinor})
		}
	}
	events = append(events, Event{Kind: "ssh_failed", Source: "auth", Grade: GradeMinor})

	text := sink.compose(events)
	want := "and 7 more events: honeypot_hit 3, path_scan 3, ssh_failed 1"
	if !strings.Contains(text, want) {
		t.Errorf("the count reads %q, expected to contain %q", text, want)
	}
}

// A sink that cannot be reached at all reports it, the same as a refusal.
func TestTelegramReportsUnreachable(t *testing.T) {
	sink := NewTelegramSink(TelegramConfig{
		Token: "t", ChatID: "1", MinSeverity: SevInfo, MinGrade: GradeMinor,
	}, "srv", t.TempDir())
	// A port nothing listens on: the request fails before any answer.
	sink.apiBase = "http://127.0.0.1:1"

	err := sink.Send([]Event{{Kind: "ssh_bruteforce", Severity: SevWarn, IP: "1.1.1.1", Grade: GradeMinor}})
	if err == nil {
		t.Fatal("an unreachable sink must be reported")
	}
}

// An event with no subject and no repeats is still readable: the line is built
// from what there is, without empty fields.
func TestTelegramLineWithoutSubject(t *testing.T) {
	line := formatTelegramLine(Event{Kind: "load_high", Source: "resources", Grade: GradeSystem, Count: 1})
	if strings.Contains(line, "subject:") || strings.Contains(line, "repeats:") {
		t.Errorf("empty fields made it into the line: %q", line)
	}
	if !strings.Contains(line, "load_high") || !strings.Contains(line, "system") {
		t.Errorf("the line lost what matters: %q", line)
	}
}
