package watch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// botForTest assembles the bot over empty stores and a server standing in for
// Telegram, and returns a way to look at what was answered.
func botForTest(t *testing.T, cfg TelegramConfig) (*Bot, func() []sentMessage) {
	t.Helper()
	dir := t.TempDir()
	sent := []sentMessage{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got := sentMessage{}
		_ = json.Unmarshal(body, &got)
		sent = append(sent, got)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	sink := NewTelegramSink(cfg, "srv", t.TempDir())
	sink.apiBase = server.URL
	report := func(Event) {}
	bot := NewBot(cfg, "srv", sink,
		NewActorStore(ActorsConfig{Enabled: true}, dir, report),
		NewBlocklist(BlockingConfig{}, dir, report),
		NewDossierStore(dir),
		NewMetrics(dir))
	return bot, func() []sentMessage { return sent }
}

// Only the people named by their identifier may use the bot: a chat can be
// joined, a list of identifiers cannot.
func TestBotAllowsOnlyNamedPeople(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111", " 222 "}})
	for _, item := range []struct {
		user int64
		want bool
	}{{111, true}, {222, true}, {333, false}, {11, false}, {1112, false}} {
		if got := bot.allowed(item.user); got != item.want {
			t.Errorf("user %d: allowed %v, expected %v", item.user, got, item.want)
		}
	}
}

// A command from a stranger gets no answer at all: a refusal would tell them
// there is something here to talk to.
func TestBotSaysNothingToStrangers(t *testing.T) {
	bot, sent := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	bot.handle(update(1, 999, 999, "/status"))
	if len(sent()) != 0 {
		t.Fatalf("a stranger was answered: %+v", sent())
	}
}

// An allowed person gets an answer.
func TestBotAnswersAllowedPerson(t *testing.T) {
	bot, sent := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	bot.handle(update(1, 111, 111, "/status"))
	messages := sent()
	if len(messages) != 1 {
		t.Fatalf("expected one answer, got %d", len(messages))
	}
	if !strings.Contains(messages[0].text(), "security-watch") {
		t.Errorf("the answer does not look like a status: %q", messages[0].text())
	}
	if messages[0]["chat_id"] != "111" {
		t.Errorf("the answer went to the wrong chat: %q", messages[0]["chat_id"])
	}
}

// The update number is remembered, so Telegram does not repeat what has been
// answered already.
func TestBotRemembersOffset(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	bot.handle(update(17, 111, 111, "/help"))
	if got := bot.state.offset(); got != 17 {
		t.Fatalf("offset %d, expected 17", got)
	}
}

// The bot name Telegram appends in groups does not get in the way.
func TestSplitCommand(t *testing.T) {
	for _, item := range []struct {
		text    string
		command string
		arg     string
	}{
		{"/status", "/status", ""},
		{"/ip 203.0.113.1", "/ip", "203.0.113.1"},
		{"/status@watch_bot", "/status", ""},
		{"/MUTE 3", "/mute", "3"},
		{"", "", ""},
	} {
		command, argument := splitCommand(item.text)
		if command != item.command || argument != item.arg {
			t.Errorf("%q: got (%q, %q), expected (%q, %q)", item.text, command, argument, item.command, item.arg)
		}
	}
}

// Silence asked for in the chat is capped at a day and reaches the sink.
func TestBotMuteReachesSink(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	answer := bot.answer("/mute", "100")
	if !strings.Contains(answer, "24 h") {
		t.Errorf("silence must be capped at a day: %q", answer)
	}
	until := bot.sink.MutedUntil()
	if time.Until(until) < 23*time.Hour {
		t.Errorf("the sink did not take the silence: %v", until)
	}
	bot.answer("/unmute", "")
	if !bot.sink.MutedUntil().IsZero() {
		t.Errorf("silence was not lifted: %v", bot.sink.MutedUntil())
	}
}

// The settings reply names what the bot reports, so it can be checked without
// reading the configuration file on the server.
func TestBotSettingsReply(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{
		Token: "t", AllowedUserIDs: []string{"111"},
		MinGrade: GradeCritical, SystemErrors: true, IntrusionsOnly: true, MaxPerHour: 5,
	})
	answer := bot.answer("/settings", "")
	for _, want := range []string{"critical", "system trouble: yes", "attacks only: yes", "5 messages per hour"} {
		if !strings.Contains(answer, want) {
			t.Errorf("the settings reply lacks %q: %q", want, answer)
		}
	}
}

// An unknown command is answered, so a typo does not look like a broken bot.
func TestBotUnknownCommand(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	if answer := bot.answer("/nothing", ""); !strings.Contains(answer, "no such command") {
		t.Errorf("answer to an unknown command: %q", answer)
	}
}

// /ip asks for an address and reports when nothing is known about it.
func TestBotAboutUnknownAddress(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	if answer := bot.answer("/ip", ""); !strings.Contains(answer, "address is needed") {
		t.Errorf("without an argument: %q", answer)
	}
	if answer := bot.answer("/ip", "203.0.113.9"); !strings.Contains(answer, "nothing known") {
		t.Errorf("about an unknown address: %q", answer)
	}
}

// update builds a Telegram update for the tests.
func update(id, user, chat int64, text string) telegramUpdate {
	result := telegramUpdate{UpdateID: id}
	result.Message = &struct {
		Text string `json:"text"`
		From *struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Chat *struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	}{Text: text}
	result.Message.From = &struct {
		ID int64 `json:"id"`
	}{ID: user}
	result.Message.Chat = &struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	}{ID: chat, Type: "private"}
	return result
}

// Updates are asked for starting after the last one taken: otherwise Telegram
// would hand back what has already been answered.
func TestBotPollAsksAfterLastUpdate(t *testing.T) {
	asked := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked <- r.URL.Query().Get("offset")
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":5,
			"message":{"text":"/help","from":{"id":111},"chat":{"id":111,"type":"private"}}}]}`))
	}))
	defer server.Close()

	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	bot.apiBase = server.URL

	updates, err := bot.poll(context.Background())
	if err != nil {
		t.Fatalf("the updates were not taken: %v", err)
	}
	if len(updates) != 1 || updates[0].UpdateID != 5 {
		t.Fatalf("the answer was not parsed: %+v", updates)
	}
	if got := <-asked; got != "1" {
		t.Errorf("the first request asked from %q, expected 1", got)
	}

	bot.handle(updates[0])
	if _, err := bot.poll(context.Background()); err != nil {
		t.Fatalf("the second round failed: %v", err)
	}
	if got := <-asked; got != "6" {
		t.Errorf("after update 5 the request must ask from 6, got %q", got)
	}
}

// Telegram answering with a refusal or with broken JSON is reported as an
// error rather than taken as an empty list of updates.
func TestBotPollReportsRefusal(t *testing.T) {
	for _, item := range []struct {
		name string
		body string
		code int
	}{
		{"a refusal in the body", `{"ok":false,"description":"Unauthorized"}`, 200},
		{"an error code", `{"ok":true,"result":[]}`, 401},
		{"broken JSON", `{`, 200},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(item.code)
			_, _ = w.Write([]byte(item.body))
		}))
		bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
		bot.apiBase = server.URL
		if _, err := bot.poll(context.Background()); err == nil {
			t.Errorf("%s: an error was expected", item.name)
		}
		server.Close()
	}
}

// The command loop answers what arrives and stops when the context is
// cancelled, without leaving the goroutine behind.
func TestBotRunAnswersAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rounds := 0
	updates := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "getUpdates") {
			rounds++
			if rounds == 1 {
				_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":1,
					"message":{"text":"/help","from":{"id":111},"chat":{"id":111,"type":"private"}}}]}`))
				return
			}
			// Everything that had to arrive has arrived; the loop is told to stop.
			cancel()
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer updates.Close()

	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	bot.apiBase = updates.URL
	bot.sink.apiBase = updates.URL

	done := make(chan struct{})
	go func() {
		bot.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop on cancellation")
	}
	if bot.state.offset() != 1 {
		t.Errorf("the update was not remembered: %d", bot.state.offset())
	}
}

// With nobody allowed the loop does not start at all: there would be no one to
// answer, and asking Telegram for updates would be pointless work.
func TestBotRunStopsWithNobodyAllowed(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{Token: "t"})
	done := make(chan struct{})
	go func() {
		bot.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop started although nobody is allowed")
	}
}

// Silence and the last update taken survive a restart: the rest of the service
// keeps its state on disk the same way.
func TestBotStateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	first := newBotState(dir)
	until := time.Now().Add(3 * time.Hour).Round(time.Second)
	first.setMuted(until)
	first.setOffset(42)

	second := newBotState(dir)
	if !second.mutedUntil().Equal(until) {
		t.Errorf("silence was not remembered: %v, expected %v", second.mutedUntil(), until)
	}
	if second.offset() != 42 {
		t.Errorf("the update number was not remembered: %d", second.offset())
	}
}

// The update number only moves forward: Telegram may repeat an older update,
// and taking it as the newest would make the bot ask for what it has answered.
func TestBotOffsetOnlyGrows(t *testing.T) {
	state := newBotState(t.TempDir())
	state.setOffset(10)
	state.setOffset(4)
	if state.offset() != 10 {
		t.Errorf("the number went backwards: %d", state.offset())
	}
}

// The listings answer from what the service has collected.
func TestBotListings(t *testing.T) {
	dir := t.TempDir()
	report := func(Event) {}
	actors := NewActorStore(ActorsConfig{Enabled: true, AlertScore: 50,
		Weights: map[string]int{"sqli_union": 15}}, dir, report)
	blocklist := NewBlocklist(BlockingConfig{}, dir, report)
	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1"}, "srv", dir)
	bot := NewBot(TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}}, "srv", sink,
		actors, blocklist, NewDossierStore(dir), NewMetrics(dir))

	if answer := bot.answer("/actors", ""); !strings.Contains(answer, "no actors yet") {
		t.Errorf("an empty store: %q", answer)
	}
	if answer := bot.answer("/candidates", ""); !strings.Contains(answer, "no block proposals") {
		t.Errorf("no proposals: %q", answer)
	}

	actors.Observe(Event{At: time.Now(), Source: "access", Kind: "sqli_union", IP: "203.0.113.5",
		Details: map[string]string{"country": "NL"}})
	answer := bot.answer("/actors", "")
	for _, want := range []string{"203.0.113.5", "NL", "sqli_union"} {
		if !strings.Contains(answer, want) {
			t.Errorf("the listing lacks %q: %q", want, answer)
		}
	}
	if about := bot.answer("/ip", "203.0.113.5"); !strings.Contains(about, "score: 15") {
		t.Errorf("the address reply: %q", about)
	}
}

// Blocking from the chat is the same blocking as from the command line: the
// command from the configuration is run, and the answer says what happened.
func TestBotBlockingFromChat(t *testing.T) {
	dir := t.TempDir()
	// The command is split on spaces, not handed to a shell, so the test uses
	// plain commands rather than a shell line.
	marker := filepath.Join(dir, "blocked-203.0.113.7")
	report := func(Event) {}
	blocklist := NewBlocklist(BlockingConfig{
		Enabled:        true,
		Command:        "touch " + filepath.Join(dir, "blocked-%s"),
		UnblockCommand: "rm " + filepath.Join(dir, "blocked-%s"),
		ProposeOn:      []string{"trap_hit"},
	}, dir, report)
	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1"}, "srv", dir)
	bot := NewBot(TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}}, "srv", sink,
		NewActorStore(ActorsConfig{Enabled: true}, dir, report), blocklist,
		NewDossierStore(dir), NewMetrics(dir))

	if answer := bot.answer("/block", ""); !strings.Contains(answer, "address is needed") {
		t.Errorf("/block without an argument: %q", answer)
	}
	if answer := bot.answer("/unblock", ""); !strings.Contains(answer, "address is needed") {
		t.Errorf("/unblock without an argument: %q", answer)
	}

	if answer := bot.answer("/block", "203.0.113.7"); !strings.Contains(answer, "blocked") {
		t.Fatalf("/block: %q", answer)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the blocking command did not run: %v", err)
	}

	if answer := bot.answer("/unblock", "203.0.113.7"); !strings.Contains(answer, "unblocked") {
		t.Fatalf("/unblock: %q", answer)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("the unblocking command did not run: %v", err)
	}
}

// A blocking command that fails is reported rather than passed over in silence.
func TestBotBlockingFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	bot.blocklist = NewBlocklist(BlockingConfig{Enabled: true, Command: ""}, dir, func(Event) {})

	if answer := bot.answer("/block", "203.0.113.8"); !strings.Contains(answer, "could not block") {
		t.Errorf("a failure must be reported: %q", answer)
	}
	if answer := bot.answer("/unblock", "203.0.113.8"); !strings.Contains(answer, "could not unblock") {
		t.Errorf("a failure must be reported: %q", answer)
	}
}

// The proposals listing names the address, what it did and the command that
// closes it, so that the decision can be made without leaving the chat.
func TestBotCandidatesListing(t *testing.T) {
	dir := t.TempDir()
	report := func(Event) {}
	blocklist := NewBlocklist(BlockingConfig{ProposeOn: []string{"trap_hit"}}, dir, report)
	blocklist.Consider(Event{At: time.Now(), Source: "trap", Kind: "trap_hit",
		IP: "203.0.113.11", Subject: "/admin/.env"})

	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1"}, "srv", dir)
	bot := NewBot(TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}}, "srv", sink,
		NewActorStore(ActorsConfig{Enabled: true}, dir, report), blocklist,
		NewDossierStore(dir), NewMetrics(dir))

	answer := bot.answer("/candidates", "")
	for _, want := range []string{"203.0.113.11", "trap_hit", "/block 203.0.113.11"} {
		if !strings.Contains(answer, want) {
			t.Errorf("the proposals listing lacks %q: %q", want, answer)
		}
	}
}

// The status reply says when the bot is silent, so that a quiet chat is not
// mistaken for a quiet server.
func TestBotStatusShowsSilence(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	if answer := bot.answer("/status", ""); strings.Contains(answer, "silent until") {
		t.Errorf("silence was reported where there is none: %q", answer)
	}
	bot.sink.Mute(time.Now().Add(2 * time.Hour))
	if answer := bot.answer("/status", ""); !strings.Contains(answer, "silent until") {
		t.Errorf("the silence was not reported: %q", answer)
	}
}

// A dossier without an actor is still answered: the trap records visitors the
// actor store may have already forgotten.
func TestBotAboutAddressFromDossier(t *testing.T) {
	dir := t.TempDir()
	dossier := NewDossierStore(dir)
	dossier.Record("203.0.113.12", "/admin/.env", "curl/8.5.0", "", nil, "trap")

	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1"}, "srv", dir)
	bot := NewBot(TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}}, "srv", sink,
		NewActorStore(ActorsConfig{Enabled: true}, dir, func(Event) {}),
		NewBlocklist(BlockingConfig{}, dir, func(Event) {}), dossier, NewMetrics(dir))

	answer := bot.answer("/ip", "203.0.113.12")
	if !strings.Contains(answer, "dossier") || !strings.Contains(answer, "/admin/.env") {
		t.Errorf("the dossier did not reach the answer: %q", answer)
	}
}

// A failed request does not stop the loop and does not turn into a request
// loop either: the bot waits and tries again.
func TestBotRunKeepsGoingAfterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rounds := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rounds++
		switch rounds {
		case 1:
			w.WriteHeader(http.StatusInternalServerError)
		case 2:
			_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":3,
				"message":{"text":"/help","from":{"id":111},"chat":{"id":111,"type":"private"}}}]}`))
		default:
			cancel()
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
		}
	}))
	defer server.Close()

	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	bot.apiBase = server.URL
	bot.sink.apiBase = server.URL
	bot.retryPause = time.Millisecond

	done := make(chan struct{})
	go func() {
		bot.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not survive the failure")
	}
	if bot.state.offset() != 3 {
		t.Errorf("the update after the failure was not taken: %d", bot.state.offset())
	}
}

// An update with no message, or one from nobody, is passed over without an
// answer and without a panic: Telegram sends more kinds of update than the bot
// asks for.
func TestBotIgnoresUpdatesWithoutMessage(t *testing.T) {
	bot, sent := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	bot.handle(telegramUpdate{UpdateID: 2})
	bot.handle(update(3, 111, 111, "   "))
	if len(sent()) != 0 {
		t.Fatalf("an answer was sent to nothing: %+v", sent())
	}
	if bot.state.offset() != 3 {
		t.Errorf("the update must still be counted as taken: %d", bot.state.offset())
	}
}

// The settings reply states the switches that are off as plainly as those that
// are on: "no" is an answer, an omission is not.
func TestBotSettingsShowsSwitchesOff(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	answer := bot.answer("/settings", "")
	for _, want := range []string{"system trouble: no", "attacks only: no", "significant"} {
		if !strings.Contains(answer, want) {
			t.Errorf("the settings reply lacks %q: %q", want, answer)
		}
	}
	if strings.Contains(answer, "messages per hour") {
		t.Errorf("a cap that is not set must not be mentioned: %q", answer)
	}
}

// The status reply shows the service's own counters: how much was seen, sent,
// suppressed and merged, and what failed to be delivered.
func TestBotStatusShowsCounters(t *testing.T) {
	dir := t.TempDir()
	metrics := NewMetrics(dir)
	metrics.Seen()
	metrics.Seen()
	metrics.Sent(Event{Source: "access", Kind: "path_scan", Severity: SevWarn})
	metrics.Ignored()
	metrics.Merged()
	metrics.SinkError()

	sink := NewTelegramSink(TelegramConfig{Token: "t", ChatID: "1"}, "srv", dir)
	bot := NewBot(TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}}, "srv", sink,
		NewActorStore(ActorsConfig{Enabled: true}, dir, func(Event) {}),
		NewBlocklist(BlockingConfig{}, dir, func(Event) {}), NewDossierStore(dir), metrics)

	answer := bot.answer("/status", "")
	for _, want := range []string{"events seen: 2", "sent on: 1", "delivery failures: 1", "by source: access 1"} {
		if !strings.Contains(answer, want) {
			t.Errorf("the status reply lacks %q: %q", want, answer)
		}
	}
}

// The settings reply names the holding window when one is set, so that a chat
// that stays quiet for two minutes is not taken for a broken bot.
func TestBotSettingsShowsHoldingWindow(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{
		Token: "t", AllowedUserIDs: []string{"111"},
		MaxPerHour: 20, GroupWindow: Duration{Duration: 2 * time.Minute},
	})
	answer := bot.answer("/settings", "")
	if !strings.Contains(answer, "held for 2m") {
		t.Errorf("the holding window was not named: %q", answer)
	}
}

// An answer that cannot be delivered does not stop the bot: the next command
// is still taken.
func TestBotSurvivesUndeliverableAnswer(t *testing.T) {
	bot, _ := botForTest(t, TelegramConfig{Token: "t", AllowedUserIDs: []string{"111"}})
	bot.sink.apiBase = "http://127.0.0.1:1"

	bot.handle(update(1, 111, 111, "/help"))
	bot.handle(update(2, 111, 111, "/help"))
	if bot.state.offset() != 2 {
		t.Errorf("the bot stopped taking updates: %d", bot.state.offset())
	}
}
