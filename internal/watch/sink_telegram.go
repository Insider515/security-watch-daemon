// Sending events to Telegram: the fastest way to get a trace off the server
// before whoever broke in reaches it.
package watch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// TelegramConfig - the bot, who it writes to and what it writes about.
type TelegramConfig struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
	// Where to write. Empty means the allowed people in private, which is the
	// usual case: there is then no group whose membership has to be watched.
	ChatID string `json:"chat_id"`
	// Messages are sent only for events at this level or above.
	MinSeverity Severity `json:"min_severity"`
	Timeout     Duration `json:"timeout"`

	// Numeric Telegram identifiers of the people allowed to use the bot. The
	// bot answers nobody else and, when chat_id is empty, writes to these
	// people in private. Empty means nobody may use the commands.
	AllowedUserIDs []string `json:"allowed_user_ids"`
	// The lowest grade worth a message: notice, minor, major or critical.
	// Empty means major - a deliberate attempt at the application and worse.
	MinGrade Grade `json:"min_grade"`
	// Whether to report the machine's own trouble: memory, disk, a watcher that
	// failed. Such events are outside the grade scale and are switched on their
	// own.
	SystemErrors bool `json:"system_errors"`
	// Report only what points at an attack, leaving out the service's own
	// doings even when their grade would pass.
	IntrusionsOnly bool `json:"intrusions_only"`
	// Accept commands from the allowed people. The bot asks Telegram for
	// updates itself, so the server needs no address reachable from outside.
	Commands bool `json:"commands"`
	// The cap on messages per hour. What does not fit is counted and goes out
	// as one summary: a deploy touches thousands of files, and without the cap
	// the chat becomes unreadable at the very moment it is needed.
	MaxPerHour int `json:"max_per_hour"`
	// How long to hold same-kind events together before sending the summary.
	GroupWindow Duration `json:"group_window"`
}

// Recipients returns the chats to write to: the one named in the configuration,
// or the allowed people in private when none is named.
func (c TelegramConfig) Recipients() []string {
	if c.ChatID != "" {
		return []string{c.ChatID}
	}
	return c.AllowedUserIDs
}

// Grade returns the lowest grade worth a message. The default is a deliberate
// attempt at the application and worse: reconnaissance from outside goes on
// around the clock and says nothing on its own.
func (c TelegramConfig) Grade() Grade {
	if c.MinGrade != "" {
		return c.MinGrade
	}
	return GradeMajor
}

// TelegramSink sends messages through the bot API. Unlike email it needs no
// configured mail server.
type TelegramSink struct {
	cfg    TelegramConfig
	host   string
	client *http.Client
	// Base address of the messaging API. A separate field so the sink can be
	// tested against a server started by a test instead of real Telegram.
	apiBase string

	mu sync.Mutex
	// When the last message went out and how many have gone out this hour: the
	// cap and the holding window are counted from these.
	lastSent  time.Time
	hourStart time.Time
	sentHour  int
	now       func() time.Time // replaced in tests

	// Shared with the bot's command side: silence asked for with /mute, and the
	// number of the last update taken. Kept on disk, so a restart does not
	// quietly undo either of them.
	state *botState
}

// NewTelegramSink creates the sink. The state directory holds what the bot
// must remember across a restart.
func NewTelegramSink(cfg TelegramConfig, host, stateDir string) *TelegramSink {
	timeout := cfg.Timeout.Duration
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = SevWarn
	}
	return &TelegramSink{
		cfg: cfg, host: host,
		client:  &http.Client{Timeout: timeout},
		apiBase: "https://api.telegram.org",
		now:     time.Now,
		state:   newBotState(stateDir),
	}
}

// Send delivers what is worth a message, or defers it.
//
// Three things are decided here. What is worth sending at all - by grade, not
// by severity, because a file changed by a deploy and a file changed by an
// intruder carry the same severity. Whether to send now - anything critical
// goes at once, the rest waits out the holding window so that a thousand
// events of one kind become one summary. And whether the hourly cap still
// allows it: what does not fit is deferred, and the on-disk queue brings it
// back later, so nothing is lost and the chat stays readable.
func (t *TelegramSink) Send(events []Event) error {
	batch := t.wanted(events)
	if len(batch) == 0 {
		return nil
	}

	t.mu.Lock()
	now := t.now()
	t.rollHour(now)
	urgent := hasCritical(batch)
	if !urgent && now.Before(t.state.mutedUntil()) {
		t.mu.Unlock()
		return errDeferred
	}
	held := t.cfg.GroupWindow.Duration > 0 && now.Sub(t.lastSent) < t.cfg.GroupWindow.Duration
	capped := t.cfg.MaxPerHour > 0 && t.sentHour >= t.cfg.MaxPerHour

	if !urgent && (held || capped) {
		t.mu.Unlock()
		return errDeferred
	}
	t.lastSent = now
	t.sentHour++
	t.mu.Unlock()

	return t.deliver(batch)
}

// SendNow sends regardless of the window and the cap. Used on shutdown, so that
// what was held does not die with the service.
func (t *TelegramSink) SendNow(events []Event) error {
	batch := t.wanted(events)
	if len(batch) == 0 {
		return nil
	}
	t.mu.Lock()
	t.lastSent = t.now()
	t.mu.Unlock()
	return t.deliver(batch)
}

// Name is used in the log.
func (t *TelegramSink) Name() string { return "telegram" }

// Mute asks for silence until the given moment; a zero moment lifts it.
// Critical events go out regardless: silence is asked for to stop the noise,
// not to miss a break-in.
func (t *TelegramSink) Mute(until time.Time) {
	t.state.setMuted(until)
}

// MutedUntil reports until when silence was asked for.
func (t *TelegramSink) MutedUntil() time.Time {
	return t.state.mutedUntil()
}

// wanted keeps the events the operator asked to see.
func (t *TelegramSink) wanted(events []Event) []Event {
	batch := make([]Event, 0, len(events))
	minGrade := gradeRank(t.cfg.Grade())
	for _, event := range events {
		if severityRank(event.Severity) < severityRank(t.cfg.MinSeverity) {
			continue
		}
		grade := gradeOrDerive(event)
		if grade == GradeSystem {
			// The machine's own trouble is a separate switch: it has no
			// attacker behind it and is not measured on the same scale.
			if t.cfg.SystemErrors {
				batch = append(batch, event)
			}
			continue
		}
		if t.cfg.IntrusionsOnly && !intrusionEvent(event) {
			continue
		}
		if gradeRank(grade) < minGrade {
			continue
		}
		batch = append(batch, event)
	}
	return batch
}

// rollHour resets the hourly counter when the hour has passed.
func (t *TelegramSink) rollHour(now time.Time) {
	if now.Sub(t.hourStart) >= time.Hour {
		t.hourStart = now
		t.sentHour = 0
	}
}

// intrusionEvent reports whether somebody from outside is behind the event. The
// service's own doings - a block it performed, the heartbeat, the digest - are
// not attacks even when they matter.
func intrusionEvent(event Event) bool {
	switch event.Source {
	case "self", "action", "actor":
		return event.Kind == "actor_threshold" || event.Kind == "trap_hit"
	}
	return true
}

// hasCritical reports whether the batch holds anything that must not wait.
func hasCritical(events []Event) bool {
	for _, event := range events {
		if gradeOrDerive(event) == GradeCritical {
			return true
		}
	}
	return false
}

// deliver builds the message and sends it to every recipient.
func (t *TelegramSink) deliver(events []Event) error {
	text := t.compose(events)
	var failed error
	for _, chat := range t.cfg.Recipients() {
		if err := t.post(chat, text); err != nil && failed == nil {
			failed = err
		}
	}
	return failed
}

// compose builds the message text: the worst events in full, the rest counted
// by kind.
func (t *TelegramSink) compose(events []Event) string {
	sorted := make([]Event, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		return gradeRank(gradeOrDerive(sorted[i])) > gradeRank(gradeOrDerive(sorted[j]))
	})

	samples := pickSamples(sorted)
	lines := make([]string, 0, len(samples)+1)
	for _, event := range samples {
		lines = append(lines, formatTelegramLine(event))
	}
	if rest := countRest(sorted, samples); rest != "" {
		lines = append(lines, rest)
	}

	worst := gradeOrDerive(sorted[0])
	header := fmt.Sprintf("security-watch %s: %s", t.host, gradeMark(worst))
	text := header + "\n\n" + strings.Join(lines, "\n\n")

	// Telegram refuses messages longer than 4096 characters.
	if len([]rune(text)) > 3900 {
		runes := []rune(text)
		text = string(runes[:3900]) + "\n..."
	}
	return text
}

// pickSamples takes one event of each kind worth showing in full, worst first.
//
// The rest is counted instead. A batch left by a deploy holds a thousand events
// identical to each other: listing them all would push out the one that
// matters, while listing none of a kind would hide what was tried.
func pickSamples(sorted []Event) []Event {
	// Shown in full are a deliberate attempt and worse, plus the machine's own
	// trouble - a different kind of trouble rather than a lesser one. When the
	// batch holds nothing of that weight, which is a quiet night with one
	// scanner, the worst grade present is shown instead, so that the message is
	// not a bare count.
	const maxKinds = 5
	floor := GradeMajor
	if worst := gradeOrDerive(sorted[0]); gradeRank(worst) < gradeRank(GradeMajor) {
		floor = worst
	}

	picked := []Event{}
	seen := map[string]bool{}
	for _, event := range sorted {
		if seen[event.Kind] || len(seen) >= maxKinds {
			continue
		}
		grade := gradeOrDerive(event)
		if grade != GradeSystem && gradeRank(grade) < gradeRank(floor) {
			continue
		}
		seen[event.Kind] = true
		picked = append(picked, event)
	}
	return picked
}

// countRest renders everything that was not shown in full, counted by kind and
// ordered by how much of it there was. An empty string means the samples
// covered the whole batch.
func countRest(sorted, samples []Event) string {
	counts := map[string]int{}
	for _, event := range sorted {
		counts[event.Kind]++
	}
	for _, event := range samples {
		if counts[event.Kind] > 1 {
			counts[event.Kind]--
		} else {
			delete(counts, event.Kind)
		}
	}
	if len(counts) == 0 {
		return ""
	}

	kinds := make([]string, 0, len(counts))
	total := 0
	for kind, count := range counts {
		kinds = append(kinds, kind)
		total += count
	}
	sort.Slice(kinds, func(i, j int) bool {
		if counts[kinds[i]] != counts[kinds[j]] {
			return counts[kinds[i]] > counts[kinds[j]]
		}
		return kinds[i] < kinds[j]
	})
	parts := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		parts = append(parts, fmt.Sprintf("%s %d", kind, counts[kind]))
	}
	return fmt.Sprintf("and %d more events: %s", total, strings.Join(parts, ", "))
}

// post hands one message to the bot API.
func (t *TelegramSink) post(chat, text string) error {
	payload := map[string]string{
		"chat_id":                  chat,
		"text":                     text,
		"disable_web_page_preview": "true",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/bot%s/sendMessage", t.apiBase, t.cfg.Token)
	response, err := t.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("telegram replied %d", response.StatusCode)
	}
	return nil
}

// gradeMark is the word that names the grade in a message. An unknown grade -
// written into the configuration and not caught because the service was started
// without -check - is shown as it was written rather than dropped.
func gradeMark(g Grade) string {
	if name := GradeNames[g]; name != "" {
		return name
	}
	return string(g)
}

// formatTelegramLine builds the readable line of one event.
func formatTelegramLine(event Event) string {
	grade := gradeOrDerive(event)
	line := fmt.Sprintf("[%s] %s / %s", gradeMark(grade), event.Source, event.Kind)
	if event.IP != "" {
		line += "\naddress: " + event.IP
		if score := event.Details["actor_score"]; score != "" {
			line += " (score " + score + ")"
		}
	}
	if event.Subject != "" {
		line += "\nsubject: " + sampleOf(event.Subject, 200)
	}
	if event.Count > 1 {
		line += fmt.Sprintf("\nrepeats: %d", event.Count)
	}
	for _, key := range []string{"owner", "country", "ptr", "abuse_contact", "tor_exit", "agent", "cmdline", "description"} {
		if value := event.Details[key]; value != "" {
			line += fmt.Sprintf("\n%s: %s", key, sampleOf(value, 120))
		}
	}
	return line
}
