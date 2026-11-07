// The bot's own side: taking commands from the operator in Telegram.
//
// The service asks Telegram for updates itself, so the server needs no address
// reachable from outside and no certificate: nothing has to be opened up for
// the bot to work. Commands are answered only for the people named in the
// configuration by their numeric identifier - to everyone else the bot does not
// reply at all, so silence does not even reveal that the commands exist.
package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// botState is what the bot must remember across a restart: until when silence
// was asked for and which update was the last one taken.
//
// Without the first, a restart would quietly undo a /mute and the chat would
// fill again; without the second, Telegram would hand back the command it has
// not seen confirmed and the bot would carry it out twice. The rest of the
// service keeps its state on disk the same way - the chain, the actors, the
// block list - so the bot does not get its own kind of memory.
type botState struct {
	MutedUntil time.Time `json:"muted_until"`
	Offset     int64     `json:"offset"`

	mu   sync.Mutex
	path string
}

// newBotState reads what was remembered, or starts empty.
func newBotState(stateDir string) *botState {
	state := &botState{path: filepath.Join(stateDir, "bot.state.json")}
	loadJSONState(state.path, state)
	return state
}

// mutedUntil reports until when silence was asked for.
func (s *botState) mutedUntil() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.MutedUntil
}

// setMuted remembers the silence.
func (s *botState) setMuted(until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MutedUntil = until
	saveJSONState(s.path, s, 0o600)
}

// offset returns the number of the last update taken.
func (s *botState) offset() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Offset
}

// setOffset remembers the update as taken.
func (s *botState) setOffset(value int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value <= s.Offset {
		return
	}
	s.Offset = value
	saveJSONState(s.path, s, 0o600)
}

// Bot takes commands and answers them from what the service has collected.
type Bot struct {
	cfg  TelegramConfig
	host string
	sink *TelegramSink

	actors    *ActorStore
	blocklist *Blocklist
	dossier   *DossierStore
	metrics   *Metrics

	client  *http.Client
	apiBase string
	// How long to wait after a failed request. A field rather than a constant
	// so that a test does not have to wait it out for real.
	retryPause time.Duration
	// The number of the last update taken: Telegram repeats an update until it
	// is confirmed by asking for the next one.
	state *botState
}

// NewBot creates the command side of the bot over what the service already
// keeps: the same actors, the same block list, so the chat and the command line
// show one and the same state.
func NewBot(cfg TelegramConfig, host string, sink *TelegramSink,
	actors *ActorStore, blocklist *Blocklist, dossier *DossierStore, metrics *Metrics) *Bot {
	return &Bot{
		cfg: cfg, host: host, sink: sink, state: sink.state,
		actors: actors, blocklist: blocklist, dossier: dossier, metrics: metrics,
		// The request waits for an update for half a minute, so the timeout has
		// to be longer than that wait.
		client:     &http.Client{Timeout: 70 * time.Second},
		apiBase:    sink.apiBase,
		retryPause: 15 * time.Second,
	}
}

// telegramUpdate is the part of an update the bot reads.
type telegramUpdate struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Text string `json:"text"`
		From *struct {
			ID int64 `json:"id"`
		} `json:"from"`
		Chat *struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	} `json:"message"`
}

// Run takes updates until the context is cancelled.
func (b *Bot) Run(ctx context.Context) {
	if len(b.cfg.AllowedUserIDs) == 0 {
		slog.Warn("the bot takes no commands: nobody is allowed in allowed_user_ids")
		return
	}
	slog.Info("the bot is taking commands", slog.Int("allowed", len(b.cfg.AllowedUserIDs)))

	for {
		if ctx.Err() != nil {
			return
		}
		updates, err := b.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("could not get updates", slog.Any("error", err))
			// A pause after a failure: without it a broken link turns into a
			// request loop.
			select {
			case <-ctx.Done():
				return
			case <-time.After(b.retryPause):
			}
			continue
		}
		for _, update := range updates {
			b.handle(update)
		}
	}
}

// poll asks for the updates that came after the last one taken.
func (b *Bot) poll(ctx context.Context) ([]telegramUpdate, error) {
	query := url.Values{}
	query.Set("timeout", "30")
	query.Set("offset", strconv.FormatInt(b.state.offset()+1, 10))
	query.Set("allowed_updates", `["message"]`)
	address := fmt.Sprintf("%s/bot%s/getUpdates?%s", b.apiBase, b.cfg.Token, query.Encode())

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	response, err := b.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return nil, fmt.Errorf("telegram replied %d", response.StatusCode)
	}

	body := struct {
		OK     bool             `json:"ok"`
		Result []telegramUpdate `json:"result"`
	}{}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return nil, err
	}
	if !body.OK {
		return nil, fmt.Errorf("telegram refused the request")
	}
	return body.Result, nil
}

// handle answers one update.
func (b *Bot) handle(update telegramUpdate) {
	b.state.setOffset(update.UpdateID)
	message := update.Message
	if message == nil || message.From == nil || message.Chat == nil {
		return
	}
	if !b.allowed(message.From.ID) {
		// Not a word to anyone else: an answer, even a refusal, would tell a
		// stranger that there is something here to talk to.
		slog.Info("a command from a stranger was ignored", slog.Int64("user", message.From.ID))
		return
	}

	text := strings.TrimSpace(message.Text)
	if text == "" {
		return
	}
	command, argument := splitCommand(text)
	answer := b.answer(command, argument)
	if answer == "" {
		return
	}
	if err := b.sink.post(strconv.FormatInt(message.Chat.ID, 10), answer); err != nil {
		slog.Warn("could not answer the command", slog.Any("error", err))
	}
}

// allowed reports whether this person may use the bot.
func (b *Bot) allowed(userID int64) bool {
	want := strconv.FormatInt(userID, 10)
	for _, allowed := range b.cfg.AllowedUserIDs {
		if strings.TrimSpace(allowed) == want {
			return true
		}
	}
	return false
}

// splitCommand separates the command from its argument and drops the bot name
// that Telegram appends in groups (/status@mybot).
func splitCommand(text string) (string, string) {
	parts := strings.Fields(text)
	if len(parts) == 0 {
		return "", ""
	}
	command := parts[0]
	if at := strings.Index(command, "@"); at > 0 {
		command = command[:at]
	}
	return strings.ToLower(command), strings.Join(parts[1:], " ")
}

// answer builds the reply to a command.
func (b *Bot) answer(command, argument string) string {
	switch command {
	case "/start", "/help":
		return botHelp

	case "/status":
		return b.status()

	case "/actors":
		return b.topActors()

	case "/candidates":
		return b.candidates()

	case "/ip":
		if argument == "" {
			return "An address is needed: /ip 203.0.113.1"
		}
		return b.aboutAddress(argument)

	case "/block":
		if argument == "" {
			return "An address is needed: /block 203.0.113.1"
		}
		if err := b.blocklist.Block(argument); err != nil {
			return "could not block: " + err.Error()
		}
		return "address " + argument + " blocked"

	case "/unblock":
		if argument == "" {
			return "An address is needed: /unblock 203.0.113.1"
		}
		if err := b.blocklist.Unblock(argument); err != nil {
			return "could not unblock: " + err.Error()
		}
		return "address " + argument + " unblocked"

	case "/mute":
		hours := 1
		if value, err := strconv.Atoi(argument); err == nil && value > 0 {
			hours = min(value, 24)
		}
		until := time.Now().Add(time.Duration(hours) * time.Hour)
		b.sink.Mute(until)
		return fmt.Sprintf("silent for %d h, until %s. Undo with /unmute",
			hours, until.Format("15:04 on 02.01"))

	case "/unmute":
		b.sink.Mute(time.Time{})
		return "reporting again"

	case "/settings":
		return b.settings()

	default:
		return "no such command: " + command + ". See /help"
	}
}

// status is what the service sees right now.
func (b *Bot) status() string {
	counts := b.metrics.Snapshot()
	lines := []string{"security-watch " + b.host, ""}
	for _, line := range strings.Split(formatMetrics(counts), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	if until := b.sink.MutedUntil(); !until.IsZero() && until.After(time.Now()) {
		lines = append(lines, "", "silent until "+until.Format("15:04 on 02.01"))
	}
	top := b.actors.Top(3)
	if len(top) > 0 {
		lines = append(lines, "", "most persistent addresses:")
		for _, actor := range top {
			lines = append(lines, fmt.Sprintf("%s - score %d, %d events",
				actor.IP, actor.Score, actor.Events))
		}
	}
	return strings.Join(lines, "\n")
}

// topActors lists the addresses ranked by score.
func (b *Bot) topActors() string {
	items := b.actors.Top(10)
	if len(items) == 0 {
		return "no actors yet"
	}
	lines := []string{"addresses by score:", ""}
	for _, actor := range items {
		line := fmt.Sprintf("%s - %d (%d events)", actor.IP, actor.Score, actor.Events)
		if actor.Country != "" {
			line += ", " + actor.Country
		}
		lines = append(lines, line, sampleOf(describeActor(actor), 120), "")
	}
	return strings.Join(lines, "\n")
}

// candidates lists what the service proposes to block and why.
func (b *Bot) candidates() string {
	items := b.blocklist.Candidates()
	if len(items) == 0 {
		return "no block proposals"
	}
	lines := []string{"proposed for blocking:", ""}
	for _, item := range items {
		mark := ""
		if item.Blocked {
			mark = " [already blocked]"
		}
		lines = append(lines, fmt.Sprintf("%s - %d hits%s", item.IP, item.Count, mark),
			sampleOf(strings.Join(item.Reasons, "; "), 150),
			"block it: /block "+item.IP, "")
	}
	return strings.Join(lines, "\n")
}

// aboutAddress is everything known about one address.
func (b *Bot) aboutAddress(ip string) string {
	lines := []string{ip, ""}
	found := false

	if actor := b.actors.Get(ip); actor != nil {
		found = true
		lines = append(lines,
			fmt.Sprintf("score: %d, events: %d", actor.Score, actor.Events),
			"first seen: "+actor.FirstSeen.Format("15:04 on 02.01.2006"),
			"last seen: "+actor.LastSeen.Format("15:04 on 02.01.2006"))
		if actor.Country != "" {
			lines = append(lines, "country: "+actor.Country)
		}
		if actor.Owner != "" {
			lines = append(lines, "owner: "+actor.Owner)
		}
		kinds := make([]string, 0, len(actor.Kinds))
		for kind, count := range actor.Kinds {
			kinds = append(kinds, fmt.Sprintf("%s %d", kind, count))
		}
		sort.Strings(kinds)
		if len(kinds) > 0 {
			lines = append(lines, "what it did: "+strings.Join(kinds, ", "))
		}
	}

	if item := b.dossier.Get(ip); item != nil {
		found = true
		lines = append(lines, "", fmt.Sprintf("dossier: %d hits", item.Hits))
		if len(item.Paths) > 0 {
			lines = append(lines, "paths: "+sampleOf(strings.Join(item.Paths, " "), 200))
		}
	}

	if !found {
		return "nothing known about " + ip
	}
	lines = append(lines, "", "block it: /block "+ip)
	return strings.Join(lines, "\n")
}

// settings shows what the bot is set to report.
func (b *Bot) settings() string {
	lines := []string{
		"what the bot reports:",
		"",
		"lowest grade: " + GradeNames[b.cfg.Grade()],
		"system trouble: " + yesNo(b.cfg.SystemErrors),
		"attacks only: " + yesNo(b.cfg.IntrusionsOnly),
		"lowest severity: " + string(b.cfg.MinSeverity),
	}
	if b.cfg.MaxPerHour > 0 {
		lines = append(lines, fmt.Sprintf("at most %d messages per hour", b.cfg.MaxPerHour))
	}
	if b.cfg.GroupWindow.Duration > 0 {
		lines = append(lines, "same-kind events held for "+b.cfg.GroupWindow.Duration.String())
	}
	lines = append(lines, "", "grades: warning < minor < significant < critical, and system apart from them",
		"", "changed in /etc/security-watch/config.json, section sinks.telegram")
	return strings.Join(lines, "\n")
}

// yesNo renders a switch for the settings reply.
func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

// botHelp is the reply to /help.
const botHelp = `security-watch bot

Reports attempts to break in. Single repelled attempts are not reported: they
go on around the clock and mean nothing on their own.

/status - what the service sees now
/actors - addresses ranked by score
/candidates - what is proposed for blocking and why
/ip ADDRESS - everything known about an address
/block ADDRESS - block it
/unblock ADDRESS - unblock it
/mute HOURS - stay silent (1 h by default, 24 at most)
/unmute - report again
/settings - what the bot is set to report`
