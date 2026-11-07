// Where events go: a file, an HTTP receiver, email. Any combination at once.
package watch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sink is an event sink. A failure of one sink must not get in the way of the
// others, so Send only returns the error and the caller decides what to do.
type Sink interface {
	Send(events []Event) error
	Name() string
}

// errDeferred means the sink refuses to send right now on purpose, not because
// of a failure: the email sink waits out its throttle period. The queue stores
// such events on disk and offers them again later, and the caller does not count
// them as a delivery failure.
var errDeferred = errors.New("delivery deferred until the throttle period passes")

// immediateSink is a sink that can be asked to send regardless of its own
// timing. Used on shutdown so the last batch is not left waiting.
type immediateSink interface {
	SendNow(events []Event) error
}

// MultiSink delivers events to every configured sink.
type MultiSink struct {
	sinks []Sink
	boxes []*Outbox
	// The Telegram sink, kept apart: the bot's command side answers through the
	// same sink, so that the chat and the configuration agree about silence and
	// about what is worth a message.
	telegram *TelegramSink
}

// NewMultiSink assembles the set of sinks from the configuration, skipping the
// disabled ones. Network sinks are wrapped in an on-disk queue so events are not
// lost when the link goes down.
func NewMultiSink(cfg SinksConfig, host, stateDir string) *MultiSink {
	multi := &MultiSink{}
	if cfg.File != "" {
		multi.sinks = append(multi.sinks, &FileSink{
			path:    cfg.File,
			maxSize: int64(cfg.FileMaxMB) * 1024 * 1024,
			keep:    cfg.FileKeep,
		})
	}
	if cfg.Webhook.Enabled && cfg.Webhook.URL != "" {
		boxed := NewOutbox(&WebhookSink{cfg: cfg.Webhook, host: host}, stateDir, cfg.OutboxMax)
		multi.sinks = append(multi.sinks, boxed)
		multi.boxes = append(multi.boxes, boxed)
	}
	if cfg.Telegram.Enabled && cfg.Telegram.Token != "" && len(cfg.Telegram.Recipients()) > 0 {
		telegram := NewTelegramSink(cfg.Telegram, host, stateDir)
		boxed := NewOutbox(telegram, stateDir, cfg.OutboxMax)
		multi.sinks = append(multi.sinks, boxed)
		multi.boxes = append(multi.boxes, boxed)
		multi.telegram = telegram
	}
	if cfg.Email.Enabled && len(cfg.Email.To) > 0 {
		boxed := NewOutbox(NewEmailSink(cfg.Email, host), stateDir, cfg.OutboxMax)
		multi.sinks = append(multi.sinks, boxed)
		multi.boxes = append(multi.boxes, boxed)
	}
	return multi
}

// RetryPending periodically delivers what the queues deferred.
func (m *MultiSink) RetryPending(ctx context.Context, every time.Duration) {
	for _, box := range m.boxes {
		go box.Retry(ctx, every)
	}
}

// Send delivers events to every sink, logs the ones that failed and returns the
// first failure so the caller can count it. A failure of one sink does not keep
// the others from receiving the events: the watcher does not stop because email
// is unreachable.
func (m *MultiSink) Send(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	var failed error
	for _, sink := range m.sinks {
		if err := sink.Send(events); err != nil {
			slog.Warn("sink did not accept the events", slog.String("sink", sink.Name()),
				slog.Int("events", len(events)), slog.Any("error", err))
			if failed == nil {
				failed = fmt.Errorf("%s: %w", sink.Name(), err)
			}
		}
	}
	return failed
}

// Flush makes the sinks that hold events back send them now. Called on
// shutdown: the email sink waits out its throttle period and its events sit in
// the queue, so without this the last batch would wait until the next restart.
func (m *MultiSink) Flush() {
	for _, sink := range m.sinks {
		flusher, ok := sink.(interface{ Flush() error })
		if !ok {
			continue
		}
		if err := flusher.Flush(); err != nil {
			slog.Warn("sink did not accept the last events", slog.String("sink", sink.Name()),
				slog.Any("error", err))
		}
	}
}

// Name is used in the log.
func (m *MultiSink) Name() string {
	names := make([]string, 0, len(m.sinks))
	for _, sink := range m.sinks {
		names = append(names, sink.Name())
	}
	sort.Strings(names)
	return strings.Join(names, "+")
}

// Empty reports that there are no sinks at all - a reason to warn at startup.
func (m *MultiSink) Empty() bool { return len(m.sinks) == 0 }

// Telegram returns the Telegram sink, or nil when it is switched off.
func (m *MultiSink) Telegram() *TelegramSink { return m.telegram }

// FileSink is a line-based log: one event per line as JSON. Works without the
// network. It rotates itself by size instead of relying on an external
// logrotate.
type FileSink struct {
	path    string
	mu      sync.Mutex
	maxSize int64
	keep    int
}

// Send appends the events to the file, rotating it when needed.
func (f *FileSink) Send(events []Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rotateIfNeeded()
	// #nosec G302 G304 -- mode 0640 is deliberate: the event log is read by the
	// group (a log collector) and closed to others; the path comes from the
	// configuration.
	file, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, event := range events {
		line, err := json.Marshal(event)
		if err != nil {
			continue
		}
		if _, err := file.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// rotateIfNeeded renames an oversized log and removes the oldest pieces. Called
// with the lock already held.
func (f *FileSink) rotateIfNeeded() {
	limit := f.maxSize
	if limit <= 0 {
		limit = 50 * 1024 * 1024
	}
	info, err := os.Stat(f.path)
	if err != nil || info.Size() < limit {
		return
	}
	keep := f.keep
	if keep <= 0 {
		keep = 7
	}
	// The oldest piece goes away and the rest shift up: events.jsonl.1 ->
	// events.jsonl.2 and so on.
	_ = os.Remove(fmt.Sprintf("%s.%d", f.path, keep))
	for index := keep - 1; index >= 1; index-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", f.path, index), fmt.Sprintf("%s.%d", f.path, index+1))
	}
	_ = os.Rename(f.path, f.path+".1")
}

// Name is used in the log.
func (f *FileSink) Name() string { return "file" }

// WebhookSink sends a POST with an array of events. Through it the events reach
// another system: a dashboard, a log collector, anything that speaks JSON.
type WebhookSink struct {
	cfg  WebhookConfig
	host string
}

// Send delivers a batch of events in one request.
func (w *WebhookSink) Send(events []Event) error {
	payload := map[string]any{"host": w.host, "events": events}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range w.cfg.Headers {
		request.Header.Set(key, value)
	}
	client := &http.Client{Timeout: w.cfg.Timeout.Duration}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("the receiver replied %d", response.StatusCode)
	}
	return nil
}

// Name is used in the log.
func (w *WebhookSink) Name() string { return "webhook" }

// EmailSink sends email over SMTP using the standard library. Events pile up and
// go out in a single message no more often than the throttle setting allows.
type EmailSink struct {
	cfg      EmailConfig
	host     string
	mu       sync.Mutex
	lastSent time.Time
	now      func() time.Time // replaced in tests
	send     func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error
}

// NewEmailSink creates the email sink.
func NewEmailSink(cfg EmailConfig, host string) *EmailSink {
	return &EmailSink{cfg: cfg, host: host, now: time.Now, send: smtp.SendMail}
}

// Send sends the events in one message, or returns errDeferred while the
// throttle period has not passed. The events are not kept in memory: holding
// them is the job of the on-disk queue, so they survive a restart.
func (e *EmailSink) Send(events []Event) error {
	batch := make([]Event, 0, len(events))
	for _, event := range events {
		if severityRank(event.Severity) >= severityRank(e.cfg.MinSeverity) {
			batch = append(batch, event)
		}
	}
	if len(batch) == 0 {
		return nil
	}

	e.mu.Lock()
	if e.now().Sub(e.lastSent) < e.cfg.Throttle.Duration {
		e.mu.Unlock()
		return errDeferred
	}
	e.lastSent = e.now()
	e.mu.Unlock()

	return e.deliver(batch)
}

// SendNow sends the events regardless of the throttle period. Used on shutdown.
func (e *EmailSink) SendNow(events []Event) error {
	batch := make([]Event, 0, len(events))
	for _, event := range events {
		if severityRank(event.Severity) >= severityRank(e.cfg.MinSeverity) {
			batch = append(batch, event)
		}
	}
	if len(batch) == 0 {
		return nil
	}
	e.mu.Lock()
	e.lastSent = e.now()
	e.mu.Unlock()
	return e.deliver(batch)
}

// deliver builds the message and hands it to the SMTP server.
func (e *EmailSink) deliver(events []Event) error {
	subject := fmt.Sprintf("[security-watch] %s: %d events", e.host, len(events))
	var body strings.Builder
	body.WriteString(fmt.Sprintf("Server: %s\nEvents: %d\n\n", e.host, len(events)))
	for _, event := range events {
		body.WriteString(event.At.Format(time.RFC3339))
		body.WriteString("  ")
		body.WriteString(event.String())
		body.WriteString("\n")
	}
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		e.cfg.From, strings.Join(e.cfg.To, ", "), subject, body.String())

	addr := net.JoinHostPort(e.cfg.Host, fmt.Sprintf("%d", e.cfg.Port))
	var auth smtp.Auth
	if e.cfg.User != "" {
		auth = smtp.PlainAuth("", e.cfg.User, e.cfg.Pass, e.cfg.Host)
	}
	return e.send(addr, auth, e.cfg.From, e.cfg.To, []byte(message))
}

// Name is used in the log.
func (e *EmailSink) Name() string { return "email" }

// severityRank turns a level into a number so levels can be compared.
func severityRank(s Severity) int {
	switch s {
	case SevAlert:
		return 3
	case SevWarn:
		return 2
	case SevInfo:
		return 1
	default:
		return 0
	}
}
