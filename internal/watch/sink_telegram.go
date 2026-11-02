// Sending events to Telegram: the fastest way to get a trace off the server
// before whoever broke in reaches it.
package watch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TelegramConfig - the bot and the recipient.
type TelegramConfig struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
	ChatID  string `json:"chat_id"`
	// Messages are sent only for events at this level or above.
	MinSeverity Severity `json:"min_severity"`
	Timeout     Duration `json:"timeout"`
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
}

// NewTelegramSink creates the sink.
func NewTelegramSink(cfg TelegramConfig, host string) *TelegramSink {
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
	}
}

// Send delivers the events as a single message.
func (t *TelegramSink) Send(events []Event) error {
	lines := []string{}
	for _, event := range events {
		if severityRank(event.Severity) < severityRank(t.cfg.MinSeverity) {
			continue
		}
		lines = append(lines, formatTelegramLine(event))
	}
	if len(lines) == 0 {
		return nil
	}

	text := fmt.Sprintf("security-watch %s\n\n%s", t.host, strings.Join(lines, "\n\n"))
	// Telegram refuses messages longer than 4096 characters.
	if len([]rune(text)) > 3900 {
		runes := []rune(text)
		text = string(runes[:3900]) + "\n..."
	}

	payload := map[string]string{
		"chat_id":                  t.cfg.ChatID,
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

// Name is used in the log.
func (t *TelegramSink) Name() string { return "telegram" }

// formatTelegramLine builds the readable line of one event.
func formatTelegramLine(event Event) string {
	mark := "[info]"
	switch event.Severity {
	case SevWarn:
		mark = "[warning]"
	case SevAlert:
		mark = "[alert]"
	}
	line := fmt.Sprintf("%s %s / %s", mark, event.Source, event.Kind)
	if event.IP != "" {
		line += "\naddress: " + event.IP
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
