package watch

import (
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

// The HTTP sink delivers the events in one request and reports a refusal.
func TestWebhookSink(t *testing.T) {
	var received struct {
		Host   string  `json:"host"`
		Events []Event `json:"events"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Watch-Token") != "secret" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	sink := &WebhookSink{host: "srv", cfg: WebhookConfig{
		URL: server.URL, Headers: map[string]string{"X-Watch-Token": "secret"}, Timeout: Duration{5 * time.Second},
	}}
	err := sink.Send([]Event{{At: time.Now(), Source: "trap", Kind: "trap_hit", IP: "203.0.113.1"}})

	if err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if received.Host != "srv" || len(received.Events) != 1 || received.Events[0].Kind != "trap_hit" {
		t.Errorf("the wrong thing was received: %+v", received)
	}

	// A refusal from the receiver must come back as an error, otherwise the event
	// disappears silently.
	bad := &WebhookSink{host: "srv", cfg: WebhookConfig{URL: server.URL, Timeout: Duration{time.Second}}}
	if err := bad.Send([]Event{{Kind: "x"}}); err == nil {
		t.Errorf("a refusal from the receiver must be visible")
	}
}

// Telegram: events at or above the configured severity go out in one message.
func TestTelegramSink(t *testing.T) {
	var got map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink := NewTelegramSink(TelegramConfig{Token: "token", ChatID: "42", MinSeverity: SevWarn}, "srv", t.TempDir())
	sink.apiBase = server.URL

	err := sink.Send([]Event{
		{At: time.Now(), Source: "self", Kind: "heartbeat", Severity: SevInfo},
		{At: time.Now(), Source: "trap", Kind: "trap_hit", Severity: SevAlert, IP: "203.0.113.2", Subject: "/.env"},
	})

	if err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if got["chat_id"] != "42" {
		t.Errorf("wrong chat: %+v", got)
	}
	if !strings.Contains(got["text"], "trap_hit") {
		t.Errorf("the important event did not make it into the message: %q", got["text"])
	}
	if strings.Contains(got["text"], "heartbeat") {
		t.Errorf("an event below the configured severity must not be sent: %q", got["text"])
	}
}

// The set of sinks: a failure of one does not get in the way of the others.
func TestMultiSinkKeepsGoing(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	sinks := NewMultiSink(SinksConfig{
		File:    logPath,
		Webhook: WebhookConfig{Enabled: true, URL: server.URL, Timeout: Duration{time.Second}},
	}, "srv", dir)

	if sinks.Empty() {
		t.Fatal("the sinks must have been assembled")
	}
	_ = sinks.Send([]Event{{At: time.Now(), Source: "access", Kind: "path_scan"}})

	// The file received the event despite the network sink failing.
	raw, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(raw), "path_scan") {
		t.Fatalf("the file sink should have worked: %v %q", err, string(raw))
	}
	// What could not be delivered landed in the queue and waits there.
	if _, err := os.Stat(filepath.Join(dir, "outbox.webhook.jsonl")); err != nil {
		t.Errorf("undelivered events must land in the queue: %v", err)
	}
}
