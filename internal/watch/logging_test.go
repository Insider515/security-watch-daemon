package watch

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// A log collector needs parsing without guesswork, so in the json format every
// record must be a separate parsable object carrying our fields.
func TestSetupLoggingJSON(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := SetupLogging(LogConfig{Format: "json", Level: "info"}, buffer)
	logger.Info("probe", slog.String("field", "value"))

	record := map[string]any{}
	if err := json.Unmarshal(bytes.TrimSpace(buffer.Bytes()), &record); err != nil {
		t.Fatalf("the record does not parse as json: %v (%q)", err, buffer.String())
	}
	if record["msg"] != "probe" || record["field"] != "value" {
		t.Errorf("record fields: %+v", record)
	}
}

// The level cuts off the small stuff: at level=warn informational records do not
// reach the log, otherwise the setting would be useless.
func TestSetupLoggingLevel(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := SetupLogging(LogConfig{Format: "text", Level: "warn"}, buffer)
	logger.Info("this must not get through")
	logger.Warn("this must get through")

	out := buffer.String()
	if strings.Contains(out, "must not") {
		t.Errorf("informational records got through at level warn: %q", out)
	}
	if !strings.Contains(out, "must get through") {
		t.Errorf("the warning did not reach the log: %q", out)
	}
}

// An unknown level and an empty format must not break logging: the log is needed
// even when the configuration has a typo.
func TestSetupLoggingFallback(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := SetupLogging(LogConfig{Format: "", Level: "nonsense"}, buffer)
	logger.Info("probe")
	if !strings.Contains(buffer.String(), "probe") {
		t.Fatalf("with unintelligible settings the log must stay at info level: %q", buffer.String())
	}
}

// The event severity must become the record level: alarms are searched for by
// the ERROR level, not by words in the text.
func TestLogEventSeverityBecomesLevel(t *testing.T) {
	for _, item := range []struct {
		severity Severity
		level    string
	}{
		{SevInfo, "INFO"},
		{SevWarn, "WARN"},
		{SevAlert, "ERROR"},
	} {
		buffer := &bytes.Buffer{}
		SetupLogging(LogConfig{Format: "json", Level: "debug"}, buffer)
		logEvent(Event{
			At: time.Now(), Source: "access", Kind: "path_scan", Severity: item.severity,
			IP: "1.2.3.4", Subject: "/admin", Count: 3, Seq: 7,
		})

		record := map[string]any{}
		if err := json.Unmarshal(bytes.TrimSpace(buffer.Bytes()), &record); err != nil {
			t.Fatalf("the record does not parse: %v", err)
		}
		if record["level"] != item.level {
			t.Errorf("severity %s produced level %v, expected %s", item.severity, record["level"], item.level)
		}
		if record["ip"] != "1.2.3.4" || record["kind"] != "path_scan" || record["seq"] != float64(7) {
			t.Errorf("event fields: %+v", record)
		}
	}
}

// The logging settings must have defaults: without a logging section the service
// still writes a readable log at info level.
func TestLoggingDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	if cfg.Log.Format != "text" || cfg.Log.Level != "info" {
		t.Fatalf("logging defaults: %+v", cfg.Log)
	}
}
