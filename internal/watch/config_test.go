package watch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Reading the configuration: what is set comes from the file, what is not comes
// from the defaults.
func TestLoadConfigAndDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
	  "host": "srv-1",
	  "dedup_window": "3m",
	  "access_log": { "enabled": true, "path": "/var/log/nginx/access.log", "not_found_per_minute": 11 },
	  "sinks": { "file": "/var/log/security-watch/events.jsonl" }
	}`
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("the configuration must parse: %v", err)
	}
	if cfg.Host != "srv-1" || cfg.DedupWindow.Duration != 3*time.Minute {
		t.Errorf("what was set was not read: %+v", cfg.Host)
	}
	if cfg.Access.NotFoundPerMinute != 11 {
		t.Errorf("the configured threshold was overwritten by a default: %d", cfg.Access.NotFoundPerMinute)
	}
	// Defaults.
	if cfg.StateDir != "/var/lib/security-watch" || cfg.Auth.Path != "/var/log/auth.log" {
		t.Errorf("the defaults were not filled in: %+v", cfg.StateDir)
	}
	if cfg.Access.RequestsPerMinute != 600 || cfg.Sinks.FileMaxMB != 50 {
		t.Errorf("the numeric defaults were not filled in: %+v", cfg.Access)
	}
	if cfg.Actors.DigestInterval.Duration != time.Hour || cfg.Self.CheckInterval.Duration != time.Minute {
		t.Errorf("the default durations were not filled in")
	}
}

// An invalid configuration file is rejected with a clear message.
func TestLoadConfigErrors(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.json")
	os.WriteFile(broken, []byte(`{"host": `), 0o640)

	if _, err := LoadConfig(broken); err == nil {
		t.Errorf("a corrupted file must be rejected")
	}
	if _, err := LoadConfig(filepath.Join(dir, "no-such-file.json")); err == nil {
		t.Errorf("a missing file must be rejected")
	}
}

// The configuration check catches meaningless combinations before startup.
func TestCheckConfigFindsProblems(t *testing.T) {
	cfg := &Config{}
	cfg.Access.Enabled = true        // no path is set
	cfg.Canary.Enabled = true        // no tokens are set
	cfg.Blocking.Auto.Enabled = true // while blocking itself is off
	cfg.DB.Enabled = true
	cfg.DB.DSN = ""
	cfg.DB.Checks = []DBCheck{{Name: "bad one", Query: "DELETE FROM users"}}
	cfg.Access.Regexp = "([("
	cfg.applyDefaults()

	err := CheckConfig(cfg)
	if err == nil {
		t.Fatal("an unusable configuration must be rejected")
	}
	text := err.Error()
	for _, expected := range []string{"access_log", "canary", "blocking.auto", "db", "regexp"} {
		if !strings.Contains(text, expected) {
			t.Errorf("the explanation does not mention %q: %s", expected, text)
		}
	}
}

// A sensible configuration is accepted.
func TestCheckConfigAcceptsSaneSetup(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	os.WriteFile(logPath, []byte(""), 0o640)

	cfg := &Config{}
	cfg.Access.Enabled = true
	cfg.Access.Path = logPath
	cfg.Sinks.File = filepath.Join(dir, "events.jsonl")
	cfg.applyDefaults()

	if err := CheckConfig(cfg); err != nil {
		t.Fatalf("a sensible configuration must be accepted: %v", err)
	}
}

// The service is assembled from the configuration and performs a single pass
// without continuous watching.
func TestServiceScanOnce(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "app")
	os.MkdirAll(watched, 0o750)
	os.WriteFile(filepath.Join(watched, "a.js"), []byte("one"), 0o640)

	cfg := &Config{StateDir: filepath.Join(dir, "state")}
	cfg.Sinks.File = filepath.Join(dir, "events.jsonl")
	cfg.Files.Enabled = true
	cfg.Files.Paths = []string{watched}
	cfg.applyDefaults()

	service, err := NewService(cfg, filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("the service must assemble: %v", err)
	}
	defer service.Close()

	service.ScanOnce() // the first pass remembers
	os.WriteFile(filepath.Join(watched, "a.js"), []byte("two"), 0o640)
	service.ScanOnce() // the second notices the replacement

	raw, err := os.ReadFile(cfg.Sinks.File)
	if err != nil || !strings.Contains(string(raw), "file_changed") {
		t.Fatalf("the file replacement must reach the event log: %v %q", err, string(raw))
	}
	// The event went the whole way: it carries a sequence number and a chain hash.
	if !strings.Contains(string(raw), "\"seq\":1") || !strings.Contains(string(raw), "\"hash\":") {
		t.Errorf("the event must carry a number and a hash: %q", string(raw))
	}
}

// Threshold tuning computes them from a real log.
func TestTuneOnSample(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	lines := []string{}
	for i := 0; i < 30; i++ {
		lines = append(lines, `1.2.3.4 - - [31/Oct/2026:10:00:0`+string(rune('0'+i%10))+` +0100] "GET /x HTTP/1.1" 404 10 "-" "bot"`)
	}
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o640)

	if err := Tune(path); err != nil {
		t.Fatalf("tuning must work: %v", err)
	}
	// A log in a foreign format is rejected with an explanation.
	other := filepath.Join(dir, "other.log")
	os.WriteFile(other, []byte("not that format at all\n"), 0o640)
	if err := Tune(other); err == nil {
		t.Errorf("a log in a foreign format must be rejected")
	}
}
