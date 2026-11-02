package watch

import (
	"regexp"
	"testing"
	"time"
)

// A custom log format: the service must understand more than combined,
// otherwise it only fits nginx with default settings.
func TestParseByCustomRegexp(t *testing.T) {
	expression := regexp.MustCompile(`^(?P<time>\S+) (?P<ip>\S+) "(?P<method>\w+) (?P<path>\S+)" (?P<status>\d+) "(?P<agent>[^"]*)"$`)
	line := `2026-10-31T15:04:05Z 203.0.113.9 "POST /api/login" 401 "curl/8.4"`

	got := parseByRegexp(expression, line)

	if !got.Valid {
		t.Fatalf("the line must parse: %+v", got)
	}
	if got.IP != "203.0.113.9" || got.Path != "/api/login" || got.Status != 401 {
		t.Errorf("parsed incorrectly: %+v", got)
	}
	if got.Agent != "curl/8.4" || got.Method != "POST" {
		t.Errorf("client or request method: %+v", got)
	}
	if got.At.IsZero() {
		t.Errorf("the time was not parsed")
	}
}

// The watcher reads the log with the custom pattern when one is set.
func TestAccessWatcherUsesCustomRegexp(t *testing.T) {
	events := []Event{}
	watcher := NewAccessWatcher(AccessConfig{
		Regexp:            `^(?P<ip>\S+) (?P<method>\w+) (?P<path>\S+) (?P<status>\d+)$`,
		NotFoundPerMinute: 2, DeniedPerMinute: 99, RequestsPerMinute: 99, ErrorsPerMinute: 99,
	}, nil, func(e Event) { events = append(events, e) })

	watcher.Handle("198.51.100.4 GET /nope 404")
	watcher.Handle("198.51.100.4 GET /nope2 404")

	if len(events) != 1 || events[0].Kind != "path_scan" {
		t.Fatalf("the custom log format was not parsed: %+v", events)
	}
}

// A custom injection signature is added by configuration, a built-in one is
// turned off the same way.
func TestCustomAndDisabledSignatures(t *testing.T) {
	extra := compileExtraSignatures([]CustomSignature{
		{Kind: "custom_backdoor", Pattern: `/cgi-bin/\w+\.cgi\?cmd=`, Severity: SevAlert},
	})

	if sig, found := matchInjectionWith("/cgi-bin/shell.cgi?cmd=ls", extra, nil); !found || sig.Kind != "custom_backdoor" {
		t.Errorf("the custom signature did not fire: %+v %v", sig, found)
	}
	// A built-in signature can be disabled when it is noisy on this traffic.
	if _, found := matchInjectionWith("/p?id=1 union select 1", nil, []string{"sqli_union"}); found {
		t.Errorf("a disabled signature must not fire")
	}
	if _, found := matchInjectionWith("/p?id=1 union select 1", nil, nil); !found {
		t.Errorf("without being disabled the signature must work")
	}
}

// Suppression rules: your own monitoring system requests paths that do not
// exist, and that is no reason to wake the operator.
func TestFilterIgnoreRules(t *testing.T) {
	filter := NewFilter([]IgnoreRule{
		{Source: "access", Kind: "path_scan", IP: "10.0.0.7"},
		{Kind: "file_changed", SubjectContains: "/var/cache/"},
		{}, // an empty rule would silence everything and must be ignored
	}, nil)

	if _, keep := filter.Apply(Event{Source: "access", Kind: "path_scan", IP: "10.0.0.7"}); keep {
		t.Errorf("an event from your own monitoring must be suppressed")
	}
	if _, keep := filter.Apply(Event{Source: "access", Kind: "path_scan", IP: "203.0.113.1"}); !keep {
		t.Errorf("another address must not be suppressed")
	}
	if _, keep := filter.Apply(Event{Kind: "file_changed", Subject: "/var/cache/app/x"}); keep {
		t.Errorf("a change in the cache must be suppressed")
	}
	if _, keep := filter.Apply(Event{Kind: "file_changed", Subject: "/opt/myapp/app/x.js"}); !keep {
		t.Errorf("a change in the code must not be suppressed")
	}
}

// The event severity is adjusted by configuration: for one installation an SSH
// login is routine, for another it is an alarm.
func TestFilterSeverityOverrides(t *testing.T) {
	filter := NewFilter(nil, map[string]Severity{"ssh_login": SevInfo, "path_scan": SevAlert})

	got, keep := filter.Apply(Event{Kind: "ssh_login", Severity: SevAlert})
	if !keep || got.Severity != SevInfo {
		t.Errorf("the severity was not lowered: %+v", got)
	}
	got, _ = filter.Apply(Event{Kind: "path_scan", Severity: SevWarn})
	if got.Severity != SevAlert {
		t.Errorf("the severity was not raised: %+v", got)
	}
}

// An unknown database is rejected with a clear message instead of a crash.
func TestDBWatcherUnknownDriver(t *testing.T) {
	_, err := NewDBWatcher(DBConfig{Enabled: true, DSN: "x", Driver: "oracle"}, t.TempDir(), func(Event) {})
	if err == nil {
		t.Fatalf("an unknown database must be rejected")
	}
}

// A duration in the configuration is read in human-readable form.
func TestDurationParsing(t *testing.T) {
	d := Duration{}
	if err := d.UnmarshalJSON([]byte(`"90s"`)); err != nil || d.Duration != 90*time.Second {
		t.Errorf("the duration was parsed incorrectly: %v %v", d.Duration, err)
	}
	if err := d.UnmarshalJSON([]byte(`"winter"`)); err == nil {
		t.Errorf("an invalid duration must be rejected")
	}
}
