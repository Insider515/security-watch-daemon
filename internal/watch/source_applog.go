// Watching the application log: database messages about a failed query parse are
// a sign that an injected value reached SQL.
package watch

import (
	"regexp"
	"strings"
	"time"
)

// dbErrorPatterns - database messages produced by a malformed query. They land
// in the application log and reveal injection that arrived in a POST body, which
// the web server log does not contain. A separate pattern catches the sign that
// the query did run and returned system tables.
var dbErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`you have an error in your sql syntax`),
	regexp.MustCompile(`er_parse_error|er_bad_field_error|er_wrong_value_count`),
	regexp.MustCompile(`sqlstate\[\w+\]`),
	regexp.MustCompile(`unknown column '.*' in`),
	regexp.MustCompile(`pq: syntax error at or near`),
	regexp.MustCompile(`sqlite error|sql: converting argument`),
}

// AppLogWatcher parses the application log.
type AppLogWatcher struct {
	cfg    AppLogConfig
	extra  []*regexp.Regexp
	canary *RuntimeCanary
	emit   func(Event)
}

// NewAppLogWatcher creates the application log watcher. Extra substrings from
// the configuration are added to the built-in set.
func NewAppLogWatcher(cfg AppLogConfig, canary *RuntimeCanary, emit func(Event)) *AppLogWatcher {
	extra := make([]*regexp.Regexp, 0, len(cfg.ExtraPatterns))
	for _, raw := range cfg.ExtraPatterns {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		compiled, err := regexp.Compile("(?i)" + regexp.QuoteMeta(raw))
		if err != nil {
			continue
		}
		extra = append(extra, compiled)
	}
	if canary == nil {
		canary = NewRuntimeCanary(nil)
	}
	return &AppLogWatcher{cfg: cfg, extra: extra, canary: canary, emit: emit}
}

// Handle parses one line of the application log.
func (a *AppLogWatcher) Handle(line string) {
	if line == "" {
		return
	}
	lower := strings.ToLower(line)

	// A canary token in the application log: a value that cannot be obtained
	// anywhere except by reading files on the server.
	if token, found := a.canary.Match(line); found {
		a.emit(Event{
			At: time.Now(), Source: "app", Kind: "canary_used", Severity: SevAlert,
			Subject: sampleOf(line, 300), Count: 1,
			Details: map[string]string{"token": sampleOf(token, 12)},
		})
		return
	}

	builtin := dbErrorPatterns
	if a.cfg.DisableBuiltinPatterns {
		// Where the application logs database errors as a matter of course, the
		// built-in set only adds noise and is turned off by configuration.
		builtin = nil
	}
	for _, pattern := range builtin {
		if pattern.MatchString(lower) {
			a.emit(Event{
				At: time.Now(), Source: "app", Kind: "db_error", Severity: SevAlert,
				Subject: sampleOf(line, 300), Count: 1,
				Details: map[string]string{"hint": "SQL error in the application log: check whose input caused it"},
			})
			return
		}
	}
	for _, pattern := range a.extra {
		if pattern.MatchString(line) {
			a.emit(Event{
				At: time.Now(), Source: "app", Kind: "custom_pattern", Severity: SevWarn,
				Subject: sampleOf(line, 300), Count: 1,
			})
			return
		}
	}

	// Whether to look for injection signatures in the application log. Enabled
	// separately: in some logs such lines appear as a matter of course.
	if !a.cfg.DetectInjection {
		return
	}
	if sig, found := matchInjection(line); found {
		a.emit(Event{
			At: time.Now(), Source: "app", Kind: sig.Kind, Severity: sig.Severity,
			Subject: sampleOf(line, 300), Count: 1,
			Details: map[string]string{"source": "application log"},
		})
	}
}
