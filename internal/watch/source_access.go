// Watching the web server log: path scanning, access guessing, request floods
// from one address.
package watch

import (
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// accessLine is a parsed web server log line.
type accessLine struct {
	IP     string
	At     time.Time
	Method string
	Path   string
	Status int
	Agent  string
	// Extra holds the additional fields at the end of the line when they were
	// added to log_format (TLS fingerprint, real client address and the like).
	Extra []string
	Valid bool
}

// parseCombined parses a line in the combined format (nginx, apache):
//
//	1.2.3.4 - - [30/Oct/2026:22:13:00 +0100] "POST /api/pay HTTP/2.0" 404 153 "-" "UA"
//
// A line of a different shape is marked as unparsed.
func parseCombined(line string) accessLine {
	out := accessLine{}
	if line == "" {
		return out
	}
	// The address comes before the first space.
	space := strings.IndexByte(line, ' ')
	if space <= 0 {
		return out
	}
	out.IP = line[:space]

	// The time sits in square brackets.
	openBracket := strings.IndexByte(line, '[')
	closeBracket := strings.IndexByte(line, ']')
	if openBracket > 0 && closeBracket > openBracket {
		if at, err := time.Parse("02/Jan/2006:15:04:05 -0700", line[openBracket+1:closeBracket]); err == nil {
			out.At = at
		}
	}

	// The request sits in the first quotes after the time.
	rest := line
	if closeBracket > 0 && closeBracket+1 < len(line) {
		rest = line[closeBracket+1:]
	}
	firstQuote := strings.IndexByte(rest, '"')
	if firstQuote < 0 {
		return out
	}
	secondQuote := strings.IndexByte(rest[firstQuote+1:], '"')
	if secondQuote < 0 {
		return out
	}
	request := rest[firstQuote+1 : firstQuote+1+secondQuote]
	parts := strings.Fields(request)
	if len(parts) >= 2 {
		out.Method = parts[0]
		out.Path = parts[1]
	}

	// The status code is the first number after the request's closing quote.
	tail := rest[firstQuote+1+secondQuote+1:]
	for _, field := range strings.Fields(tail) {
		if code, err := strconv.Atoi(field); err == nil && code >= 100 && code < 600 {
			out.Status = code
			break
		}
	}

	// The quoted fields after the status code: referrer, client and whatever was
	// appended to log_format after them.
	quoted := quotedFields(tail)
	if len(quoted) >= 2 {
		out.Agent = quoted[1]
		if len(quoted) > 2 {
			out.Extra = quoted[2:]
		}
	}

	out.Valid = out.IP != "" && out.Path != ""
	return out
}

// quotedFields returns the contents of every pair of quotes in order: referrer,
// client and the appended fields.
func quotedFields(text string) []string {
	fields := []string{}
	for {
		open := strings.IndexByte(text, '"')
		if open < 0 {
			return fields
		}
		rest := text[open+1:]
		close := strings.IndexByte(rest, '"')
		if close < 0 {
			return fields
		}
		fields = append(fields, rest[:close])
		text = rest[close+1:]
	}
}

// parseByRegexp parses a line with a custom pattern using named groups. Group
// names: ip, time, method, path, status, agent; other groups land in the extra
// fields.
func parseByRegexp(expression *regexp.Regexp, line string) accessLine {
	out := accessLine{}
	match := expression.FindStringSubmatch(line)
	if match == nil {
		return out
	}
	for i, name := range expression.SubexpNames() {
		if i == 0 || name == "" || i >= len(match) {
			continue
		}
		value := match[i]
		switch name {
		case "ip":
			out.IP = value
		case "method":
			out.Method = value
		case "path":
			out.Path = value
		case "agent":
			out.Agent = value
		case "status":
			if code, err := strconv.Atoi(value); err == nil {
				out.Status = code
			}
		case "time":
			for _, layout := range []string{
				"02/Jan/2006:15:04:05 -0700",
				time.RFC3339,
				"2006-01-02T15:04:05Z07:00",
				"2006-01-02 15:04:05",
			} {
				if parsed, err := time.Parse(layout, value); err == nil {
					out.At = parsed
					break
				}
			}
		default:
			out.Extra = append(out.Extra, value)
		}
	}
	out.Valid = out.IP != "" && out.Path != ""
	return out
}

// AccessWatcher watches the web server log. It counts requests from one address
// in one-minute windows and emits an event when a threshold on 404, 401/403 or
// 5xx responses, or on the request count, is exceeded. The count restarts with
// every new minute.
type AccessWatcher struct {
	cfg      AccessConfig
	canary   *RuntimeCanary
	counters *minuteTracker
	custom   *regexp.Regexp
	extraSig []signature
	emit     func(Event)
}

// NewAccessWatcher creates the web server log watcher.
func NewAccessWatcher(cfg AccessConfig, canary *RuntimeCanary, emit func(Event)) *AccessWatcher {
	if canary == nil {
		canary = NewRuntimeCanary(nil)
	}
	watcher := &AccessWatcher{cfg: cfg, canary: canary, counters: newMinuteTracker(), emit: emit}
	// Custom line parsing when the log format is not combined.
	if strings.TrimSpace(cfg.Regexp) != "" {
		if compiled, err := regexp.Compile(cfg.Regexp); err == nil {
			watcher.custom = compiled
		} else {
			slog.Warn("the log parsing pattern was rejected, falling back to the combined format", slog.Any("error", err))
		}
	}
	// Custom injection signatures in addition to the built-in ones.
	watcher.extraSig = compileExtraSignatures(cfg.ExtraInjectionPatterns)
	return watcher
}

// realIP returns the client address: the one from the extra field named in
// real_ip_field when it is set and parses as an address, otherwise the first
// field of the line. Behind a reverse proxy the first field is the proxy.
func (a *AccessWatcher) realIP(parsed accessLine) string {
	if a.cfg.RealIPField == "" {
		return parsed.IP
	}
	for i, name := range a.cfg.ExtraFields {
		if name != a.cfg.RealIPField || i >= len(parsed.Extra) {
			continue
		}
		candidate := strings.TrimSpace(parsed.Extra[i])
		// A proxy may leave the field empty or write a list: the first address
		// of a list is the client.
		if comma := strings.IndexByte(candidate, ','); comma > 0 {
			candidate = strings.TrimSpace(candidate[:comma])
		}
		if net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	return parsed.IP
}

// detailsFor assembles the event details: status code, request method, client
// and the extra log fields.
func (a *AccessWatcher) detailsFor(parsed accessLine) map[string]string {
	details := map[string]string{
		"status": strconv.Itoa(parsed.Status),
		"method": parsed.Method,
		"agent":  parsed.Agent,
	}
	for i, name := range a.cfg.ExtraFields {
		if name == "" || i >= len(parsed.Extra) {
			continue
		}
		details[name] = parsed.Extra[i]
	}
	return details
}

// Handle parses a log line and emits events. The order of checks: trap path,
// canary token, suspicious path, injection signatures, thresholds.
func (a *AccessWatcher) Handle(line string) {
	parsed := a.parse(line)
	if !parsed.Valid {
		return
	}
	parsed.IP = a.realIP(parsed)
	at := parsed.At
	if at.IsZero() {
		at = time.Now()
	}

	a.checkHoneypot(parsed, at)
	a.checkCanary(parsed, at)
	a.checkSuspiciousPath(parsed, at)
	a.checkInjection(parsed, at)
	a.checkThresholds(parsed, at)
}

// parse uses the custom pattern when one is set, otherwise the combined
// format.
func (a *AccessWatcher) parse(line string) accessLine {
	if a.custom != nil {
		return parseByRegexp(a.custom, line)
	}
	return parseCombined(line)
}

// checkHoneypot: a trap path. No such path exists on the site, so whoever asked
// for it did not see it but guessed it - no thresholds needed.
func (a *AccessWatcher) checkHoneypot(parsed accessLine, at time.Time) {
	for _, trap := range a.cfg.HoneypotPaths {
		if trap != "" && strings.HasPrefix(parsed.Path, trap) {
			a.emit(Event{
				At: at, Source: "access", Kind: "honeypot_hit", Severity: SevAlert,
				IP: parsed.IP, Subject: parsed.Path, Count: 1,
				Details: a.detailsFor(parsed),
			})
			return
		}
	}
}

// checkCanary: canary credentials in the request. There is nowhere to get them
// except by reading files on the server.
func (a *AccessWatcher) checkCanary(parsed accessLine, at time.Time) {
	token, found := a.canary.Match(parsed.Path)
	if !found {
		return
	}
	a.emit(Event{
		At: at, Source: "access", Kind: "canary_used", Severity: SevAlert,
		IP: parsed.IP, Subject: sampleOf(parsed.Path, 200), Count: 1,
		Details: map[string]string{"token": sampleOf(token, 12), "agent": parsed.Agent},
	})
}

// checkSuspiciousPath: paths that are suspicious to request in themselves.
func (a *AccessWatcher) checkSuspiciousPath(parsed accessLine, at time.Time) {
	for _, needle := range a.cfg.SuspiciousPaths {
		if needle != "" && strings.Contains(parsed.Path, needle) {
			a.emit(Event{
				At: at, Source: "access", Kind: "suspicious_path", Severity: SevWarn,
				IP: parsed.IP, Subject: parsed.Path, Count: 1,
				Details: a.detailsFor(parsed),
			})
			return
		}
	}
}

// checkInjection: injection signatures in the request. Reported on the first
// occurrence: a single union select in a URL is already an attempt, not noise.
func (a *AccessWatcher) checkInjection(parsed accessLine, at time.Time) {
	if !a.cfg.DetectInjection {
		return
	}
	sig, found := matchInjectionWith(parsed.Path, a.extraSig, a.cfg.DisabledSignatures)
	if !found {
		return
	}
	a.emit(Event{
		At: at, Source: "access", Kind: sig.Kind, Severity: sig.Severity,
		IP: parsed.IP, Subject: sampleOf(parsed.Path, 200), Count: 1,
		Details: a.detailsFor(parsed),
	})
}

// checkThresholds counts requests per minute and emits an event exactly at the
// threshold: merging repeats takes care of the rest.
func (a *AccessWatcher) checkThresholds(parsed accessLine, at time.Time) {
	total := a.counters.Add(parsed.IP, at, "total")
	notFound, denied, failed := 0, 0, 0
	switch {
	case parsed.Status == 404:
		notFound = a.counters.Add(parsed.IP, at, "not_found")
	case parsed.Status == 401 || parsed.Status == 403:
		denied = a.counters.Add(parsed.IP, at, "denied")
	case parsed.Status >= 500:
		failed = a.counters.Add(parsed.IP, at, "failed")
	}

	for _, rule := range []struct {
		value, limit int
		kind         string
		severity     Severity
		subject      string
	}{
		{notFound, a.cfg.NotFoundPerMinute, "path_scan", SevWarn, parsed.Path},
		{denied, a.cfg.DeniedPerMinute, "access_denied_burst", SevWarn, parsed.Path},
		{failed, a.cfg.ErrorsPerMinute, "server_error_burst", SevAlert, sampleOf(parsed.Path, 200)},
		{total, a.cfg.RequestsPerMinute, "request_flood", SevWarn, ""},
	} {
		if rule.limit > 0 && rule.value == rule.limit {
			a.emit(Event{
				At: at, Source: "access", Kind: rule.kind, Severity: rule.severity,
				IP: parsed.IP, Subject: rule.subject, Count: rule.value,
				Details: a.detailsFor(parsed),
			})
		}
	}
}

// Sweep drops counters of past minutes.
func (a *AccessWatcher) Sweep(now time.Time) { a.counters.Sweep(now) }
