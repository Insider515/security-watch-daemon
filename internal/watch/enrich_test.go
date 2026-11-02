package watch

import (
	"testing"
	"time"
)

// Disabled enrichment leaves the event alone: the service must work without any
// outside queries.
func TestEnricherDisabled(t *testing.T) {
	enricher := NewEnricher(EnrichConfig{Enabled: false})
	event := Event{IP: "8.8.8.8", Details: map[string]string{"agent": "bot"}}

	got := enricher.Apply(event)

	if len(got.Details) != 1 {
		t.Errorf("the details must not change: %+v", got.Details)
	}
}

// Internal addresses are not looked up: there is nothing to ask about them.
func TestEnricherSkipsPrivate(t *testing.T) {
	enricher := NewEnricher(EnrichConfig{Enabled: true, ReverseDNS: true, RDAP: true})
	before := time.Now()

	got := enricher.Apply(Event{IP: "10.0.0.5"})

	if time.Since(before) > time.Second {
		t.Errorf("an internal address must cause no outside queries")
	}
	if _, has := got.Details["ptr"]; has {
		t.Errorf("an internal address must carry no facts: %+v", got.Details)
	}
}

// Facts already in memory are put into the event details.
func TestEnricherAppliesCachedFacts(t *testing.T) {
	enricher := NewEnricher(EnrichConfig{Enabled: true, CacheTTL: Duration{time.Hour}})
	enricher.cache["203.0.113.5"] = ipFacts{
		PTR: "scanner.example.net", Network: "NET-203-0-113-0", Owner: "Example Hosting",
		Country: "NL", Abuse: "abuse@example.net", Tor: true, at: time.Now(),
	}

	got := enricher.Apply(Event{IP: "203.0.113.5", Kind: "path_scan"})

	if got.Details["ptr"] != "scanner.example.net" {
		t.Errorf("reverse name: %q", got.Details["ptr"])
	}
	if got.Details["owner"] != "Example Hosting" || got.Details["country"] != "NL" {
		t.Errorf("network owner: %+v", got.Details)
	}
	if got.Details["abuse_contact"] != "abuse@example.net" {
		t.Errorf("abuse contact: %+v", got.Details)
	}
	if got.Details["tor_exit"] != "yes" {
		t.Errorf("Tor membership: %+v", got.Details)
	}
}

// Parsing the abuse contact out of the registry answer.
func TestFirstEmailFromVcard(t *testing.T) {
	vcard := []any{
		"vcard",
		[]any{
			[]any{"version", map[string]any{}, "text", "4.0"},
			[]any{"fn", map[string]any{}, "text", "Abuse Team"},
			[]any{"email", map[string]any{}, "text", "abuse@example.net"},
		},
	}

	if got := firstEmailFromVcard(vcard); got != "abuse@example.net" {
		t.Errorf("got %q", got)
	}
	if got := firstEmailFromVcard([]any{"garbage"}); got != "" {
		t.Errorf("nothing must be extracted from garbage, got %q", got)
	}
}

// A canary token: a value from the decoy configuration file found in a request.
func TestCanaryMatch(t *testing.T) {
	canary := NewCanary(CanaryConfig{Enabled: true, Tokens: []string{"CANARY_7f3b91e4d2", "ab"}})

	if token, found := canary.Match("/api/login?key=CANARY_7f3b91e4d2"); !found || token != "CANARY_7f3b91e4d2" {
		t.Errorf("the token did not fire: %q %v", token, found)
	}
	if _, found := canary.Match("/dashboard/users"); found {
		t.Errorf("a token must not fire on an ordinary path")
	}
	// Short values are dropped: they match by accident too easily.
	if _, found := canary.Match("/about"); found {
		t.Errorf("a short token must not be taken into account")
	}
}

// A request to a trap path gets the highest severity and needs no thresholds.
func TestAccessWatcherHoneypot(t *testing.T) {
	events := []Event{}
	watcher := NewAccessWatcher(AccessConfig{
		NotFoundPerMinute: 99, DeniedPerMinute: 99, RequestsPerMinute: 99, ErrorsPerMinute: 99,
		HoneypotPaths: []string{"/wp-login.php", "/.env"},
	}, nil, func(e Event) { events = append(events, e) })

	watcher.Handle(`6.6.6.6 - - [31/Oct/2026:10:00:00 +0100] "GET /wp-login.php HTTP/1.1" 404 0 "-" "bot"`)

	if len(events) != 1 || events[0].Kind != "honeypot_hit" || events[0].Severity != SevAlert {
		t.Fatalf("expected a trap path event, got %+v", events)
	}
}

// Extra log fields (the TLS fingerprint, for example) land in the details.
func TestAccessWatcherExtraFields(t *testing.T) {
	events := []Event{}
	watcher := NewAccessWatcher(AccessConfig{
		NotFoundPerMinute: 99, DeniedPerMinute: 99, RequestsPerMinute: 99, ErrorsPerMinute: 99,
		HoneypotPaths: []string{"/.env"}, ExtraFields: []string{"ja3", "cf_ip"},
	}, nil, func(e Event) { events = append(events, e) })

	watcher.Handle(`6.6.6.6 - - [31/Oct/2026:10:00:00 +0100] "GET /.env HTTP/1.1" 404 0 "-" "bot" "771,4866-4867" "203.0.113.9"`)

	if len(events) != 1 {
		t.Fatalf("expected one event, got %+v", events)
	}
	if events[0].Details["ja3"] != "771,4866-4867" {
		t.Errorf("the TLS fingerprint was not picked up: %+v", events[0].Details)
	}
	if events[0].Details["cf_ip"] != "203.0.113.9" {
		t.Errorf("the extra field was not picked up: %+v", events[0].Details)
	}
}
