package watch

import "testing"

// Scanners encode quotes and spaces (%27, %20, +), so the injection signatures
// are checked against the encoded form, not only the readable one.
func TestInjectionEncodedShapes(t *testing.T) {
	for _, item := range []struct {
		name string
		line string
		kind string
	}{
		{
			"quote and spaces as codes",
			`203.0.113.78 - - [01/Nov/2026:00:27:08 +0100] "GET /api/user?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 50 "-" "sqlmap"`,
			"sqli_tautology",
		},
		{
			"plus instead of space",
			`203.0.113.78 - - [01/Nov/2026:00:27:08 +0100] "GET /api/user?id=1%27+union+select+1 HTTP/1.1" 200 50 "-" "sqlmap"`,
			"sqli_union",
		},
		{
			"quote as code, word as is",
			`203.0.113.78 - - [01/Nov/2026:00:27:08 +0100] "GET /api/user?id=1%27union%20select HTTP/1.1" 200 50 "-" "sqlmap"`,
			"sqli_union",
		},
	} {
		events := []Event{}
		watcher := NewAccessWatcher(AccessConfig{
			NotFoundPerMinute: 99, DeniedPerMinute: 99, RequestsPerMinute: 99, ErrorsPerMinute: 99,
			DetectInjection: true,
		}, nil, func(e Event) { events = append(events, e) })

		watcher.Handle(item.line)

		found := false
		for _, event := range events {
			if event.Kind == item.kind {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no %s event, got %+v", item.name, item.kind, events)
		}
	}
}
