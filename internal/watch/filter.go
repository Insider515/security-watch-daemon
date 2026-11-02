// Suppression and severity overrides: without them the service quickly turns
// into a source of noise, and noise stops being read.
package watch

import "strings"

// Filter decides whether an event is emitted and with which severity.
type Filter struct {
	rules     []IgnoreRule
	overrides map[string]Severity
}

// NewFilter builds the suppression rules from the configuration.
func NewFilter(rules []IgnoreRule, overrides map[string]Severity) *Filter {
	return &Filter{rules: rules, overrides: overrides}
}

// Apply returns the event with its severity corrected and a flag telling whether
// to emit it. A suppression rule fires when every field set in it matches; empty
// fields are not checked.
func (f *Filter) Apply(event Event) (Event, bool) {
	for _, rule := range f.rules {
		if rule.Source != "" && rule.Source != event.Source {
			continue
		}
		if rule.Kind != "" && rule.Kind != event.Kind {
			continue
		}
		if rule.IP != "" && rule.IP != event.IP {
			continue
		}
		if rule.SubjectContains != "" && !strings.Contains(event.Subject, rule.SubjectContains) {
			continue
		}
		// A rule with no field set would silence everything; that is treated as
		// a configuration mistake and ignored.
		if rule.Source == "" && rule.Kind == "" && rule.IP == "" && rule.SubjectContains == "" {
			continue
		}
		return Event{}, false
	}
	if level, has := f.overrides[event.Kind]; has && level != "" {
		event.Severity = level
	}
	return event, true
}
