// Tokens issued at run time: the list from the configuration is extended with
// the ones the trap handed out to attackers.
package watch

import (
	"strings"
	"sync"
)

// RuntimeCanary is a token matcher extended while running: keys issued by the
// trap are added to the tokens from the configuration.
type RuntimeCanary struct {
	mu      sync.RWMutex
	base    *Canary
	dynamic map[string]bool
}

// NewRuntimeCanary wraps the tokens from the configuration.
func NewRuntimeCanary(base *Canary) *RuntimeCanary {
	if base == nil {
		base = NewCanary(CanaryConfig{})
	}
	return &RuntimeCanary{base: base, dynamic: map[string]bool{}}
}

// Add registers a token issued at run time.
func (r *RuntimeCanary) Add(token string) {
	if len(token) < 8 {
		return
	}
	r.mu.Lock()
	r.dynamic[token] = true
	r.mu.Unlock()
}

// Match looks for any of the tokens in the text.
func (r *RuntimeCanary) Match(text string) (string, bool) {
	if token, found := r.base.Match(text); found {
		return token, true
	}
	if text == "" {
		return "", false
	}
	lower := strings.ToLower(text)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for token := range r.dynamic {
		if strings.Contains(lower, strings.ToLower(token)) {
			return token, true
		}
	}
	return "", false
}
