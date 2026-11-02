// Canary tokens: values that cannot show up in normal life.
package watch

import "strings"

// Canary looks for canary tokens in text. A token can only be obtained from the
// decoy configuration file on the server, so its appearance in a request or in
// a log means the files were read. Such events get the highest severity.
type Canary struct {
	tokens []string
}

// NewCanary creates the token matcher. Short values are dropped: they match by
// accident too easily.
func NewCanary(cfg CanaryConfig) *Canary {
	tokens := []string{}
	if cfg.Enabled {
		for _, token := range cfg.Tokens {
			token = strings.TrimSpace(token)
			if len(token) >= 8 {
				tokens = append(tokens, token)
			}
		}
	}
	return &Canary{tokens: tokens}
}

// Match returns the token that fired.
func (c *Canary) Match(text string) (string, bool) {
	if len(c.tokens) == 0 || text == "" {
		return "", false
	}
	for _, token := range c.tokens {
		if strings.Contains(text, token) {
			return token, true
		}
	}
	return "", false
}
