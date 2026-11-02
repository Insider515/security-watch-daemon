// Detecting injection attempts in a request: SQL, shell commands, directory
// traversal.
package watch

import (
	"net/url"
	"regexp"
	"strings"
)

// signature is one detection rule: name, pattern and severity.
type signature struct {
	Kind     string
	Severity Severity
	Pattern  *regexp.Regexp
}

// injectionSignatures is the set of injection rules. The patterns are narrow:
// they look for word combinations and telltale punctuation rather than single
// words such as select, which occur in ordinary requests.
var injectionSignatures = []signature{
	{Kind: "sqli_union", Severity: SevAlert, Pattern: regexp.MustCompile(`union\s+(all\s+)?select\b`)},
	{Kind: "sqli_tautology", Severity: SevAlert, Pattern: regexp.MustCompile(`['")]\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`)},
	{Kind: "sqli_comment", Severity: SevWarn, Pattern: regexp.MustCompile(`(--\s|#)\s*$|/\*!|;\s*--`)},
	{Kind: "sqli_sleep", Severity: SevAlert, Pattern: regexp.MustCompile(`\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(`)},
	{Kind: "sqli_schema", Severity: SevAlert, Pattern: regexp.MustCompile(`\binformation_schema\b|\bsysobjects\b|\bpg_catalog\b`)},
	{Kind: "sqli_file", Severity: SevAlert, Pattern: regexp.MustCompile(`\b(load_file|into\s+outfile|into\s+dumpfile|xp_cmdshell)\b`)},
	{Kind: "sqli_stacked", Severity: SevAlert, Pattern: regexp.MustCompile(`;\s*(drop|insert|update|delete|alter|create)\s+`)},
	// A command separator followed by a program name (";wget",
	// "; /bin/bash -c") and command substitution ($(...), backticks).
	{Kind: "shell_injection", Severity: SevAlert, Pattern: regexp.MustCompile(
		`[;|&]\s*(/[\w./-]*/)?(wget|curl|nc|ncat|bash|sh|zsh|python[23]?|perl|ruby|php)\b` +
			`|\$\(|` + "`" + `\w|\(\s*\)\s*\{\s*:\s*;\s*\}`)},
	{Kind: "path_traversal", Severity: SevAlert, Pattern: regexp.MustCompile(`\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/proc/self/environ`)},
	{Kind: "template_injection", Severity: SevWarn, Pattern: regexp.MustCompile(`\{\{.*\}\}|\$\{jndi:`)},
}

// normalizeRequest prepares a request string for matching: percent decoding
// twice (double encoding such as %2527 instead of %27 is common) and plus signs
// treated as spaces.
func normalizeRequest(raw string) string {
	text := raw
	for i := 0; i < 2; i++ {
		decoded, err := url.QueryUnescape(strings.ReplaceAll(text, "+", " "))
		if err != nil {
			break
		}
		if decoded == text {
			break
		}
		text = decoded
	}
	text = strings.ReplaceAll(text, "+", " ")
	return strings.ToLower(text)
}

// matchInjection returns the rule that matched first. The second value is false
// when nothing matched.
func matchInjection(raw string) (signature, bool) {
	return matchInjectionWith(raw, nil, nil)
}

// matchInjectionWith matches the string against the built-in rules, the custom
// rules from the configuration and the list of disabled ones.
func matchInjectionWith(raw string, extra []signature, disabled []string) (signature, bool) {
	normalized := normalizeRequest(raw)
	off := map[string]bool{}
	for _, kind := range disabled {
		off[strings.TrimSpace(kind)] = true
	}
	for _, sig := range injectionSignatures {
		if off[sig.Kind] {
			continue
		}
		if sig.Pattern.MatchString(normalized) {
			return sig, true
		}
	}
	for _, sig := range extra {
		if off[sig.Kind] {
			continue
		}
		if sig.Pattern.MatchString(normalized) {
			return sig, true
		}
	}
	return signature{}, false
}

// compileExtraSignatures turns patterns from the configuration into rules. An
// invalid pattern is skipped.
func compileExtraSignatures(patterns []CustomSignature) []signature {
	out := []signature{}
	for _, item := range patterns {
		if strings.TrimSpace(item.Pattern) == "" {
			continue
		}
		compiled, err := regexp.Compile("(?i)" + item.Pattern)
		if err != nil {
			continue
		}
		severity := item.Severity
		if severity == "" {
			severity = SevWarn
		}
		kind := item.Kind
		if kind == "" {
			kind = "custom_signature"
		}
		out = append(out, signature{Kind: kind, Severity: severity, Pattern: compiled})
	}
	return out
}

// sampleOf shortens a string for event details: in full it can run to a
// kilobyte, while a message only needs a recognizable piece.
func sampleOf(raw string, limit int) string {
	if len(raw) <= limit {
		return raw
	}
	return raw[:limit] + "..."
}
