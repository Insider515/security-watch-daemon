// Checking the configuration before startup: better to refuse right away with a
// clear explanation than to silently watch the wrong thing.
package watch

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// CheckConfig checks the configuration: whether the files and directories named
// in it exist and whether the enabled sections have what they need. Anything
// that does not prevent the service from working is printed as a note rather
// than an error.
func CheckConfig(cfg *Config) error {
	report := &configReport{}

	checkLogs(cfg, report)
	checkWatchers(cfg, report)
	checkSinks(cfg, report)
	checkDatabase(cfg, report)
	checkBlocking(cfg, report)
	checkPatterns(cfg, report)
	checkLogging(cfg, report)

	for _, note := range report.notes {
		fmt.Printf("note: %s\n", note)
	}
	if len(report.problems) > 0 {
		return fmt.Errorf("the configuration is unusable:\n  - %s", strings.Join(report.problems, "\n  - "))
	}
	fmt.Printf("configuration is fine: server %s, state in %s\n", cfg.Host, cfg.StateDir)
	return nil
}

// configReport collects the findings: a problem prevents work, a note does not.
type configReport struct {
	problems []string
	notes    []string
}

// problem adds something the service must not start with.
func (r *configReport) problem(format string, args ...any) {
	r.problems = append(r.problems, fmt.Sprintf(format, args...))
}

// note adds something worth a look.
func (r *configReport) note(format string, args ...any) {
	r.notes = append(r.notes, fmt.Sprintf(format, args...))
}

// checkLogs: the log named must exist, otherwise watching it is a wasted
// setting.
func checkLogs(cfg *Config, report *configReport) {
	for _, item := range []struct {
		name    string
		enabled bool
		path    string
	}{
		{"access_log", cfg.Access.Enabled, cfg.Access.Path},
		{"auth_log", cfg.Auth.Enabled, cfg.Auth.Path},
		{"app_log", cfg.AppLog.Enabled, cfg.AppLog.Path},
		{"audit", cfg.Audit.Enabled, cfg.Audit.Path},
	} {
		if !item.enabled {
			continue
		}
		if strings.TrimSpace(item.path) == "" {
			report.problem("%s: enabled, but no path is set", item.name)
			continue
		}
		if strings.ContainsAny(item.path, "*?[") {
			continue // a name pattern cannot be checked in advance
		}
		if _, err := os.Stat(item.path); err != nil {
			report.note("%s: the file %s does not exist right now", item.name, item.path)
		}
	}
}

// checkWatchers: what is enabled must make sense.
func checkWatchers(cfg *Config, report *configReport) {
	if cfg.Files.Enabled && len(cfg.Files.Paths) == 0 {
		report.problem("files: enabled, but no paths are set")
	}
	for _, path := range cfg.Files.Paths {
		if _, err := os.Stat(path); err != nil {
			report.note("files: the path %s does not exist right now", path)
		}
	}
	if cfg.Trap.Enabled && len(cfg.Trap.Paths) == 0 {
		report.note("trap: no paths listed - check that nginx routes them to the trap")
	}
	if cfg.Canary.Enabled && len(cfg.Canary.Tokens) == 0 {
		report.problem("canary: enabled, but no tokens are set")
	}
	if cfg.Mirror.Enabled && len(cfg.Mirror.PrivilegedFields) > 0 && len(cfg.Mirror.AllowPaths) == 0 {
		report.note("mirror: allow_paths is empty - administrator actions will raise alarms")
	}
}

// checkSinks: an enabled sink needs its settings.
func checkSinks(cfg *Config, report *configReport) {
	if cfg.Sinks.Email.Enabled && len(cfg.Sinks.Email.To) == 0 {
		report.problem("sinks.email: enabled, but no recipients are set")
	}
	if cfg.Sinks.Telegram.Enabled && (cfg.Sinks.Telegram.Token == "" || cfg.Sinks.Telegram.ChatID == "") {
		report.problem("sinks.telegram: enabled, but the token or the chat is not set")
	}
	if cfg.Sinks.Webhook.Enabled && cfg.Sinks.Webhook.URL == "" {
		report.problem("sinks.webhook: enabled, but no URL is set")
	}
	if cfg.Sinks.File == "" && !cfg.Sinks.Email.Enabled && !cfg.Sinks.Telegram.Enabled && !cfg.Sinks.Webhook.Enabled {
		report.note("no sink is enabled: events will only go to the service log")
	}
}

// checkDatabase: the queries must be read-only and the identifiers safe.
func checkDatabase(cfg *Config, report *configReport) {
	if !cfg.DB.Enabled {
		return
	}
	if cfg.DB.DSN == "" {
		report.problem("db: enabled, but no connection string is set")
	}
	for _, check := range cfg.DB.Checks {
		if !isReadOnlyQuery(check.Query) {
			report.problem("db.checks[%s]: the query is not read-only", check.Name)
		}
	}
	for _, watch := range cfg.DB.ColumnWatches {
		if err := validateIdentifiers(watch); err != nil {
			report.problem("db.column_watches[%s]: %v", watch.Name, err)
		}
	}
}

// checkBlocking: blocking without a command, and self-directed blocking without
// blocking itself, make no sense.
func checkBlocking(cfg *Config, report *configReport) {
	if cfg.Blocking.Enabled && strings.TrimSpace(cfg.Blocking.Command) == "" {
		report.problem("blocking: enabled, but no command is set")
	}
	if cfg.Blocking.Auto.Enabled && !cfg.Blocking.Enabled {
		report.problem("blocking.auto: enabled while blocking itself is not")
	}
	if cfg.Blocking.Auto.Enabled && !cfg.Blocking.Auto.DryRun && len(cfg.Blocking.Auto.Allowlist) == 0 {
		report.note("blocking.auto: the allowlist is empty - put your own addresses there")
	}
}

// checkPatterns: patterns from the configuration must compile, and an empty
// suppression rule is not applied.
func checkPatterns(cfg *Config, report *configReport) {
	if strings.TrimSpace(cfg.Access.Regexp) != "" {
		if _, err := regexp.Compile(cfg.Access.Regexp); err != nil {
			report.problem("access_log.regexp: %v", err)
		}
	}
	for _, item := range cfg.Access.ExtraInjectionPatterns {
		if _, err := regexp.Compile(item.Pattern); err != nil {
			report.problem("access_log.extra_injection_patterns[%s]: %v", item.Kind, err)
		}
	}
	for _, pattern := range cfg.Auth.ExtraFailurePatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			report.problem("auth_log.extra_failure_patterns: %v", err)
		}
	}
	for i, rule := range cfg.Ignore {
		if rule.Source == "" && rule.Kind == "" && rule.IP == "" && rule.SubjectContains == "" {
			report.note("ignore[%d]: the rule is empty and is not applied", i)
		}
	}
}

// checkLogging: a typo in the log format or level is silently replaced with the
// default, so it has to be pointed out before startup.
func checkLogging(cfg *Config, report *configReport) {
	format := strings.ToLower(strings.TrimSpace(cfg.Log.Format))
	if format != "text" && format != "json" {
		report.note("logging.format=%q is not recognized, the log will be text (text or json)", cfg.Log.Format)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Log.Level)) {
	case "debug", "info", "warn", "warning", "error":
	default:
		report.note("logging.level=%q is not recognized, the log will be at info level (debug, info, warn, error)", cfg.Log.Level)
	}
}
