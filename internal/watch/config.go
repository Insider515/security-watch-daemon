// Watcher configuration: one JSON file, with no dependency on any particular
// project. Everything server-specific is set here.
package watch

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config is the complete set of settings. Any section may be omitted: a
// disabled source simply does not start.
type Config struct {
	// The server name used in messages. Empty means the machine's hostname.
	Host string `json:"host"`
	// Where to keep the read marks for logs, so they are not re-read from the
	// beginning after a restart.
	StateDir string `json:"state_dir"`
	// The merge window for repeats: the same event from the same address inside
	// the window is sent once, with the number of repeats.
	DedupWindow Duration `json:"dedup_window"`
	// Sources (or source/kind pairs) whose subject is left out of the merge key.
	// For the web server log, the trap and the mirror the subject is the request
	// path, which changes with every request of a scan, so without this a single
	// scanner produces hundreds of events.
	DedupIgnoreSubject []string `json:"dedup_ignore_subject"`

	Sinks     SinksConfig     `json:"sinks"`
	Access    AccessConfig    `json:"access_log"`
	Auth      AuthConfig      `json:"auth_log"`
	Files     FilesConfig     `json:"files"`
	Ports     PortsConfig     `json:"ports"`
	AppLog    AppLogConfig    `json:"app_log"`
	Canary    CanaryConfig    `json:"canary"`
	Enrich    EnrichConfig    `json:"enrich"`
	DB        DBConfig        `json:"db"`
	Self      SelfGuardConfig `json:"self_guard"`
	Audit     AuditConfig     `json:"audit"`
	Mirror    MirrorConfig    `json:"mirror"`
	Processes ProcessConfig   `json:"processes"`
	Resources ResourcesConfig `json:"resources"`
	Trap      TrapConfig      `json:"trap"`
	Blocking  BlockingConfig  `json:"blocking"`
	Actors    ActorsConfig    `json:"actors"`
	Baseline  BaselineConfig  `json:"baseline"`
	Archive   ArchiveConfig   `json:"archive"`
	Actions   ActionsConfig   `json:"actions"`
	Log       LogConfig       `json:"logging"`
	Realtime  bool            `json:"files_realtime"`
	// Suppression rules: what not to treat as an event at all.
	Ignore []IgnoreRule `json:"ignore"`
	// Severity overrides by event kind: kind -> level.
	SeverityOverrides map[string]Severity `json:"severity_overrides"`
	// Grade overrides by event kind: kind -> notice, minor, major, critical or
	// system. What counts as serious differs from server to server, and saying
	// so should not require rebuilding the service.
	GradeOverrides map[string]Grade `json:"grade_overrides"`
}

// IgnoreRule is a suppression rule: an event matching it is not emitted.
type IgnoreRule struct {
	// Any field may be omitted, in which case it is not checked.
	Source string `json:"source"`
	Kind   string `json:"kind"`
	IP     string `json:"ip"`
	// A substring of the event subject (path, file, user name).
	SubjectContains string `json:"subject_contains"`
}

// SinksConfig - where to report. Several sinks can be enabled at once.
type SinksConfig struct {
	// The line-based event log file (one JSON object per line).
	File string `json:"file"`
	// The size limit of that file in megabytes and how many previous pieces to
	// keep. On reaching the limit the service rotates the log itself.
	FileMaxMB int `json:"file_max_mb"`
	FileKeep  int `json:"file_keep"`
	// HTTP receiver: a POST with an array of events. A dashboard reads from it.
	Webhook WebhookConfig `json:"webhook"`
	// Email.
	Email EmailConfig `json:"email"`
	// Telegram - the fastest way to get a trace off the server.
	Telegram TelegramConfig `json:"telegram"`
	// How many events to keep in the on-disk queue when the network is down.
	OutboxMax int `json:"outbox_max"`
	// How often to retry what was deferred.
	OutboxRetry Duration `json:"outbox_retry"`
}

// WebhookConfig - sending events to a URL of your own.
type WebhookConfig struct {
	Enabled bool              `json:"enabled"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Timeout Duration          `json:"timeout"`
}

// EmailConfig - sending mail over plain SMTP.
type EmailConfig struct {
	Enabled bool     `json:"enabled"`
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	User    string   `json:"user"`
	Pass    string   `json:"pass"`
	From    string   `json:"from"`
	To      []string `json:"to"`
	// Mail is sent only for events at this level or above.
	MinSeverity Severity `json:"min_severity"`
	// At most one message per this period: during a flood the events pile up and
	// go out in a single message.
	Throttle Duration `json:"throttle"`
}

// AccessConfig - watching the web server log.
type AccessConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
	// How many 404 responses per minute from one address count as path scanning.
	NotFoundPerMinute int `json:"not_found_per_minute"`
	// How many 401/403 responses per minute from one address count as guessing.
	DeniedPerMinute int `json:"denied_per_minute"`
	// How many requests per minute from one address count as a flood.
	RequestsPerMinute int `json:"requests_per_minute"`
	// Path fragments that are suspicious to request in themselves.
	SuspiciousPaths []string `json:"suspicious_paths"`
	// How many 5xx responses per minute from one address suggest that an attempt
	// broke something.
	ErrorsPerMinute int `json:"errors_per_minute"`
	// Whether to look for injection signatures in the request (SQL, shell,
	// directory traversal).
	DetectInjection bool `json:"detect_injection"`
	// Trap paths: they do not exist on the site, so any request to them is
	// certainly not a real client. No thresholds, highest severity.
	HoneypotPaths []string `json:"honeypot_paths"`
	// Names of extra fields at the end of the log line (from log_format), such
	// as the TLS fingerprint. They land in the event details in order.
	// The name of the extra field holding the real client address. Behind a
	// reverse proxy (Cloudflare and the like) the first field of the line is the
	// proxy address, while the client address arrives in a header and has to be
	// added to log_format; naming that field here makes the events carry the
	// client address rather than the proxy one.
	ExtraFields []string `json:"extra_fields"`
	RealIPField string   `json:"real_ip_field"`
	// A custom parsing pattern with named groups for logs that are not in the
	// combined format. Group names: ip, time, method, path, status, agent.
	Regexp string `json:"regexp"`
	// Custom injection signatures in addition to the built-in ones.
	ExtraInjectionPatterns []CustomSignature `json:"extra_injection_patterns"`
	// Built-in signatures to disable, by name (sqli_comment and so on).
	DisabledSignatures []string `json:"disabled_signatures"`
}

// CustomSignature - a custom injection rule: name, pattern, severity.
type CustomSignature struct {
	Kind     string   `json:"kind"`
	Pattern  string   `json:"pattern"`
	Severity Severity `json:"severity"`
}

// CanaryConfig - canary tokens: fake values placed in decoy configuration
// files. Such a value appearing in a log means the files on the server were
// read.
type CanaryConfig struct {
	Enabled bool     `json:"enabled"`
	Tokens  []string `json:"tokens"`
}

// ProcessConfig - watching processes and outbound connections.
type ProcessConfig struct {
	Enabled  bool     `json:"enabled"`
	Interval Duration `json:"interval"`
	// Directories where starting a program is suspicious in itself.
	SuspiciousDirs []string `json:"suspicious_dirs"`
	// Ports the server legitimately connects out to: anything else is an event.
	AllowedOutboundPorts []int `json:"allowed_outbound_ports"`
}

// AppLogConfig - watching the application log: database messages about failed
// query parsing and injection signatures. It sees what arrives in a POST body
// and never reaches the web server log.
type AppLogConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
	// Extra substrings to treat as signatures. The main set (MySQL/MariaDB and
	// PostgreSQL messages) is built into the service.
	ExtraPatterns []string `json:"extra_patterns"`
	// Disable the built-in set of database messages: needed where the
	// application log contains them as a matter of course.
	DisableBuiltinPatterns bool `json:"disable_builtin_patterns"`
	// Whether to look for injection signatures in the application log lines.
	DetectInjection bool `json:"detect_injection"`
}

// AuthConfig - watching system logins (sshd, sudo).
type AuthConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
	// How many failed logins per minute from an address count as password
	// guessing.
	FailuresPerMinute int `json:"failures_per_minute"`
	// Addresses a login is normal from (your office, your VPN). An entry may be
	// a single address or a network in CIDR form: "10.0.0.0/8".
	KnownIPs []string `json:"known_ips"`
	// Custom patterns for failed logins: the first group is the user name, the
	// second one is the address.
	ExtraFailurePatterns []string `json:"extra_failure_patterns"`
}

// FilesConfig - watching important files for changes.
type FilesConfig struct {
	Enabled bool     `json:"enabled"`
	Paths   []string `json:"paths"`
	// How often to re-scan.
	Interval Duration `json:"interval"`
	// Do not descend deeper than this many levels (keeps node_modules out).
	MaxDepth int `json:"max_depth"`
	// Path fragments to skip.
	Skip []string `json:"skip"`
}

// PortsConfig - watching listening ports.
type PortsConfig struct {
	Enabled  bool     `json:"enabled"`
	Interval Duration `json:"interval"`
	// Ports that are supposed to listen; the appearance of others is an event.
	Expected []int `json:"expected"`
}

// Duration is a human-readable period ("30s", "5m") inside JSON.
type Duration struct{ time.Duration }

// UnmarshalJSON parses a string such as "5m" into a duration.
func (d *Duration) UnmarshalJSON(raw []byte) error {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return err
	}
	if text == "" {
		d.Duration = 0
		return nil
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", text, err)
	}
	d.Duration = parsed
	return nil
}

// LoadConfig reads the configuration file and fills in the defaults. An error is
// returned only for an unreadable file or invalid JSON.
func LoadConfig(path string) (*Config, error) {
	// #nosec G304 -- this is the configuration file named on the command line.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the configuration %s: %w", path, err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parsing the configuration %s: %w", path, err)
	}
	cfg.applyDefaults()
	return cfg, nil
}

// applyDefaults fills in default values in place of empty ones.
func (c *Config) applyDefaults() {
	if c.Host == "" {
		if name, err := os.Hostname(); err == nil {
			c.Host = name
		} else {
			c.Host = "unknown"
		}
	}

	for _, item := range []struct {
		target *string
		value  string
	}{
		{&c.StateDir, "/var/lib/security-watch"},
		{&c.Auth.Path, "/var/log/auth.log"},
		{&c.Log.Format, "text"},
		{&c.Log.Level, "info"},
		{&c.Audit.Path, "/var/log/audit/audit.log"},
	} {
		if *item.target == "" {
			*item.target = item.value
		}
	}

	for _, item := range []struct {
		target *int
		value  int
	}{
		{&c.Access.NotFoundPerMinute, 60},
		{&c.Access.DeniedPerMinute, 30},
		{&c.Access.RequestsPerMinute, 600},
		{&c.Access.ErrorsPerMinute, 10},
		{&c.Auth.FailuresPerMinute, 5},
		{&c.Files.MaxDepth, 6},
		{&c.Sinks.Email.Port, 587},
		{&c.Sinks.FileMaxMB, 50},
		{&c.Sinks.FileKeep, 7},
		{&c.Sinks.OutboxMax, 5000},
		{&c.Actors.AlertScore, 50},
		{&c.Sinks.Telegram.MaxPerHour, 20},
		{&c.Resources.MemoryFreePercent, 10},
		{&c.Resources.DiskFreePercent, 10},
		{&c.Resources.InodesFreePercent, 10},
		{&c.Baseline.LearnDays, 14},
	} {
		if *item.target == 0 {
			*item.target = item.value
		}
	}

	for _, item := range []struct {
		target *Duration
		value  time.Duration
	}{
		{&c.DedupWindow, 10 * time.Minute},
		{&c.Files.Interval, 5 * time.Minute},
		{&c.Ports.Interval, time.Minute},
		{&c.Processes.Interval, time.Minute},
		{&c.DB.Interval, 5 * time.Minute},
		{&c.Sinks.Webhook.Timeout, 10 * time.Second},
		{&c.Sinks.Email.Throttle, 15 * time.Minute},
		{&c.Sinks.OutboxRetry, time.Minute},
		{&c.Self.HeartbeatInterval, 15 * time.Minute},
		{&c.Self.CheckInterval, time.Minute},
		{&c.Actors.DigestInterval, time.Hour},
		{&c.Actors.Forget, 7 * 24 * time.Hour},
		{&c.Archive.Interval, 24 * time.Hour},
		{&c.Sinks.Telegram.GroupWindow, 2 * time.Minute},
		{&c.Resources.Interval, time.Minute},
		{&c.Resources.Repeat, time.Hour},
	} {
		if item.target.Duration == 0 {
			item.target.Duration = item.value
		}
	}

	if c.Sinks.Email.MinSeverity == "" {
		c.Sinks.Email.MinSeverity = SevAlert
	}
	// The bot's default is a deliberate attempt at the application and worse.
	// Reconnaissance from outside goes on around the clock and says nothing on
	// its own, so it is left out unless asked for.
	if c.Sinks.Telegram.MinGrade == "" {
		c.Sinks.Telegram.MinGrade = GradeMajor
	}
	if c.Sinks.Telegram.MinSeverity == "" {
		c.Sinks.Telegram.MinSeverity = SevWarn
	}
	if c.Resources.LoadPerCPU == 0 {
		c.Resources.LoadPerCPU = 4
	}
	if len(c.Resources.Paths) == 0 {
		c.Resources.Paths = []string{"/"}
	}
	if len(c.Self.WatchPaths) == 0 {
		c.Self.WatchPaths = []string{"/etc/systemd/system/security-watch.service"}
	}
	if len(c.DedupIgnoreSubject) == 0 {
		c.DedupIgnoreSubject = []string{"access", "trap", "mirror"}
	}
	if len(c.Processes.SuspiciousDirs) == 0 {
		c.Processes.SuspiciousDirs = []string{"/tmp", "/dev/shm", "/var/tmp", "/run/user"}
	}
}
