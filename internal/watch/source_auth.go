// Watching logins: password guessing, successful login, privilege escalation.
package watch

import (
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	// sshd[123]: Failed password for root from 1.2.3.4 port 5 ssh2
	// sshd[123]: Failed password for invalid user admin from 1.2.3.4 ...
	reFailed = regexp.MustCompile(`Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)`)
	// sshd[123]: Accepted publickey for root from 1.2.3.4 port 5 ssh2: RSA SHA256:...
	reAccepted = regexp.MustCompile(`Accepted (\S+) for (\S+) from (\S+)`)
	// sshd[123]: Invalid user admin from 1.2.3.4
	reInvalid = regexp.MustCompile(`Invalid user (\S+) from (\S+)`)
	// sudo: user : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash
	reSudo = regexp.MustCompile(`sudo:\s+(\S+)\s+:.*COMMAND=(.+)$`)
)

// AuthWatcher parses the auth log. Failed attempts produce an event only when
// the per-minute threshold is exceeded; a successful login from an unknown
// address is reported right away and with the highest severity.
type AuthWatcher struct {
	cfg   AuthConfig
	known map[string]bool
	// Known networks in CIDR form ("10.0.0.0/8", "2001:db8::/32"): a provider
	// address that changes within one network should not raise an alarm on
	// every login.
	knownNets []*net.IPNet
	counters  *minuteTracker
	// Custom patterns for failed attempts: sshd records differ between systems,
	// and logins happen outside SSH too - a control panel, a VPN, mail.
	extra []*regexp.Regexp
	emit  func(Event)
}

// NewAuthWatcher creates the auth log watcher.
func NewAuthWatcher(cfg AuthConfig, emit func(Event)) *AuthWatcher {
	known := make(map[string]bool, len(cfg.KnownIPs))
	nets := []*net.IPNet{}
	for _, entry := range cfg.KnownIPs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, network)
			continue
		}
		known[entry] = true
	}
	extra := []*regexp.Regexp{}
	for _, pattern := range cfg.ExtraFailurePatterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		// An invalid pattern is skipped: a typo in the configuration must not
		// keep the service from starting.
		if compiled, err := regexp.Compile(pattern); err == nil {
			extra = append(extra, compiled)
		}
	}
	return &AuthWatcher{cfg: cfg, known: known, knownNets: nets, counters: newMinuteTracker(), extra: extra, emit: emit}
}

// Handle parses one line of the auth log.
func (a *AuthWatcher) Handle(line string) {
	now := time.Now()

	if match := reAccepted.FindStringSubmatch(line); match != nil {
		method, user, ip := match[1], match[2], match[3]
		familiar := a.isKnown(ip)
		severity := SevInfo
		if !familiar {
			severity = SevAlert
		}
		a.emit(Event{
			At: now, Source: "auth", Kind: "ssh_login", Severity: severity,
			IP: ip, Subject: user, Count: 1,
			Details: map[string]string{"method": method, "known_ip": boolText(familiar)},
		})
		return
	}

	if match := reSudo.FindStringSubmatch(line); match != nil {
		a.emit(Event{
			At: now, Source: "auth", Kind: "sudo", Severity: SevInfo,
			IP: "", Subject: match[1], Count: 1,
			Details: map[string]string{"command": match[2]},
		})
		return
	}

	user, ip := "", ""
	if match := reFailed.FindStringSubmatch(line); match != nil {
		user, ip = match[1], match[2]
	} else if match := reInvalid.FindStringSubmatch(line); match != nil {
		user, ip = match[1], match[2]
	} else {
		// Custom login kinds from the configuration: the first group is the
		// user, the second one is the address.
		for _, pattern := range a.extra {
			if match := pattern.FindStringSubmatch(line); len(match) >= 3 {
				user, ip = match[1], match[2]
				break
			}
		}
	}
	if ip == "" {
		return
	}

	failures := a.counters.Add(ip, now, "failures")
	if failures == a.cfg.FailuresPerMinute {
		a.emit(Event{
			At: now, Source: "auth", Kind: "ssh_bruteforce", Severity: SevWarn,
			IP: ip, Subject: user, Count: failures,
			Details: map[string]string{"last_user": user},
		})
	}
}

// isKnown reports whether a login from this address is routine: an exact match
// in known_ips or an address inside one of the listed networks.
func (a *AuthWatcher) isKnown(ip string) bool {
	if a.known[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range a.knownNets {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// Sweep drops counters of past minutes.
func (a *AuthWatcher) Sweep(now time.Time) { a.counters.Sweep(now) }

// boolText renders a flag for a details field.
func boolText(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
