// Block proposals and carrying them out - only on the operator's decision.
package watch

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// BlockingConfig - what to block an address with. By default the service only
// collects proposals with evidence, and a separate command does the blocking.
type BlockingConfig struct {
	Enabled bool `json:"enabled"`
	// The blocking command. %s is where the address goes.
	// For example: "ufw deny from %s", or a Cloudflare API call via curl.
	Command string `json:"command"`
	// The unblocking command.
	UnblockCommand string `json:"unblock_command"`
	// Event kinds that open a proposal.
	ProposeOn []string `json:"propose_on"`
	// Self-directed blocking, off by default.
	Auto AutoBlockConfig `json:"auto"`
}

// AutoBlockConfig - the conditions for self-directed blocking. They filter out
// accidental hits: following someone else's link gives one reason and one visit,
// while scanning gives many reasons and many visits.
type AutoBlockConfig struct {
	Enabled bool `json:"enabled"`
	// How many times the address must show up. A browser that loaded someone
	// else's image comes once; a scanner comes many times.
	MinHits int `json:"min_hits"`
	// How many distinct reasons must accumulate. An accidental hit gives one
	// reason, real scanning gives several.
	MinReasons int `json:"min_reasons"`
	// Event kinds that must be among the reasons. For example, require that
	// besides a trap hit there is also path scanning or an injection attempt.
	RequireKinds []string `json:"require_kinds"`
	// Addresses and networks never to block: your own, operational, test ones.
	Allowlist []string `json:"allowlist"`
	// Limit on self-directed blocks per hour: if someone floods the trap with
	// requests from other people's addresses, the service will not shut out half
	// the internet.
	MaxPerHour int `json:"max_per_hour"`
	// Only show what would be blocked, without doing anything. Running like this
	// for a week and seeing who lands there is a sensible start.
	DryRun bool `json:"dry_run"`
}

// BlockCandidate is a proposal to block an address.
type BlockCandidate struct {
	IP        string    `json:"ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
	Reasons   []string  `json:"reasons"`
	Kinds     []string  `json:"kinds"`
	Blocked   bool      `json:"blocked"`
	BlockedAt time.Time `json:"blocked_at,omitempty"`
}

// Blocklist keeps the list of proposals and carries out the operator's
// decisions.
type Blocklist struct {
	cfg       BlockingConfig
	mu        sync.Mutex
	path      string
	items     map[string]*BlockCandidate
	emit      func(Event)
	autoTimes []time.Time // timestamps of self-directed blocks in the last hour
}

// NewBlocklist reads the list from disk.
func NewBlocklist(cfg BlockingConfig, stateDir string, emit func(Event)) *Blocklist {
	list := &Blocklist{
		cfg:   cfg,
		path:  filepath.Join(stateDir, "block_candidates.json"),
		items: map[string]*BlockCandidate{},
		emit:  emit,
	}
	loadJSONState(list.path, &list.items)
	return list
}

// Consider opens or extends a proposal based on an event.
func (b *Blocklist) Consider(event Event) {
	if event.IP == "" || len(b.cfg.ProposeOn) == 0 {
		return
	}
	match := false
	for _, kind := range b.cfg.ProposeOn {
		if strings.TrimSpace(kind) == event.Kind {
			match = true
			break
		}
	}
	if !match {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	item, known := b.items[event.IP]
	if !known {
		item = &BlockCandidate{IP: event.IP, FirstSeen: time.Now()}
		b.items[event.IP] = item
	}
	item.LastSeen = time.Now()
	item.Count++
	reason := fmt.Sprintf("%s/%s: %s", event.Source, event.Kind, sampleOf(event.Subject, 80))
	item.Reasons = appendUnique(item.Reasons, reason, 10)
	item.Kinds = appendUnique(item.Kinds, event.Kind, 20)
	b.save()

	if ready, why := b.autoReady(item); ready {
		b.mu.Unlock()
		b.autoBlock(item.IP, why)
		b.mu.Lock()
	}
}

// autoReady decides whether the conditions for self-directed blocking are met.
// Called with the lock already held.
func (b *Blocklist) autoReady(item *BlockCandidate) (bool, string) {
	auto := b.cfg.Auto
	if !auto.Enabled || item.Blocked {
		return false, ""
	}
	if isPrivateIP(item.IP) {
		return false, ""
	}
	for _, allowed := range auto.Allowlist {
		if matchesAllow(item.IP, allowed) {
			return false, ""
		}
	}
	minHits := auto.MinHits
	if minHits <= 0 {
		minHits = 3
	}
	if item.Count < minHits {
		return false, ""
	}
	if auto.MinReasons > 0 && len(item.Reasons) < auto.MinReasons {
		return false, ""
	}
	for _, required := range auto.RequireKinds {
		found := false
		for _, kind := range item.Kinds {
			if kind == strings.TrimSpace(required) {
				found = true
				break
			}
		}
		if !found {
			return false, ""
		}
	}
	// The hourly limit: protection against a flood from other people's
	// addresses.
	limit := auto.MaxPerHour
	if limit <= 0 {
		limit = 10
	}
	cutoff := time.Now().Add(-time.Hour)
	fresh := b.autoTimes[:0]
	for _, moment := range b.autoTimes {
		if moment.After(cutoff) {
			fresh = append(fresh, moment)
		}
	}
	b.autoTimes = fresh
	if len(b.autoTimes) >= limit {
		return false, ""
	}
	return true, fmt.Sprintf("hits %d, reasons %d: %s", item.Count, len(item.Reasons), strings.Join(item.Reasons, "; "))
}

// autoBlock carries out the self-directed block, or reports what it would do.
func (b *Blocklist) autoBlock(ip, why string) {
	if b.cfg.Auto.DryRun {
		b.emit(Event{
			At: time.Now(), Source: "action", Kind: "auto_block_proposed", Severity: SevWarn,
			IP: ip, Subject: ip, Count: 1,
			Details: map[string]string{"reason": sampleOf(why, 300), "mode": "report only (dry_run)"},
		})
		return
	}
	if err := b.Block(ip); err != nil {
		b.emit(Event{
			At: time.Now(), Source: "action", Kind: "auto_block_failed", Severity: SevWarn,
			IP: ip, Subject: ip, Count: 1,
			Details: map[string]string{"error": err.Error()},
		})
		return
	}
	b.mu.Lock()
	b.autoTimes = append(b.autoTimes, time.Now())
	b.mu.Unlock()
	b.emit(Event{
		At: time.Now(), Source: "action", Kind: "ip_auto_blocked", Severity: SevAlert,
		IP: ip, Subject: ip, Count: 1,
		Details: map[string]string{"reason": sampleOf(why, 300)},
	})
}

// matchesAllow matches an address against an allowlist entry: either exactly or
// by prefix (whole networks are written this way: "10.", "192.168.").
func matchesAllow(ip, allowed string) bool {
	allowed = strings.TrimSpace(allowed)
	if allowed == "" {
		return false
	}
	if ip == allowed {
		return true
	}
	return strings.HasSuffix(allowed, ".") && strings.HasPrefix(ip, allowed)
}

// Candidates returns the proposals, most recent first.
func (b *Blocklist) Candidates() []*BlockCandidate {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*BlockCandidate, 0, len(b.items))
	for _, item := range b.items {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Block carries out the block on the operator's decision.
func (b *Blocklist) Block(ip string) error {
	if !b.cfg.Enabled {
		return fmt.Errorf("blocking is disabled in the configuration (blocking.enabled)")
	}
	if strings.TrimSpace(b.cfg.Command) == "" {
		return fmt.Errorf("no blocking command is set (blocking.command)")
	}
	if err := validateIP(ip); err != nil {
		return err
	}
	output, err := runCommand(b.cfg.Command, ip)
	if err != nil {
		return fmt.Errorf("the blocking command failed: %w (%s)", err, output)
	}

	b.mu.Lock()
	item, known := b.items[ip]
	if !known {
		item = &BlockCandidate{IP: ip, FirstSeen: time.Now()}
		b.items[ip] = item
	}
	item.Blocked = true
	item.BlockedAt = time.Now()
	b.save()
	b.mu.Unlock()

	b.emit(Event{
		At: time.Now(), Source: "action", Kind: "ip_blocked", Severity: SevInfo,
		IP: ip, Subject: ip, Count: 1,
		Details: map[string]string{"by": "operator decision", "output": sampleOf(output, 200)},
	})
	return nil
}

// Unblock removes the block.
func (b *Blocklist) Unblock(ip string) error {
	if strings.TrimSpace(b.cfg.UnblockCommand) == "" {
		return fmt.Errorf("no unblocking command is set (blocking.unblock_command)")
	}
	if err := validateIP(ip); err != nil {
		return err
	}
	output, err := runCommand(b.cfg.UnblockCommand, ip)
	if err != nil {
		return fmt.Errorf("the unblocking command failed: %w (%s)", err, output)
	}
	b.mu.Lock()
	if item, known := b.items[ip]; known {
		item.Blocked = false
	}
	b.save()
	b.mu.Unlock()

	b.emit(Event{
		At: time.Now(), Source: "action", Kind: "ip_unblocked", Severity: SevInfo,
		IP: ip, Subject: ip, Count: 1,
	})
	return nil
}

// save writes the list to disk.
func (b *Blocklist) save() {
	saveJSONState(b.path, b.items, 0o600)
}

// validateIP checks that the string is an IPv4 or IPv6 address. The address is
// substituted into a command, so the check is mandatory.
func validateIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("empty address")
	}
	for _, symbol := range ip {
		isDigit := symbol >= '0' && symbol <= '9'
		isHex := (symbol >= 'a' && symbol <= 'f') || (symbol >= 'A' && symbol <= 'F')
		if !isDigit && !isHex && symbol != '.' && symbol != ':' {
			return fmt.Errorf("disallowed address %q", ip)
		}
	}
	return nil
}

// runCommand runs the command with the address substituted in.
func runCommand(template, ip string) (string, error) {
	command := strings.ReplaceAll(template, "%s", ip)
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", fmt.Errorf("empty command")
	}
	// #nosec G204 -- the whole command is written by the operator in the
	// configuration, and the substituted address is checked by validateIP first.
	cmd := exec.Command(parts[0], parts[1:]...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}
