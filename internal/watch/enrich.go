// Facts about an address: reverse name, network owner, abuse contact and
// membership in well-known lists.
package watch

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EnrichConfig - what to enrich events with.
type EnrichConfig struct {
	Enabled bool `json:"enabled"`
	// Reverse name of the address (PTR). The query goes to your own resolver.
	ReverseDNS bool `json:"reverse_dns"`
	// Network owner and abuse contact through the open RDAP protocol.
	RDAP bool `json:"rdap"`
	// The Tor exit node list, refreshed from this URL.
	TorListURL string   `json:"tor_list_url"`
	Timeout    Duration `json:"timeout"`
	// How long to remember the answers: network facts change rarely and outside
	// queries should be rare.
	CacheTTL Duration `json:"cache_ttl"`
}

// ipFacts - what could be learned about an address.
type ipFacts struct {
	PTR     string
	Network string
	Owner   string
	Country string
	Abuse   string
	Tor     bool
	at      time.Time
}

// Enricher obtains facts about an address (reverse name, network owner through
// RDAP, Tor membership) and keeps them in memory for the configured time. If a
// query fails, the event goes out without the extras.
type Enricher struct {
	cfg    EnrichConfig
	mu     sync.Mutex
	cache  map[string]ipFacts
	tor    map[string]bool
	torAt  time.Time
	client *http.Client
}

// NewEnricher creates the enricher.
func NewEnricher(cfg EnrichConfig) *Enricher {
	timeout := cfg.Timeout.Duration
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if cfg.CacheTTL.Duration == 0 {
		cfg.CacheTTL.Duration = 12 * time.Hour
	}
	return &Enricher{
		cfg:    cfg,
		cache:  map[string]ipFacts{},
		tor:    map[string]bool{},
		client: &http.Client{Timeout: timeout},
	}
}

// Apply adds the address facts to an event. The event is returned either way,
// with the extras or without them.
func (e *Enricher) Apply(event Event) Event {
	if !e.cfg.Enabled || event.IP == "" || isPrivateIP(event.IP) {
		return event
	}
	facts := e.lookup(event.IP)
	if event.Details == nil {
		event.Details = map[string]string{}
	}
	if facts.PTR != "" {
		event.Details["ptr"] = facts.PTR
	}
	if facts.Network != "" {
		event.Details["network"] = facts.Network
	}
	if facts.Owner != "" {
		event.Details["owner"] = facts.Owner
	}
	if facts.Country != "" {
		event.Details["country"] = facts.Country
	}
	if facts.Abuse != "" {
		event.Details["abuse_contact"] = facts.Abuse
	}
	if facts.Tor {
		event.Details["tor_exit"] = "yes"
	}
	return event
}

// lookup returns facts from memory or obtains them.
func (e *Enricher) lookup(ip string) ipFacts {
	e.mu.Lock()
	if facts, known := e.cache[ip]; known && time.Since(facts.at) < e.cfg.CacheTTL.Duration {
		e.mu.Unlock()
		return facts
	}
	e.mu.Unlock()

	facts := ipFacts{at: time.Now()}
	if e.cfg.ReverseDNS {
		facts.PTR = reverseName(ip, e.client.Timeout)
	}
	if e.cfg.RDAP {
		facts.Network, facts.Owner, facts.Country, facts.Abuse = rdapLookup(e.client, ip)
	}
	if e.cfg.TorListURL != "" {
		facts.Tor = e.isTorExit(ip)
	}

	e.mu.Lock()
	e.cache[ip] = facts
	e.mu.Unlock()
	return facts
}

// reverseName asks for the reverse name of an address.
func reverseName(ip string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// rdapResponse - the part of the RDAP registry answer that is needed.
type rdapResponse struct {
	Handle   string `json:"handle"`
	Name     string `json:"name"`
	Country  string `json:"country"`
	Entities []struct {
		Roles      []string `json:"roles"`
		VcardArray []any    `json:"vcardArray"`
	} `json:"entities"`
}

// rdapLookup asks the open registry service whose network this is and where to
// complain. RDAP replaced whois and answers in JSON.
func rdapLookup(client *http.Client, ip string) (network, owner, country, abuse string) {
	request, err := http.NewRequest(http.MethodGet, "https://rdap.org/ip/"+ip, nil)
	if err != nil {
		return "", "", "", ""
	}
	request.Header.Set("Accept", "application/rdap+json")
	response, err := client.Do(request)
	if err != nil {
		return "", "", "", ""
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", "", "", ""
	}
	parsed := rdapResponse{}
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return "", "", "", ""
	}
	for _, entity := range parsed.Entities {
		for _, role := range entity.Roles {
			if role == "abuse" {
				abuse = firstEmailFromVcard(entity.VcardArray)
			}
		}
	}
	return parsed.Handle, parsed.Name, parsed.Country, abuse
}

// firstEmailFromVcard pulls the email out of the vCard array RDAP uses for
// contacts. The parsing is lenient: registries differ in format.
func firstEmailFromVcard(vcard []any) string {
	for _, item := range vcard {
		list, ok := item.([]any)
		if !ok {
			continue
		}
		for _, field := range list {
			entry, ok := field.([]any)
			if !ok || len(entry) < 4 {
				continue
			}
			if name, _ := entry[0].(string); name == "email" {
				if value, ok := entry[3].(string); ok {
					return value
				}
			}
		}
	}
	return ""
}

// isTorExit checks the address against the Tor exit node list. The list is
// refreshed at most once an hour.
func (e *Enricher) isTorExit(ip string) bool {
	e.mu.Lock()
	stale := time.Since(e.torAt) > time.Hour
	e.mu.Unlock()
	if stale {
		e.refreshTorList()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tor[ip]
}

// refreshTorList downloads the exit node list.
func (e *Enricher) refreshTorList() {
	response, err := e.client.Get(e.cfg.TorListURL)
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return
	}
	buffer := make([]byte, 1<<20) // a megabyte is more than the address list takes
	read, _ := response.Body.Read(buffer)
	list := map[string]bool{}
	for _, line := range strings.Split(string(buffer[:read]), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && net.ParseIP(line) != nil {
			list[line] = true
		}
	}
	e.mu.Lock()
	e.tor = list
	e.torAt = time.Now()
	e.mu.Unlock()
}
