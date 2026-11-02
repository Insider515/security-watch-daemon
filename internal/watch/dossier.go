// A dossier on an attacker: everything they told about themselves, collected per
// address and kept across service restarts.
package watch

import (
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Dossier holds what is known about one address, gathered from what it sent
// itself: request headers, scanned paths, issued canary tokens.
type Dossier struct {
	IP          string            `json:"ip"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	Hits        int               `json:"hits"`
	Paths       []string          `json:"paths"`
	UserAgents  []string          `json:"user_agents"`
	Headers     map[string]string `json:"headers"`
	Fingerprint string            `json:"fingerprint"`
	// Tokens issued to this address: if they surface during a login attempt, the
	// link between "poked at the trap" and "is trying to log in" is proven.
	BaitTokens []string `json:"bait_tokens"`
	// Tokens it has already tried to use.
	BaitUsed []string `json:"bait_used"`
	Notes    []string `json:"notes"`
}

// DossierStore keeps the dossiers on disk.
type DossierStore struct {
	mu    sync.Mutex
	path  string
	items map[string]*Dossier
}

// NewDossierStore reads the dossiers from disk.
func NewDossierStore(stateDir string) *DossierStore {
	store := &DossierStore{
		path:  filepath.Join(stateDir, "dossier.json"),
		items: map[string]*Dossier{},
	}
	loadJSONState(store.path, &store.items)
	return store
}

// Record adds what the latest request revealed to the dossier.
func (d *DossierStore) Record(ip, path, agent, fingerprint string, headers map[string]string, note string) *Dossier {
	d.mu.Lock()
	defer d.mu.Unlock()

	item, known := d.items[ip]
	if !known {
		item = &Dossier{IP: ip, FirstSeen: time.Now(), Headers: map[string]string{}}
		d.items[ip] = item
	}
	item.LastSeen = time.Now()
	item.Hits++
	item.Paths = appendUnique(item.Paths, path, 50)
	item.UserAgents = appendUnique(item.UserAgents, agent, 10)
	if fingerprint != "" {
		item.Fingerprint = fingerprint
	}
	for name, value := range headers {
		if _, has := item.Headers[name]; !has && len(item.Headers) < 40 {
			item.Headers[name] = value
		}
	}
	if note != "" {
		item.Notes = appendUnique(item.Notes, note, 20)
	}
	d.save()
	return item
}

// AddBait remembers a token issued to the address.
func (d *DossierStore) AddBait(ip, token string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if item, known := d.items[ip]; known {
		item.BaitTokens = appendUnique(item.BaitTokens, token, 20)
		d.save()
	}
}

// MarkBaitUsed records that an issued token has been used.
func (d *DossierStore) MarkBaitUsed(token string) *Dossier {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, item := range d.items {
		for _, issued := range item.BaitTokens {
			if issued == token {
				item.BaitUsed = appendUnique(item.BaitUsed, token, 20)
				d.save()
				return item
			}
		}
	}
	return nil
}

// All returns the dossiers, most recent first.
func (d *DossierStore) All() []*Dossier {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]*Dossier, 0, len(d.items))
	for _, item := range d.items {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Get returns the dossier for an address.
func (d *DossierStore) Get(ip string) *Dossier {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.items[ip]
}

// save writes the dossiers to disk.
func (d *DossierStore) save() {
	saveJSONState(d.path, d.items, 0o600)
}

// appendUnique adds a value unless it is already there, respecting the limit.
func appendUnique(list []string, value string, limit int) []string {
	if value == "" {
		return list
	}
	for _, item := range list {
		if item == value {
			return list
		}
	}
	if len(list) >= limit {
		return list
	}
	return append(list, value)
}
