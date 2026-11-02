// The trap: pages that no link on the site points to. They can only be reached
// by scanning, so whoever arrives there is scanning.
package watch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TrapConfig - trap settings.
type TrapConfig struct {
	Enabled bool `json:"enabled"`
	// Listen on the loopback only: nginx is what exposes the trap outside and
	// passes the real visitor address along.
	Addr string `json:"addr"`
	// The paths nginx routes here. They must not appear in links, in the
	// sitemap or in robots.txt, or search crawlers will come to them.
	Paths []string `json:"paths"`
	// Whether to serve bait content: a plausible configuration file with fake
	// credentials, unique for every visitor.
	ServeBait bool `json:"serve_bait"`
	// Template for the bait content. %s is where the fake key goes.
	BaitTemplate string `json:"bait_template"`
}

// TrapServer handles requests to the trap. Nothing links to the trap paths, so
// the request itself means scanning. The server records what the visitor sent
// (address, headers, fingerprint, scanned paths) and, when enabled, serves a
// fake configuration file with a key unique to that visitor. An attempt to log
// in with that key ties the trap hit to the login attempt.
type TrapServer struct {
	cfg    TrapConfig
	store  *DossierStore
	canary *RuntimeCanary
	emit   func(Event)
	server *http.Server
	mu     sync.Mutex
	addr   string
	issued map[string]string // token -> address it was issued to
}

// NewTrapServer creates the trap.
func NewTrapServer(cfg TrapConfig, store *DossierStore, canary *RuntimeCanary, emit func(Event)) *TrapServer {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:9778"
	}
	if cfg.BaitTemplate == "" {
		cfg.BaitTemplate = "APP_ENV=production\nAPP_DEBUG=false\nDB_HOST=127.0.0.1\nDB_USER=app\nDB_PASSWORD=%s\nAPI_KEY=%s\n"
	}
	return &TrapServer{cfg: cfg, store: store, canary: canary, emit: emit, issued: map[string]string{}}
}

// Run starts the trap.
func (t *TrapServer) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", t.cfg.Addr)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.addr = listener.Addr().String()
	t.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", t.handle)
	t.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = t.server.Close()
	}()
	slog.Info("trap listening", slog.String("address", t.Addr()), slog.Int("paths", len(t.cfg.Paths)))
	if err := t.server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Addr returns the address the trap listens on.
func (t *TrapServer) Addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.addr != "" {
		return t.addr
	}
	return t.cfg.Addr
}

// handle records the request and serves the bait when told to.
func (t *TrapServer) handle(w http.ResponseWriter, r *http.Request) {
	ip := firstNonEmpty(
		r.Header.Get("CF-Connecting-IP"),
		r.Header.Get("X-Real-IP"),
		strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0],
	)
	path := firstNonEmpty(r.Header.Get("X-Original-URI"), r.URL.RequestURI())
	agent := r.Header.Get("User-Agent")
	fingerprint := firstNonEmpty(r.Header.Get("X-TLS-Fingerprint"), r.Header.Get("X-JA3"))

	headers := map[string]string{}
	for name, values := range r.Header {
		if name == "Authorization" || name == "Cookie" {
			// Someone else's secrets are of no use here: only the fact that
			// they were presented is recorded.
			headers[name] = "presented"
			continue
		}
		headers[name] = strings.Join(values, " ")
	}

	dossier := t.store.Record(ip, path, agent, fingerprint, headers, "trap hit")

	details := map[string]string{
		"method":     r.Method,
		"agent":      agent,
		"hits_total": strconv.Itoa(dossier.Hits),
		"paths_seen": strconv.Itoa(len(dossier.Paths)),
	}
	if fingerprint != "" {
		details["tls_fingerprint"] = fingerprint
	}

	// The bait is issued once per address: repeat requests get the same token,
	// otherwise the token list would grow and the link would be lost.
	if t.cfg.ServeBait {
		token := t.tokenFor(ip)
		details["bait_token"] = token
		body := fmt.Sprintf(t.cfg.BaitTemplate, token, token)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	} else {
		// Without the bait the trap answers like any missing address, so it
		// gives nothing away.
		http.NotFound(w, r)
	}

	t.emit(Event{
		At: time.Now(), Source: "trap", Kind: "trap_hit", Severity: SevAlert,
		IP: ip, Subject: path, Count: 1, Details: details,
	})
}

// tokenFor issues a bait token for an address and remembers the link.
func (t *TrapServer) tokenFor(ip string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	for token, owner := range t.issued {
		if owner == ip {
			return token
		}
	}
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		raw = []byte(time.Now().Format("150405.000000000"))
	}
	token := "SWBAIT_" + hex.EncodeToString(raw)
	t.issued[token] = ip
	t.store.AddBait(ip, token)
	// The token is taken under watch immediately: its appearance anywhere - in a
	// request, in the application log, in a POST body - will be noticed.
	t.canary.Add(token)
	return token
}
