// The nginx mirror receiver: it makes the request body visible, which is in
// neither the web server log nor anywhere else.
package watch

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MirrorConfig - mirror receiver settings.
type MirrorConfig struct {
	Enabled bool `json:"enabled"`
	// Listen on the loopback only: this receiver must never be exposed.
	Addr string `json:"addr"`
	// How many bytes of the body to parse. More is pointless: injection
	// signatures fit in the beginning, and holding someone else's uploads in
	// memory serves no purpose.
	MaxBodyBytes int64 `json:"max_body_bytes"`
	// Field names that must not appear in a request from an outsider: role_id,
	// is_admin, balance and the like (injecting such fields is mass assignment).
	PrivilegedFields []string `json:"privileged_fields"`
	// Paths where these fields are legitimate: the admin sections. A request
	// with such fields to any other path is treated as coming from an outsider.
	AllowPaths []string `json:"allow_paths"`
}

// MirrorServer receives request copies from nginx (the mirror directive) and
// looks for injection signatures and privileged field injection in the body and
// headers. It answers immediately and does not delay the visitor's request.
type MirrorServer struct {
	mu     sync.Mutex
	addr   string
	cfg    MirrorConfig
	canary *RuntimeCanary
	emit   func(Event)
	server *http.Server
}

// NewMirrorServer creates the receiver.
func NewMirrorServer(cfg MirrorConfig, canary *RuntimeCanary, emit func(Event)) *MirrorServer {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:9777"
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 64 * 1024
	}
	if canary == nil {
		canary = NewRuntimeCanary(nil)
	}
	return &MirrorServer{cfg: cfg, canary: canary, emit: emit}
}

// Run starts the receiver and works until ctx is cancelled. The listener is
// opened before serving begins, and its real address is available through Addr.
func (m *MirrorServer) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", m.cfg.Addr)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.addr = listener.Addr().String()
	m.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handle)
	m.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = m.server.Close()
	}()
	slog.Info("mirror receiver listening", slog.String("address", m.Addr()))
	if err := m.server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Addr returns the address the receiver listens on.
func (m *MirrorServer) Addr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addr != "" {
		return m.addr
	}
	return m.cfg.Addr
}

// handle parses the request copy.
func (m *MirrorServer) handle(w http.ResponseWriter, r *http.Request) {
	// Answer right away: nginx waits for the mirror's response, and a delay here
	// is a delay for the real visitor.
	w.WriteHeader(http.StatusNoContent)

	body, _ := io.ReadAll(io.LimitReader(r.Body, m.cfg.MaxBodyBytes))
	_ = r.Body.Close()

	// nginx passes the visitor's real address in a header; the connection itself
	// always comes from the loopback.
	ip := firstNonEmpty(
		r.Header.Get("CF-Connecting-IP"),
		r.Header.Get("X-Real-IP"),
		strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0],
	)
	path := r.Header.Get("X-Original-URI")
	if path == "" {
		path = r.URL.RequestURI()
	}

	// Privileged fields in the body of a request to a non-privileged path.
	if field, found := m.privilegedField(path, string(body)); found {
		m.emit(Event{
			At: time.Now(), Source: "mirror", Kind: "mass_assignment_attempt", Severity: SevAlert,
			IP: ip, Subject: path, Count: 1,
			Details: map[string]string{
				"field":  field,
				"method": r.Method,
				"agent":  r.Header.Get("User-Agent"),
				"sample": sampleOf(string(body), 200),
			},
		})
		return
	}

	// Both the body and the headers are checked: injection hides in both.
	haystacks := []struct{ where, text string }{
		{"body", string(body)},
		{"headers", headerText(r)},
	}
	for _, item := range haystacks {
		if item.text == "" {
			continue
		}
		if token, found := m.canary.Match(item.text); found {
			m.emit(Event{
				At: time.Now(), Source: "mirror", Kind: "canary_used", Severity: SevAlert,
				IP: ip, Subject: path, Count: 1,
				Details: map[string]string{"where": item.where, "token": sampleOf(token, 12)},
			})
			return
		}
		if sig, found := matchInjection(item.text); found {
			m.emit(Event{
				At: time.Now(), Source: "mirror", Kind: sig.Kind, Severity: sig.Severity,
				IP: ip, Subject: path, Count: 1,
				Details: map[string]string{
					"where":  item.where,
					"method": r.Method,
					"agent":  r.Header.Get("User-Agent"),
					"sample": sampleOf(item.text, 200),
				},
			})
			return
		}
	}
}

// privilegedField looks for a field name in the request body that an outsider
// must not send. Admin paths are skipped entirely: such fields are legitimate
// there.
func (m *MirrorServer) privilegedField(path, body string) (string, bool) {
	if len(m.cfg.PrivilegedFields) == 0 || body == "" {
		return "", false
	}
	for _, allowed := range m.cfg.AllowPaths {
		if allowed != "" && strings.HasPrefix(path, allowed) {
			return "", false
		}
	}
	lower := strings.ToLower(body)
	for _, field := range m.cfg.PrivilegedFields {
		field = strings.ToLower(strings.TrimSpace(field))
		if field == "" {
			continue
		}
		// The field name is searched for as it arrives: "role_id": in JSON and
		// role_id= in a form. A plain substring match would also hit words such
		// as user_role_id_description.
		if strings.Contains(lower, `"`+field+`"`) || strings.Contains(lower, field+"=") ||
			strings.Contains(lower, `'`+field+`'`) || strings.Contains(lower, field+`":`) {
			return field, true
		}
	}
	return "", false
}

// headerText joins the headers into one string for matching.
func headerText(r *http.Request) string {
	parts := make([]string, 0, len(r.Header))
	for name, values := range r.Header {
		// There is no point in matching our own headers, and authorization data
		// must not end up in the event details.
		if name == "Authorization" || name == "Cookie" {
			continue
		}
		parts = append(parts, name+": "+strings.Join(values, " "))
	}
	return strings.Join(parts, "\n")
}

// firstNonEmpty returns the first non-empty value.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
