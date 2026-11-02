package watch

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The mirror receiver starts and accepts requests over the network, not only in
// a handler test: otherwise a mistake in the address setting would go unnoticed.
func TestMirrorServerRuns(t *testing.T) {
	events := make(chan Event, 4)
	server := NewMirrorServer(MirrorConfig{Addr: "127.0.0.1:0"}, nil, func(e Event) { events <- e })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := server.Run(ctx); err != nil {
			t.Errorf("the mirror did not start: %v", err)
		}
	}()
	addr := waitForServer(t, server.Addr)

	response, err := http.Post("http://"+addr+"/api/login", "application/json",
		strings.NewReader(`{"login":"admin' UNION SELECT 1 --"}`))
	if err != nil {
		t.Fatalf("the request to the mirror failed: %v", err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()

	select {
	case event := <-events:
		if event.Source != "mirror" || !strings.HasPrefix(event.Kind, "sqli") {
			t.Errorf("unexpected event: %+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event arrived from the mirror")
	}
}

// The trap starts, serves the bait and opens a dossier.
func TestTrapServerRuns(t *testing.T) {
	dir := t.TempDir()
	store := NewDossierStore(dir)
	events := make(chan Event, 4)
	trap := NewTrapServer(TrapConfig{Addr: "127.0.0.1:0", ServeBait: true}, store,
		NewRuntimeCanary(nil), func(e Event) { events <- e })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := trap.Run(ctx); err != nil {
			t.Errorf("the trap did not start: %v", err)
		}
	}()
	addr := waitForServer(t, trap.Addr)

	request, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/.env.bak", nil)
	request.Header.Set("CF-Connecting-IP", "203.0.113.77")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("the request to the trap failed: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()

	if !strings.Contains(string(body), "SWBAIT_") {
		t.Errorf("the bait was not served: %q", string(body))
	}
	select {
	case event := <-events:
		if event.Kind != "trap_hit" || event.IP != "203.0.113.77" {
			t.Errorf("unexpected event: %+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event arrived from the trap")
	}
	if store.Get("203.0.113.77") == nil {
		t.Errorf("no dossier was opened")
	}
}

// A scheduled repeating action stops when it is cancelled.
func TestRunEveryStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan struct{}, 10)
	go runEvery(ctx, 10*time.Millisecond, func() { calls <- struct{}{} })

	// The first call happens immediately, without waiting for the interval.
	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("the first call must be immediate")
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
	drain := len(calls)
	time.Sleep(50 * time.Millisecond)
	if len(calls) > drain+1 {
		t.Errorf("after cancellation the calls must stop")
	}
}

// What was deferred in the queue goes out once the sink answers again.
func TestOutboxRetryDelivers(t *testing.T) {
	dir := t.TempDir()
	inner := &failingSink{failures: 1}
	outbox := NewOutbox(inner, dir, 10)
	_ = outbox.Send([]Event{{At: time.Now(), Kind: "trap_hit"}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go outbox.Retry(ctx, 10*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if inner.delivered() > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the deferred event never went out")
}

// waitForServer waits until the server takes the port and returns its real
// address (the tests use port zero). It waits by connecting rather than by
// sending a request: a request to the trap would itself produce an event.
func waitForServer(t *testing.T, addrOf func() string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		addr := addrOf()
		if addr != "" && !strings.HasSuffix(addr, ":0") {
			connection, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if err == nil {
				connection.Close()
				return addr
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the server never started")
	return ""
}
