// An on-disk queue for sinks that need the network: an event is not lost when
// the link goes down and is sent as soon as it is back.
package watch

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Outbox wraps a sink: events that could not be sent land on disk and go out at
// the first opportunity.
type Outbox struct {
	inner    Sink
	path     string
	mu       sync.Mutex
	maxItems int
}

// NewOutbox wraps a sink with the queue.
func NewOutbox(inner Sink, stateDir string, maxItems int) *Outbox {
	if maxItems <= 0 {
		maxItems = 5000
	}
	return &Outbox{
		inner:    inner,
		path:     filepath.Join(stateDir, "outbox."+inner.Name()+".jsonl"),
		maxItems: maxItems,
	}
}

// Send tries to deliver right away and puts the events on disk when that is not
// possible. A deliberate deferral (the email throttle period) is not a failure:
// the events are stored and nil is returned, so the counters stay honest.
func (o *Outbox) Send(events []Event) error {
	err := o.inner.Send(events)
	switch {
	case err == nil:
		o.flush()
		return nil
	case errors.Is(err, errDeferred):
		o.store(events)
		return nil
	default:
		o.store(events)
		return err
	}
}

// Name is used in the log.
func (o *Outbox) Name() string { return o.inner.Name() }

// Flush sends what the queue holds, ignoring the timing of the wrapped sink. The
// queue file is removed only after a successful send, so nothing is lost on
// shutdown.
func (o *Outbox) Flush() error {
	immediate, ok := o.inner.(immediateSink)
	if !ok {
		return nil
	}
	o.mu.Lock()
	pending := o.readPending()
	o.mu.Unlock()
	if len(pending) == 0 {
		return nil
	}
	if err := immediate.SendNow(pending); err != nil {
		return err
	}
	o.mu.Lock()
	_ = os.Remove(o.path)
	o.mu.Unlock()
	slog.Info("the last events were sent on shutdown", slog.String("sink", o.inner.Name()),
		slog.Int("events", len(pending)))
	return nil
}

// store appends events to the queue.
func (o *Outbox) store(events []Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_ = os.MkdirAll(filepath.Dir(o.path), 0o750)
	file, err := os.OpenFile(o.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer file.Close()
	for _, event := range events {
		if line, err := json.Marshal(event); err == nil {
			_, _ = file.Write(append(line, '\n'))
		}
	}
}

// flush tries to deliver what was deferred. The queue is cleared only after a
// successful send: better to deliver twice than to lose an event.
func (o *Outbox) flush() {
	o.mu.Lock()
	defer o.mu.Unlock()

	pending := o.readPending()
	if len(pending) == 0 {
		return
	}
	if err := o.inner.Send(pending); err != nil {
		// A deliberate deferral is not worth a warning: the sink is simply
		// waiting out its period and the events stay in the queue.
		if !errors.Is(err, errDeferred) {
			slog.Warn("deferred events still cannot be delivered", slog.String("sink", o.inner.Name()),
				slog.Int("events", len(pending)), slog.Any("error", err))
		}
		return
	}
	_ = os.Remove(o.path)
	slog.Info("deferred events delivered", slog.String("sink", o.inner.Name()), slog.Int("events", len(pending)))
}

// readPending reads the queue from disk.
func (o *Outbox) readPending() []Event {
	file, err := os.Open(o.path)
	if err != nil {
		return nil
	}
	defer file.Close()

	events := []Event{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		event := Event{}
		if json.Unmarshal(scanner.Bytes(), &event) == nil {
			events = append(events, event)
		}
		// The queue length limit: during a long outage the earliest events are
		// kept, the ones that relate to the beginning of what happened.
		if len(events) >= o.maxItems {
			break
		}
	}
	return events
}

// Retry periodically tries to deliver what was deferred until ctx is cancelled.
func (o *Outbox) Retry(ctx context.Context, every time.Duration) {
	runEvery(ctx, every, o.flush)
}
