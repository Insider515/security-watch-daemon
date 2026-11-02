//go:build linux

package watch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The defect this covers: the descriptor was read blocking, and closing it does
// not interrupt a blocking read on Linux. The goroutine stayed alive after
// cancellation, so the service never exited and systemd killed it with SIGKILL
// after the stop timeout (measured: 1m30s). Run must return on cancellation.
func TestRealtimeFilesStopsOnCancel(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "watched"), 0o750); err != nil {
		t.Fatal(err)
	}

	realtime := NewRealtimeFiles(FilesConfig{
		Paths: []string{filepath.Join(dir, "watched")}, MaxDepth: 3,
	}, func(Event) {})

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- realtime.Run(ctx) }()

	// Let the watcher subscribe, then cancel.
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("cancellation must not be an error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the watcher did not stop on cancellation: the service would be killed by SIGKILL")
	}
}

// Watching must keep working with the non-blocking descriptor: a created file
// is reported within the wait interval.
func TestRealtimeFilesReportsCreation(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "watched")
	if err := os.MkdirAll(watched, 0o750); err != nil {
		t.Fatal(err)
	}

	events := make(chan Event, 8)
	realtime := NewRealtimeFiles(FilesConfig{Paths: []string{watched}, MaxDepth: 3},
		func(e Event) { events <- e })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = realtime.Run(ctx) }()
	time.Sleep(200 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(watched, "new.js"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}

	select {
	case event := <-events:
		if event.Source != "files" || event.Details["source"] != "inotify" {
			t.Errorf("unexpected event: %+v", event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the created file was not reported")
	}
}
