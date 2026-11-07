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

// The defect this covers: a single file named in the configuration was watched
// through its directory, and that directory was then subscribed to
// recursively. One named file - /app/.env - dragged the whole application tree
// beside it under watch: 479 directories instead of 24 on a live server, and
// 35336 events a day from deployments that nobody asked about. Only the named
// file must be reported.
func TestRealtimeWatchesOneFileNotItsNeighbours(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.conf")
	neighbour := filepath.Join(dir, "neighbour.conf")
	deep := filepath.Join(dir, "subdir")

	for _, path := range []string{target, neighbour} {
		if err := os.WriteFile(path, []byte("before\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}

	seen := make(chan string, 16)
	realtime := NewRealtimeFiles(FilesConfig{Paths: []string{target}, MaxDepth: 6},
		func(e Event) { seen <- e.Subject })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = realtime.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)

	// A neighbour in the same directory and a file in a subdirectory are not
	// our business.
	if err := os.WriteFile(neighbour, []byte("after\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "inside.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The named file is.
	if err := os.WriteFile(target, []byte("after\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(3 * time.Second)
	gotTarget := false
	for !gotTarget {
		select {
		case subject := <-seen:
			switch {
			case subject == target:
				gotTarget = true
			case subject == neighbour:
				t.Fatalf("a neighbour in the same directory was reported: %s", subject)
			default:
				t.Fatalf("something outside the named file was reported: %s", subject)
			}
		case <-deadline:
			t.Fatal("the change to the named file was not reported")
		}
	}

	// Nothing about the neighbours must arrive afterwards either.
	select {
	case subject := <-seen:
		t.Fatalf("an event about the neighbours arrived late: %s", subject)
	case <-time.After(400 * time.Millisecond):
	}

	if len(realtime.paths) != 1 {
		t.Errorf("one named file must mean one watched directory, got %d", len(realtime.paths))
	}
}

// A directory named in its own right is still watched whole, including what
// appears inside it later.
func TestRealtimeWatchesWholeDirectoryWhenNamed(t *testing.T) {
	dir := t.TempDir()
	inside := filepath.Join(dir, "anything.conf")

	seen := make(chan string, 8)
	realtime := NewRealtimeFiles(FilesConfig{Paths: []string{dir}, MaxDepth: 6},
		func(e Event) { seen <- e.Subject })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = realtime.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)

	if err := os.WriteFile(inside, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case subject := <-seen:
		if subject != inside {
			t.Errorf("reported %s, expected %s", subject, inside)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a file appearing in a named directory was not reported")
	}
}
