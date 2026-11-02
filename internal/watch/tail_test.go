package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Reading continues from the remembered position, while a re-created file is
// read from the beginning - otherwise the watcher goes blind after the nightly
// log rotation.
func TestTailerContinuesAndHandlesRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	stateDir := filepath.Join(dir, "state")

	if err := os.WriteFile(logPath, []byte("first\nsecond\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	tailer := NewTailer(logPath, stateDir, time.Millisecond)
	lines := []string{}
	state := tailer.loadState()
	if err := tailer.readNew(&state, func(line string) { lines = append(lines, line) }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}

	// After an append only the new part is read.
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString("third\n")
	file.Close()

	lines = nil
	state = tailer.loadState()
	if err := tailer.readNew(&state, func(line string) { lines = append(lines, line) }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "third" {
		t.Fatalf("expected only the new line, got %v", lines)
	}

	// The log was truncated (as logrotate does with copytruncate) - read from the
	// beginning.
	if err := os.WriteFile(logPath, []byte("after rotation\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	lines = nil
	state = tailer.loadState()
	if err := tailer.readNew(&state, func(line string) { lines = append(lines, line) }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "after rotation" {
		t.Fatalf("after rotation a line from the start of the file was expected, got %v", lines)
	}
}

// An unfinished line is not handed over until the newline is written: otherwise
// half a log line would be parsed as a whole one.
func TestTailerWaitsForCompleteLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")

	if err := os.WriteFile(logPath, []byte("whole\nhalf"), 0o640); err != nil {
		t.Fatal(err)
	}
	tailer := NewTailer(logPath, filepath.Join(dir, "state"), time.Millisecond)
	lines := []string{}
	state := tailer.loadState()
	if err := tailer.readNew(&state, func(line string) { lines = append(lines, line) }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "whole" {
		t.Fatalf("expected one complete line, got %v", lines)
	}
}

// Logs with the date in the name (Laravel, Symfony and others start a new file
// every day): the reader picks the most recent matching file.
func TestTailerFollowsNewestByPattern(t *testing.T) {
	dir := t.TempDir()
	older := filepath.Join(dir, "laravel-2026-10-30.log")
	newer := filepath.Join(dir, "laravel-2026-10-31.log")
	if err := os.WriteFile(older, []byte("yesterday\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte("today\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	// Make yesterday's file clearly older by modification time.
	old := time.Now().Add(-48 * time.Hour)
	os.Chtimes(older, old, old)

	tailer := NewTailer(filepath.Join(dir, "laravel-*.log"), filepath.Join(dir, "state"), time.Millisecond)
	if got := tailer.resolvePath(); got != newer {
		t.Fatalf("expected the most recent file %s, got %s", newer, got)
	}

	lines := []string{}
	state := tailer.loadState()
	if err := tailer.readNew(&state, func(line string) { lines = append(lines, line) }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "today" {
		t.Fatalf("read from the wrong file: %v", lines)
	}
}
