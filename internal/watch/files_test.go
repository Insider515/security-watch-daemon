package watch

import (
	"os"
	"path/filepath"
	"testing"
)

// The first pass only remembers the state: otherwise installing the service
// would produce an event for every existing file.
func TestFilesWatcherFirstScanIsSilent(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "app")
	os.MkdirAll(watched, 0o750)
	os.WriteFile(filepath.Join(watched, "a.js"), []byte("one"), 0o640)

	events := []Event{}
	watcher := NewFilesWatcher(FilesConfig{Paths: []string{watched}, MaxDepth: 3},
		filepath.Join(dir, "state"), func(e Event) { events = append(events, e) })

	if err := watcher.Scan(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("the first pass must produce no events, got %+v", events)
	}
}

// Replaced content, an added file and a deleted file are all noticed.
func TestFilesWatcherDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "app")
	os.MkdirAll(watched, 0o750)
	target := filepath.Join(watched, "a.js")
	os.WriteFile(target, []byte("one"), 0o640)
	doomed := filepath.Join(watched, "b.js")
	os.WriteFile(doomed, []byte("two"), 0o640)

	events := []Event{}
	watcher := NewFilesWatcher(FilesConfig{Paths: []string{watched}, MaxDepth: 3},
		filepath.Join(dir, "state"), func(e Event) { events = append(events, e) })
	if err := watcher.Scan(); err != nil {
		t.Fatal(err)
	}

	// An in-place edit of the same length is exactly what a guard comparing only
	// sizes would miss.
	os.WriteFile(target, []byte("six"), 0o640)
	os.WriteFile(filepath.Join(watched, "c.js"), []byte("fresh"), 0o640)
	os.Remove(doomed)

	events = nil
	if err := watcher.Scan(); err != nil {
		t.Fatal(err)
	}

	kinds := map[string]string{}
	for _, event := range events {
		kinds[event.Kind] = event.Subject
	}
	if kinds["file_changed"] != target {
		t.Errorf("replaced content was not noticed: %+v", events)
	}
	if kinds["file_added"] == "" {
		t.Errorf("the new file was not noticed: %+v", events)
	}
	if kinds["file_removed"] != doomed {
		t.Errorf("the deletion was not noticed: %+v", events)
	}
}

// Skipping directories works: otherwise the walk drowns in node_modules.
func TestFilesWatcherSkip(t *testing.T) {
	dir := t.TempDir()
	watched := filepath.Join(dir, "app")
	os.MkdirAll(filepath.Join(watched, "node_modules", "pkg"), 0o750)
	os.WriteFile(filepath.Join(watched, "node_modules", "pkg", "x.js"), []byte("x"), 0o640)
	os.WriteFile(filepath.Join(watched, "a.js"), []byte("one"), 0o640)

	watcher := NewFilesWatcher(FilesConfig{Paths: []string{watched}, MaxDepth: 5, Skip: []string{"node_modules"}},
		filepath.Join(dir, "state"), func(e Event) {})
	collected := map[string]fileRecord{}
	if err := watcher.walk(watched, collected); err != nil {
		t.Fatal(err)
	}
	if len(collected) != 1 {
		t.Fatalf("expected one file outside the skipped directory, collected %d: %v", len(collected), collected)
	}
}
