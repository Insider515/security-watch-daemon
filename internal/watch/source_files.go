// Watching important files for changes: replaced code, a new access key, an
// edited service unit or cron schedule.
package watch

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// fileRecord - the snapshot of one file.
type fileRecord struct {
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
	Sum     string `json:"sha256"`
	Mode    string `json:"mode"`
}

// FilesWatcher compares the current state of the selected paths with the
// previous snapshot. The snapshot is kept on disk, so a replacement that
// happened while the service was down is noticed too. Contents are compared by
// SHA-256, not by size.
type FilesWatcher struct {
	cfg       FilesConfig
	statePath string
	emit      func(Event)
}

// NewFilesWatcher creates the file watcher.
func NewFilesWatcher(cfg FilesConfig, stateDir string, emit func(Event)) *FilesWatcher {
	return &FilesWatcher{cfg: cfg, statePath: filepath.Join(stateDir, "files.state.json"), emit: emit}
}

// Scan walks the paths and emits events for differences from the snapshot.
func (f *FilesWatcher) Scan() error {
	previous := f.loadState()
	current := map[string]fileRecord{}

	for _, root := range f.cfg.Paths {
		if err := f.walk(root, current); err != nil {
			f.emit(Event{
				At: time.Now(), Source: "files", Kind: "scan_error", Severity: SevWarn,
				Subject: root, Count: 1, Details: map[string]string{"error": err.Error()},
			})
		}
	}

	// The first pass only remembers: otherwise installing the service would
	// produce an event for every existing file.
	if len(previous) == 0 {
		return f.saveState(current)
	}

	for path, now := range current {
		before, existed := previous[path]
		switch {
		case !existed:
			f.emit(Event{
				At: time.Now(), Source: "files", Kind: "file_added", Severity: SevAlert,
				Subject: path, Count: 1,
				Details: map[string]string{"size": strconv.FormatInt(now.Size, 10), "mode": now.Mode},
			})
		case before.Sum != now.Sum:
			f.emit(Event{
				At: time.Now(), Source: "files", Kind: "file_changed", Severity: SevAlert,
				Subject: path, Count: 1,
				Details: map[string]string{
					"size_before": strconv.FormatInt(before.Size, 10),
					"size_now":    strconv.FormatInt(now.Size, 10),
					"mode":        now.Mode,
				},
			})
		case before.Mode != now.Mode:
			f.emit(Event{
				At: time.Now(), Source: "files", Kind: "file_mode_changed", Severity: SevWarn,
				Subject: path, Count: 1,
				Details: map[string]string{"mode_before": before.Mode, "mode_now": now.Mode},
			})
		}
	}
	for path := range previous {
		if _, still := current[path]; !still {
			f.emit(Event{
				At: time.Now(), Source: "files", Kind: "file_removed", Severity: SevAlert,
				Subject: path, Count: 1,
			})
		}
	}
	return f.saveState(current)
}

// walk traverses a path (file or directory) and collects snapshots.
func (f *FilesWatcher) walk(root string, into map[string]fileRecord) error {
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil // something unreadable is no reason to stop the walk
		}
		for _, skip := range f.cfg.Skip {
			if skip != "" && strings.Contains(path, skip) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if entry.IsDir() {
			if strings.Count(filepath.Clean(path), string(os.PathSeparator))-rootDepth >= f.cfg.MaxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		sum, err := hashFile(path)
		if err != nil {
			return nil
		}
		into[path] = fileRecord{
			Size:    info.Size(),
			ModTime: info.ModTime().Unix(),
			Sum:     sum,
			Mode:    info.Mode().String(),
		}
		return nil
	})
}

// hashFile computes the SHA-256 of the contents.
func hashFile(path string) (string, error) {
	// #nosec G304 -- hashing a file listed in files.paths of the configuration.
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// loadState reads the previous snapshot.
func (f *FilesWatcher) loadState() map[string]fileRecord {
	state := map[string]fileRecord{}
	loadJSONState(f.statePath, &state)
	return state
}

// saveState writes the snapshot.
func (f *FilesWatcher) saveState(state map[string]fileRecord) error {
	saveJSONState(f.statePath, state, 0o600)
	return nil
}
