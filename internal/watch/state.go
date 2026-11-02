// Writing state to disk: the same way for every watcher, with a message on the
// first failure.
package watch

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// stateWriteFailed remembers which failed write has already been reported: each
// state file is reported once so the log is not flooded.
var stateWriteFailed sync.Map

// saveJSONState writes a value into a state file.
func saveJSONState(path string, value any, mode os.FileMode) {
	raw, err := json.Marshal(value)
	if err != nil {
		reportStateError(path, err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		reportStateError(path, err)
		return
	}
	if err := os.WriteFile(path, raw, mode); err != nil {
		reportStateError(path, err)
		return
	}
	stateWriteFailed.Delete(path)
}

// loadJSONState reads a state file. Any trouble means "start from empty":
// corrupted state is no reason to give up watching.
func loadJSONState(path string, target any) bool {
	// #nosec G304 -- only our own state inside state_dir is read.
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(raw, target) == nil
}

// reportStateError reports a failed write once per file.
func reportStateError(path string, err error) {
	if _, already := stateWriteFailed.LoadOrStore(path, true); already {
		return
	}
	slog.Error("cannot write state: watching continues, but logs will be re-read after a restart",
		slog.String("file", path), slog.Any("error", err))
}
