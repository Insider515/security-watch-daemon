// Reading a growing log file: from where reading stopped, handling file
// re-creation and truncation.
package watch

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Tailer reads a file line by line from the remembered position and keeps going
// as the file grows. The position is kept on disk, so a service restart loses no
// lines. Log rotation is detected by the size going down and by a change of the
// file identity.
type Tailer struct {
	path      string
	statePath string
	poll      time.Duration
}

// tailState is what survives a service restart.
type tailState struct {
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
	Inode  uint64 `json:"inode"`
}

// NewTailer creates the reader. stateDir is the directory for read marks. The
// path may contain a name pattern ("laravel-*.log") for logs that start a new
// file with the date every day: the reader picks the most recent one.
func NewTailer(path, stateDir string, poll time.Duration) *Tailer {
	name := filepath.Base(path) + ".state.json"
	name = strings.NewReplacer("*", "_", "?", "_", "[", "_", "]", "_").Replace(name)
	return &Tailer{path: path, statePath: filepath.Join(stateDir, name), poll: poll}
}

// resolvePath returns the file to read: the path itself, or the most recent one
// matching the pattern.
func (t *Tailer) resolvePath() string {
	if !strings.ContainsAny(t.path, "*?[") {
		return t.path
	}
	matches, err := filepath.Glob(t.path)
	if err != nil || len(matches) == 0 {
		return t.path
	}
	newest, newestTime := "", time.Time{}
	for _, candidate := range matches {
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.ModTime().After(newestTime) {
			newest, newestTime = candidate, info.ModTime()
		}
	}
	if newest == "" {
		return t.path
	}
	return newest
}

// Run reads the file and passes every new line to handle until ctx is cancelled.
func (t *Tailer) Run(ctx context.Context, handle func(line string)) error {
	state := t.loadState()
	ticker := time.NewTicker(t.poll)
	defer ticker.Stop()

	for {
		if err := t.readNew(&state, handle); err != nil && !os.IsNotExist(err) {
			return err
		}
		select {
		case <-ctx.Done():
			t.saveState(state)
			return nil
		case <-ticker.C:
		}
	}
}

// readNew reads whatever appeared since the last pass.
func (t *Tailer) readNew(state *tailState, handle func(line string)) error {
	path := t.resolvePath()
	// #nosec G304 -- the log path comes from the service configuration file.
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	inode := fileInode(info)

	// The file was replaced or truncated, so read from the beginning: this is
	// exactly the rotated-log case.
	if inode != state.Inode || info.Size() < state.Offset {
		state.Offset = 0
		state.Inode = inode
	}
	if info.Size() == state.Offset {
		return nil
	}
	if _, err := file.Seek(state.Offset, io.SeekStart); err != nil {
		return err
	}

	reader := bufio.NewReaderSize(file, 64*1024)
	consumed := state.Offset
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 && err == nil {
			consumed += int64(len(line))
			handle(trimNewline(line))
			continue
		}
		// An unfinished line is left alone: it will be read next time, once the
		// web server has written the newline.
		break
	}
	state.Offset = consumed
	state.Size = info.Size()
	t.saveState(*state)
	return nil
}

// trimNewline strips the trailing newline.
func trimNewline(line string) string {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}

// loadState reads the mark from disk; on any trouble it starts from zero.
func (t *Tailer) loadState() tailState {
	state := tailState{}
	loadJSONState(t.statePath, &state)
	return state
}

// saveState writes the mark. Failures are reported by saveJSONState itself:
// watching matters more than the mark, so the reader carries on.
func (t *Tailer) saveState(state tailState) {
	saveJSONState(t.statePath, state, 0o600)
}
