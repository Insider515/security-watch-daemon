//go:build !linux

// Stub for systems without inotify: the service still builds and runs, only
// real-time file watching stays off and scheduled scanning does the work.
package watch

import (
	"context"
	"errors"
)

// RealtimeFiles is a no-op outside Linux.
type RealtimeFiles struct{}

// NewRealtimeFiles creates the no-op watcher.
func NewRealtimeFiles(_ FilesConfig, _ func(Event)) *RealtimeFiles { return &RealtimeFiles{} }

// Run returns an error right away; the caller falls back to scheduled scanning.
func (r *RealtimeFiles) Run(_ context.Context) error {
	return errors.New("real-time file watching is available on Linux only")
}
