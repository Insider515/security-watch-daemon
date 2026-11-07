//go:build linux

// Watching files the moment they change: a subscription to kernel events
// (inotify) instead of scanning on schedule.
package watch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// inotifyMask - what is watched: creation, writing, deletion, moving and
// permission changes. Reading is not included: the kernel only reports it
// through auditd.
const inotifyMask = syscall.IN_CREATE | syscall.IN_MODIFY | syscall.IN_DELETE |
	syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO | syscall.IN_ATTRIB | syscall.IN_DELETE_SELF

// RealtimeFiles watches directories through inotify.
//
// Scheduled scanning notices a replacement after half an interval on average -
// two and a half minutes with a five-minute interval, which is enough to swap a
// file, do the job and put it back. A subscription to kernel events reports the
// write the moment it happens.
//
// Scanning does not go away: inotify does not survive a service restart and does
// not see what happened while the service was down, so snapshot comparison stays
// as the backstop while the subscription provides speed.
type RealtimeFiles struct {
	cfg   FilesConfig
	emit  func(Event)
	fd    int
	paths map[int]string
	// Names worth reporting in a directory that was subscribed to only because
	// a single file inside it was named in the configuration. inotify watches
	// directories, not files, so watching one file means watching its directory
	// and sifting the events by name.
	wanted map[int]map[string]bool
	// Directories named in the configuration in their own right: everything
	// inside them is reported.
	whole map[int]bool
}

// NewRealtimeFiles creates the watcher.
func NewRealtimeFiles(cfg FilesConfig, emit func(Event)) *RealtimeFiles {
	return &RealtimeFiles{
		cfg: cfg, emit: emit, fd: -1,
		paths:  map[int]string{},
		wanted: map[int]map[string]bool{},
		whole:  map[int]bool{},
	}
}

// Run subscribes to the directories and reads events until ctx is cancelled.
//
// The descriptor is opened non-blocking and waited on with select: closing a
// descriptor does not interrupt a blocking read on Linux, so the earlier
// version kept the goroutine alive after cancellation and systemd had to kill
// the service with SIGKILL after its stop timeout.
func (r *RealtimeFiles) Run(ctx context.Context) error {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return err
	}
	r.fd = fd
	defer syscall.Close(fd)

	for _, root := range r.cfg.Paths {
		r.addRecursive(root, 0)
	}
	slog.Info("real-time file watching", slog.Int("directories", len(r.paths)))

	buffer := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := syscall.Read(fd, buffer)
		switch {
		case err == syscall.EAGAIN || err == syscall.EWOULDBLOCK:
			// Nothing has happened yet: wait for events or for the timeout, so
			// cancellation is noticed within that time.
			waitForEvents(fd, 300*time.Millisecond)
			continue
		case err == syscall.EINTR:
			continue
		case err != nil:
			return nil
		}
		r.handleBuffer(buffer[:n])
	}
}

// waitForEvents waits until the descriptor has something to read or until the
// timeout passes.
func waitForEvents(fd int, timeout time.Duration) {
	set := &syscall.FdSet{}
	set.Bits[fd/64] |= 1 << (uint(fd) % 64)
	limit := syscall.NsecToTimeval(timeout.Nanoseconds())
	for {
		_, err := syscall.Select(fd+1, set, nil, nil, &limit)
		if err != syscall.EINTR {
			return
		}
	}
}

// addRecursive subscribes to a directory and its subdirectories.
func (r *RealtimeFiles) addRecursive(path string, depth int) {
	if depth > r.cfg.MaxDepth {
		return
	}
	for _, skip := range r.cfg.Skip {
		if skip != "" && strings.Contains(path, skip) {
			return
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	// A single file named in the configuration is watched through its own
	// directory, because that is all inotify can subscribe to. Only that file is
	// then reported, and the neighbouring directories are left alone: otherwise
	// one named file - /app/.env, say - drags the whole tree beside it under
	// watch, which on a deployed application is hundreds of directories and
	// tens of thousands of events a day that nobody asked for.
	if !info.IsDir() {
		directory := filepath.Dir(path)
		watch, err := syscall.InotifyAddWatch(r.fd, directory, inotifyMask)
		if err != nil {
			return
		}
		r.paths[watch] = directory
		if !r.whole[watch] {
			if r.wanted[watch] == nil {
				r.wanted[watch] = map[string]bool{}
			}
			r.wanted[watch][filepath.Base(path)] = true
		}
		return
	}

	watch, err := syscall.InotifyAddWatch(r.fd, path, inotifyMask)
	if err != nil {
		return
	}
	r.paths[watch] = path
	// The directory was named in its own right, so the sifting by name that an
	// earlier single file may have set up no longer applies.
	r.whole[watch] = true
	delete(r.wanted, watch)

	entries, err := os.ReadDir(path)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			r.addRecursive(filepath.Join(path, entry.Name()), depth+1)
		}
	}
}

// handleBuffer parses a batch of kernel events.
func (r *RealtimeFiles) handleBuffer(data []byte) {
	offset := 0
	for offset+syscall.SizeofInotifyEvent <= len(data) {
		raw := (*syscall.InotifyEvent)(unsafe.Pointer(&data[offset]))
		nameLen := int(raw.Len)
		name := ""
		if nameLen > 0 {
			start := offset + syscall.SizeofInotifyEvent
			end := start + nameLen
			if end <= len(data) {
				name = strings.TrimRight(string(data[start:end]), "\x00")
			}
		}
		dir := r.paths[int(raw.Wd)]
		full := dir
		if name != "" {
			full = filepath.Join(dir, name)
		}
		// In a directory watched for the sake of one file, its neighbours are
		// not our business. An event with no name is about the directory itself
		// and is always reported: the file cannot survive its directory.
		if names := r.wanted[int(raw.Wd)]; names != nil && name != "" && !names[name] {
			offset += syscall.SizeofInotifyEvent + nameLen
			continue
		}
		r.report(raw.Mask, full)
		offset += syscall.SizeofInotifyEvent + nameLen
	}
}

// report turns a kernel mask into a watcher event.
func (r *RealtimeFiles) report(mask uint32, path string) {
	if path == "" {
		return
	}
	for _, skip := range r.cfg.Skip {
		if skip != "" && strings.Contains(path, skip) {
			return
		}
	}
	kind, severity := "file_touched", SevWarn
	switch {
	case mask&syscall.IN_CREATE != 0 || mask&syscall.IN_MOVED_TO != 0:
		kind, severity = "file_added_realtime", SevAlert
	case mask&syscall.IN_DELETE != 0 || mask&syscall.IN_DELETE_SELF != 0 || mask&syscall.IN_MOVED_FROM != 0:
		kind, severity = "file_removed_realtime", SevAlert
	case mask&syscall.IN_MODIFY != 0:
		kind, severity = "file_changed_realtime", SevAlert
	case mask&syscall.IN_ATTRIB != 0:
		kind, severity = "file_mode_changed_realtime", SevWarn
	}

	// New subdirectories are taken under watch as well, otherwise a replacement
	// one level down would go unnoticed.
	if mask&syscall.IN_CREATE != 0 {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			r.addRecursive(path, 0)
		}
	}

	r.emit(Event{
		At: time.Now(), Source: "files", Kind: kind, Severity: severity,
		Subject: path, Count: 1,
		Details: map[string]string{"source": "inotify"},
	})
}
