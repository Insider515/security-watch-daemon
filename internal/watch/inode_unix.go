//go:build linux || darwin

// File identity in the filesystem: it shows that a log was replaced with a new
// file rather than merely appended to.
package watch

import (
	"io/fs"
	"syscall"
)

// fileInode returns the inode number, or 0 if the filesystem does not expose one.
func fileInode(info fs.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Ino)
}
