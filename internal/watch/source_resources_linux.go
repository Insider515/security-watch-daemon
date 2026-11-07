//go:build linux

// Reading the machine's resources on Linux: the kernel reports memory and load
// through /proc, and free space through the file system itself.
package watch

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// readResources takes one look at memory, load and the given mount points.
func readResources(paths []string) (resourceState, error) {
	state := resourceState{CPUs: runtime.NumCPU()}

	if err := readMeminfo(&state); err != nil {
		return state, err
	}
	if err := readLoad(&state); err != nil {
		return state, err
	}
	for _, path := range paths {
		disk, err := readDisk(path)
		if err != nil {
			// A mount point that is gone is not a reason to give up the rest of
			// the pass: the remaining ones still get looked at.
			continue
		}
		state.Disks = append(state.Disks, disk)
	}
	return state, nil
}

// readMeminfo reads the memory figures the kernel reports.
//
// MemAvailable is taken rather than MemFree: the kernel gives away free memory
// to caches, and MemFree on a healthy server is small at all times, so a report
// built on it would be false every hour of the day.
func readMeminfo(state *resourceState) error {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return err
	}
	defer file.Close()

	wanted := map[string]*uint64{
		"MemTotal":     &state.MemoryTotalKB,
		"MemAvailable": &state.MemoryAvailableKB,
		"SwapTotal":    &state.SwapTotalKB,
		"SwapFree":     &state.SwapFreeKB,
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSuffix(parts[0], ":")
		target, needed := wanted[name]
		if !needed {
			continue
		}
		if value, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
			*target = value
		}
	}
	return scanner.Err()
}

// readLoad reads the one-minute load average.
func readLoad(state *resourceState) error {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return err
	}
	parts := strings.Fields(string(raw))
	if len(parts) == 0 {
		return fmt.Errorf("/proc/loadavg is empty")
	}
	value, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return err
	}
	state.Load1 = value
	return nil
}

// readDisk reads the free space and free file slots of one mount point.
func readDisk(path string) (diskState, error) {
	stat := syscall.Statfs_t{}
	if err := syscall.Statfs(path, &stat); err != nil {
		return diskState{}, err
	}
	// Bavail rather than Bfree: part of the free space is reserved for root,
	// and an application that is not root cannot use it.
	return diskState{
		Path:        path,
		TotalBlocks: stat.Blocks,
		FreeBlocks:  stat.Bavail,
		FreeBytes:   stat.Bavail * uint64(stat.Bsize),
		TotalInodes: stat.Files,
		FreeInodes:  stat.Ffree,
	}, nil
}
