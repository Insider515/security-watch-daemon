//go:build !linux

// Stub for systems other than Linux: the figures live in /proc, which exists
// nowhere else, so the watcher reports nothing and the service still builds and
// runs. It is there so the package can be built and tested on a workstation.
package watch

import "errors"

// readResources is unavailable outside Linux.
func readResources(_ []string) (resourceState, error) {
	return resourceState{}, errors.New("watching resources is available on Linux only")
}
