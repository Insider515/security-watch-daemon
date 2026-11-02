package watch

import (
	"os"
	"path/filepath"
	"testing"
)

// Parsing /proc/net/tcp: only the lines in the LISTEN state (0A) are taken, and
// the port is read from the hexadecimal notation.
func TestListeningPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0D05 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 1
   1: 0100007F:0D06 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 1
   2: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 1 1 1
`
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}

	ports := listeningPorts(path)
	if len(ports) != 2 {
		t.Fatalf("expected two listening ports, got %v", ports)
	}
	if ports[0] != 3333 || ports[1] != 3334 {
		t.Errorf("the ports were parsed incorrectly: %v", ports)
	}
}

// An undeclared port is noticed, a declared one is not.
func TestPortsWatcherReportsUnexpected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	os.WriteFile(path, []byte(`  sl  local_address rem_address   st
   0: 00000000:0050 00000000:0000 0A 0 0 0 0 0 0
   1: 00000000:1F90 00000000:0000 0A 0 0 0 0 0 0
`), 0o640)

	events := []Event{}
	watcher := NewPortsWatcher(PortsConfig{Expected: []int{80}}, func(e Event) { events = append(events, e) })
	watcher.sources = []string{path}

	watcher.Scan()
	if len(events) != 1 || events[0].Subject != "8080" {
		t.Fatalf("expected one event about port 8080, got %+v", events)
	}

	// A second pass stays silent about the same port: one appearance, one event.
	events = nil
	watcher.Scan()
	if len(events) != 0 {
		t.Fatalf("a repeat must produce no events, got %+v", events)
	}
}
