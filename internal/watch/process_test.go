package watch

import (
	"os"
	"path/filepath"
	"testing"
)

// Parsing established connections: the lines in state 01 are taken and the
// address is assembled from the swapped bytes.
func TestEstablishedConnections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	// 0100007F = 127.0.0.1, D2B4A8C0 = 192.168.180.210, port 01BB = 443.
	content := `  sl  local_address rem_address   st
   0: 0100007F:8C5A D2B4A8C0:01BB 01 0 0 0 0 0 0
   1: 0100007F:0D06 00000000:0000 0A 0 0 0 0 0 0
`
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}

	conns := establishedConnections(path)
	if len(conns) != 1 {
		t.Fatalf("expected one established connection, got %+v", conns)
	}
	if conns[0].RemoteIP != "192.168.180.210" || conns[0].RemotePort != 443 {
		t.Errorf("the address was parsed incorrectly: %+v", conns[0])
	}
}

// Internal addresses do not count as outbound connections.
func TestIsPrivateIP(t *testing.T) {
	private := []string{"127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.9.9", "169.254.1.1"}
	for _, addr := range private {
		if !isPrivateIP(addr) {
			t.Errorf("%s must count as internal", addr)
		}
	}
	for _, addr := range []string{"8.8.8.8", "203.0.113.10"} {
		if isPrivateIP(addr) {
			t.Errorf("%s must count as external", addr)
		}
	}
}

// A program started from a temporary directory and a program whose file was
// deleted are two different events, both of the highest severity.
func TestProcessWatcherSuspicious(t *testing.T) {
	dir := t.TempDir()
	procRoot := filepath.Join(dir, "proc")

	// A stand-in /proc: a directory per process, the exe link and cmdline.
	makeProc := func(pid, exe, cmdline string) {
		base := filepath.Join(procRoot, pid)
		os.MkdirAll(base, 0o750)
		target := filepath.Join(dir, "fake-binary-"+pid)
		os.WriteFile(target, []byte("x"), 0o750)
		os.Symlink(exe, filepath.Join(base, "exe"))
		os.WriteFile(filepath.Join(base, "cmdline"), []byte(cmdline), 0o640)
	}
	makeProc("101", "/tmp/miner", "/tmp/miner --pool evil")
	makeProc("102", "/usr/bin/nginx", "nginx: master process")
	makeProc("103", "/usr/bin/evil (deleted)", "./evil")

	events := []Event{}
	watcher := NewProcessWatcher(ProcessConfig{SuspiciousDirs: []string{"/tmp"}},
		func(e Event) { events = append(events, e) })
	watcher.procRoot = procRoot
	watcher.netFiles = nil

	watcher.Scan()

	kinds := map[string]string{}
	for _, event := range events {
		kinds[event.Kind] = event.Subject
	}
	if kinds["process_from_temp"] != "/tmp/miner" {
		t.Errorf("the start from a temporary directory was not noticed: %+v", events)
	}
	if kinds["deleted_binary"] != "/usr/bin/evil" {
		t.Errorf("the deleted program file was not noticed: %+v", events)
	}
	if len(events) != 2 {
		t.Errorf("an ordinary process must produce no events: %+v", events)
	}

	// A second pass stays silent: the same thing is reported once.
	events = nil
	watcher.Scan()
	if len(events) != 0 {
		t.Errorf("a repeat must produce no events: %+v", events)
	}
}

// An outbound connection to an undeclared port is noticed, one to an allowed
// port is not.
func TestProcessWatcherOutbound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	// 08080808 = 8.8.8.8 port 01BB (443, allowed); 2D9FE490 = 144.228.159.45 port 1F90 (8080).
	os.WriteFile(path, []byte(`  sl  local  rem st
   0: 0100007F:8C5A 08080808:01BB 01 0 0 0 0 0 0
   1: 0100007F:8C5B 2D9FE490:1F90 01 0 0 0 0 0 0
`), 0o640)

	events := []Event{}
	watcher := NewProcessWatcher(ProcessConfig{AllowedOutboundPorts: []int{443, 53}},
		func(e Event) { events = append(events, e) })
	watcher.procRoot = filepath.Join(dir, "no-proc")
	watcher.netFiles = []string{path}

	watcher.scanOutbound()

	if len(events) != 1 || events[0].Kind != "outbound_connection" {
		t.Fatalf("expected one outbound connection event, got %+v", events)
	}
	if events[0].Details["local_port"] == "" {
		t.Errorf("the local port is missing: %+v", events[0].Details)
	}
}
