// Watching listening ports: a newly opened port is a common trace of someone
// else's presence (a shell, a tunnel, a miner).
package watch

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PortsWatcher compares the current set of listening ports with the expected one
// and with the previous one. It reads /proc/net/tcp and /proc/net/tcp6 directly,
// without ss or netstat.
type PortsWatcher struct {
	cfg      PortsConfig
	expected map[int]bool
	previous map[int]bool
	emit     func(Event)
	// The paths are replaced in tests.
	sources []string
}

// NewPortsWatcher creates the port watcher.
func NewPortsWatcher(cfg PortsConfig, emit func(Event)) *PortsWatcher {
	expected := make(map[int]bool, len(cfg.Expected))
	for _, port := range cfg.Expected {
		expected[port] = true
	}
	return &PortsWatcher{
		cfg:      cfg,
		expected: expected,
		emit:     emit,
		sources:  []string{"/proc/net/tcp", "/proc/net/tcp6"},
	}
}

// Scan reads the current listening ports and emits events for the new ones.
func (p *PortsWatcher) Scan() {
	current := map[int]bool{}
	for _, path := range p.sources {
		for _, port := range listeningPorts(path) {
			current[port] = true
		}
	}
	if len(current) == 0 {
		return // reading failed - stay silent, a false alarm is worse
	}

	for port := range current {
		if p.expected[port] {
			continue
		}
		if p.previous != nil && p.previous[port] {
			continue // already reported
		}
		severity := SevAlert
		if p.previous == nil {
			// First pass: undeclared ports are reported as a warning rather than
			// an alarm - this is an inventory, not an event.
			severity = SevWarn
		}
		p.emit(Event{
			At: time.Now(), Source: "ports", Kind: "listening_port", Severity: severity,
			Subject: strconv.Itoa(port), Count: 1,
			Details: map[string]string{"expected": strings.Join(portList(p.expected), ",")},
		})
	}
	for port := range p.previous {
		if !current[port] && p.expected[port] {
			p.emit(Event{
				At: time.Now(), Source: "ports", Kind: "port_gone", Severity: SevWarn,
				Subject: strconv.Itoa(port), Count: 1,
			})
		}
	}
	p.previous = current
}

// listeningPorts parses /proc/net/tcp and returns the ports in the LISTEN state
// (0A).
func listeningPorts(path string) []int {
	// #nosec G304 -- this is /proc/net/tcp; the path is only replaced in tests.
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	ports := []int{}
	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first { // the table header
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		local := fields[1]
		colon := strings.LastIndexByte(local, ':')
		if colon < 0 {
			continue
		}
		raw, err := hex.DecodeString(local[colon+1:])
		if err != nil || len(raw) != 2 {
			continue
		}
		ports = append(ports, int(raw[0])<<8|int(raw[1]))
	}
	return ports
}

// portList turns a set of ports into an ordered list of strings for the event
// details.
func portList(set map[int]bool) []string {
	out := make([]string, 0, len(set))
	for port := range set {
		out = append(out, strconv.Itoa(port))
	}
	sort.Strings(out)
	return out
}

// connection is one established connection from the kernel table.
type connection struct {
	LocalPort  int
	RemoteIP   string
	RemotePort int
}

// establishedConnections parses /proc/net/tcp and returns the connections in the
// ESTABLISHED state (01). Those are the ones showing where the server goes by
// itself.
func establishedConnections(path string) []connection {
	// #nosec G304 -- this is /proc/net/tcp; the path is only replaced in tests.
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	out := []connection{}
	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "01" {
			continue
		}
		localIP, localPort, okLocal := splitHexAddr(fields[1])
		remoteIP, remotePort, okRemote := splitHexAddr(fields[2])
		if !okLocal || !okRemote || localIP == "" {
			continue
		}
		out = append(out, connection{LocalPort: localPort, RemoteIP: remoteIP, RemotePort: remotePort})
	}
	return out
}

// splitHexAddr parses an entry such as "0100007F:1F90" into an address and a
// port. The kernel writes the address in reverse byte order, so the bytes are
// swapped back.
func splitHexAddr(raw string) (string, int, bool) {
	colon := strings.LastIndexByte(raw, ':')
	if colon < 0 {
		return "", 0, false
	}
	portBytes, err := hex.DecodeString(raw[colon+1:])
	if err != nil || len(portBytes) != 2 {
		return "", 0, false
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	addrBytes, err := hex.DecodeString(raw[:colon])
	if err != nil {
		return "", 0, false
	}
	switch len(addrBytes) {
	case 4:
		return fmt.Sprintf("%d.%d.%d.%d", addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0]), port, true
	case 16:
		// IPv6 is written in four-byte groups with the bytes swapped inside each.
		parts := make([]string, 0, 8)
		for i := 0; i < 16; i += 4 {
			quad := []byte{addrBytes[i+3], addrBytes[i+2], addrBytes[i+1], addrBytes[i]}
			parts = append(parts, hex.EncodeToString(quad[:2]), hex.EncodeToString(quad[2:]))
		}
		return strings.Join(parts, ":"), port, true
	}
	return "", 0, false
}

// isPrivateIP tells internal addresses from external ones: connections inside
// the server and inside a private network are of no interest to the watcher.
func isPrivateIP(addr string) bool {
	parsed := net.ParseIP(addr)
	if parsed == nil {
		return true // unparsed - better to stay silent than raise a false alarm
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() ||
		parsed.IsUnspecified() || parsed.IsMulticast()
}
