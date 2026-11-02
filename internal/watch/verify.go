// Verifying the event chain and shipping the log to another machine.
package watch

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ArchiveConfig - daily shipping of the event log off the host.
//
// The chain only becomes meaningful once a copy of the log sits where whoever
// broke into the server cannot reach it. The command is set in the
// configuration: rsync, scp, an upload to object storage, anything. %s in the
// command is replaced with the path to the file.
type ArchiveConfig struct {
	Enabled  bool     `json:"enabled"`
	Command  string   `json:"command"`
	Interval Duration `json:"interval"`
}

// VerifyFile checks an event file: sequence numbers run consecutively and the
// hashes match.
//
// It makes sense to run this not on the watched server but on your own machine:
// the point is to confirm that nothing was cut out of the copy you received.
func VerifyFile(path string) error {
	// #nosec G304 -- the path is named by the operator on the command line; the
	// whole point of the command is to check the file they pointed at.
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", path, err)
	}
	defer file.Close()

	events := []Event{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		event := Event{}
		if err := json.Unmarshal([]byte(text), &event); err != nil {
			return fmt.Errorf("line %d does not parse: %w", line, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(events) == 0 {
		return fmt.Errorf("the file contains no events")
	}

	if broken := VerifyChain(events); broken != 0 {
		return fmt.Errorf("chain broken at event #%d: the record was changed or something was cut out of the log", broken)
	}
	fmt.Printf("chain intact: %d events, from #%d to #%d, from %s to %s\n",
		len(events), events[0].Seq, events[len(events)-1].Seq,
		events[0].At.Format(time.RFC3339), events[len(events)-1].At.Format(time.RFC3339))
	return nil
}

// RunArchive ships the event log off the host.
func RunArchive(cfg ArchiveConfig, eventsPath string, emit func(Event)) {
	if !cfg.Enabled || strings.TrimSpace(cfg.Command) == "" || eventsPath == "" {
		return
	}
	output, err := runCommand(cfg.Command, eventsPath)
	if err != nil {
		emit(Event{
			At: time.Now(), Source: "self", Kind: "archive_failed", Severity: SevWarn,
			Subject: eventsPath, Count: 1,
			Details: map[string]string{"error": err.Error(), "output": sampleOf(output, 200)},
		})
		return
	}
	emit(Event{
		At: time.Now(), Source: "self", Kind: "archive_done", Severity: SevInfo,
		Subject: eventsPath, Count: 1,
		Details: map[string]string{"output": sampleOf(output, 200)},
	})
}
