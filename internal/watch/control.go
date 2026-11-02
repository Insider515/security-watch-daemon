// Control commands: show what has been collected, block an address on the
// operator's decision, run a response action.
package watch

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ControlRequest - the requested control command. Command-line parsing stays in
// cmd/security-watch; the engine receives a ready-made request.
type ControlRequest struct {
	// Show actors ranked by score.
	Actors bool
	// Show block proposals.
	Candidates bool
	// A dossier for an address, or * for the list.
	Dossier string
	// Address to block and address to unblock.
	Block   string
	Unblock string
	// Name of the response action from the configuration and its value.
	Action    string
	ActionArg string
}

// Requested reports whether any control command was asked for.
func (r ControlRequest) Requested() bool {
	return r.Actors || r.Candidates || r.Dossier != "" ||
		r.Block != "" || r.Unblock != "" || r.Action != ""
}

// RunControlCommand executes the requested control command: show what has been
// collected, block or unblock an address, run an action.
func RunControlCommand(cfg *Config, request ControlRequest) error {
	report := func(e Event) { logEvent(e) }
	blocklist := NewBlocklist(cfg.Blocking, cfg.StateDir, report)
	store := NewDossierStore(cfg.StateDir)

	switch {
	case request.Actors:
		printActors(NewActorStore(cfg.Actors, cfg.StateDir, report).Top(20))
	case request.Action != "":
		return RunAction(cfg.Actions, request.Action, request.ActionArg, report)
	case request.Candidates:
		printCandidates(blocklist.Candidates())
	case request.Dossier == "*":
		printDossiers(store.All())
	case request.Dossier != "":
		item := store.Get(request.Dossier)
		if item == nil {
			fmt.Printf("no dossier for %s\n", request.Dossier)
			return nil
		}
		raw, _ := json.MarshalIndent(item, "", "  ")
		fmt.Println(string(raw))
	case request.Block != "":
		if err := blocklist.Block(request.Block); err != nil {
			return err
		}
		fmt.Printf("address %s blocked\n", request.Block)
	case request.Unblock != "":
		if err := blocklist.Unblock(request.Unblock); err != nil {
			return err
		}
		fmt.Printf("address %s unblocked\n", request.Unblock)
	}
	return nil
}

// printActors prints actors ranked by score.
func printActors(items []*Actor) {
	if len(items) == 0 {
		fmt.Println("no actors yet")
		return
	}
	fmt.Printf("%-18s %6s %7s %-20s %s\n", "address", "score", "events", "last seen", "what it did")
	for _, actor := range items {
		fmt.Printf("%-18s %6d %7d %-20s %s\n", actor.IP, actor.Score, actor.Events,
			actor.LastSeen.Format("2006-01-02 15:04:05"), sampleOf(describeActor(actor), 120))
	}
}

// printCandidates prints block proposals.
func printCandidates(items []*BlockCandidate) {
	if len(items) == 0 {
		fmt.Println("no block proposals")
		return
	}
	fmt.Printf("%-18s %6s %-20s %s\n", "address", "hits", "last seen", "reasons")
	for _, item := range items {
		mark := ""
		if item.Blocked {
			mark = " [blocked]"
		}
		fmt.Printf("%-18s %6d %-20s %s%s\n", item.IP, item.Count,
			item.LastSeen.Format("2006-01-02 15:04:05"), strings.Join(item.Reasons, "; "), mark)
	}
}

// printDossiers prints the list of dossiers.
func printDossiers(items []*Dossier) {
	if len(items) == 0 {
		fmt.Println("no dossiers yet")
		return
	}
	fmt.Printf("%-18s %6s %-20s %s\n", "address", "hits", "last seen", "paths")
	for _, item := range items {
		fmt.Printf("%-18s %6d %-20s %s\n", item.IP, item.Hits,
			item.LastSeen.Format("2006-01-02 15:04:05"), sampleOf(strings.Join(item.Paths, " "), 70))
	}
}
