// The event chain: a sequence number and the hash of the previous event. They
// show whether something was cut out of the event log or replaced.
package watch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
)

// Chain numbers events and links them by hashes: every event carries its own
// number and the hash of the previous one. Deleting or editing a record breaks
// the chain, and that shows up when checking with -verify.
type Chain struct {
	mu        sync.Mutex
	statePath string
	seq       uint64
	prev      string
}

// chainState is what survives a restart.
type chainState struct {
	Seq  uint64 `json:"seq"`
	Prev string `json:"prev"`
}

// NewChain restores the chain from state or starts a new one.
func NewChain(stateDir string) *Chain {
	chain := &Chain{statePath: filepath.Join(stateDir, "chain.state.json")}
	state := chainState{}
	if loadJSONState(chain.statePath, &state) {
		chain.seq = state.Seq
		chain.prev = state.Prev
	}
	return chain
}

// Stamp assigns the event its number and the hash of the previous one.
func (c *Chain) Stamp(event Event) Event {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seq++
	event.Seq = c.seq
	event.PrevHash = c.prev
	event.Hash = hashEvent(event)
	c.prev = event.Hash
	c.save()
	return event
}

// Head returns the current number and hash of the chain. They go off the host
// with the heartbeat: the number can only grow, so a number that went down or a
// hash that does not match means the state on the server was tampered with.
func (c *Chain) Head() (uint64, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seq, c.prev
}

// save writes the chain state.
func (c *Chain) save() {
	saveJSONState(c.statePath, chainState{Seq: c.seq, Prev: c.prev}, 0o600)
}

// hashEvent computes the event hash together with the hash of the previous one.
func hashEvent(event Event) string {
	payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%d|%s",
		event.Seq, event.At.UTC().Format("2006-01-02T15:04:05Z"),
		event.Source, event.Kind, event.IP, event.Subject, event.Count, event.PrevHash)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// VerifyChain checks a sequence of events: the numbers run consecutively and
// every hash matches the recomputed one. Returns the number of the first
// corrupted event, or 0 if everything is intact.
func VerifyChain(events []Event) uint64 {
	prev := ""
	var lastSeq uint64
	for i, event := range events {
		if i > 0 && event.Seq != lastSeq+1 {
			return event.Seq
		}
		if event.PrevHash != prev && i > 0 {
			return event.Seq
		}
		if hashEvent(Event{
			Seq: event.Seq, At: event.At, Source: event.Source, Kind: event.Kind,
			IP: event.IP, Subject: event.Subject, Count: event.Count, PrevHash: event.PrevHash,
		}) != event.Hash {
			return event.Seq
		}
		prev = event.Hash
		lastSeq = event.Seq
	}
	return 0
}
