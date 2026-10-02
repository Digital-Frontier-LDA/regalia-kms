// Package reauth holds the rule a token provider applies to a token that was gone and is back.
//
// A TOKEN THAT WAS GONE WAITS FOR A FRESH LEASE (regalia-kms#72, PoC 12.4). A token pulled from a
// running node, used elsewhere or tampered with, and put back must not resume on the strength of
// a runtime lease the node was given before: no peer has vouched for the node since. So a provider
// tells its Tracker when a token did not answer (Gone) and asks it, once the token has proved to
// be the right one, whether it may serve (Serves). It may once the node holds a lease it ASKED FOR
// after the token was first seen back.
//
// EVERY TOKEN STARTS AS JUST ARRIVED. A provider cannot know what happened to a token before its
// process started (pulled, the daemon restarted, put back), so a token never seen in this process
// is treated as having returned when the process started.
//
// WHAT IT CANNOT SEE: an absence nobody looked during. A token is known to be gone only when a
// provider tried to use it and it did not answer.
//
// The logic is the PKCS#11 provider's (internal/backend/nitrokey, regalia-kms#151), here so that
// every provider that serves keys from a removable token applies the same one.
package reauth

import (
	"context"
	"errors"
	"sync"
)

// served is the return time of a token that has been vouched for since: any lease is after it.
const served = -1

type absence struct {
	returned     bool
	returnedAtMs int64
}

// Tracker records, per device, whether a token is gone, back and waiting, or serving. Its zero
// value requires nothing: every token serves, as before the rule existed.
type Tracker struct {
	mu       sync.Mutex
	gate     Gate
	boottime func() (int64, error)
	// absences is keyed by device id. The entry "" is the baseline for a device never seen.
	absences map[string]absence
}

// Require turns the rule on. sinceMs is when this process started, on the boot clock: the moment
// every token is taken to have arrived. It must not be in the future, which would ask for a lease
// nobody can request.
func (tracker *Tracker) Require(gate Gate, boottime func() (int64, error), sinceMs int64) error {
	if tracker == nil || gate == nil || boottime == nil {
		return errors.New("reauthorization needs the admission gate and the boot clock")
	}
	now, err := boottime()
	if err != nil {
		return errors.New("reauthorization cannot read the boot clock")
	}
	if sinceMs <= 0 || sinceMs > now {
		return errors.New("reauthorization needs the time this process started, on the boot clock and not in the future")
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.gate, tracker.boottime = gate, boottime
	tracker.absences = map[string]absence{"": {returned: true, returnedAtMs: sinceMs}}
	return nil
}

// Gone records that a token did not answer. Whatever lease the node holds now was asked for
// before the token comes back.
func (tracker *Tracker) Gone(deviceID string) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.gate != nil {
		tracker.absences[deviceID] = absence{}
	}
}

// Serves reports whether a token that has just answered, and has proved to be the right one, may
// serve. The first time it is seen back, that moment is recorded; it serves once the node holds a
// lease asked for after it.
func (tracker *Tracker) Serves(ctx context.Context, deviceID string) bool {
	tracker.mu.Lock()
	gate := tracker.gate
	if gate == nil {
		tracker.mu.Unlock()
		return true
	}
	current, known := tracker.absences[deviceID]
	if !known {
		current = tracker.absences[""]
	}
	if !current.returned {
		now, err := tracker.boottime()
		if err != nil {
			tracker.mu.Unlock()
			return false
		}
		current = absence{returned: true, returnedAtMs: now}
	}
	tracker.absences[deviceID] = current
	tracker.mu.Unlock()
	if !gate.RequestedAfter(ctx, current.returnedAtMs) {
		return false
	}
	tracker.mu.Lock()
	// Cleared only if nothing changed meanwhile: a token that went away again during the check
	// stays marked.
	if latest, still := tracker.absences[deviceID]; still && latest == current {
		tracker.absences[deviceID] = absence{returned: true, returnedAtMs: served}
	}
	tracker.mu.Unlock()
	return true
}

// Awaiting lists the devices that are present but not yet serving, each with the CLOCK_BOOTTIME
// (ms) since which a lease must have been asked for, and the devices last seen gone (-1).
func (tracker *Tracker) Awaiting() map[string]int64 {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	waiting := map[string]int64{}
	for device, current := range tracker.absences {
		switch {
		case device == "":
		case !current.returned:
			waiting[device] = -1
		case current.returnedAtMs != served:
			waiting[device] = current.returnedAtMs
		}
	}
	return waiting
}
