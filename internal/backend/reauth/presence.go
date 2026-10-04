package reauth

import "sync"

// Readers is the PC/SC watcher as a provider asks it (regalia-kms#72, G2;
// internal/backend/pcscwatch): a reader's current generation, which moves on every insertion or
// removal and never repeats, and whether the reader is watched right now.
type Readers interface {
	Generation(reader string) (uint64, bool)
}

// Watched is a provider that takes the reader watcher. The daemon gives it to every provider that
// requires reauthorization (cmd/regalia-kms); a provider that is never given one serves no removable
// token while reauthorization is required.
type Watched interface {
	WatchReaders(Readers)
}

// Presence remembers, for each device, the reader and generation under which its token was last let
// through, so that a token pulled and put back BETWEEN two operations, which no operation saw, is
// known to have been away (G2). Its zero value watches nothing: every removable token is refused.
//
// A WARM RESET IS NOT AN ABSENCE. A card reset with no removal moves no generation (pcscwatch), and is
// let through: the PIN is presented on every operation under the current lease, so the card's own login
// state never authorized anything.
type Presence struct {
	mu      sync.Mutex
	readers Readers
	seen    map[string]seenAt
}

type seenAt struct {
	reader     string
	generation uint64
}

// Watch gives the presence its watcher.
func (presence *Presence) Watch(readers Readers) {
	presence.mu.Lock()
	defer presence.mu.Unlock()
	presence.readers = readers
}

// Check is asked once a token has proved to be the right one, before anything is done with it. A token
// on a slot that cannot be removed serves as before. A removable one serves only if its reader is
// watched now (else serve is false: it is refused, never served unwatched); and if its reader or that
// reader's generation is not the one it was last let through under, `away` is true: the provider
// records it as gone, so that it waits for a lease asked for after this moment.
func (presence *Presence) Check(deviceID, reader string, removable bool) (serve, away bool) {
	if !removable {
		return true, false
	}
	presence.mu.Lock()
	defer presence.mu.Unlock()
	if presence.readers == nil || reader == "" || deviceID == "" {
		return false, false
	}
	generation, watched := presence.readers.Generation(reader)
	if !watched {
		return false, false
	}
	if presence.seen == nil {
		presence.seen = map[string]seenAt{}
	}
	now := seenAt{reader: reader, generation: generation}
	last, known := presence.seen[deviceID]
	presence.seen[deviceID] = now
	return true, known && last != now
}
