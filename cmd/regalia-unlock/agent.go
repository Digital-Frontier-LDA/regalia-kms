package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/askpass"
)

// The client as a systemd password agent (#70, the Clevis way): systemd-cryptsetup asks for the root
// volume's passphrase through the ask-password protocol, the console shows that request from the start,
// and this program answers the same request once a peer has given its half. Whichever answers first wins.
// Until then it asks the peers again and again, at backoff's cadence, for as long as the initrd lasts: a
// node that boots during a blackout unlocks by itself when a peer comes back, with the recovery key
// available at the console all along.
//
// It stands down when the volume is open (the device mapper's node for it exists: by its answer or by the
// recovery key) or when systemd stops it, and what it held is zeroed then. NOT when the request merely
// disappears: after a recovery key mistyped at the console, systemd-cryptsetup (tries=0) removes the
// request and makes a new one, and that gap must neither stop nor slow this agent. A key the volume
// refuses is not offered for ever: after maxAnswers distinct requests answered, it stops answering.

const (
	maxAnswers = 5                      // distinct requests answered with one key, at most: then it was refused
	keyPoll    = 250 * time.Millisecond // how often a held key looks for the request
	standPoll  = time.Second            // how often a pause looks whether the volume opened meanwhile
)

// agentEnv is what the agent touches besides the peers and the TPM: the ask-password directory, the
// volume's node, time.
type agentEnv struct {
	fs     askpass.FS
	opened func() bool
	sleep  func(time.Duration)
	jitter func() float64 // [0, 1)
}

func realAgentEnv(volume string) agentEnv {
	return agentEnv{
		fs:     askpass.System(),
		opened: func() bool { _, err := os.Stat(volume); return err == nil },
		sleep:  time.Sleep,
		jitter: jitter,
	}
}

// pause waits d, looking every standPoll whether the volume opened; it reports whether it did.
func (env agentEnv) pause(d time.Duration) bool {
	for d > 0 {
		step := min(d, standPoll)
		env.sleep(step)
		d -= step
		if env.opened() {
			return true
		}
	}
	return false
}

// agent runs until the volume is open, the key was refused maxAnswers times, -attempts is spent (tests), or
// nothing can be done (no path from any peer: the console's recovery key is the way). It never decides
// that the disk stays locked for good: a peer that comes back after an hour is answered then.
func (u *unlocker) agent(env agentEnv) error {
	if u.earlierSession() {
		fmt.Fprintln(u.diagnostics, "regalia-unlock: "+earlierSession)
		return nil
	}
	answered := map[string]bool{}
	for step := 0; ; {
		if env.opened() {
			fmt.Fprintf(u.out, "regalia-unlock: %s is open: standing down\n", u.o.volume)
			return nil
		}
		if u.key == nil {
			if u.o.attempts > 0 && step >= u.o.attempts {
				return fmt.Errorf("no peer helped in %d attempts", step)
			}
			key, peer, slot, reasons, err := attempt(u.config, step, u.paths, u.local, u.boot, u.dial, u.presenting)
			if err != nil {
				return err // nothing to ask anybody: the console asks for the recovery key
			}
			if key == nil {
				wait := backoff(step, env.jitter())
				fmt.Fprintf(u.diagnostics, "regalia-unlock: attempt %d: %s; asking again in %s\n", step+1, strings.Join(reasons, "; "), wait.Round(time.Second))
				step++
				env.pause(wait) // the volume opened meanwhile: the loop's first check stands down
				continue
			}
			if len(reasons) > 0 { // the peers asked before this one, in this attempt: still one line for it
				fmt.Fprintf(u.diagnostics, "regalia-unlock: attempt %d: %s; then %s gave its half\n", step+1, strings.Join(reasons, "; "), peer)
			}
			// this boot's one response is used; the key is kept, for each request systemd-cryptsetup makes
			u.key, u.peer, u.slot = key, peer, slot
			u.spent()
			fmt.Fprintf(u.out, "regalia-unlock: %s gave its half (keyslot %s); waiting for the request for %s\n", peer, slot, u.o.volume)
		}
		request, err := askpass.Find(env.fs, u.o.askDir, u.o.requestID)
		if err != nil {
			fmt.Fprintln(u.diagnostics, "regalia-unlock: "+err.Error())
		}
		if request != nil && !answered[request.Path] {
			if len(answered) >= maxAnswers {
				fmt.Fprintf(u.diagnostics, "regalia-unlock: %s refused the key %d times: no longer answering; the console asks for the recovery key\n",
					u.o.volume, len(answered))
				return nil
			}
			if err := askpass.Answer(env.fs, *request, u.key); err != nil {
				fmt.Fprintln(u.diagnostics, "regalia-unlock: the answer did not reach the request ("+err.Error()+"): it is answered again if it is asked again")
			} else {
				answered[request.Path] = true
				fmt.Fprintf(u.out, "regalia-unlock: gave the key of %s for keyslot %s, through %s\n", u.config.Device, u.slot, u.peer)
				// for the journal and the probe: whose half the key was made with
				if u.o.sessionDir != "" {
					_ = writeFile(u.o.sessionDir, "key-given-through", fmt.Sprintf("%s %s\n", u.peer, u.slot))
				}
			}
		}
		env.sleep(keyPoll)
	}
}

// attempt is one pass over the peers of the boot configuration: each peer asked ONCE, by one of its paths
// (the newest at the first attempt, the next one at the next: a peer holding two paths during a rotation
// is still asked once per attempt, which the peers' hello limit, #314, is sized for). It returns the key,
// the peer and the keyslot, or the reason each peer gave (one line between them, for the attempt's one
// diagnostic), or an error when there is nothing to ask.
func attempt(config *bootConfig, step int, paths map[string][]pathToken, local []byte, boot *session, dial func(string, time.Time) transport,
	quote quoter) (key []byte, peerID, slot string, reasons []string, err error) {
	asked := false
	for _, peer := range config.Peers {
		tokens := paths[peer.NodeID]
		if len(tokens) == 0 {
			continue
		}
		token := tokens[step%len(tokens)]
		asked = true
		spoke, unsteady := boot.spokeVersion1, boot.unsteadyPCRs
		contribution, askErr := boot.ask(peer, token.PathEpoch, dial(peer.Endpoint, time.Time{}), quote)
		var notes []string
		if boot.unsteadyPCRs && !unsteady {
			notes = append(notes, "the quoted PCRs kept changing, asked without PCR values")
		}
		if boot.spokeVersion1 && !spoke {
			notes = append(notes, "it speaks only version 1 of the exchange (upgrade the peers)")
		}
		if askErr != nil {
			reasons = append(reasons, fmt.Sprintf("%s (path epoch %d): %s", peer.NodeID, token.PathEpoch, strings.Join(append(notes, askErr.Error()), ", ")))
			continue
		}
		key, err := credential(local, contribution, config.NodeID, peer.NodeID, token.PathEpoch)
		wipe(contribution)
		if err != nil {
			return nil, "", "", nil, err
		}
		return key, peer.NodeID, token.Keyslots[0], reasons, nil
	}
	if !asked {
		return nil, "", "", nil, errors.New("the disk stays locked: it has no path from any peer of the boot configuration; the console asks for the recovery key")
	}
	return nil, "", "", reasons, nil
}

// jitter is a fraction in [0, 1) from the kernel's random source: nodes rebooting together do not ask in step.
func jitter() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5
	}
	return float64(binary.BigEndian.Uint64(b[:])>>11) / float64(uint64(1)<<53)
}

// earlierSession is whether another client of this boot already presented a session (its record is there):
// a peer accepts one session per boot, so this process asks nobody.
func (u *unlocker) earlierSession() bool {
	if u.o.sessionDir == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(u.o.sessionDir, "boot-session"))
	return err == nil
}
