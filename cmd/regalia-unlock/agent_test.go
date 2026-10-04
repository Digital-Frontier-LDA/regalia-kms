package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/askpass"
)

// world is what the agent sees besides the peers: the ask-password directory (requests by file, each with
// its reply socket), whether the volume is open, and time. `tick` runs at every pause or poll, so a test
// changes the world as time passes.
type world struct {
	requests map[string]string // ask file -> Id
	answers  map[string][]byte // ask file -> what was sent to its socket
	open     bool
	slept    []time.Duration
	tick     func(w *world)
	n        int
}

func newWorld() *world {
	return &world{requests: map[string]string{}, answers: map[string][]byte{}}
}

// request puts a request for `id` in the directory, as systemd-cryptsetup does; its file name is new each time.
func (w *world) request(id string) string {
	w.n++
	path := fmt.Sprintf("%s/ask.%d", askpass.Dir, w.n)
	w.requests[path] = id
	return path
}

func (w *world) env() agentEnv {
	socketOf := func(path string) string {
		return askpass.Dir + "/sck." + strings.TrimPrefix(filepath.Base(path), "ask.")
	}
	return agentEnv{
		fs: askpass.FS{
			ReadDir: func(string) ([]string, error) {
				var names []string
				for path := range w.requests {
					names = append(names, filepath.Base(path))
				}
				return names, nil
			},
			ReadFile: func(path string) ([]byte, error) {
				id, ok := w.requests[path]
				if !ok {
					return nil, os.ErrNotExist
				}
				return []byte(fmt.Sprintf("[Ask]\nPID=1\nSocket=%s\nNotAfter=0\nId=%s\n", socketOf(path), id)), nil
			},
			Lstat: func(path string) (os.FileMode, uint32, error) { return os.ModeSocket | 0o600, 0, nil },
			Send: func(socket string, datagram []byte) error {
				for path := range w.requests {
					if socketOf(path) == socket {
						w.answers[path] = append([]byte(nil), datagram...)
						return nil
					}
				}
				return errors.New("no such socket")
			},
			Now: func() uint64 { return 1 },
		},
		opened: func() bool { return w.open },
		sleep: func(d time.Duration) {
			w.slept = append(w.slept, d)
			if w.tick != nil {
				w.tick(w)
			}
			if len(w.slept) > 10000 {
				panic("the agent does not end")
			}
		},
		jitter: func() float64 { return 0.5 },
	}
}

// The agent answers the root volume's request with the key of the first peer that helps, under ONE session
// across all its attempts, recorded before the first quote; it stands down once the volume is open, with
// what it held zeroed.
func TestTheAgentAnswersTheRootRequestOnceAPeerHelps(t *testing.T) {
	directory := t.TempDir()
	porto := newFakePeer(t, "porto")
	porto.deny = "DENIED" // a blackout: no peer helps for two attempts
	var log bytes.Buffer
	u := newUnlocker(t, directory, &log, porto)
	mine := hex.EncodeToString(u.boot.id)
	private := u.boot.key
	w := newWorld()
	root := w.request(askpass.RootID) // the console shows it from the start
	attempts := 0
	w.tick = func(w *world) {
		if strings.Count(log.String(), "asking again in") > attempts {
			attempts++
			if attempts == 2 {
				porto.deny = "" // the peer comes back
			}
		}
		if len(w.answers[root]) > 0 {
			w.open = true // systemd-cryptsetup opens the volume with it
		}
	}
	if err := u.agent(w.env()); err != nil {
		t.Fatal(err)
	}
	want, _ := credential(bytes.Repeat([]byte{0x11}, 32), porto.contribution, "lisbon", "porto", 3)
	if string(w.answers[root]) != "+"+string(want) {
		t.Fatalf("the root request got %q", w.answers[root])
	}
	if id, _ := recordOf(t, directory); id != mine+"\n" {
		t.Fatalf("the record is %q, not this boot's session", id)
	}
	sessions, unlocks := unlockSessions(porto)
	if len(sessions) != 1 || !sessions[mine] || unlocks != 1 {
		t.Fatalf("%d unlock requests under %v", unlocks, sessions)
	}
	through, _ := os.ReadFile(filepath.Join(directory, "key-given-through"))
	if string(through) != "porto 1\n" {
		t.Fatalf("key-given-through is %q", through)
	}
	// one diagnostic line per attempt, and the pauses are backoff's
	if strings.Count(log.String(), "regalia-unlock: attempt ") != 2 || !strings.Contains(log.String(), "attempt 1: porto (path epoch 3): hello: the peer refused (DENIED); asking again in 2s") {
		t.Fatalf("the diagnostics:\n%s", log.String())
	}
	// the first pause, 2 s at the jitter's middle, slept in steps of at most standPoll (the volume is looked at
	// between them)
	if w.slept[0] != standPoll || w.slept[1] != standPoll || backoff(0, 0.5) != 2*standPoll {
		t.Fatalf("the first pause: %v, not backoff's %v in steps of %v", w.slept[:2], backoff(0, 0.5), standPoll)
	}
	// the one response is spent; forget zeroes the key
	if !bytes.Equal(u.local, make([]byte, 32)) || u.boot.key != nil {
		t.Fatal("the local half or the session key outlived the boot's one response")
	}
	u.forget()
	zero := func(number *big.Int) bool { // zeroed in place: every word 0 (the length is not normalized)
		for _, word := range number.Bits() {
			if word != 0 {
				return false
			}
		}
		return len(number.Bits()) > 0
	}
	if !bytes.Equal(u.key, make([]byte, len(want))) || !zero(private.D) || !zero(private.Primes[0]) || !zero(private.Precomputed.Qinv) {
		t.Fatal("forget left the key or the session's private key")
	}
}

// Only the root volume's request is answered: another volume's, or a prompt with another Id, never is.
func TestOnlyTheRootVolumesRequestIsAnswered(t *testing.T) {
	porto := newFakePeer(t, "porto")
	u := newUnlocker(t, t.TempDir(), &bytes.Buffer{}, porto)
	w := newWorld()
	other := w.request("cryptsetup:/dev/disk/by-partlabel/regalia-data")
	pin := w.request("systemd-ask-password:pin")
	polls := 0
	w.tick = func(w *world) {
		if polls++; polls == 20 {
			w.open = true
		}
	}
	if err := u.agent(w.env()); err != nil {
		t.Fatal(err)
	}
	if len(w.answers[other]) != 0 || len(w.answers[pin]) != 0 {
		t.Fatalf("answered %v", w.answers)
	}
}

// A recovery key mistyped at the console: systemd-cryptsetup (tries=0) removes the request and makes another.
// That neither stops nor slows the agent: its backoff goes on where it was, and it answers the new request.
func TestAMistypedRecoveryKeyNeitherStopsNorResetsTheAgent(t *testing.T) {
	porto := newFakePeer(t, "porto")
	porto.deny = "DENIED"
	var log bytes.Buffer
	u := newUnlocker(t, t.TempDir(), &log, porto)
	w := newWorld()
	first := w.request(askpass.RootID)
	var second string
	w.tick = func(w *world) {
		attempts := strings.Count(log.String(), "asking again in")
		if attempts == 2 && second == "" {
			delete(w.requests, first)          // the operator typed a wrong key: answered, refused,
			second = w.request(askpass.RootID) // and asked again
		}
		if attempts == 4 {
			porto.deny = ""
		}
		if second != "" && len(w.answers[second]) > 0 {
			w.open = true
		}
	}
	if err := u.agent(w.env()); err != nil {
		t.Fatal(err)
	}
	if len(w.answers[second]) == 0 {
		t.Fatal("the request made again was not answered")
	}
	// the pauses kept growing across the gap: 2, 4, 8, 16 s (at the jitter's middle), never back to 2
	for i, want := range []time.Duration{2, 4, 8, 16} {
		if !strings.Contains(log.String(), fmt.Sprintf("attempt %d: ", i+1)) || !strings.Contains(log.String(), fmt.Sprintf("asking again in %s", want*time.Second)) {
			t.Fatalf("attempt %d did not pause %s:\n%s", i+1, want*time.Second, log.String())
		}
	}
}

// A key the volume refuses (it asks again after each answer) is offered to maxAnswers requests, then no more.
func TestARefusedKeyIsNotOfferedForEver(t *testing.T) {
	porto := newFakePeer(t, "porto")
	var log bytes.Buffer
	u := newUnlocker(t, t.TempDir(), &log, porto)
	w := newWorld()
	current := w.request(askpass.RootID)
	w.tick = func(w *world) {
		if len(w.answers[current]) > 0 { // tried, refused, asked again
			delete(w.requests, current)
			current = w.request(askpass.RootID)
		}
	}
	if err := u.agent(w.env()); err != nil {
		t.Fatal(err)
	}
	if len(w.answers) != maxAnswers || !strings.Contains(log.String(), fmt.Sprintf("refused the key %d times: no longer answering", maxAnswers)) {
		t.Fatalf("%d answers:\n%s", len(w.answers), log.String())
	}
}

// Each peer is asked ONCE per attempt, by one path: the newest first, the next at the next attempt (a peer
// holding two paths during a rotation is still asked once: the peers' hello limit is sized for that).
// Unusable tokens are reported, by number only.
func TestEachPeerIsAskedOncePerAttemptByOnePath(t *testing.T) {
	porto, faro := newFakePeer(t, "porto"), newFakePeer(t, "faro")
	faro.contribution = bytes.Repeat([]byte{0x43}, 32)
	tokens := tokensFor(porto, faro)
	tokens["5"] = token("porto", "5", 9) // a rotation: the new keyslot beside the old
	tokens["6"] = token("porto", "6", 4)
	tokens["6"].(map[string]any)["target"] = "faro"
	tokens["7"] = token("porto", "7", 4)
	tokens["7"].(map[string]any)["local"] = base64.StdEncoding.EncodeToString(make([]byte, 40)) // not sealed to the TPM alone
	tokens["11\x1b[2J\nregalia-unlock: all is well"] = token("faro", "3", 4)                    // an ID that is not a number is never printed
	paths, skipped := pathsOf(t, tokens)
	local := bytes.Repeat([]byte{0x11}, 32)
	porto.deny, faro.deny = "DENIED", "DENIED"
	boot := testSession(t)
	key, _, _, reasons, err := attempt(configFor(porto, faro), 0, paths, local, boot, dialer(porto, faro), noQuote)
	if err != nil || key != nil || len(reasons) != 2 || len(porto.requests) != 1 || len(faro.requests) != 1 {
		t.Fatalf("attempt 1: %v %v; porto %d, faro %d requests", reasons, err, len(porto.requests), len(faro.requests))
	}
	if porto.requests[0]["op"] != "hello" || !strings.Contains(reasons[0], "porto (path epoch 9)") || boot.consumed {
		t.Fatalf("attempt 1 did not ask porto's newest path once: %v", reasons)
	}
	porto.deny = ""
	key, peer, slot, _, err := attempt(configFor(porto, faro), 1, paths, local, boot, dialer(porto, faro), noQuote)
	want, _ := credential(local, porto.contribution, "lisbon", "porto", 3)
	if err != nil || peer != "porto" || slot != "1" || !bytes.Equal(key, want) {
		t.Fatalf("attempt 2 (the next path, epoch 3): %s %s %v", peer, slot, err)
	}
	if strings.Contains(strings.Join(reasons, ""), hex.EncodeToString(local)) {
		t.Fatal("a secret reached the diagnostics")
	}
	reported := strings.Join(skipped, "\n")
	if strings.Contains(reported, "all is well") || strings.ContainsAny(reported, "\x1b") ||
		!strings.Contains(reported, "token 6: it is for node faro") || !strings.Contains(reported, "token 7: its local contribution is not a systemd credential sealed to the TPM alone") {
		t.Fatalf("the unusable tokens:\n%q", reported)
	}
	// a disk with no path from any configured peer: nothing to ask, said, and the console is the way
	none, _ := pathsOf(t, map[string]any{})
	_, _, _, _, err = attempt(configFor(porto), 0, none, local, testSession(t), dialer(porto), noQuote)
	wantError(t, err, "it has no path from any peer of the boot configuration; the console asks for the recovery key")
}

// A peer not yet upgraded answers a version 2 hello INVALID_REQUEST: it is asked again in version 1, without
// values, and the attempt says so; a quote whose PCRs would not hold goes in version 1, said too.
func TestVersion1AndUnsteadyQuotesAreSaid(t *testing.T) {
	porto := newFakePeer(t, "porto")
	porto.onlyV1 = true
	paths, _ := pathsOf(t, tokensFor(porto))
	key, _, _, _, err := attempt(configFor(porto), 0, paths, bytes.Repeat([]byte{0x11}, 32), testSession(t), dialer(porto), noQuote)
	versions := []any{}
	for _, request := range porto.requests {
		versions = append(versions, request["v"])
	}
	if err != nil || len(key) == 0 || fmt.Sprint(versions) != "[2 1 1]" {
		t.Fatalf("%v; versions %v", err, versions)
	}
	porto2 := newFakePeer(t, "porto")
	porto2.deny = "DENIED"
	unsteady := func(qualifying []byte) ([]byte, []byte, map[string]string, error) {
		attest, signature, _, err := noQuote(qualifying)
		return attest, signature, nil, err
	}
	porto2.deny = ""
	paths2, _ := pathsOf(t, tokensFor(porto2))
	if _, _, _, _, err := attempt(configFor(porto2), 0, paths2, bytes.Repeat([]byte{0x11}, 32), testSession(t), dialer(porto2), unsteady); err != nil {
		t.Fatal(err)
	}
	for _, request := range porto2.requests {
		if request["op"] == "unlock" && request["v"] != float64(1) {
			t.Fatalf("a request without values in version %v", request["v"])
		}
	}
}

// The key the agent sends is the keyslot's passphrase as enrolled (unlock.py: base64 of the HKDF output, 44
// characters), with nothing after it: the requester strips nothing.
func TestTheAnswerIsTheEnrolledPassphraseExactly(t *testing.T) {
	porto := newFakePeer(t, "porto")
	key, err := credential(bytes.Repeat([]byte{0x11}, 32), porto.contribution, "lisbon", "porto", 3)
	if err != nil || len(key) != 44 {
		t.Fatalf("the credential is %d bytes, %v", len(key), err)
	}
	if _, err := base64.StdEncoding.DecodeString(string(key)); err != nil || bytes.ContainsAny(key, "\n\x00 ") {
		t.Fatalf("the credential is not plain base64: %q", key)
	}
}

// A client started again in the same boot would be a second session: it asks nobody. One whose earlier client
// ended before a quote (no boot-session) goes on. A record that cannot be written is said, and is not a reason
// to leave the disk locked.
func TestASecondClientInTheSameBootAsksNoPeer(t *testing.T) {
	directory := t.TempDir()
	porto := newFakePeer(t, "porto")
	if err := publishSession(directory, testSession(t)); err != nil {
		t.Fatal(err)
	}
	earlierID, _ := recordOf(t, directory)
	var log bytes.Buffer
	u := newUnlocker(t, directory, &log, porto)
	w := newWorld()
	w.request(askpass.RootID)
	if err := u.agent(w.env()); err != nil || len(porto.requests) != 0 || len(w.answers) != 0 {
		t.Fatalf("a second client of the boot: %v, %d requests, answers %v", err, len(porto.requests), w.answers)
	}
	if id, _ := recordOf(t, directory); id != earlierID || !strings.Contains(log.String(), "reboot, or use the recovery key") {
		t.Fatal("the earlier record was changed, or what to do is not said")
	}
	halfway := t.TempDir()
	_ = os.WriteFile(filepath.Join(halfway, "boot-session.pub"), []byte("00\n"), 0o644)
	second := newUnlocker(t, halfway, &log, porto)
	w2 := newWorld()
	root := w2.request(askpass.RootID)
	w2.tick = func(w *world) { w.open = len(w.answers[root]) > 0 }
	if err := second.agent(w2.env()); err != nil || len(w2.answers[root]) == 0 {
		t.Fatalf("a client after one that presented nothing did not answer: %v", err)
	}
	// a pair, or nothing
	blocked := t.TempDir()
	_ = os.Mkdir(filepath.Join(blocked, "boot-session"), 0o755)
	_ = os.WriteFile(filepath.Join(blocked, "boot-session", "x"), nil, 0o644)
	wantError(t, publishSession(blocked, testSession(t)), "cannot record boot-session")
	if _, err := os.Stat(filepath.Join(blocked, "boot-session.pub")); err == nil {
		t.Fatal("a public key was left on record without its session")
	}
	log.Reset()
	lost := newUnlocker(t, filepath.Join(directory, "absent"), &log, porto)
	w3 := newWorld()
	root3 := w3.request(askpass.RootID)
	w3.tick = func(w *world) { w.open = len(w.answers[root3]) > 0 }
	if err := lost.agent(w3.env()); err != nil || len(w3.answers[root3]) == 0 || !strings.Contains(log.String(), "leases may be refused until the next boot") {
		t.Fatalf("an unwritable record left the disk locked or unsaid: %v\n%s", err, log.String())
	}
}

// -attempts bounds the attempts (tests); the volume already open stands the agent down before any attempt.
func TestAttemptsAndAnOpenVolume(t *testing.T) {
	porto := newFakePeer(t, "porto")
	porto.deny = "DENIED"
	u := newUnlocker(t, t.TempDir(), &bytes.Buffer{}, porto)
	u.o.attempts = 3
	wantError(t, u.agent(newWorld().env()), "no peer helped in 3 attempts")
	open := newUnlocker(t, t.TempDir(), &bytes.Buffer{}, porto)
	w := newWorld()
	w.open = true
	if err := open.agent(w.env()); err != nil || len(porto.requests) != 3 {
		t.Fatalf("an open volume: %v, %d requests (the 3 of before only)", err, len(porto.requests))
	}
}

func TestTheCommandLine(t *testing.T) {
	var out, diagnostics bytes.Buffer
	_, err := loadBootConfig(filepath.Join(t.TempDir(), "absent"))
	wantError(t, err, "cannot read the boot configuration")
	wantError(t, run([]string{"-attempts", "-1"}, &out, &diagnostics), "usage:")
	wantError(t, run([]string{"extra"}, &out, &diagnostics), "usage:")
	wantError(t, run([]string{"-request", ""}, &out, &diagnostics), "usage:")
	if err := run([]string{"-h"}, &out, &diagnostics); !errors.Is(err, errHelp()) || !strings.Contains(out.String(), "-request") ||
		!strings.Contains(out.String(), askpass.RootID) {
		t.Fatalf("%v\n%s", err, out.String())
	}
	wantError(t, run([]string{"-config", filepath.Join(t.TempDir(), "absent")}, &out, &diagnostics), "cannot read the boot configuration")
	_, err = localContribution("")
	wantError(t, err, "no credentials directory")
	directory := t.TempDir()
	_, err = localContribution(directory)
	wantError(t, err, "is missing or is not 32 bytes")
	_ = os.WriteFile(filepath.Join(directory, localName), bytes.Repeat([]byte{7}, 32), 0o600)
	if local, err := localContribution(directory); err != nil || len(local) != 32 {
		t.Fatal(err)
	}
}
