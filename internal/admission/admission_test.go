package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	testBoot    = "0f3a9c1e-1111-4222-8333-444455556666"
	testSession = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
	testDigest  = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
)

// GUARD SWEEP: each of the 63 refusal guards in admission.go was neutralised in turn against this
// file. Eight are not pinned by a test, and are recorded here with what was found rather than left
// for the next sweep to rediscover:
//
//	Boottime: ClockGettime error        UNREACHABLE from a test: the kernel does not fail it.
//	KernelBootID: ReadFile error        UNREACHABLE without removing /proc; Open's own BootID error
//	                                    path is pinned through the injected reader.
//	readTrusted: Fstat error            UNREACHABLE: the descriptor was opened one line above.
//	readTrusted: ReadAll error          UNREACHABLE for a regular file that was just opened.
//	Parse/count: Unmarshal error        NEVER THE SOLE REFUSER: the digits-only pattern before it
//	                                    admits at most 18 digits, which always fit an int64.
//	object: opening token, key token,   NEVER THE SOLE REFUSERS: input that trips one of them is
//	  loop Token error, value Decode    refused by a later check with the same answer ("not one flat
//	                                    JSON object"); the cases below cover each such input.
//
// THE ANCESTOR WALK SEES THE TEST'S OWN TEMPORARY DIRECTORY. With TMPDIR (or GOTMPDIR) under a group- or
// world-writable directory without the sticky bit (a umask 002 home, ~/.cache at 0775), the tests that
// expect an admission are refused: that is the rule working, not a fault. /tmp, or any 0755/0700 chain, passes.
//
// world is one node's /run: a directory only its owner or root can write, the admission file and the boot
// session file in it, and a CLOCK_BOOTTIME the test moves.
type world struct {
	t         *testing.T
	directory string
	now       int64
	events    []Status
	gate      *Gate
}

func good(now int64) map[string]any {
	return map[string]any{
		"schema": Schema, "node_id": "a", "session_id": testSession, "boot_id": testBoot, "epoch": 7,
		"manifest_digest": testDigest, "hsm_serials": "DENK0404144 36345471", "lease_issued_at": "2026-10-02T09:00:00Z",
		"requested_boottime_ms": now - 5_000, "serve_until_boottime_ms": now + 290_000, "reason": "",
	}
}

// serials is n distinct serials, one space apart.
func serials(n int) string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("S%02d", i)
	}
	return strings.Join(out, " ")
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, directory: t.TempDir(), now: 1_000_000}
	// The suite runs under umask 002 in CI: say what the directory is rather than inherit it.
	if err := os.Chmod(w.directory, 0o755); err != nil {
		t.Fatal(err)
	}
	w.write("boot-session", []byte(testSession+"\n"), 0o644)
	w.put(good(w.now))
	gate, err := Open(Options{
		Path: w.path("admission.json"), NodeID: "a", SessionPath: w.path("boot-session"), OwnerUID: uint32(os.Getuid()), SessionOwnerUID: uint32(os.Getuid()),
		Boottime:     func() (int64, error) { return w.now, nil },
		BootID:       func() (string, error) { return testBoot, nil },
		OnTransition: func(status Status) { w.events = append(w.events, status) },
	})
	if err != nil {
		t.Fatal(err)
	}
	w.gate = gate
	return w
}

func (w *world) path(name string) string { return filepath.Join(w.directory, name) }

func (w *world) write(name string, contents []byte, mode os.FileMode) {
	w.t.Helper()
	_ = os.Remove(w.path(name))
	if err := os.WriteFile(w.path(name), contents, 0o600); err != nil {
		w.t.Fatal(err)
	}
	if err := os.Chmod(w.path(name), mode); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) put(document map[string]any) {
	w.t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		w.t.Fatal(err)
	}
	w.write("admission.json", encoded, 0o644)
}

func (w *world) refused(want string) {
	w.t.Helper()
	status := w.gate.Check(context.Background())
	if status.Admitted {
		w.t.Fatalf("admitted, want a refusal containing %q", want)
	}
	if !strings.Contains(status.Reason, want) {
		w.t.Fatalf("refused with %q, want it to contain %q", status.Reason, want)
	}
	if w.gate.Ready(context.Background()) {
		w.t.Fatal("Ready is true after a refusal")
	}
}

func TestANodeWithACurrentAdmissionIsAdmitted(t *testing.T) {
	w := newWorld(t)
	status := w.gate.Check(context.Background())
	if !status.Admitted || status.Reason != "" || status.Epoch != 7 || status.RequestedBoottimeMs != w.now-5_000 {
		t.Fatalf("status = %+v", status)
	}
	if !w.gate.Ready(context.Background()) {
		t.Fatal("Ready is false for a current admission")
	}
	// up to the last millisecond, and not at it
	w.now += 289_999
	if !w.gate.Ready(context.Background()) {
		t.Fatal("refused one millisecond before serve_until")
	}
	w.now++
	w.refused("the admission ran out")
}

func TestEveryDefectOfTheFileIsNotAdmitted(t *testing.T) {
	change := func(key string, value any) func(*world) {
		return func(w *world) {
			document := good(w.now)
			document[key] = value
			w.put(document)
		}
	}
	raw := func(contents string) func(*world) {
		return func(w *world) { w.write("admission.json", []byte(contents), 0o644) }
	}
	whole := func(w *world) string {
		encoded, _ := json.Marshal(good(w.now))
		return string(encoded)
	}
	cases := []struct {
		name, want string
		arrange    func(*world)
	}{
		{"missing", "it cannot be opened", func(w *world) { _ = os.Remove(w.path("admission.json")) }},
		{"unreadable", "it cannot be opened", func(w *world) {
			if os.Getuid() == 0 {
				w.t.Skip("root reads a mode-000 file")
			}
			w.write("admission.json", []byte("{}"), 0o000)
		}},
		{"a symlink to a good file", "it cannot be opened", func(w *world) {
			w.write("real.json", []byte(whole(w)), 0o644)
			_ = os.Remove(w.path("admission.json"))
			if err := os.Symlink(w.path("real.json"), w.path("admission.json")); err != nil {
				w.t.Fatal(err)
			}
		}},
		{"a directory", "it is not a regular file", func(w *world) {
			_ = os.Remove(w.path("admission.json"))
			if err := os.Mkdir(w.path("admission.json"), 0o755); err != nil {
				w.t.Fatal(err)
			}
		}},
		{"group-writable", "it is not a file only its owner or root can write", func(w *world) { w.write("admission.json", []byte(whole(w)), 0o664) }},
		{"world-writable", "it is not a file only its owner or root can write", func(w *world) { w.write("admission.json", []byte(whole(w)), 0o646) }},
		{"its directory group-writable", "its directory is not one only its owner or root can write", func(w *world) { _ = os.Chmod(w.directory, 0o775) }},
		{"its directory world-writable", "its directory is not one only its owner or root can write", func(w *world) { _ = os.Chmod(w.directory, 0o757) }},
		{"oversized", "it is oversized", raw("{" + strings.Repeat(" ", maxFileBytes) + "}")},
		{"empty", "not one flat JSON object", raw("")},
		{"not JSON", "not one flat JSON object", raw("admitted")},
		{"an array", "not one flat JSON object", raw("[]")},
		{"truncated", "not one flat JSON object", func(w *world) { text := whole(w); raw(text[:len(text)-1])(w) }},
		{"trailing data", "not one flat JSON object", func(w *world) { raw(whole(w) + "{}")(w) }},
		{"a nested object", "not one flat JSON object", change("reason", map[string]any{"x": 1})},
		{"a nested list", "not one flat JSON object", change("epoch", []int{7})},
		{"a repeated key", "the admission file repeats serve_until_boottime_ms", func(w *world) {
			text := whole(w)
			raw(text[:len(text)-1] + `,"serve_until_boottime_ms":0}`)(w)
		}},
		{"an unknown field", "does not have exactly its fields", change("site", "sitea")},
		{"a missing field", "does not have exactly its fields", func(w *world) {
			document := good(w.now)
			delete(document, "reason")
			w.put(document)
		}},
		{"a field swapped for another", "the admission file lacks reason", func(w *world) {
			document := good(w.now)
			delete(document, "reason")
			document["note"] = ""
			w.put(document)
		}},
		{"another schema", "another schema", change("schema", "regalia.admission/v0")},
		{"a schema that is not a string", "schema is not a string", change("schema", 1)},
		{"a node ID that is not a string", "node_id is not a string", change("node_id", 7)},
		{"a session ID that is not a string", "session_id is not a string", change("session_id", 7)},
		{"a boot ID that is not a string", "boot_id is not a string", change("boot_id", 7)},
		{"a digest that is not a string", "manifest_digest is not a string", change("manifest_digest", 7)},
		{"an issue time that is not a string", "lease_issued_at is not a string", change("lease_issued_at", 7)},
		{"another node", "for another node", change("node_id", "b")},
		{"a malformed node", "node_id is not a node ID", change("node_id", "A")},
		{"another boot session", "for another boot session", change("session_id", strings.Repeat("0b", 32))},
		{"a malformed session", "session_id is not 64 lowercase hex", change("session_id", "5E")},
		{"another boot, with times that look valid", "from another boot", change("boot_id", "0f3a9c1e-1111-4222-8333-444455557777")},
		{"a malformed boot ID", "boot_id is not a UUID", change("boot_id", "boot")},
		{"an epoch as text", "epoch is not a whole number", change("epoch", "7")},
		{"a negative epoch", "epoch is not a whole number", change("epoch", -1)},
		{"a fractional epoch", "epoch is not a whole number", change("epoch", 7.5)},
		{"a malformed digest", "manifest_digest is not 64 lowercase hex", change("manifest_digest", "D1")},
		{"serials as a list", "not one flat JSON object", change("hsm_serials", []any{"DENK0404144"})},
		{"serials that are not a string", "hsm_serials is not a string", change("hsm_serials", 7)},
		{"two spaces between serials", "hsm_serials is not distinct serials", change("hsm_serials", "DENK0404144  36345471")},
		{"a leading space", "hsm_serials is not distinct serials", change("hsm_serials", " DENK0404144")},
		{"a serial twice", "hsm_serials is not distinct serials", change("hsm_serials", "DENK0404144 DENK0404144")},
		{"a serial with a dash", "hsm_serials is not distinct serials", change("hsm_serials", "DENK-0404144")},
		{"a serial of 33 characters", "hsm_serials is not distinct serials", change("hsm_serials", strings.Repeat("S", 33))},
		{"seventeen serials", "lists more than 16 hardware tokens", change("hsm_serials", serials(17))},
		{"the old schema", "another schema", change("schema", "regalia.admission/v1")},
		{"a local time", "lease_issued_at is not UTC", change("lease_issued_at", "2026-10-02T09:00:00+02:00")},
		{"a fractional bound", "serve_until_boottime_ms is not a whole number", change("serve_until_boottime_ms", 1.0e6+0.5)},
		{"an exponent bound", "serve_until_boottime_ms is not a whole number", raw(`{"schema":"regalia.admission/v2","node_id":"a","session_id":"` + testSession +
			`","boot_id":"` + testBoot + `","epoch":7,"manifest_digest":"` + testDigest + `","hsm_serials":"DENK0404144` +
			`","lease_issued_at":"2026-10-02T09:00:00Z","requested_boottime_ms":1,"serve_until_boottime_ms":1e9,"reason":""}`)},
		{"a bound as text", "serve_until_boottime_ms is not a whole number", change("serve_until_boottime_ms", "1290000")},
		{"a negative request time", "requested_boottime_ms is not a whole number", change("requested_boottime_ms", -1)},
		{"a reason that is not a string", "reason is not a string", change("reason", 0)},
		{"a reason with a control character", "reason is not printable ASCII", change("reason", "bad\x1b[31m")},
		{"a reason too long", "reason is too long", change("reason", strings.Repeat("x", 241))},
		{"zero, with the service's reason", "not admitted by the lease service: a may not serve under epoch 8 (REVOKED_STOLEN)", func(w *world) {
			document := good(w.now)
			document["serve_until_boottime_ms"], document["reason"] = 0, "a may not serve under epoch 8 (REVOKED_STOLEN)"
			w.put(document)
		}},
		{"zero, with no reason", "not admitted by the lease service: the lease service reports no admission", change("serve_until_boottime_ms", 0)},
		{"run out", "the admission ran out", change("serve_until_boottime_ms", 999_999)},
		{"run out this millisecond", "the admission ran out", change("serve_until_boottime_ms", 1_000_000)},
		{"further ahead than a lease lives", "further ahead than one lease lifetime", change("serve_until_boottime_ms", 1_000_000+MaxAheadMilliseconds+1)},
		{"asked for in the future", "a request made in the future", change("requested_boottime_ms", 1_000_001)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			if !w.gate.Ready(context.Background()) {
				t.Fatal("the fixture is not admitted before it is broken")
			}
			c.arrange(w)
			w.refused(c.want)
		})
	}
}

func TestTheLongestAdmissionAllowedIsOneLeaseLifetime(t *testing.T) {
	w := newWorld(t)
	document := good(w.now)
	document["serve_until_boottime_ms"] = w.now + MaxAheadMilliseconds
	w.put(document)
	if !w.gate.Ready(context.Background()) {
		t.Fatal("an admission of exactly one lease lifetime is refused")
	}
}

func TestTheBootSessionFileIsHeldToTheSameRules(t *testing.T) {
	cases := []struct {
		name, want string
		arrange    func(*world)
	}{
		{"missing", "the boot session: it cannot be opened", func(w *world) { _ = os.Remove(w.path("boot-session")) }},
		{"group-writable", "the boot session: it is not a file only its owner or root can write", func(w *world) {
			w.write("boot-session", []byte(testSession), 0o664)
		}},
		{"a symlink", "the boot session: it cannot be opened", func(w *world) {
			w.write("real-session", []byte(testSession), 0o644)
			_ = os.Remove(w.path("boot-session"))
			_ = os.Symlink(w.path("real-session"), w.path("boot-session"))
		}},
		{"another session", "for another boot session", func(w *world) { w.write("boot-session", []byte(strings.Repeat("0b", 32)), 0o644) }},
		{"not a session ID", "for another boot session", func(w *world) { w.write("boot-session", []byte("session"), 0o644) }},
		{"empty", "for another boot session", func(w *world) { w.write("boot-session", nil, 0o644) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			c.arrange(w)
			w.refused(c.want)
		})
	}
}

func TestAFileInADirectoryThatIsNotThereIsNotAdmitted(t *testing.T) {
	w := newWorld(t)
	gate, err := Open(Options{Path: w.path("absent/admission.json"), NodeID: "a", SessionPath: w.path("boot-session"), OwnerUID: uint32(os.Getuid()), SessionOwnerUID: uint32(os.Getuid()),
		Boottime: func() (int64, error) { return w.now, nil }, BootID: func() (string, error) { return testBoot, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if status := gate.Check(context.Background()); status.Admitted || status.Reason != "the admission file: its directory cannot be examined" {
		t.Fatalf("status = %+v", status)
	}
}

func TestAFileOwnedBySomeoneElseIsNotAdmitted(t *testing.T) {
	w := newWorld(t)
	other, err := Open(Options{Path: w.path("admission.json"), NodeID: "a", SessionPath: w.path("boot-session"), SessionOwnerUID: uint32(os.Getuid()),
		OwnerUID: uint32(os.Getuid()) + 1, Boottime: func() (int64, error) { return w.now, nil }, BootID: func() (string, error) { return testBoot, nil }})
	if err != nil {
		t.Fatal(err)
	}
	status := other.Check(context.Background())
	if status.Admitted || !strings.Contains(status.Reason, "its directory is not one only its owner or root can write") {
		t.Fatalf("status = %+v", status)
	}
}

// THE LEASE SERVICE IS NOT ROOT (regalia-kms#191). Its user may write the admission file, never the
// boot session: the session is what the admission is checked against, so it stays root's (or, here,
// whoever SessionOwnerUID names), whatever OwnerUID says.
func TestTheBootSessionIsHeldToItsOwnOwnerNotTheLeaseServices(t *testing.T) {
	w := newWorld(t)
	gate, err := Open(Options{Path: w.path("admission.json"), NodeID: "a", SessionPath: w.path("boot-session"),
		OwnerUID: uint32(os.Getuid()), SessionOwnerUID: uint32(os.Getuid()) + 1,
		Boottime: func() (int64, error) { return w.now, nil }, BootID: func() (string, error) { return testBoot, nil }})
	if err != nil {
		t.Fatal(err)
	}
	status := gate.Check(context.Background())
	if status.Admitted || !strings.Contains(status.Reason, "the boot session: its directory is not one only its owner or root can write") {
		t.Fatalf("status = %+v", status)
	}
}

// A file of root's is trusted whatever OwnerUID names: root can write it anyway. /etc/hostname is
// root's, 0644, in root's /etc, on every host this suite runs on.
func TestAFileOfRootsIsTrustedForAnyWriter(t *testing.T) {
	var stat unix.Stat_t
	if err := unix.Stat("/etc/hostname", &stat); err != nil || stat.Uid != 0 || stat.Mode&0o022 != 0 {
		t.Skip("no root-owned /etc/hostname here")
	}
	if _, err := readTrusted("/etc/hostname", uint32(os.Getuid())+1); err != nil {
		t.Fatalf("a root file was refused: %v", err)
	}
}

// ABOVE THE DIRECTORY, NOBODY ELSE MAY BE ABLE TO SWAP IT. A directory that is the writer's own but sits
// in one anyone can write, without the sticky bit, can be renamed away and replaced by anyone.
func TestADirectoryUnderOneOthersCanWriteIsNotTrusted(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil { // CI's umask 002 makes it group-writable
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, want string
		mode       os.FileMode
		ok         bool
	}{
		{"world-writable, not sticky", "lets someone else replace what is below it", 0o777, false},
		{"group-writable, not sticky", "lets someone else replace what is below it", 0o775, false},
		{"world-writable and sticky, the child the writer's own", "", 0o777 | os.ModeSticky, true},
		{"only its owner can write", "", 0o755, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			above := filepath.Join(base, strings.NewReplacer(" ", "-", ",", "", "'", "").Replace(test.name))
			directory := filepath.Join(above, "admission")
			if err := os.MkdirAll(directory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(directory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(above, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "admission.json"), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := readTrusted(filepath.Join(directory, "admission.json"), uint32(os.Getuid()))
			if test.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !test.ok && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("got %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

// A link on the way up is refused: the path would name a directory other than the one examined.
func TestALinkAboveTheDirectoryIsNotTrusted(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "admission"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(real, "admission"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "admission", "admission.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	_, err := readTrusted(filepath.Join(base, "link", "admission", "admission.json"), uint32(os.Getuid()))
	if err == nil || !strings.Contains(err.Error(), "is not a directory of its owner or root") {
		t.Fatalf("got %v", err)
	}
}

func TestAnUnreadableClockACancelledRequestAndANilGateAreNotAdmitted(t *testing.T) {
	w := newWorld(t)
	gate, err := Open(Options{Path: w.path("admission.json"), NodeID: "a", SessionPath: w.path("boot-session"), OwnerUID: uint32(os.Getuid()), SessionOwnerUID: uint32(os.Getuid()),
		Boottime: func() (int64, error) { return 0, errors.New("no clock") }, BootID: func() (string, error) { return testBoot, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if status := gate.Check(context.Background()); status.Admitted || status.Reason != "CLOCK_BOOTTIME cannot be read" {
		t.Fatalf("status = %+v", status)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if status := w.gate.Check(cancelled); status.Admitted || status.Reason != "the request was cancelled" {
		t.Fatalf("status = %+v", status)
	}
	var missing *Gate
	if missing.Ready(context.Background()) || missing.Check(context.Background()).Reason != "admission is not wired" {
		t.Fatal("a nil gate is admitted")
	}
	if missing.RequestedAfter(context.Background(), 0) {
		t.Fatal("a nil gate vouches for a request time")
	}
}

func TestOpenRefusesAnIncompleteOrUnusableConfiguration(t *testing.T) {
	boot := func() (string, error) { return testBoot, nil }
	cases := []struct {
		name, want string
		options    Options
	}{
		{"no admission path", "needs the admission file path", Options{NodeID: "a", SessionPath: "/run/regalia/boot-session", BootID: boot}},
		{"no session path", "needs the admission file path", Options{Path: "/run/regalia/admission.json", NodeID: "a", BootID: boot}},
		{"a relative path", "must be absolute", Options{Path: "admission.json", NodeID: "a", SessionPath: "/run/regalia/boot-session", BootID: boot}},
		{"a path with .. in it", "must be clean", Options{Path: "/run/regalia/admission/l/../admission.json", NodeID: "a", SessionPath: "/run/regalia/boot-session", BootID: boot}},
		{"a session path with a repeated slash", "must be clean", Options{Path: "/run/regalia/admission/admission.json", NodeID: "a", SessionPath: "/run/regalia//boot-session", BootID: boot}},
		{"a relative session path", "must be absolute", Options{Path: "/run/regalia/admission.json", NodeID: "a", SessionPath: "boot-session", BootID: boot}},
		{"no node ID", "needs this node's ID", Options{Path: "/run/regalia/admission.json", SessionPath: "/run/regalia/boot-session", BootID: boot}},
		{"a node ID the manifest could not hold", "needs this node's ID", Options{Path: "/run/regalia/admission.json", NodeID: "Site A", SessionPath: "/run/regalia/boot-session", BootID: boot}},
		{"no boot ID", "read the kernel boot ID", Options{Path: "/run/regalia/admission.json", NodeID: "a", SessionPath: "/run/regalia/boot-session",
			BootID: func() (string, error) { return "", errors.New("no /proc") }}},
		{"a boot ID that is not one", "is not a UUID", Options{Path: "/run/regalia/admission.json", NodeID: "a", SessionPath: "/run/regalia/boot-session",
			BootID: func() (string, error) { return "boot", nil }}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Open(c.options); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Open = %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestTheRealClockAndBootID(t *testing.T) {
	first, err := Boottime()
	if err != nil || first <= 0 {
		t.Fatalf("Boottime = %d, %v", first, err)
	}
	id, err := KernelBootID()
	if err != nil || !bootIDPattern.MatchString(id) {
		t.Fatalf("KernelBootID = %q, %v", id, err)
	}
	// with the defaults, a gate opens, and a file from the fixture's boot is from another boot
	w := newWorld(t)
	gate, err := Open(Options{Path: w.path("admission.json"), NodeID: "a", SessionPath: w.path("boot-session"), OwnerUID: uint32(os.Getuid()), SessionOwnerUID: uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	if status := gate.Check(context.Background()); status.Admitted || status.Reason != "the admission file is from another boot" {
		t.Fatalf("status = %+v", status)
	}
}

func TestEveryChangeOfAnswerIsReportedOnceWithItsReasonAndEpoch(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.gate.Check(ctx)
	w.gate.Check(ctx)
	if len(w.events) != 1 || !w.events[0].Admitted || w.events[0].Epoch != 7 {
		t.Fatalf("after two admitted checks: %+v", w.events)
	}
	// the lease service learns of a revocation and writes zero
	document := good(w.now)
	document["serve_until_boottime_ms"], document["epoch"], document["reason"] = 0, 8, "a may not serve under epoch 8 (REVOKED_STOLEN)"
	w.put(document)
	w.gate.Check(ctx)
	w.gate.Check(ctx)
	if len(w.events) != 2 || w.events[1].Admitted || w.events[1].Epoch != 8 ||
		w.events[1].Reason != "not admitted by the lease service: a may not serve under epoch 8 (REVOKED_STOLEN)" {
		t.Fatalf("after the revocation: %+v", w.events)
	}
	// admitted again, then the file is simply not rewritten: time alone ends it
	w.put(good(w.now))
	w.gate.Check(ctx)
	w.now += 290_000
	w.gate.Check(ctx)
	if len(w.events) != 4 || !w.events[2].Admitted || w.events[3].Admitted || w.events[3].Reason != "the admission ran out" {
		t.Fatalf("after expiry: %+v", w.events)
	}
	// a first answer of "no" is reported too
	fresh := newWorld(t)
	_ = os.Remove(fresh.path("admission.json"))
	fresh.gate.Check(ctx)
	if len(fresh.events) != 1 || fresh.events[0].Admitted {
		t.Fatalf("first answer: %+v", fresh.events)
	}
}

func TestRequestedAfterNeedsAnAdmissionAskedForLater(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	requested := w.now - 5_000
	if !w.gate.RequestedAfter(ctx, requested-1) {
		t.Fatal("a lease asked for after the moment is not accepted")
	}
	if w.gate.RequestedAfter(ctx, requested) || w.gate.RequestedAfter(ctx, requested+1) {
		t.Fatal("a lease asked for at or before the moment is accepted")
	}
	w.now += 290_000
	if w.gate.RequestedAfter(ctx, 0) {
		t.Fatal("an admission that ran out vouches for a request time")
	}
}

// scriptedHolder answers Ready from a list, one answer per call.
type scriptedHolder struct {
	answers []bool
	calls   int
}

func (holder *scriptedHolder) Ready(context.Context) bool {
	answer := holder.calls < len(holder.answers) && holder.answers[holder.calls]
	holder.calls++
	return answer
}

type directRunner struct{ ran int }

func (runner *directRunner) Run(ctx context.Context, operation func(context.Context) error) error {
	runner.ran++
	return operation(ctx)
}

func TestTheRunnerChecksAdmissionBeforeDuringAndAfterAnOperation(t *testing.T) {
	failure := errors.New("the token failed")
	cases := []struct {
		name      string
		answers   []bool
		operation error
		want      error
		executed  bool
		checks    int
	}{
		{"admitted throughout", []bool{true, true, true}, nil, nil, true, 3},
		{"not admitted", []bool{false}, nil, ErrNotAdmitted, false, 1},
		{"lapsed while queued", []bool{true, false}, nil, ErrNotAdmitted, false, 2},
		{"lapsed while the token worked", []bool{true, true, false}, nil, ErrNotAdmitted, true, 3},
		{"the operation's own error is passed on", []bool{true, true, true}, failure, failure, true, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			holder, base, executed := &scriptedHolder{answers: c.answers}, &directRunner{}, false
			err := NewRunner(holder, base).Run(context.Background(), func(context.Context) error {
				executed = true
				return c.operation
			})
			if !errors.Is(err, c.want) || (c.want == nil && err != nil) {
				t.Fatalf("Run = %v, want %v", err, c.want)
			}
			if executed != c.executed || holder.calls != c.checks {
				t.Fatalf("executed = %v (want %v), admission checked %d times (want %d)", executed, c.executed, holder.calls, c.checks)
			}
		})
	}
	var missing *AdmittedRunner
	for name, runner := range map[string]*AdmittedRunner{"nil runner": missing, "no gate": NewRunner(nil, &directRunner{}),
		"no executor": NewRunner(&scriptedHolder{answers: []bool{true}}, nil)} {
		if err := runner.Run(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, ErrNotAdmitted) {
			t.Fatalf("%s: Run = %v, want ErrNotAdmitted", name, err)
		}
	}
}

// The daemon's start, as the kernel dates it: the number the lease service reads for the same PID.
func TestProcessStartIsThisProcessOnTheBootClock(t *testing.T) {
	started, err := ProcessStart()
	if err != nil {
		t.Fatal(err)
	}
	now, err := Boottime()
	if err != nil {
		t.Fatal(err)
	}
	if started <= 0 || started > now {
		t.Fatalf("the process started at %d and the boot clock reads %d", started, now)
	}
	if again, _ := ProcessStart(); again != started {
		t.Fatalf("the start time moved: %d then %d", started, again)
	}
	if started%10 != 0 {
		t.Fatalf("%d is not a whole number of 10 ms ticks", started)
	}
}

func TestParseProcessStartCountsFromTheLastParenthesis(t *testing.T) {
	tail := " S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456 20 21\n"
	for _, name := range []string{"(regalia-kms)", "(a b)", "(evil) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99 20)", "(()"} {
		got, err := parseProcessStart("4242 " + name + tail)
		if err != nil || got != 1234570 { // tick 123456 at 100 Hz, and one tick more: never before the true start
			t.Fatalf("%q: %d, %v", name, got, err)
		}
	}
	for label, stat := range map[string]string{
		"no command name": "4242 regalia-kms S 1 2",
		"too short":       "4242 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18",
		"not a number":    "4242 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 soon 20",
		"zero":            "4242 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 0 20",
		"negative":        "4242 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 -5 20",
		"overflowing":     "4242 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 9223372036854775807 20",
		"empty":           "",
	} {
		if got, err := parseProcessStart(stat); err == nil {
			t.Fatalf("%s: accepted as %d", label, got)
		}
	}
}

// A key is served from a token only while the manifest lists its serial for this node, and under a
// lease asked for after the moment given (regalia-kms#72, G1 and PoC 12.4): one reading of the file.
func TestAdmitsNeedsTheSerialListedAndALeaseAskedForLater(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	requested := w.now - 5_000
	if !w.gate.Admits(ctx, "DENK0404144", requested-1) || !w.gate.Admits(ctx, "36345471", requested-1) {
		t.Fatal("a listed token under a lease asked for since is not admitted")
	}
	for _, serial := range []string{"DENK0404547", "", "DENK040414", "denk0404144"} {
		if w.gate.Admits(ctx, serial, requested-1) {
			t.Errorf("serial %q, which the manifest does not list, is admitted", serial)
		}
	}
	if w.gate.Admits(ctx, "DENK0404144", requested) {
		t.Error("a listed token is admitted under a lease asked for before the moment")
	}
	none := good(w.now)
	none["hsm_serials"] = ""
	w.put(none)
	if w.gate.Admits(ctx, "DENK0404144", requested-1) || !w.gate.Ready(ctx) {
		t.Error("with no token listed, a token is admitted, or the node itself is not")
	}
	revoked := good(w.now)
	revoked["serve_until_boottime_ms"], revoked["reason"] = 0, "revoked"
	w.put(revoked)
	if w.gate.Admits(ctx, "DENK0404144", requested-1) {
		t.Error("a listed token is admitted while the node is not")
	}
}
