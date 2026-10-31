package admission

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// store makes the survivor's store as survivor.py keeps it, owned by this test's user: a 0700 directory holding the
// directives file (0640), and returns the file's path.
func store(t *testing.T, contents []byte) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "regalia-survivor")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "survivor-directives.jsonl")
	if contents != nil {
		if err := os.WriteFile(path, contents, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o640); err != nil { // the umask may have taken bits WriteFile asked for
			t.Fatal(err)
		}
	}
	return path
}

func uid() uint32 { return uint32(os.Getuid()) }

func sortedKeys(set map[string]bool) []string {
	out := []string{}
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// The daemon refuses exactly the keys the survivor applied, and every key whenever the survivor's own reader would
// (survivor.Directives): the same bytes, the same answer (tests/vectors/make-survivor-directives-v1.py).
func TestSurvivorDirectivesVector(t *testing.T) {
	raw, err := os.ReadFile("../../tests/vectors/survivor-directives-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Cases []struct {
			Name     string          `json:"name"`
			File     string          `json:"file"`
			Disabled json.RawMessage `json:"disabled"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.Cases) < 40 {
		t.Fatalf("the vector has %d cases: not the file the generator writes", len(vector.Cases))
	}
	refused, accepted := 0, 0
	for _, c := range vector.Cases {
		t.Run(c.Name, func(t *testing.T) {
			contents, err := hex.DecodeString(c.File)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadDisabled(store(t, contents), uid())
			if string(c.Disabled) == `"refused"` {
				refused++
				if err == nil {
					t.Fatalf("survivor.py refuses every key for this file; the daemon read it as disabling %v", sortedKeys(got))
				}
				if !strings.HasSuffix(err.Error(), ": every key is refused") {
					t.Fatalf("a refusal that does not say what it does: %v", err)
				}
				return
			}
			accepted++
			var want []string
			if err := json.Unmarshal(c.Disabled, &want); err != nil {
				t.Fatal(err)
			}
			if err != nil {
				t.Fatalf("survivor.py reads this file as disabling %v; the daemon refused it: %v", want, err)
			}
			if !reflect.DeepEqual(sortedKeys(got), want) {
				t.Fatalf("disabled %v, survivor.py %v", sortedKeys(got), want)
			}
		})
	}
	if refused == 0 || accepted == 0 {
		t.Fatalf("the vector must hold both answers: %d refused, %d accepted", refused, accepted)
	}
}

const oneDirective = `{"directive":{"issued_at":"2026-10-30T12:00:00Z","object_id":"kek-a","quarantine_digest":"` +
	"abababababababababababababababababababababababababababababababab" + `","quarantine_epoch":7,"reason":"seen",` +
	`"schema":"regalia.survivor-directive/v1","state":"disabled"},"signature":{}}` + "\n"

func TestAStoreNotYetWrittenDisablesNothing(t *testing.T) {
	got, err := ReadDisabled(store(t, nil), uid())
	if err != nil || len(got) != 0 {
		t.Fatalf("no file yet: %v, %v", got, err)
	}
	got, err = ReadDisabled(store(t, []byte(oneDirective)), uid())
	if err != nil || !got["kek-a"] || len(got) != 1 {
		t.Fatalf("the control: %v, %v", got, err)
	}
}

// Everything survivor.py's _directory and _root_s refuse, the daemon refuses: every key, never "nothing disabled".
func TestAStoreThatCannotBeTrustedRefusesEveryKey(t *testing.T) {
	cases := map[string]func(t *testing.T) (string, uint32){
		"its directory is missing": func(t *testing.T) (string, uint32) {
			return filepath.Join(t.TempDir(), "absent", "survivor-directives.jsonl"), uid()
		},
		"its directory lets the group in": func(t *testing.T) (string, uint32) {
			path := store(t, []byte(oneDirective))
			if err := os.Chmod(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			return path, uid()
		},
		"its directory is a link": func(t *testing.T) (string, uint32) {
			path := store(t, []byte(oneDirective))
			link := filepath.Join(t.TempDir(), "linked")
			if err := os.Symlink(filepath.Dir(path), link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, filepath.Base(path)), uid()
		},
		"the file is a link": func(t *testing.T) (string, uint32) {
			path := store(t, nil)
			real := filepath.Join(filepath.Dir(path), "real")
			if err := os.WriteFile(real, []byte(oneDirective), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, path); err != nil {
				t.Fatal(err)
			}
			return path, uid()
		},
		"the file has a second link": func(t *testing.T) (string, uint32) {
			path := store(t, []byte(oneDirective))
			if err := os.Link(path, filepath.Join(filepath.Dir(path), "other")); err != nil {
				t.Fatal(err)
			}
			return path, uid()
		},
		"the group may write the file": func(t *testing.T) (string, uint32) {
			path := store(t, []byte(oneDirective))
			if err := os.Chmod(path, 0o660); err != nil {
				t.Fatal(err)
			}
			return path, uid()
		},
		"the file is a directory": func(t *testing.T) (string, uint32) {
			path := store(t, nil)
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			return path, uid()
		},
		"another user owns the store": func(t *testing.T) (string, uint32) {
			return store(t, []byte(oneDirective)), uid() + 1
		},
		"the file is oversized": func(t *testing.T) (string, uint32) {
			return store(t, []byte(strings.Repeat(oneDirective, MaxDirectivesBytes/len(oneDirective)+1))), uid()
		},
		"the path is not clean": func(t *testing.T) (string, uint32) {
			path := store(t, []byte(oneDirective))
			return filepath.Dir(path) + "/./" + filepath.Base(path), uid()
		},
		"the path is relative": func(t *testing.T) (string, uint32) {
			return "regalia-survivor/survivor-directives.jsonl", uid()
		},
	}
	for name, makeStore := range cases {
		t.Run(name, func(t *testing.T) {
			path, owner := makeStore(t)
			got, err := ReadDisabled(path, owner)
			if err == nil {
				t.Fatalf("read as disabling %v", sortedKeys(got))
			}
			if !strings.HasSuffix(err.Error(), ": every key is refused") {
				t.Fatalf("a refusal that does not say what it does: %v", err)
			}
		})
	}
}

// The largest file the survivor would write is read whole: the bound is MaxDirectivesBytes, not less.
func TestAFileAtTheBoundIsRead(t *testing.T) {
	contents := []byte(strings.Repeat(oneDirective, MaxDirectivesBytes/len(oneDirective)))
	got, err := ReadDisabled(store(t, contents), uid())
	if err != nil || !got["kek-a"] {
		t.Fatalf("%d bytes: %v, %v", len(contents), got, err)
	}
}

// Where the daemon is stricter than survivor.py, it refuses: membership.load decodes a UTF-8 byte order mark and
// UTF-16, which the store's writer never makes; this reader takes UTF-8 only, so the difference refuses every key.
func TestWhatOnlyPythonDecodesIsRefused(t *testing.T) {
	for name, contents := range map[string][]byte{
		"a byte order mark": append([]byte("\xef\xbb\xbf"), oneDirective...),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := ReadDisabled(store(t, contents), uid()); err == nil {
				t.Fatalf("read as disabling %v", sortedKeys(got))
			}
		})
	}
}

// recoveryWorld is a node in recovery whose gate reads the survivor's directives at `path` (empty: none configured).
func recoveryWorld(t *testing.T, path string) *world {
	t.Helper()
	w := newWorld(t)
	gate, err := Open(Options{
		Path: w.path("admission.json"), NodeID: "a", SessionPath: w.path("boot-session"), OwnerUID: uid(), SessionOwnerUID: uid(),
		Boottime: func() (int64, error) { return w.now, nil }, BootID: func() (string, error) { return testBoot, nil },
		DirectivesPath: path, DirectivesOwnerUID: uid(),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.gate = gate
	document := good(w.now)
	document["mode"] = "recovery"
	w.put(document)
	return w
}

// OWNER ITEM 212: in recovery, a key the owner's directives disabled is refused by name, and every key is when the
// directives cannot be read. The node still serves nothing in recovery (no stateless-only gate yet): Ready stays false.
func TestARecoveringNodeRefusesTheKeysTheDirectivesDisabled(t *testing.T) {
	ctx := context.Background()
	w := recoveryWorld(t, store(t, []byte(oneDirective)))
	if w.gate.Ready(ctx) {
		t.Fatal("a node in recovery is admitted: the stateless-only gate does not exist yet")
	}
	if got := w.gate.RefusesObject(ctx, "kek-a"); got != RefusedDisabled {
		t.Fatalf("the disabled key: %q", got)
	}
	if got := w.gate.RefusesObject(ctx, "kek-b"); got != "" {
		t.Fatalf("a key no directive names: %q", got)
	}
	// the store is read on each check: a directive applied now is refused at the next request, not at a restart
	path := store(t, []byte(oneDirective+strings.Replace(oneDirective, "kek-a", "kek-b", 1)))
	w2 := recoveryWorld(t, path)
	if got := w2.gate.RefusesObject(ctx, "kek-b"); got != RefusedDisabled {
		t.Fatalf("the second directive: %q", got)
	}
}

func TestARecoveringNodeRefusesEveryKeyWhenTheDirectivesCannotBeRead(t *testing.T) {
	ctx := context.Background()
	corrupt := store(t, []byte(oneDirective+"not json\n"))
	unreadable := store(t, []byte(oneDirective))
	if err := os.Chmod(filepath.Dir(unreadable), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"a corrupt line": corrupt, "a store the group may enter": unreadable, "no store configured": ""} {
		t.Run(name, func(t *testing.T) {
			w := recoveryWorld(t, path)
			for _, object := range []string{"kek-a", "kek-b"} {
				if got := w.gate.RefusesObject(ctx, object); got != RefusedDirectivesUnreadable {
					t.Fatalf("%s: %q", object, got)
				}
			}
			if status := w.gate.Check(ctx); !status.Recovery || !strings.HasSuffix(status.DirectivesError, "every key is refused") {
				t.Fatalf("the status does not say why: %+v", status)
			}
		})
	}
}

// Outside recovery the directives are not the gate's to apply: a lease's node serves a key a survivor once disabled
// until the majority's own state says otherwise, and an unreadable store refuses nothing.
func TestUnderALeaseTheDirectivesDoNotApply(t *testing.T) {
	ctx := context.Background()
	for name, path := range map[string]string{"a directive disables kek-a": store(t, []byte(oneDirective)),
		"a corrupt store": store(t, []byte("not json\n"))} {
		t.Run(name, func(t *testing.T) {
			w := recoveryWorld(t, path)
			w.put(good(w.now))
			if !w.gate.Ready(ctx) {
				t.Fatal("the lease fixture is not admitted")
			}
			if got := w.gate.RefusesObject(ctx, "kek-a"); got != "" {
				t.Fatalf("under a lease: %q", got)
			}
		})
	}
	var none *Gate
	if got := none.RefusesObject(ctx, "kek-a"); got != RefusedDirectivesUnreadable {
		t.Fatalf("a nil gate: %q", got)
	}
}
