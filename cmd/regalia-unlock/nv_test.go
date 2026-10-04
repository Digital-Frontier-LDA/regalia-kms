package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// steps is run by the Python against the swtpm, one step at a time: membership.HighWater writes the anchor
// through tpm2-tools, and decides each (chain, length) as Store.load would before writing (the decide()
// of tests/vectors/make-highwater-v1.py). The Go reader then reads the same TPM.
const steps = `
import json, os, subprocess, sys
sys.path.insert(0, os.getcwd())
from deploy.baremetal import membership as m
vector = json.load(open("tests/vectors/highwater-v1.json"))
chains = {name: [{"manifest": e["manifest"], "signature": {"signer": "root", "key": vector["root_public"], "sig": e["sig"]}} for e in envs]
          for name, envs in vector["chains"].items()}
def manifests(envelopes):
    current, out = None, []
    for env in envelopes:
        current = m.accept(current, env, vector["root_public"])
        out.append(current)
    return out
def decide(hw, ms):
    try:
        high = hw.value()
        epoch = ms[-1]["epoch"]
        m.require(epoch >= high, "ROLLBACK: the membership on disk is epoch %d but the TPM high-water is %d; fetch the chain from a peer" % (epoch, high))
        high = hw.verify(m.Store._digests(ms), lock=False)
        m.require(epoch - high <= hw.MAX_JUMP, "epoch jump %d exceeds the bound %d: anomaly" % (epoch - high, hw.MAX_JUMP))
        return {"high_water": high}
    except m.Unusable as reason:
        return {"unusable": str(reason)}
    except m.Refused as reason:
        return {"refused": str(reason)}
OWNER = "owner-secret-of-this-test"
hw = m.HighWater("0x1500016", tcti=os.environ["TPM2TOOLS_TCTI"], lock_path=sys.argv[1] + "/hw.lock")
step = sys.argv[2]
if step == "anchor 3":
    hw.define()
    for e in (1, 2, 3):
        hw.anchor(e, m.Store._digests(manifests(chains["main"])))
elif step == "advance 4":
    hw.advance(4)
elif step == "set the owner authorization":
    subprocess.run(["tpm2_changeauth", "-c", "o", OWNER], check=True, capture_output=True)
else:                                         # (the undefine steps come after the owner authorization is set)
    subprocess.run(["tpm2_nvundefine", step.split()[-1], "-C", "o", "-P", OWNER], check=True, capture_output=True)
print(json.dumps({"%s %d" % (name, n): decide(hw, manifests(chains[name][:n])) for name, n in json.loads(sys.argv[3])}))
`

func TestTheTPMReaderReadsWhatHighWaterWrote(t *testing.T) {
	for _, tool := range []string{"swtpm", "tpm2_nvdefine", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("REGALIA_EXPECT_SWTPM") != "" {
				t.Fatalf("REGALIA_EXPECT_SWTPM is set and %s is missing", tool)
			}
			t.Skipf("needs %s", tool)
		}
	}
	dir, err := os.MkdirTemp("", "hw") // short: a unix socket path has a length limit that t.TempDir() exceeds
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "swtpm.sock")
	start := exec.Command("swtpm", "socket", "--tpm2", "--tpmstate", "dir="+dir, "--server", "type=unixio,path="+socket,
		"--ctrl", "type=unixio,path="+socket+".ctrl", "--flags", "not-need-init,startup-clear", "--daemon", "--pid", "file="+dir+"/pid")
	if out, err := start.CombinedOutput(); err != nil {
		t.Fatalf("swtpm did not start: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if pid, err := os.ReadFile(dir + "/pid"); err == nil {
			if n, err := strconv.Atoi(string(pid)); err == nil {
				if p, err := os.FindProcess(n); err == nil {
					_ = p.Kill()
				}
			}
		}
	})
	time.Sleep(500 * time.Millisecond)

	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "highwater-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := membership.Load(raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	vector := document.(map[string]any)
	rootKey := vector["root_public"].(string)
	chain := func(name string, n int) []map[string]any {
		var envelopes []any
		for _, e := range vector["chains"].(map[string]any)[name].([]any)[:n] {
			e := e.(map[string]any)
			envelopes = append(envelopes, map[string]any{"manifest": e["manifest"], "signature": map[string]any{"signer": "root", "key": rootKey, "sig": e["sig"]}})
		}
		manifests, err := membership.ReadChain(envelopes, rootKey)
		if err != nil {
			t.Fatalf("%s %d: %v", name, n, err)
		}
		return manifests
	}

	type read struct {
		name string
		n    int
	}
	for _, step := range []struct {
		step  string
		reads []read
	}{
		{"anchor 3", []read{{"main", 3}, {"main", 2}, {"fork at 3", 3}, {"main", 5}}},
		{"advance 4", []read{{"main", 4}, {"main", 3}, {"fork at 4", 4}}},
		// #242: both readers read with each index's own authorization, so they read the same once the owner
		// authorization is set (and kept off the host)
		{"set the owner authorization", []read{{"main", 4}, {"main", 3}, {"fork at 4", 4}}},
		{"undefine 0x150001b", []read{{"main", 4}}},
		{"undefine 0x1500016", []read{{"main", 4}}},
	} {
		var pairs [][]any
		for _, r := range step.reads {
			pairs = append(pairs, []any{r.name, r.n})
		}
		arg, _ := json.Marshal(pairs)
		python := exec.Command("python3", "-BEs", "-c", steps, dir, step.step, string(arg))
		python.Dir = filepath.Join("..", "..")
		python.Env = append(os.Environ(), "TPM2TOOLS_TCTI=swtpm:path="+socket)
		out, err := python.Output()
		if err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				t.Fatalf("%s: the Python failed: %s", step.step, exit.Stderr)
			}
			t.Fatal(err)
		}
		var decided map[string]map[string]any
		if err := json.Unmarshal(out, &decided); err != nil {
			t.Fatalf("%s: %v: %s", step.step, err, out)
		}

		device, err := openTPM("unix:" + socket)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range step.reads {
			label := fmt.Sprintf("%s %d", r.name, r.n)
			want := decided[label]
			hw, err := membership.Anchored(tpmNV{device}, chain(r.name, r.n), nil)
			var unusable *membership.Unusable
			var refused *membership.Refused
			switch {
			case want["high_water"] != nil:
				if err != nil || float64(hw) != want["high_water"].(float64) {
					t.Errorf("%s, %s: Python: high-water %v; Go: %d, %v", step.step, label, want["high_water"], hw, err)
				}
			case want["unusable"] != nil:
				if !errors.As(err, &unusable) || unusable.Reason != want["unusable"] {
					t.Errorf("%s, %s: Python: unusable: %s\nGo: %v", step.step, label, want["unusable"], err)
				}
			default:
				if !errors.As(err, &refused) || refused.Reason != want["refused"] {
					t.Errorf("%s, %s: Python: refused: %s\nGo: %v", step.step, label, want["refused"], err)
				}
			}
			t.Logf("%s, %s: %v", step.step, label, want)
		}
		if err := device.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
