package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/bootcfg"
	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// vectorNV is a TPM's NV indices as tests/vectors/highwater-v1.json records them (FakeTpm's rules).
type vectorNV struct {
	nv     map[uint32]map[string]any
	broken bool
}

func (f vectorNV) Defined() (map[uint32]bool, error) {
	if f.broken {
		return nil, errors.New("the TPM said no")
	}
	out := map[uint32]bool{}
	for i := range f.nv {
		out[i] = true
	}
	return out, nil
}

func (f vectorNV) Public(index uint32) (uint32, int, []byte, error) {
	e, ok := f.nv[index]
	if f.broken || !ok {
		return 0, 0, nil, errors.New("the TPM said no")
	}
	a, _ := e["attributes"].(json.Number).Int64()
	s, _ := e["size"].(json.Number).Int64()
	var policy []byte
	if text, ok := e["policy"].(string); ok {
		policy, _ = hex.DecodeString(text)
	}
	return uint32(a), int(s), policy, nil
}

func (f vectorNV) Read(index uint32, size int) ([]byte, error) {
	e, ok := f.nv[index]
	s, _ := e["size"].(json.Number).Int64()
	if f.broken || !ok || e["data"] == nil || size > int(s) {
		return nil, errors.New("the TPM said no")
	}
	data, _ := hex.DecodeString(e["data"].(string))
	return data[:size], nil
}

type renderFixture struct {
	vector       map[string]any
	root         string
	files        map[string][]byte // what readFile returns, by path; the chain is under "ESP/" and readable only while mounted
	mounted      string
	mounts       int
	writes       map[string][]byte // what is in the output directory, temporary names included
	failOn       int               // the write that fails (1-based); 0: none
	nWrites      int
	unmountFails bool
	removed      []string
	tpm          vectorNV
	tpmFail      bool
	slept        time.Duration
	devices      map[string]bool
}

func loadVector(t *testing.T) map[string]any {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "highwater-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := membership.Load(raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return document.(map[string]any)
}

const testUUID = "6f1a2b3c-4d5e-4f60-8a7b-9c0d1e2f3a4b"

func efivar(uuid string) []byte {
	out := []byte{7, 0, 0, 0}
	for _, u := range utf16.Encode([]rune(uuid + "\x00")) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// chainBytes is the first n envelopes of one of the vector's chains, as the update path writes them.
func chainBytes(v map[string]any, name string, n int) []byte {
	var envelopes []any
	for _, e := range v["chains"].(map[string]any)[name].([]any)[:n] {
		e := e.(map[string]any)
		envelopes = append(envelopes, map[string]any{"manifest": e["manifest"],
			"signature": map[string]any{"signer": "root", "key": v["root_public"], "sig": e["sig"]}})
	}
	return membership.Canonical(envelopes)
}

// siteFor is regalia.site for node n1 of the vector's chains, its peers n2 and n3.
func siteFor(node string) []byte {
	peers := []any{map[string]any{"node_id": "n2", "underlay": "198.51.100.7", "address": "10.89.0.2"},
		map[string]any{"node_id": "n3", "underlay": "198.51.100.9", "address": "10.89.0.3"}}
	return membership.Canonical(map[string]any{"schema": bootcfg.SiteSchema, "host_ipv4": "192.0.2.10", "device": "/dev/disk/by-partlabel/regalia-root",
		"boot_mesh": map[string]any{"node_id": node, "interface": "wg-unlock", "listen_port": 51820, "address": "10.89.0.1", "unlock_port": 7443,
			"nic_mac": "52:54:00:ab:cd:02", "prefix": 32, "gateway": nil, "peers": peers}})
}

func tpmCase(t *testing.T, v map[string]any, name string) vectorNV {
	for _, value := range v["cases"].([]any) {
		c := value.(map[string]any)
		if c["name"] == name {
			state := c["tpm"].(map[string]any)
			f := vectorNV{nv: map[uint32]map[string]any{}, broken: state["broken"].(bool)}
			for text, e := range state["nv"].(map[string]any) {
				n, _ := strconv.ParseUint(text, 0, 32)
				f.nv[uint32(n)] = e.(map[string]any)
			}
			return f
		}
	}
	t.Fatalf("no TPM case %q in the vector", name)
	return vectorNV{}
}

func newFixture(t *testing.T) *renderFixture {
	v := loadVector(t)
	f := &renderFixture{vector: v, writes: map[string][]byte{}, devices: map[string]bool{"/dev/disk/by-partuuid/" + testUUID: true}}
	f.files = map[string][]byte{
		loaderDevicePartUUID:  efivar(strings.ToUpper(testUUID)), // the firmware writes it in upper case
		"/root-key.json":      membership.Canonical(v["root_public"]),
		"/creds/regalia.site": siteFor("n1"),
		"ESP/" + chainOnESP:   chainBytes(v, "main", 3),
	}
	f.tpm = tpmCase(t, v, "anchored at 3, the chain at 3")
	return f
}

func (f *renderFixture) env() renderEnv {
	return renderEnv{
		readFile: func(path string) ([]byte, error) {
			if f.mounted != "" && strings.HasPrefix(path, f.mounted+"/") {
				path = "ESP/" + strings.TrimPrefix(path, f.mounted+"/")
			} else if strings.HasPrefix(path, "ESP/") {
				return nil, errors.New("not mounted")
			}
			if body, ok := f.files[path]; ok {
				return body, nil
			}
			return nil, os.ErrNotExist
		},
		exists: func(path string) bool { return f.devices[path] },
		mount: func(device, dir string) error {
			if !f.devices[device] || f.files["mount-fails"] != nil {
				return errors.New("no such device")
			}
			f.mounted, f.mounts = dir, f.mounts+1
			return nil
		},
		unmount: func(dir string) error {
			f.mounted, f.mounts = "", f.mounts-1
			if f.unmountFails {
				return errors.New("device busy")
			}
			return nil
		},
		mkdtemp: func() (string, error) { return "/run/esp-test", nil },
		nv: func() (membership.NV, func(), error) {
			if f.tpmFail {
				return nil, nil, errors.New("no TPM")
			}
			return f.tpm, func() {}, nil
		},
		sleep: func(d time.Duration) { f.slept += d },
		write: func(path string, data []byte) error {
			f.nWrites++
			if _, exists := f.writes[path]; exists {
				return os.ErrExist
			}
			if f.nWrites == f.failOn {
				f.writes[path] = data[:len(data)/2] // a write cut half-way
				return errors.New("no space left on device")
			}
			f.writes[path] = data
			return nil
		},
		rename: func(from, to string) error {
			data, ok := f.writes[from]
			if !ok {
				return os.ErrNotExist
			}
			delete(f.writes, from)
			f.writes[to] = data
			return nil
		},
		remove: func(path string) error { f.removed = append(f.removed, path); delete(f.writes, path); return nil },
		creds:  "/creds", rootKey: "/root-key.json", pcrKey: "/pcr.pem",
	}
}

// An anchor written under a policy (#242 B2a) renders only when that policy is PolicyAuthorize of the booting
// image's own PCR-signing key (.pcrpkey): the key is read through the same reader as everything else, and
// a key that is missing or another image's refuses, writing nothing.
func TestAPolicyWrittenAnchorIsReadWithTheImagesOwnKey(t *testing.T) {
	keys := map[string][]byte{}
	for _, n := range []string{"1", "2"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "pcr-keys", "system-"+n+".pub.pem"))
		if err != nil {
			t.Fatal(err)
		}
		keys[n] = raw
	}
	_, policy, err := membership.PCRKeyPolicy(keys["1"])
	if err != nil {
		t.Fatal(err)
	}
	fixture := func(key []byte) *renderFixture {
		f := newFixture(t)
		f.tpm = tpmCase(t, f.vector, "a policy-written anchor, this node's policy")
		for _, entry := range f.tpm.nv {
			if entry["policy"] != nil {
				entry["policy"] = hex.EncodeToString(policy) // written under image key 1's policy
			}
		}
		if key != nil {
			f.files["/pcr.pem"] = key
		}
		return f
	}
	f := fixture(keys["1"])
	if _, err := render("/run/regalia-boot", f.env()); err != nil || len(f.writes) == 0 {
		t.Errorf("the image's own key: %v, %d files", err, len(f.writes))
	}
	f = fixture(keys["2"])
	_, err = render("/run/regalia-boot", f.env())
	if err == nil || !strings.Contains(err.Error(), "is written by policy "+hex.EncodeToString(policy)+", not ") || len(f.writes) != 0 {
		t.Errorf("another image's key: %v, %d files", err, len(f.writes))
	}
	f = fixture(nil)
	_, err = render("/run/regalia-boot", f.env())
	var refused *membership.Refused
	if !errors.As(err, &refused) || !strings.Contains(err.Error(), "the image's PCR public key /pcr.pem cannot be read") || len(f.writes) != 0 {
		t.Errorf("no key: %#v, %d files", err, len(f.writes))
	}
}

func TestRenderWritesWhatBootcfgRendersFromTheAnchoredChain(t *testing.T) {
	f := newFixture(t)
	summary, err := render("/run/regalia-boot", f.env())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary, "n1 under manifest epoch 3 (TPM high-water 3)") {
		t.Errorf("summary: %s", summary)
	}
	site, _ := bootcfg.ReadSite(siteFor("n1"))
	var envelopes []any
	document, _ := membership.Load(chainBytes(f.vector, "main", 3), maxChainBytes)
	envelopes = document.([]any)
	manifests, _ := membership.ReadChain(envelopes, f.vector["root_public"])
	want, err := bootcfg.Render(manifests[2], site)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 4 {
		t.Fatalf("%d files written", len(f.writes))
	}
	for name, body := range want {
		if string(f.writes["/run/regalia-boot/"+name]) != string(body) {
			t.Errorf("%s is not bootcfg's", name)
		}
	}
	if f.mounts != 0 || f.mounted != "" {
		t.Errorf("the ESP was left mounted")
	}
	// the crash window (counter one ahead of the record) renders the chain at the counter's epoch
	f = newFixture(t)
	f.tpm = tpmCase(t, f.vector, "the crash window: counter at 4, record at 3, the chain at 4")
	f.files["ESP/"+chainOnESP] = chainBytes(f.vector, "main", 4)
	if _, err := render("/run/regalia-boot", f.env()); err != nil {
		t.Errorf("the crash window: %v", err)
	}
}

// Every way the render can fail ends it with a reason, writes nothing, and leaves nothing mounted.
func TestEveryFailureWritesNothingAndSaysWhy(t *testing.T) {
	cases := map[string]struct {
		change func(*renderFixture)
		reason string
	}{
		"a stale chain, validly signed": {func(f *renderFixture) {
			f.tpm = tpmCase(t, f.vector, "anchored at 5, the chain at 3: a restored disk")
		}, "ROLLBACK"},
		"a forked chain":             {func(f *renderFixture) { f.files["ESP/"+chainOnESP] = chainBytes(f.vector, "fork at 3", 3) }, "CONFLICT"},
		"no chain on the ESP":        {func(f *renderFixture) { delete(f.files, "ESP/"+chainOnESP) }, "the ESP holds no membership chain"},
		"a chain that is not JSON":   {func(f *renderFixture) { f.files["ESP/"+chainOnESP] = []byte("{") }, "not valid JSON"},
		"a chain that is not a list": {func(f *renderFixture) { f.files["ESP/"+chainOnESP] = []byte("{}") }, "not a list"},
		"a chain signed by another root": {func(f *renderFixture) {
			f.files["/root-key.json"] = []byte(`"` + strings.Repeat("ab", 32) + `"`)
		}, "not the pinned root"},
		"an oversized chain": {func(f *renderFixture) { f.files["ESP/"+chainOnESP] = make([]byte, maxChainBytes+1) }, "over"},
		"no root-key.json":   {func(f *renderFixture) { delete(f.files, "/root-key.json") }, "cannot be read"},
		"a root-key.json that is not canonical": {func(f *renderFixture) {
			f.files["/root-key.json"] = append(f.files["/root-key.json"], '\n')
		}, "canonical"},
		"no site document": {func(f *renderFixture) { delete(f.files, "/creds/regalia.site") }, "site document"},
		"a site document that is not canonical": {func(f *renderFixture) {
			f.files["/creds/regalia.site"] = append(f.files["/creds/regalia.site"], ' ')
		}, "canonical"},
		"a site for a node the manifest does not name": {func(f *renderFixture) { f.files["/creds/regalia.site"] = siteFor("n9") }, "not in the manifest"},
		"no LoaderDevicePartUUID":                      {func(f *renderFixture) { delete(f.files, loaderDevicePartUUID) }, "LoaderDevicePartUUID"},
		"a LoaderDevicePartUUID that is no UUID": {func(f *renderFixture) {
			f.files[loaderDevicePartUUID] = efivar("../../sda")
		}, "not a partition UUID"},
		"an ESP device that never appears": {func(f *renderFixture) { f.devices = map[string]bool{} }, "did not appear"},
		"an ESP that does not mount":       {func(f *renderFixture) { f.files["mount-fails"] = []byte{1} }, "cannot be mounted read-only"},
		"a TPM that does not open":         {func(f *renderFixture) { f.tpmFail = true }, "the TPM does not answer"},
		"an anchor that is gone":           {func(f *renderFixture) { f.tpm = tpmCase(t, f.vector, "the counter is gone") }, "not defined"},
		"a TPM that does not answer":       {func(f *renderFixture) { f.tpm = tpmCase(t, f.vector, "a TPM that does not answer") }, "does not answer"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c.change(f)
			_, err := render("/run/regalia-boot", f.env())
			if err == nil || !strings.Contains(err.Error(), c.reason) {
				t.Errorf("%v, not a refusal naming %q", err, c.reason)
			}
			if len(f.writes) != 0 {
				t.Errorf("%d files written", len(f.writes))
			}
			if f.mounts != 0 || f.mounted != "" {
				t.Errorf("the ESP was left mounted")
			}
		})
	}
	f := newFixture(t)
	f.devices = map[string]bool{}
	render("/run/regalia-boot", f.env())
	if f.slept < espWait {
		t.Errorf("gave up on the ESP after %s, not %s", f.slept, espWait)
	}
}

// runRender's one line, on the console, for a refusal; and its usage.
func TestRenderSaysOneLineAndRefusesBadArguments(t *testing.T) {
	var out, diag strings.Builder
	if err := runRender([]string{"-render"}, &out, &diag); err == nil {
		t.Error("no directory accepted")
	}
	if err := runRender([]string{"-render", "a", "b"}, &out, &diag); err == nil {
		t.Error("a stray argument accepted")
	}
	f := newFixture(t)
	delete(f.files, "ESP/"+chainOnESP)
	_, err := render("/x", f.env())
	line := fmt.Sprintf("regalia-unlock: the boot configuration cannot be rendered: %v; nothing is asked of a peer, and the console asks for the recovery key\n", err)
	if strings.Count(line, "\n") != 1 {
		t.Errorf("not one line: %q", line)
	}
}

// A write that fails at any of the four leaves the directory as it was: nothing under the real names, and no
// temporary left behind (d9's read of #299).
func TestAWriteThatFailsLeavesNoPartialSet(t *testing.T) {
	for n := 1; n <= 4; n++ {
		f := newFixture(t)
		f.failOn = n
		_, err := render("/run/regalia-boot", f.env())
		if err == nil || !strings.Contains(err.Error(), "no space left on device") {
			t.Errorf("write %d failing: %v", n, err)
		}
		if len(f.writes) != 0 {
			t.Errorf("write %d failing left %v", n, f.writes)
		}
	}
}

// The ESP's mount point is removed on every path, and an unmount that fails is reported without hiding why
// the read failed.
func TestTheMountIsUndoneAndAFailedUnmountIsReported(t *testing.T) {
	for name, change := range map[string]func(*renderFixture){
		"success":       func(*renderFixture) {},
		"no chain":      func(f *renderFixture) { delete(f.files, "ESP/"+chainOnESP) },
		"no mount":      func(f *renderFixture) { f.files["mount-fails"] = []byte{1} },
		"a stale chain": func(f *renderFixture) { f.tpm = tpmCase(t, f.vector, "anchored at 5, the chain at 3: a restored disk") },
		"unmount fails": func(f *renderFixture) { f.unmountFails = true },
	} {
		f := newFixture(t)
		change(f)
		render("/run/regalia-boot", f.env())
		removed := false
		for _, path := range f.removed {
			removed = removed || path == "/run/esp-test"
		}
		if !removed {
			t.Errorf("%s: the mount point was not removed", name)
		}
	}
	f := newFixture(t)
	f.unmountFails = true
	if _, err := render("/run/regalia-boot", f.env()); err == nil || !strings.Contains(err.Error(), "cannot be unmounted: device busy") || len(f.writes) != 0 {
		t.Errorf("a failed unmount: %v, %d files", err, len(f.writes))
	}
	f = newFixture(t)
	f.unmountFails = true
	delete(f.files, "ESP/"+chainOnESP)
	_, err := render("/run/regalia-boot", f.env())
	if err == nil || !strings.Contains(err.Error(), "holds no membership chain") || !strings.Contains(err.Error(), "cannot be unmounted") {
		t.Errorf("a failed read and a failed unmount: %v", err)
	}
}

// A chain more than advance()'s bound above the high-water is an anomaly: refused, nothing written. Too long
// a chain for the vector, so it is signed here with the vector's test root (private key bytes 0..31).
func TestAChainTooFarAboveTheAnchorIsRefused(t *testing.T) {
	f := newFixture(t)
	f.tpm = tpmCase(t, f.vector, "defined only (epoch 0, a zero digest), the chain at 1")
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed)
	template := f.vector["chains"].(map[string]any)["main"].([]any)[0].(map[string]any)["manifest"].(map[string]any)
	var envelopes []any
	prev := ""
	for epoch := 1; epoch <= 1001; epoch++ {
		manifest := map[string]any{}
		for k, v := range template {
			manifest[k] = v
		}
		manifest["epoch"], manifest["prev_digest"] = json.Number(strconv.Itoa(epoch)), prev
		sig := ed25519.Sign(key, append([]byte("regalia-membership/v1\x00"), membership.Canonical(manifest)...))
		envelopes = append(envelopes, map[string]any{"manifest": manifest,
			"signature": map[string]any{"signer": "root", "key": f.vector["root_public"], "sig": hex.EncodeToString(sig)}})
		prev = membership.Digest(manifest)
	}
	f.files["ESP/"+chainOnESP] = membership.Canonical(envelopes)
	_, err := render("/run/regalia-boot", f.env())
	if err == nil || !strings.Contains(err.Error(), "epoch jump 1001 exceeds the bound 1000") || len(f.writes) != 0 {
		t.Errorf("%v, %d files", err, len(f.writes))
	}
}

// A render killed in an earlier start (the timeout, the OOM killer) leaves temporaries in the preserved
// directory: the next start removes them and renders, rather than failing once per leftover (d9's read).
func TestTemporariesOfAKilledStartDoNotBlockTheNext(t *testing.T) {
	f := newFixture(t)
	f.writes["/run/regalia-boot/.regalia.boot-nft.render-new"] = []byte("half")
	f.writes["/run/regalia-boot/.regalia.unlock-config.render-new"] = []byte("half")
	if _, err := render("/run/regalia-boot", f.env()); err != nil {
		t.Fatalf("leftovers block the render: %v", err)
	}
	if len(f.writes) != 4 {
		t.Errorf("after the render: %v", f.writes)
	}
}
