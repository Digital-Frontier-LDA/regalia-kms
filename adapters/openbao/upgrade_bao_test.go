package openbaopoc

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This is the earlier native-only plugin, before typed retries and External
// Keys. It shares the accepted envelope format, not the legacy outer frames.
const nativeUpgradeBaseline = "c16a52f8dd5abbecbc5a7497fb21fe3796526165"

func requireNativeELF(t *testing.T, name string) {
	t.Helper()
	f, err := elf.Open(name)
	if err != nil {
		t.Fatal("cannot inspect fixture executable")
	}
	defer f.Close()
	want := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[runtime.GOARCH]
	if want == elf.EM_NONE || f.Machine != want {
		t.Fatal("fixture executable does not match the test process architecture")
	}
}

func previousNativePlugin(t *testing.T) ([]byte, string) {
	t.Helper()
	name, expected := os.Getenv("OPENBAO_POC_PREVIOUS_PLUGIN"), os.Getenv("OPENBAO_POC_PREVIOUS_SHA256")
	if name == "" || expected == "" {
		if os.Getenv("OPENBAO_POC_REQUIRE_E2E") == "1" {
			t.Fatal("upgrade drill requires the checksum-bound previous native plugin")
		}
		t.Skip("set OPENBAO_POC_PREVIOUS_PLUGIN and OPENBAO_POC_PREVIOUS_SHA256 for the pinned native baseline")
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		t.Fatal("invalid previous plugin fixture")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal("cannot read previous plugin fixture")
	}
	digest := sha256.Sum256(data)
	actual := hex.EncodeToString(digest[:])
	if expected != actual {
		t.Fatal("previous plugin fixture checksum mismatch")
	}
	requireNativeELF(t, name)
	return data, actual
}

func installFixturePlugin(t *testing.T, name string, data []byte) {
	t.Helper()
	// Called only after the node stops. An atomic replacement avoids testing
	// accidental partial writes rather than catalog/checksum compatibility.
	staged := name + ".next"
	if err := os.WriteFile(staged, data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, name); err != nil {
		t.Fatal(err)
	}
}

func TestOpenBao271NativePluginUpgradeAndRollback(t *testing.T) {
	binary, dir, candidate, sum := baoTestEnvironmentFor(t, "openbao-plugin-kms-regalia")
	previous, previousDigest := previousNativePlugin(t)
	if bytes.Equal(previous, candidate) {
		t.Fatal("upgrade fixture requires genuinely distinct implementations")
	}
	pluginPath := filepath.Join(dir, "openbao-plugin-kms-regalia-poc")
	requireNativeELF(t, pluginPath)
	requireNativeELF(t, binary)
	digest := hex.EncodeToString(sum[:])
	f := newKMSFixtureMode(t, true)
	f.pki.config = nativeFixtureConfig(f.pki.config)
	f.pki.restoreConfig = nativeFixtureConfig(f.pki.restoreConfig)
	f.pki.strangerConfig = nativeFixtureConfig(f.pki.strangerConfig)
	address, cluster := freeAddress(t), freeAddress(t)
	oldConfig := baoConfigVersion(t, dir, address, cluster, previousDigest, "v0.0.1", f.pki.config)
	newConfig := baoConfigVersion(t, dir, address, cluster, digest, "v0.0.2", f.pki.config)
	b := baoAPI{base: "http://" + address, client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	installFixturePlugin(t, pluginPath, previous)
	p := startBao(t, binary, oldConfig, dir)
	b.wait(t, false, true, p)
	share := b.initialize(t)
	b.seedSyntheticKV(t)
	p.stop(t)

	// Promote before replacement. The new implementation must read the old
	// generation, discover g2 and rewrap stored/recovery keys on existing Raft.
	f.generations("retired", "active")
	installFixturePlugin(t, pluginPath, candidate)
	p = startBao(t, binary, newConfig, dir)
	b.wait(t, true, false, p)
	b.assertValue(t)
	writeHAValue(t, b, "after-upgrade")
	p.stop(t)

	// Successful rollback with g1 revoked proves the predecessor reads the
	// upgraded g2 seal state, rather than merely opening untouched g1 storage.
	f.generations("revoked", "active")
	installFixturePlugin(t, pluginPath, previous)
	p = startBao(t, binary, oldConfig, dir)
	b.wait(t, true, false, p)
	b.assertValue(t)
	assertHAValue(t, b, "after-upgrade")
	b.assertRecoveryAuthorization(t, share)
	writeHAValue(t, b, "after-rollback")
	p.stop(t)

	installFixturePlugin(t, pluginPath, candidate)
	p = startBao(t, binary, newConfig, dir)
	b.wait(t, true, false, p)
	b.assertValue(t)
	assertHAValue(t, b, "after-upgrade")
	assertHAValue(t, b, "after-rollback")
	snapshot := b.must(t, http.MethodGet, "/v1/sys/storage/raft/snapshot", nil)
	defer clear(snapshot)
	p.stop(t)
	bootstrap := b.restoreToFreshNode(t, binary, dir, candidate, digest, snapshot, f)

	// An incorrect checksum must refuse before invoking any KMS operation.
	invalid := baoConfigVersion(t, dir, address, cluster, strings.Repeat("0", 64), "v0.0.2", f.pki.config)
	seals, releases := f.audit.successful("seal-envelope"), f.audit.successful("release-secret")
	p = startBao(t, binary, invalid, dir)
	b.assertBlocked(t, p)
	if f.audit.successful("seal-envelope") != seals || f.audit.successful("release-secret") != releases {
		t.Fatal("checksum-refused plugin reached KMS")
	}
	p = startBao(t, binary, newConfig, dir)
	b.wait(t, true, false, p)
	b.assertValue(t)
	assertHAValue(t, b, "after-rollback")
	p.stop(t)
	assertBaoArtifactsClean(t, dir, pluginPath, b.token, bootstrap, share)
	t.Logf("native development revision %s -> current -> predecessor -> current preserved Raft and recovery authorization across g2 rewrap; independent normal snapshot restore and checksum refusal passed. Fixture catalog versions are not released versions.", nativeUpgradeBaseline[:12])
}
