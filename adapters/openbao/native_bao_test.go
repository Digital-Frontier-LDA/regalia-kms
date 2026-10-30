package openbaopoc

import (
	"encoding/hex"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenBao271NativeGenerationPromotionAndRecovery(t *testing.T) {
	binary, dir, plugin, sum := baoTestEnvironmentFor(t, "openbao-plugin-kms-regalia")
	digest := hex.EncodeToString(sum[:])
	f := newKMSFixtureMode(t, true)
	f.pki.config = nativeFixtureConfig(f.pki.config)
	f.pki.restoreConfig = nativeFixtureConfig(f.pki.restoreConfig)
	f.pki.strangerConfig = nativeFixtureConfig(f.pki.strangerConfig)
	address, cluster := freeAddress(t), freeAddress(t)
	config := baoConfig(t, dir, address, cluster, digest, f.pki.config)
	b := baoAPI{base: "http://" + address, client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}}
	p := startBao(t, binary, config, dir)
	b.wait(t, false, true, p)
	share := b.initialize(t)
	b.seedSyntheticKV(t)
	oldSnapshot := b.must(t, http.MethodGet, "/v1/sys/storage/raft/snapshot", nil)
	defer clear(oldSnapshot)
	// Exercise the upstream periodic seal check through the native entrypoint.
	seals, releases := f.audit.successful("seal-envelope"), f.audit.successful("release-secret")
	deadline := time.Now().Add(10 * time.Second)
	for f.audit.successful("seal-envelope") <= seals || f.audit.successful("release-secret") <= releases {
		if time.Now().After(deadline) {
			t.Fatal("native periodic seal check did not perform both KMS operations")
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.stop(t)

	f.generations("retired", "active")
	// Exactly the same config. Startup Encrypt discovers g2 and OpenBao must
	// rewrap its stored/recovery keys using the server-produced KeyId.
	p = startBao(t, binary, config, dir)
	b.wait(t, true, false, p)
	b.assertValue(t)
	p.stop(t)
	bootstrap := b.restoreToFreshNode(t, binary, dir, plugin, digest, oldSnapshot, f)

	f.generations("revoked", "active")
	p = startBao(t, binary, config, dir)
	b.wait(t, true, false, p)
	b.assertValue(t)
	b.assertRecoveryAuthorization(t, share)
	p.stop(t)
	denials := f.audit.outcomes("release-secret", "denied-kek-revoked")
	rejected := b.rejectSnapshotRestore(t, binary, dir, plugin, digest, oldSnapshot, f)
	if f.audit.outcomes("release-secret", "denied-kek-revoked") <= denials {
		t.Fatal("native historical snapshot refusal did not reach KMS revocation")
	}
	assertBaoArtifactsClean(t, dir, filepath.Join(dir, "openbao-plugin-kms-regalia-poc"), b.token, bootstrap, rejected, share)
	t.Log("native seal initialization/health, automatic generation discovery/rewrap, independent-node restore, recovery authorization and revoked snapshot refusal passed")
}
