package openbaopoc

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The source process is stopped before this drill. Only the encrypted snapshot,
// plugin executable and independently issued KMS credentials reach the new node.
func (source baoAPI) restoreToFreshNode(t *testing.T, binary, parent string, plugin []byte, digest string, snapshot []byte, f *kmsFixture) string {
	t.Helper()
	dir := filepath.Join(parent, "restore")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openbao-plugin-kms-regalia-poc"), plugin, 0o700); err != nil {
		t.Fatal(err)
	}
	address, cluster := freeAddress(t), freeAddress(t)
	config := baoConfig(t, dir, address, cluster, digest, f.pki.restoreConfig)
	restored := baoAPI{base: "http://" + address, client: source.client}
	p := startBao(t, binary, config, dir)
	restored.wait(t, false, true, p)
	restored.initialize(t)
	bootstrapToken := restored.token
	status, _, err := restored.call(http.MethodGet, "/v1/poc/data/secret", nil)
	if err != nil || status != http.StatusNotFound {
		t.Fatal("fresh node unexpectedly has the source mount")
	}
	status, _, err = restored.callBody(http.MethodPost, "/v1/sys/storage/raft/snapshot", bytes.NewReader(snapshot), "application/octet-stream")
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("normal snapshot restore failed (status %d); response omitted", status)
	}
	// Restore is asynchronous; wait for a read authorized by the source token,
	// rather than accepting an HTTP success or the target's pre-restore health.
	restored.token = source.token
	deadline := time.Now().Add(30 * time.Second)
	for {
		status, _, err := restored.call(http.MethodGet, "/v1/poc/data/secret", nil)
		if err == nil && status == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restored data did not become readable with the source identity")
		}
		time.Sleep(100 * time.Millisecond)
	}
	restored.assertValue(t)
	bootstrap := restored
	bootstrap.token = bootstrapToken
	status, _, err = bootstrap.call(http.MethodGet, "/v1/poc/data/secret", nil)
	if err != nil || status != http.StatusForbidden {
		t.Fatal("fresh initialization token survived snapshot replacement")
	}
	p.stop(t)
	p = startBao(t, binary, config, dir)
	restored.wait(t, true, false, p)
	restored.assertValue(t)
	p.stop(t)
	// The restored state must still enforce Regalia's authorization boundary.
	denials := f.audit.deniedUnwraps()
	unauthorized := baoConfig(t, dir, address, cluster, digest, f.pki.strangerConfig)
	p = startBao(t, binary, unauthorized, dir)
	restored.assertBlocked(t, p)
	if f.audit.deniedUnwraps() <= denials {
		t.Fatal("restored-node identity refusal did not reach Regalia authorization")
	}
	p = startBao(t, binary, config, dir)
	restored.wait(t, true, false, p)
	restored.assertValue(t)
	p.stop(t)
	t.Log("fresh-node normal Raft restore, independent mTLS credential, source token/data replacement and restart passed")
	return bootstrapToken
}

// A matching logical object ID cannot compensate for missing original key
// material. This fixture has a different RSA key, and no access to the source key.
func (source baoAPI) rejectWrongKeyRestore(t *testing.T, binary, parent string, plugin []byte, digest string, snapshot []byte) string {
	t.Helper()
	f := newKMSFixture(t)
	dir := filepath.Join(parent, "wrong-key")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openbao-plugin-kms-regalia-poc"), plugin, 0o700); err != nil {
		t.Fatal(err)
	}
	address, cluster := freeAddress(t), freeAddress(t)
	config := baoConfig(t, dir, address, cluster, digest, f.pki.config)
	target := baoAPI{base: "http://" + address, client: source.client}
	p := startBao(t, binary, config, dir)
	target.wait(t, false, true, p)
	target.initialize(t)
	status, data, err := target.callBody(http.MethodPost, "/v1/sys/storage/raft/snapshot", bytes.NewReader(snapshot), "application/octet-stream")
	if err != nil || status != http.StatusBadRequest || !bytes.Contains(data, []byte("snapshot is using a different autoseal key")) {
		t.Fatalf("wrong-key restore did not fail seal verification (status %d); response omitted", status)
	}
	clear(data)
	// The rejected snapshot must leave the target's original state intact.
	target.must(t, http.MethodGet, "/v1/sys/mounts", nil)
	status, _, err = target.call(http.MethodGet, "/v1/poc/data/secret", nil)
	if err != nil || status != http.StatusNotFound {
		t.Fatal("wrong-key target exposed the source mount")
	}
	sourceToken := target
	sourceToken.token = source.token
	status, _, err = sourceToken.call(http.MethodGet, "/v1/sys/mounts", nil)
	if err != nil || status != http.StatusForbidden {
		t.Fatal("wrong-key target accepted the source token")
	}
	p.stop(t)
	p = startBao(t, binary, config, dir)
	target.wait(t, true, false, p)
	target.must(t, http.MethodGet, "/v1/sys/mounts", nil)
	p.stop(t)
	t.Log("normal restore rejected absent original RSA material despite matching logical key ID; target state and restart survived")
	return target.token
}
