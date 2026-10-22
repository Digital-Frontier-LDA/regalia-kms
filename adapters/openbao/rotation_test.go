package openbaopoc

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenBao271GenerationPromotionAndHistoricalSnapshot(t *testing.T) {
	binary, dir, plugin, sum := baoTestEnvironment(t)
	digest := hex.EncodeToString(sum[:])
	f := newKMSFixtureMode(t, true)
	address, cluster := freeAddress(t), freeAddress(t)
	config := baoConfig(t, dir, address, cluster, digest, f.pki.config)
	b := baoAPI{base: "http://" + address, client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}}
	p := startBao(t, binary, config, dir)
	b.wait(t, false, true, p)
	recoveryShare := b.initialize(t)
	b.seedSyntheticKV(t)
	oldSnapshot := b.must(t, http.MethodGet, "/v1/sys/storage/raft/snapshot", nil)
	defer clear(oldSnapshot)
	p.stop(t)

	// The exact old RSA key remains under g1. The registry only changes states;
	// the plugin's current generation and explicit history change independently.
	f.generations("retired", "active")
	current := cloneConfig(f.pki.config)
	current["key_version"], current["historical_key_versions"] = "g2", "g1"
	config = baoConfig(t, dir, address, cluster, digest, current)
	p = startBao(t, binary, config, dir)
	b.wait(t, true, false, p)
	b.assertValue(t)
	p.stop(t)

	// OpenBao's changed-KeyId upgrade must have persisted new stored/recovery
	// keys. A separate process with no permission to use g1 proves that result.
	currentOnly := cloneConfig(current)
	delete(currentOnly, "historical_key_versions")
	currentConfig := baoConfig(t, dir, address, cluster, digest, currentOnly)
	p = startBao(t, binary, currentConfig, dir)
	b.wait(t, true, false, p)
	b.assertValue(t)
	p.stop(t)

	// A pre-promotion snapshot still needs g1 even though live storage uses g2.
	f.pki.restoreConfig["key_version"], f.pki.restoreConfig["historical_key_versions"] = "g2", "g1"
	f.pki.strangerConfig["key_version"], f.pki.strangerConfig["historical_key_versions"] = "g2", "g1"
	bootstrapToken := b.restoreToFreshNode(t, binary, dir, plugin, digest, oldSnapshot, f)

	f.generations("revoked", "active")
	p = startBao(t, binary, currentConfig, dir)
	b.wait(t, true, false, p)
	b.assertValue(t)
	b.assertRecoveryAuthorization(t, recoveryShare)
	p.stop(t)

	// Restore with g1 still listed by the adapter, so the real KMS registry must
	// be the layer refusing it. The fresh target remains independently usable.
	f.pki.config = current
	denials := f.audit.outcomes("release-secret", "denied-kek-revoked")
	rejectedToken := b.rejectSnapshotRestore(t, binary, dir, plugin, digest, oldSnapshot, f)
	if f.audit.outcomes("release-secret", "denied-kek-revoked") <= denials {
		t.Fatal("revoked snapshot did not reach the actual registry revocation boundary")
	}
	assertBaoArtifactsClean(t, dir, filepath.Join(dir, "openbao-plugin-kms-regalia-poc"), b.token, bootstrapToken, rejectedToken, recoveryShare)
	t.Log("real OpenBao generation promotion, automatic stored/recovery key rewrap, restart without old generation, pre-promotion snapshot restore and revoked snapshot refusal passed")
}

func (b baoAPI) assertRecoveryAuthorization(t *testing.T, share string) {
	t.Helper()
	// On a process configured for g2 only, and with g1 revoked, verifying the
	// original recovery share requires the recovery key to have been rewrapped.
	data := b.must(t, http.MethodPost, "/v1/sys/generate-root-token/attempt", map[string]any{})
	defer clear(data)
	var attempt struct {
		Data struct {
			Nonce string `json:"nonce"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &attempt) != nil || attempt.Data.Nonce == "" {
		t.Fatal("synthetic root-generation attempt returned no nonce")
	}
	result := b.must(t, http.MethodPost, "/v1/sys/generate-root-token/update", map[string]string{"key": share, "nonce": attempt.Data.Nonce})
	defer clear(result)
	var completed struct {
		Data struct {
			Complete bool `json:"complete"`
		} `json:"data"`
	}
	if json.Unmarshal(result, &completed) != nil || !completed.Data.Complete {
		t.Fatal("original recovery share did not authorize a root token after KEK promotion")
	}
	// The generated token remains encoded and is never published or used.
	t.Log("recovery-key authorization survived KEK promotion without access to the revoked predecessor")
}
