package opstate

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheSessionKeyPublishesItsPublicHalfOnly(t *testing.T) {
	const boot = "0123abcd-0000-4000-8000-0123456789ab"
	key, err := NewSessionKey(boot, 12345)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := key.Publish(dir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, SessionKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	var published map[string]any
	if err := json.Unmarshal(raw, &published); err != nil {
		t.Fatal(err)
	}
	if len(published) != 3 || published["boot_id"] != boot || published["daemon_started"] != float64(12345) || published["session_key"] != key.Hex() {
		t.Fatalf("published %v", published)
	}
	if strings.Contains(string(raw), strings.ToLower(string(key.private[:8]))) || len(key.Hex()) != 64 {
		t.Fatal("the file is not the public half alone")
	}
	if info, _ := os.Stat(filepath.Join(dir, SessionKeyFile)); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", info.Mode())
	}
	other, _ := NewSessionKey(boot, 12345)
	if other.Hex() == key.Hex() {
		t.Fatal("two starts made the same key")
	}
}

func TestASignatureIsBoundToItsDomain(t *testing.T) {
	key, _ := NewSessionKey("0123abcd-0000-4000-8000-0123456789ab", 1)
	sig, err := key.Sign("regalia-opstate-spend/v1\x00", []byte("entry"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key.Public, []byte("regalia-opstate-spend/v1\x00entry"), sig) {
		t.Fatal("the signature is not over domain ‖ message")
	}
	if ed25519.Verify(key.Public, []byte("regalia-opstate-hwm/v1\x00entry"), sig) {
		t.Fatal("a spend's signature verifies as a high-water mark's")
	}
	for _, bad := range []string{"", "no-nul"} {
		if _, err := key.Sign(bad, []byte("entry")); err == nil {
			t.Errorf("domain %q taken", bad)
		}
	}
	for _, bad := range []struct {
		boot    string
		started int64
	}{{"not-a-uuid", 1}, {"0123abcd-0000-4000-8000-0123456789ab", -1}} {
		if _, err := NewSessionKey(bad.boot, bad.started); err == nil {
			t.Errorf("%v taken", bad)
		}
	}
	if err := key.Publish("relative"); err == nil {
		t.Error("a relative directory was taken")
	}
}
