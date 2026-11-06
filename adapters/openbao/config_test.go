package openbaopoc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestConfigurationBoundary(t *testing.T) {
	pki := newFixturePKI(t)
	ctx := context.Background()
	w := New()
	if _, err := w.SetConfig(ctx, wrapping.WithConfigMap(pki.config)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.SetConfig(ctx, wrapping.WithConfigMap(pki.config)); err == nil {
		t.Fatal("reconfiguration accepted")
	}
	for _, tc := range []struct{ field, value string }{
		{"kms_url", "http://127.0.0.1:1"}, {"kms_url", "https://user:secret@localhost"}, {"kms_url", "https://localhost/path"},
		{"environment", "production"}, {"environment", "staging"}, {"kms_purpose", "invalid/purpose"}, {"repository", "invalid"},
		{"path", "../outside"}, {"path", "/absolute"}, {"path", "a/../b"}, {"path", strings.Repeat("a", 191)},
		{"timeout", "0s"}, {"timeout", "2m"}, {"timeout", "junk"}, {"object_id", ""}, {"unknown", "secret"},
		{"ca_path", "/missing/private/path"}, {"server_name", "https://wrong"},
	} {
		t.Run(tc.field+"="+tc.value, func(t *testing.T) {
			c := cloneConfig(pki.config)
			c[tc.field] = tc.value
			if _, err := New().SetConfig(ctx, wrapping.WithConfigMap(c)); err != errConfig {
				t.Fatalf("invalid configuration accepted or leaked: %v", err)
			}
		})
	}
	t.Setenv("REGALIA_KMS_URL", pki.config["kms_url"])
	if _, err := New().SetConfig(ctx, wrapping.WithDisallowEnvVars(true)); err == nil {
		t.Fatal("ambient credentials/config discovered")
	}
}

func TestPrivateKeyFileCannotBeSharedOrSymlinked(t *testing.T) {
	pki := newFixturePKI(t)
	file := pki.config["private_key_path"]
	if err := os.Chmod(file, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := New().SetConfig(context.Background(), wrapping.WithConfigMap(pki.config)); err == nil {
		t.Fatal("shared key accepted")
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "identity-link.pem")
	if err := os.Symlink(file, symlink); err != nil {
		t.Fatal(err)
	}
	c := cloneConfig(pki.config)
	c["private_key_path"] = symlink
	if _, err := New().SetConfig(context.Background(), wrapping.WithConfigMap(c)); err == nil {
		t.Fatal("symlinked key accepted")
	}
}
