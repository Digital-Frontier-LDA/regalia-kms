package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRequiresPrivateLocalSocketAndHTTPSOrigin(t *testing.T) {
	valid := config{SocketPath: "/run/regalia-sops-kms/service.sock", KMSURL: "https://kms.internal:8443", ServerName: "kms.internal", CAPath: "/run/credentials/ca.pem", CertificatePath: "/run/credentials/cert.pem", PrivateKeyPath: "/run/credentials/key.pem", Timeout: "15s"}
	if _, err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	tests := []func(*config){
		func(c *config) { c.SocketPath = "relative.sock" },
		func(c *config) { c.KMSURL = "http://kms.internal" },
		func(c *config) { c.KMSURL = "https://user@kms.internal" },
		func(c *config) { c.KMSURL = "https://kms.internal/path" },
		func(c *config) { c.ServerName = "https://kms.internal" },
		func(c *config) { c.Timeout = "5m" },
	}
	for index, mutate := range tests {
		candidate := valid
		mutate(&candidate)
		if _, err := candidate.validate(); err == nil {
			t.Fatalf("unsafe config %d accepted", index)
		}
	}
}

func TestProtectedReaderRejectsWritableAndSymlinkedSecrets(t *testing.T) {
	directory := t.TempDir()
	secret := filepath.Join(directory, "identity.key")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if contents, err := readProtected(secret, 64, true); err != nil || string(contents) != "secret" {
		t.Fatalf("read = %q, %v", contents, err)
	}
	if err := os.Chmod(secret, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtected(secret, 64, true); err == nil {
		t.Fatal("group-readable identity key accepted")
	}
	if err := os.Chmod(secret, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.key")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtected(link, 64, true); err == nil {
		t.Fatal("symlinked identity key accepted")
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	value := `{"socket_path":"/run/sops.sock","kms_url":"https://kms.internal","server_name":"kms.internal","ca_path":"/run/ca","certificate_path":"/run/cert","private_key_path":"/run/key","timeout":"15s","pin":"forbidden"}`
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("unknown secret-bearing field accepted")
	}
}
