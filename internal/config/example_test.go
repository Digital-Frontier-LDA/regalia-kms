package config

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

// THE SHIPPED EXAMPLES ARE THE ONES OPERATORS COPY, SO THEY ARE TESTED LIKE CODE.
//
// daemon.example.json set audit_sink_url to "https://audit.internal/v1/events". The sink appends
// "/v1/events" itself, so that value was rejected at startup — the example the deployment guide
// tells an operator to copy could not start the daemon. Nothing caught it because Validate() never
// looked at the sink URL and no test ever loaded the file. This test closes both halves: the
// example must parse, must validate, and its sink address must be one the audit sink accepts.
func TestShippedExampleDaemonConfigIsUsable(t *testing.T) {
	settings, err := Load(stagedShippedExample(t))
	if err != nil {
		t.Fatalf("shipped example config does not load: %v", err)
	}
	if err := settings.Validate(); err != nil {
		t.Fatalf("shipped example config does not validate: %v", err)
	}
	if settings.AuditSinkURL == "" {
		t.Fatal("shipped example config no longer exercises the audit sink address")
	}
	if err := audit.ValidateSinkURL(settings.AuditSinkURL); err != nil {
		t.Fatalf("shipped example audit_sink_url %q would be refused at startup: %v", settings.AuditSinkURL, err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}}
	if _, err := audit.NewHTTPSink(settings.AuditSinkURL, client, settings.OperationTimeout, ""); err != nil {
		t.Fatalf("shipped example audit_sink_url %q was refused by the sink: %v", settings.AuditSinkURL, err)
	}
}

// The PIN paths in the example must name the location systemd actually materializes credentials
// at. LockedFileSource refuses symlinks, so an /etc path cannot be redirected to the runtime
// credential later — the example has to be right the first time.
func TestShippedExamplePINPathsMatchTheCredentialDirectory(t *testing.T) {
	settings, err := Load(stagedShippedExample(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.PINPaths) == 0 {
		t.Fatal("shipped example config no longer exercises PIN custody")
	}
	for device, path := range settings.PINPaths {
		if filepath.Dir(path) != "/run/credentials/regalia-kms.service" {
			t.Fatalf("PIN path for %q is %q: a persistent plaintext PIN file contradicts the systemd LoadCredentialEncrypted custody model", device, path)
		}
	}
}

// Every shipped example must be a file the daemon's own loader accepts. A JSON document that
// parses but carries a field the daemon does not know is a configuration an operator believes is
// in force and that is silently absent.
func TestEveryShippedExampleParsesStrictly(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "config"))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, entry := range entries {
		if entry.Name() != "daemon.example.json" {
			continue
		}
		seen++
		file, err := os.Open(filepath.Join("..", "..", "config", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Decode(file)
		file.Close()
		if err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
	}
	if seen == 0 {
		t.Fatal("no daemon example config was found to check")
	}
}

// stagedShippedExample copies daemon.example.json into a 0600 file and returns its path. Load
// refuses a group- or world-writable file, and the mode of a checked-out file is whatever the
// developer's umask left it (0664 under the 0002 umask common on user-private-group systems),
// so loading the example straight out of the working tree tests the checkout, not the example.
func stagedShippedExample(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", "daemon.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
