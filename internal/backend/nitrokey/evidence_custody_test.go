package nitrokey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const usableEvidence = `{"schema_version":1,"devices":[{"device_serial":"serial-1","verified_by":"custodian",
  "verified_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z",
  "firmware":"6.6","secure_messaging_established":true}]}`

// THE EVIDENCE FILE IS AN AUTHORIZATION, SO ITS CUSTODY IS PART OF THE CONTROL.
//
// This document is what lets the KMS operate a token at all: it asserts secure messaging is
// established when PKCS#11 offers no way to prove it. Reading it with os.ReadFile trusted whatever
// the path resolved to at that instant — a symlink into a writable directory, a FIFO, or a file
// any group member could rewrite. Each case below is a way to make the KMS believe an unproven
// channel was proven.
func TestSecureChannelEvidenceRejectsUntrustworthyFiles(t *testing.T) {
	directory := t.TempDir()
	now := func() time.Time { return time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC) }

	good := filepath.Join(directory, "evidence.json")
	if err := os.WriteFile(good, []byte(usableEvidence), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecureChannelEvidence(good, now); err != nil {
		t.Fatalf("well-guarded evidence was refused: %v", err)
	}

	// A symlink means the file that was inspected is not necessarily the file that is read.
	link := filepath.Join(directory, "evidence.link.json")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecureChannelEvidence(link, now); err == nil {
		t.Fatal("a symlinked evidence file was followed: the read target can be swapped after inspection")
	}

	// Group- or world-writable evidence can be rewritten by anyone in that set.
	loose := filepath.Join(directory, "loose.json")
	if err := os.WriteFile(loose, []byte(usableEvidence), 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod explicitly: the umask would otherwise strip the very bits under test, and the
	// assertion would pass against a file that was never actually world-writable.
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(loose); err != nil || info.Mode().Perm()&0o022 == 0 {
		t.Fatalf("test setup failed to create a world-writable file: mode=%v err=%v", info.Mode().Perm(), err)
	}
	if _, err := LoadSecureChannelEvidence(loose, now); err == nil {
		t.Fatal("world-writable evidence was accepted: any local user could assert secure messaging")
	}

	// A directory is not a document.
	if _, err := LoadSecureChannelEvidence(directory, now); err == nil {
		t.Fatal("a directory was accepted as secure-channel evidence")
	}
}

// A file holding two documents was read as though it held one. The second could say the opposite
// of the first — including for a device the first never mentioned — and nothing would report it.
func TestSecureChannelEvidenceRejectsASecondDocument(t *testing.T) {
	directory := t.TempDir()
	now := func() time.Time { return time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC) }

	path := filepath.Join(directory, "two.json")
	shadow := strings.Replace(usableEvidence, "serial-1", "serial-2", 1)
	if err := os.WriteFile(path, []byte(usableEvidence+"\n"+shadow), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecureChannelEvidence(path, now); err == nil {
		t.Fatal("a file carrying two evidence documents was accepted: only the first was ever read")
	}

	trailing := filepath.Join(directory, "trailing.json")
	if err := os.WriteFile(trailing, []byte(usableEvidence+" not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecureChannelEvidence(trailing, now); err == nil {
		t.Fatal("trailing non-JSON content after the evidence document was ignored")
	}
}
