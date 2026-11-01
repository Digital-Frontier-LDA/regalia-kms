package main

// #220: the commissioning record decides what the absence of the four state paths MEANS. The
// matrix is the test — fresh-with-record, uncommissioned-empty, history-without-provenance
// (one row per file kind), wrong-site record, unattributable record — because each refusal
// alone passes against a rule that refuses everything, and the unconfigured row keeps today's
// behaviour honest instead of silently becoming strict.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
)

// authorityKeyFor generates the commissioning authority's ed25519 pair, publishes the public
// half where the config points fencing_public_key_path, and returns the private half so tests
// can sign records the way the ceremony tool would.
func authorityKeyFor(t *testing.T, settings *config.Config) ed25519.PrivateKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(settings.FencingPublicKeyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings.FencingPublicKeyPath, []byte(base64.StdEncoding.EncodeToString(public)), 0o644); err != nil {
		t.Fatal(err)
	}
	return private
}

func provenanceSettings(t *testing.T) (config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	settings := completeSettings(t)
	settings.FencingStatePath = filepath.Join(dir, "epochs.jsonl")
	settings.AuditJournalPath = filepath.Join(dir, "audit.jsonl")
	settings.RevokedSerialsPath = filepath.Join(dir, "revoked.jsonl")
	settings.PolicyStatePath = filepath.Join(dir, "policy-state.jsonl")
	settings.CommissioningRecordPath = filepath.Join(dir, "commissioned.json")
	settings.FencingPublicKeyPath = filepath.Join(dir, "authority.pub")
	return settings, dir
}

func writeRecord(t *testing.T, path string, record commissioningRecord, key ed25519.PrivateKey) {
	t.Helper()
	payload := commissioningPayload(record)
	record.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func unsignedRecord(t *testing.T, path string, record commissioningRecord) {
	t.Helper()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

var recordBody = commissioningRecord{
	Site: "sitea", CommissionedAt: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
	DeploymentVersion: "regalia-kms 1.0.0", Nonce: "commission-2026-09-01-a1b2c3",
}

func TestProvenanceDecidesWhatAbsenceMeans(t *testing.T) {
	t.Run("a commissioned site with no history is fine", func(t *testing.T) {
		settings, _ := provenanceSettings(t)
		key := authorityKeyFor(t, &settings)
		writeRecord(t, settings.CommissioningRecordPath, recordBody, key)
		record, err := checkProvenance(settings)
		if err != nil || record == nil {
			t.Fatalf("a commissioned, never-used site was refused (err=%v) — absence WITH provenance is a legitimate state", err)
		}
	})
	t.Run("an uncommissioned host with no history refuses rather than passing as fresh", func(t *testing.T) {
		settings, _ := provenanceSettings(t)
		_, err := checkProvenance(settings) // no key file either: the refusal must stand on the record alone
		if err == nil || !strings.Contains(err.Error(), "COMMISSIONED") {
			t.Fatalf("a wiped host passed as a first boot (err=%v) — the record is the only thing that separates them", err)
		}
	})
	for name, pathOf := range map[string]func(config.Config) string{
		"fencing epochs":  func(s config.Config) string { return s.FencingStatePath },
		"policy state":    func(s config.Config) string { return s.PolicyStatePath },
		"audit journal":   func(s config.Config) string { return s.AuditJournalPath },
		"revocation list": func(s config.Config) string { return s.RevokedSerialsPath },
	} {
		t.Run("history without provenance refuses: "+name, func(t *testing.T) {
			settings, _ := provenanceSettings(t)
			if err := os.WriteFile(pathOf(settings), []byte("anything\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := checkProvenance(settings)
			if err == nil || !strings.Contains(err.Error(), "history without provenance") {
				t.Fatalf("%s exists with no commissioning record and was accepted (err=%v) — a host may not serve state it cannot account for", name, err)
			}
		})
	}
	t.Run("a record naming another site refuses", func(t *testing.T) {
		settings, _ := provenanceSettings(t)
		key := authorityKeyFor(t, &settings)
		foreign := recordBody
		foreign.Site = "siteb"
		writeRecord(t, settings.CommissioningRecordPath, foreign, key)
		if _, err := checkProvenance(settings); err == nil {
			t.Fatal("a siteb commissioning record vouched for a sitea host")
		}
	})
	t.Run("an unattributable record is not provenance", func(t *testing.T) {
		settings, _ := provenanceSettings(t)
		key := authorityKeyFor(t, &settings)
		nameless := recordBody
		nameless.Site = ""
		writeRecord(t, settings.CommissioningRecordPath, nameless, key)
		// The call was lost in an earlier edit and the row silently asserted nothing —
		// the exact failure mode the #221/#222 thread is about, arrived in a test written
		// to close it. Found by review; restored with the assertion the row always meant.
		if _, err := checkProvenance(settings); err == nil {
			t.Fatal("a record with no site or time passed as provenance — an unattributable record is a claim, not evidence")
		}
	})
	t.Run("an unsigned record the host could have written is not provenance", func(t *testing.T) {
		// Row 2/4 of the #220 measurement table, one layer up: anything the host can
		// author, a compromised host can forge after wiping. The signature is what makes
		// the record evidence rather than a claim.
		settings, _ := provenanceSettings(t)
		authorityKeyFor(t, &settings)
		unsignedRecord(t, settings.CommissioningRecordPath, recordBody)
		if _, err := checkProvenance(settings); err == nil {
			t.Fatal("an unsigned commissioning record passed — the host wrote its own provenance")
		}
	})
	t.Run("a record signed by the wrong key is not provenance", func(t *testing.T) {
		settings, _ := provenanceSettings(t)
		pinned := authorityKeyFor(t, &settings) // what the config trusts
		_ = pinned
		_, impostor, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		writeRecord(t, settings.CommissioningRecordPath, recordBody, impostor)
		if _, err := checkProvenance(settings); err == nil {
			t.Fatal("a record signed by a key other than the pinned authority passed")
		}
	})
	t.Run("unconfigured keeps today's behaviour and names the ambiguity", func(t *testing.T) {
		settings, _ := provenanceSettings(t)
		settings.AuditJournalPath = ""
		settings.CommissioningRecordPath = ""
		settings.FencingPublicKeyPath = ""
		settings.FencingStatePath = ""
		if record, err := checkProvenance(settings); err != nil || record != nil {
			t.Fatalf("an unconfigured host was checked anyway (err=%v) — strictness arrives with the deployment that configures it", err)
		}
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(report.Unchecked, "\n")
		if !strings.Contains(joined, "commissioning record") {
			t.Fatalf("preflight did not name the ambiguity it cannot resolve: %q", joined)
		}
	})
	t.Run("preflight no longer calls an absent journal fine without provenance", func(t *testing.T) {
		// The sentence this issue was filed over: "ok — the daemon will create it on first
		// start", printed at a host that may have LOST the journal. Without provenance the
		// note must carry the ambiguity, not the reassurance. (Asserted on the POLICY
		// journal's note: the audit path would drag the PKCS#11 quartet into Validate.)
		settings, _ := provenanceSettings(t)
		settings.AuditJournalPath = ""
		settings.CommissioningRecordPath = ""
		settings.FencingPublicKeyPath = ""
		settings.FencingStatePath = ""
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatal(err)
		}
		for _, checked := range report.Checked {
			if strings.Contains(checked, "will be created on first start") {
				t.Fatalf("the reassuring note survived: %q", checked)
			}
		}
		joined := strings.Join(report.Checked, "\n")
		if !strings.Contains(joined, "indistinguishable from losing it") {
			t.Fatalf("the absent journal is reported without its ambiguity: %q", joined)
		}
	})
	t.Run("with a record, an absent journal is reported as commissioned-and-unused", func(t *testing.T) {
		settings, _ := provenanceSettings(t)
		key := authorityKeyFor(t, &settings)
		settings.AuditJournalPath = ""
		settings.FencingLeasePath = filepath.Join(filepath.Dir(settings.CommissioningRecordPath), "lease.json")
		writeRecord(t, settings.CommissioningRecordPath, recordBody, key)
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(report.Checked, "\n")
		if !strings.Contains(joined, "commissioning record makes that a commissioned site") {
			t.Fatalf("provenance did not resolve the absence into its meaning: %q", joined)
		}
	})
}

// AS ROOT (regalia-sp1). The test below skips as root, which reads a directory whatever its mode. A stat error
// root still gets is ENOTDIR: a state path under a regular file. It must refuse the same way, not read as absent.
// CI's privileged-and-fuzz job runs this under sudo with REGALIA_EXPECT_ROOT_TESTS=1, which makes a skip a failure.
func TestAsRootAStatePathThatCannotBeStatedIsNotAnAbsentOne(t *testing.T) {
	if os.Getenv("REGALIA_EXPECT_ROOT_TESTS") == "1" && os.Geteuid() != 0 {
		t.Fatalf("REGALIA_EXPECT_ROOT_TESTS=1 and euid %d: the as-root half this run was meant to reach was not reached", os.Geteuid())
	}
	if os.Geteuid() != 0 {
		t.Skip("the as-root half: as any other user the mode-000 test below covers this branch")
	}
	settings, _ := provenanceSettings(t)
	notADirectory := filepath.Join(filepath.Dir(settings.CommissioningRecordPath), "state")
	if err := os.WriteFile(notADirectory, []byte("a file, not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings.FencingStatePath = filepath.Join(notADirectory, "epochs.jsonl")
	_, err := checkProvenance(settings)
	if err == nil || !strings.Contains(err.Error(), "cannot tell whether "+settings.FencingStatePath+" exists") ||
		!strings.Contains(err.Error(), "not a directory") || !strings.Contains(err.Error(), "unreadable state path") {
		t.Fatalf("a state path root cannot stat read as absent (err=%v) — unaccountable must not report as uncommissioned", err)
	}
}

// A SYMBOLIC LINK AT A STATE PATH (regalia-ibh, found by regalia-c6 on #648). os.Stat follows the last link, so a
// dangling one read as absent and an unaccountable host as a fresh one. A dangling link is "cannot tell", by name; a
// live link to a file is state that exists; a linked parent directory resolves as it always has. None needs root or
// mode bits, so this runs as any user.
func TestASymbolicLinkAtAStatePathIsNeverAbsence(t *testing.T) {
	t.Run("a dangling link cannot be told from state", func(t *testing.T) {
		settings, dir := provenanceSettings(t)
		if err := os.Symlink(filepath.Join(dir, "gone"), settings.FencingStatePath); err != nil {
			t.Fatal(err)
		}
		_, err := checkProvenance(settings)
		want := "cannot tell whether " + settings.FencingStatePath + " exists: it is a symbolic link whose target is missing"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("a dangling link at a state path read as absent (err=%v)", err)
		}
	})
	t.Run("an Lstat that fails otherwise after Stat's ENOENT is not absence", func(t *testing.T) {
		// Reachable on disk only through a race, so the seam stands in for it. Not parallel:
		// lstat is package state.
		settings, _ := provenanceSettings(t)
		// the arm under test is Stat's ENOENT one, not the default stat-error one
		if _, err := os.Stat(settings.FencingStatePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("precondition: Stat must find %s absent (err=%v)", settings.FencingStatePath, err)
		}
		t.Cleanup(func() { lstat = os.Lstat })
		lstat = func(p string) (os.FileInfo, error) {
			if p != settings.FencingStatePath {
				return os.Lstat(p)
			}
			return nil, &os.PathError{Op: "lstat", Path: p, Err: syscall.EACCES}
		}
		_, err := checkProvenance(settings)
		want := "cannot tell whether " + settings.FencingStatePath + " exists: lstat " + settings.FencingStatePath + ": permission denied — a state path that cannot be ruled out is not an absent one"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("an Lstat EACCES after Stat's ENOENT read as absent (err=%v)", err)
		}
	})
	t.Run("a live link to a file is state that exists", func(t *testing.T) {
		settings, dir := provenanceSettings(t)
		target := filepath.Join(dir, "elsewhere.jsonl")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, settings.FencingStatePath); err != nil {
			t.Fatal(err)
		}
		_, err := checkProvenance(settings)
		want := "is absent but state exists (" + settings.FencingStatePath + ")"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("a live link to a state file did not count as existing state (err=%v)", err)
		}
	})
	t.Run("a linked parent directory resolves as before", func(t *testing.T) {
		settings, dir := provenanceSettings(t)
		realDir := filepath.Join(dir, "real")
		if err := os.Mkdir(realDir, 0o755); err != nil {
			t.Fatal(err)
		}
		linked := filepath.Join(dir, "linked")
		if err := os.Symlink(realDir, linked); err != nil {
			t.Fatal(err)
		}
		settings.FencingStatePath = filepath.Join(linked, "epochs.jsonl")
		// absent through the linked parent: the fresh-host reading
		if _, err := checkProvenance(settings); err == nil || !strings.Contains(err.Error(), "is absent and no state exists") {
			t.Fatalf("an absent file under a linked directory did not read as absent (err=%v)", err)
		}
		// present through the linked parent: existing state
		if err := os.WriteFile(filepath.Join(realDir, "epochs.jsonl"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := checkProvenance(settings); err == nil || !strings.Contains(err.Error(), "is absent but state exists ("+settings.FencingStatePath+")") {
			t.Fatalf("a file under a linked directory did not count as existing state (err=%v)", err)
		}
	})
}

func TestAnUnreadableStatePathIsNotAnAbsentOne(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory whatever its mode: no state path is unreadable to it")
	}
	// Third instance of the stat-error class, and the one that is directly constructible:
	// the provenance loop stats state paths but never reads them, so an unreadable directory
	// reaches the probe. Before the fix it counted as absent and an unaccountable host was
	// reported as merely uncommissioned — the milder refusal, in the wrong direction.
	settings, _ := provenanceSettings(t)
	// The state path gets its OWN subdirectory: the commissioning record lives in the main
	// temp dir, and chmodding that makes the RECORD unreadable first — a refusal, but by
	// the wrong detector, which proves nothing about this branch.
	stateDir := filepath.Join(filepath.Dir(settings.CommissioningRecordPath), "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settings.FencingStatePath = filepath.Join(stateDir, "epochs.jsonl")
	if err := os.WriteFile(settings.FencingStatePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(stateDir, 0o755)
	_, err := checkProvenance(settings)
	if err == nil || !strings.Contains(err.Error(), "unreadable state path") {
		t.Fatalf("an unreadable state path read as absent (err=%v) — unaccountable must not report as uncommissioned", err)
	}
}
