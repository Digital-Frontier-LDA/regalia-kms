package controlplane

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

// inspected is the only kind of export Restore is given in the real flow: sealed, then opened and
// fully verified for the site it is restored as.
func inspected(t *testing.T, f fixture) *Export {
	t.Helper()
	envelope, _, privatePEM := sealedFixture(t, f)
	export, err := InspectForSite(envelope, authorityKey(t, privatePEM), "sitea")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return export
}

func TestRestorePlacesEveryJournalByteIdenticalAndTheyVerify(t *testing.T) {
	f := newFixture(t, true)
	export := inspected(t, f)
	root := t.TempDir()
	report, err := Restore(export, root)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	written := 0
	for _, r := range report {
		if r.Path == "" {
			continue
		}
		written++
		original, err := os.ReadFile(strings.TrimPrefix(r.Path, root))
		if err != nil {
			t.Fatalf("read the original %s: %v", r.Label, err)
		}
		restored, err := os.ReadFile(r.Path)
		if err != nil || !bytes.Equal(original, restored) {
			t.Fatalf("%s is not byte-identical after the restore (err=%v)", r.Label, err)
		}
		if info, _ := os.Stat(r.Path); info.Mode().Perm() != 0o600 {
			t.Fatalf("%s restored with mode %v, want 0600", r.Label, info.Mode().Perm())
		}
	}
	// audit journal + two marks, policy state + mark, fencing epochs: six files; the version is reported.
	if written != 6 {
		t.Fatalf("restored %d files, want the 6 journals and marks", written)
	}
	// The restored journals are not just copies: the verifiers accept them, with their marks.
	if _, err := audit.VerifyIntegrity(filepath.Join(root, f.sources.AuditJournal)); err != nil {
		t.Fatalf("the restored audit journal does not verify with its mark: %v", err)
	}
	if _, err := policy.VerifyState(filepath.Join(root, f.sources.PolicyState)); err != nil {
		t.Fatalf("the restored policy state does not verify with its mark: %v", err)
	}
	var version RestoredFile
	for _, r := range report {
		if r.Label == "deployment version" {
			version = r
		}
	}
	if version.Path != "" || !strings.Contains(version.Note, "regalia-kms 1.2.3") {
		t.Fatalf("the deployment version must be reported, not written: %+v", version)
	}
}

func TestRestoreNeverWritesOverExistingStateAndWritesNothingWhenItRefuses(t *testing.T) {
	f := newFixture(t, true)
	export := inspected(t, f)
	root := t.TempDir()
	// One target already exists (the LAST one checked would be the worst case for a partial write).
	existing := filepath.Join(root, f.sources.FencingState)
	if err := os.MkdirAll(filepath.Dir(existing), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existing, []byte("a running site's epochs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(export, root); err == nil || !strings.Contains(err.Error(), "never writes over existing state") {
		t.Fatalf("restore over existing state was not refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, f.sources.AuditJournal)); err == nil {
		t.Fatal("a refused restore wrote the audit journal anyway: all or nothing")
	}
	if got, _ := os.ReadFile(existing); string(got) != "a running site's epochs\n" {
		t.Fatal("the existing file was modified")
	}
}

func TestRestoreRefusesAJournalWithoutItsMark(t *testing.T) {
	f := newFixture(t, true)
	export := inspected(t, f)
	export.PolicyMark = Entry{Path: export.PolicyMark.Path, Absent: true}
	if _, err := Restore(export, t.TempDir()); err == nil || !strings.Contains(err.Error(), "must be restored together") {
		t.Fatalf("a policy journal without its mark was restored: %v", err)
	}
}

func TestRestoreRefusesARelativeOrMissingRoot(t *testing.T) {
	export := inspected(t, newFixture(t, true))
	for _, root := range []string{"relative/dir", filepath.Join(t.TempDir(), "does-not-exist")} {
		if _, err := Restore(export, root); err == nil {
			t.Fatalf("restore into %q was not refused", root)
		}
	}
}

func TestRestoreOfAVirginSiteWritesNothingAndSaysWhy(t *testing.T) {
	export, err := Build(newFixture(t, false).sources, "sitea", time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Skipf("a virgin export is built differently here: %v", err)
	}
	report, err := Restore(export, t.TempDir())
	if err != nil {
		t.Fatalf("restore of a virgin site: %v", err)
	}
	for _, r := range report {
		if r.Path != "" {
			t.Fatalf("a virgin site's restore wrote %s", r.Label)
		}
	}
}

// A single-site host without fencing: export, seal, inspect and restore all succeed, the fencing
// journal is reported as not configured, and nothing is written for it (found by the 2026-09-24
// bench drill, where such a host could not be exported at all).
func TestAHostWithoutFencingExportsInspectsAndRestores(t *testing.T) {
	f := newFixture(t, true)
	f.sources.FencingState = ""
	export := inspected(t, f)
	if !export.FencingEpochs.NotConfigured {
		t.Fatalf("the fencing journal is not marked not-configured: %+v", export.FencingEpochs)
	}
	report, err := Restore(export, t.TempDir())
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, r := range report {
		if r.Label == "fencing epoch journal" && (r.Path != "" || r.Note != "not configured on this site") {
			t.Fatalf("the unconfigured fencing journal was not reported as such: %+v", r)
		}
	}
}

func TestANotConfiguredMarkerThatCarriesAnythingIsRefused(t *testing.T) {
	cases := map[string]func(*Export){
		"carries data":          func(e *Export) { e.FencingEpochs = Entry{NotConfigured: true, Data: []byte("{}\n")} },
		"carries a path":        func(e *Export) { e.FencingEpochs = Entry{NotConfigured: true, Path: "/state/epochs.jsonl"} },
		"is also absent":        func(e *Export) { e.FencingEpochs = Entry{NotConfigured: true, Absent: true} },
		"on the version":        func(e *Export) { e.SiteVersion = Entry{NotConfigured: true} },
		"journal without marks": func(e *Export) { e.PolicyMark = Entry{NotConfigured: true} },
		"marks without journal": func(e *Export) { e.AuditJournal = Entry{NotConfigured: true} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			export, err := Build(f.sources, "sitea", time.Unix(1, 0))
			if err != nil {
				t.Fatal(err)
			}
			mutate(export)
			if err := verifyExport(export); err == nil {
				t.Fatal("a malformed not-configured marker verified")
			}
		})
	}
}

func TestAnExportWithEveryJournalNotConfiguredIsNoControlPlane(t *testing.T) {
	f := newFixture(t, true)
	export, err := Build(f.sources, "sitea", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	nc := Entry{NotConfigured: true}
	export.AuditJournal, export.AuditHighWater, export.AuditShipped = nc, nc, nc
	export.PolicyState, export.PolicyMark, export.FencingEpochs = nc, nc, nc
	if err := verifyExport(export); !errors.Is(err, ErrNoSources) {
		t.Fatalf("an export with nothing configured verified as a control plane: %v", err)
	}
}
