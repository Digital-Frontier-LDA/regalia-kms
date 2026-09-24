package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// RestoredFile is one file Restore wrote, or one entry it deliberately did not.
type RestoredFile struct {
	Label  string
	Path   string // where it was written (root-joined); empty when nothing was written
	SHA256 string
	Note   string
}

// Restore places a VERIFIED export's journals at their recorded paths under root, the missing step
// of #49's carry-out-and-restore procedure. The procedure said the exported journals "are placed at
// their configured paths", and nothing placed them: an operator had the verified envelope and no
// tool to write its contents, so the step left for hand-editing was the one that loses history.
//
// The export must come from InspectForSite: this function writes only what was verified. The rules,
// each one the difference between a restored site and a quietly wrong one:
//
//   - ALL OR NOTHING, AND NEVER OVER EXISTING STATE. Every target must be absent before the first
//     byte is written. A restore over a running site's journals would splice two histories, and a
//     half-finished one is a site that believes it has history it lacks.
//   - A JOURNAL TRAVELS WITH ITS MARK. The audit journal with its high-water mark, the policy state
//     with its mark: both or neither. A journal restored without its mark has truncation detection
//     disabled and reports intact (RUNBOOK-DISASTER-RECOVERY).
//   - Written 0600 in 0700 directories, synced, and re-read: each file's digest must equal the
//     export's before Restore reports it.
//   - The deployment version is REPORTED, never written. The deployed tree comes from the reviewed
//     repository, not from a recovery point.
//
// root is the directory the guest's absolute paths are placed under: "/" on the rebuilt guest
// itself, a scratch directory in a drill.
func Restore(export *Export, root string) ([]RestoredFile, error) {
	if export == nil {
		return nil, errors.New("controlplane: nothing to restore")
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("controlplane: restore root %q must be absolute", root)
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("controlplane: restore root %q is not a directory", root)
	}
	for _, pair := range [][2]Entry{{export.AuditJournal, export.AuditHighWater}, {export.PolicyState, export.PolicyMark}} {
		if pair[0].Absent != pair[1].Absent {
			return nil, fmt.Errorf("controlplane: %s and its mark must be restored together, and the export carries only one", pair[0].Path)
		}
	}

	type target struct {
		label string
		entry Entry
		path  string
	}
	var targets []target
	var report []RestoredFile
	for _, named := range exportEntries(export) {
		switch {
		case named.label == "deployment version":
			note := "not written: the deployed tree comes from the reviewed repository"
			if !named.entry.Absent {
				note = fmt.Sprintf("recorded %q; %s", string(named.entry.Data), note)
			}
			report = append(report, RestoredFile{Label: named.label, Note: note})
		case named.entry.Absent:
			report = append(report, RestoredFile{Label: named.label, Note: "absent in the export: the site had not created it"})
		default:
			if err := validateEntryPath(named.entry.Path); err != nil {
				return nil, err
			}
			targets = append(targets, target{named.label, named.entry, filepath.Join(root, named.entry.Path)})
		}
	}
	// Every target absent BEFORE anything is written.
	for _, t := range targets {
		if _, err := os.Lstat(t.path); err == nil {
			return nil, fmt.Errorf("controlplane: %s already exists at %s — a restore never writes over existing state", t.label, t.path)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("controlplane: cannot check %s: %w", t.path, err)
		}
	}
	for _, t := range targets {
		if err := os.MkdirAll(filepath.Dir(t.path), 0o700); err != nil {
			return nil, fmt.Errorf("controlplane: create the directory for %s: %w", t.label, err)
		}
		if err := writeExclusive(t.path, t.entry.Data); err != nil {
			return nil, fmt.Errorf("controlplane: write %s: %w", t.label, err)
		}
		written, err := os.ReadFile(t.path)
		if err != nil {
			return nil, fmt.Errorf("controlplane: re-read %s: %w", t.label, err)
		}
		sum := sha256.Sum256(written)
		if hex.EncodeToString(sum[:]) != t.entry.SHA256 {
			return nil, fmt.Errorf("controlplane: %s at %s does not read back as the exported bytes", t.label, t.path)
		}
		report = append(report, RestoredFile{Label: t.label, Path: t.path, SHA256: t.entry.SHA256})
	}
	return report, nil
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
