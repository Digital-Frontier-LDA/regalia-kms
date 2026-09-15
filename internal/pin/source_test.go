package pin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLockedFileSourceReadsStrictCredentialAndReleasesIt(t *testing.T) {
	directory := t.TempDir()
	path := writeCredential(t, directory, "hsm.pin", "123456", 0o400)
	source, err := NewLockedFileSource(map[string]string{"hsm-sitea": path})
	if err != nil {
		t.Fatal(err)
	}
	value, err := source.PIN(context.Background(), "hsm-sitea")
	if err != nil || string(value) != "123456" {
		t.Fatalf("PIN length=%d err=%v", len(value), err)
	}
	if err := source.Release(value); err != nil {
		t.Fatal(err)
	}
	for _, item := range value {
		if item != 0 {
			t.Fatal("released credential was not zeroed")
		}
	}
}

func TestLockedFileSourceRejectsUnknownLooseSymlinkedAndMalformedCredentials(t *testing.T) {
	directory := t.TempDir()
	good := writeCredential(t, directory, "good.pin", "123456", 0o400)
	// 0644 is the one mode here a umask can strip. writeCredential chmods and then asserts the
	// bits actually landed, so this row cannot quietly become a second 0600 file that the guard
	// correctly accepts.
	loose := writeCredential(t, directory, "loose.pin", "123456", 0o644)
	symlink := filepath.Join(directory, "link.pin")
	if err := os.Symlink(good, symlink); err != nil {
		t.Fatal(err)
	}
	newline := writeCredential(t, directory, "newline.pin", "123456\n", 0o400)
	source, err := NewLockedFileSource(map[string]string{"good": good, "loose": loose, "link": symlink, "newline": newline})
	if err != nil {
		t.Fatal(err)
	}
	for _, deviceID := range []string{"unknown", "loose", "link", "newline"} {
		if value, err := source.PIN(context.Background(), deviceID); err == nil || value != nil {
			t.Fatalf("unsafe credential %q accepted", deviceID)
		}
	}
}
