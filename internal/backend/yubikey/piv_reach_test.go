//go:build piv

package yubikey

import (
	"context"
	"errors"
	"go/build"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

func reachWith(t *testing.T, readers []string, cardsErr, openErr error) ([]string, bool, error) {
	t.Helper()
	previousCards, previousOpen := pivCards, pivOpen
	t.Cleanup(func() { pivCards, pivOpen = previousCards, previousOpen })
	pivCards = func() ([]string, error) { return readers, cardsErr }
	pivOpen = func(string) (*piv.YubiKey, error) { return nil, openErr }
	driver, err := NewPIVDriver(map[string]string{"b-site": "22222222", "a-site": "11111111"})
	if err != nil {
		t.Fatal(err)
	}
	return driver.Reach(context.Background())
}

func TestReachSaysWhichCardsAreMissingAndWhetherAReaderIsHeld(t *testing.T) {
	both := []string{"a-site", "b-site"}
	// a reader that another connection holds: the cards behind it cannot be seen
	missing, held, err := reachWith(t, []string{"Yubico YubiKey 00 00"}, nil, errors.New("connecting to smart card: "+sharingViolationText))
	if err != nil || !held || !reflect.DeepEqual(missing, both) {
		t.Fatalf("held reader: missing=%v held=%v err=%v", missing, held, err)
	}
	// the HSM's reader is held by the PKCS#11 module by design: that says nothing about a YubiKey,
	// and a YubiKey that is merely unplugged must not look locked out on a host with an HSM
	missing, held, err = reachWith(t, []string{"Nitrokey Nitrokey HSM (DENK04041440000         ) 00 00"}, nil, errors.New("connecting to smart card: "+sharingViolationText))
	if err != nil || held || !reflect.DeepEqual(missing, both) {
		t.Fatalf("held HSM reader, no YubiKey: missing=%v held=%v err=%v", missing, held, err)
	}
	// a reader that refuses for another reason (no card in it) is not a held one
	missing, held, err = reachWith(t, []string{"ACR40U 00 00"}, nil, errors.New("connecting to smart card: no smart card inserted"))
	if err != nil || held || !reflect.DeepEqual(missing, both) {
		t.Fatalf("empty reader: missing=%v held=%v err=%v", missing, held, err)
	}
	// no reader at all
	missing, held, err = reachWith(t, nil, nil, nil)
	if err != nil || held || !reflect.DeepEqual(missing, both) {
		t.Fatalf("no reader: missing=%v held=%v err=%v", missing, held, err)
	}
	// the readers cannot be listed: nothing is claimed about the cards
	if _, _, err = reachWith(t, nil, errors.New("pcscd"), nil); err == nil {
		t.Fatal("a reader list that could not be read was reported as an answer")
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	driver, _ := NewPIVDriver(map[string]string{"a-site": "11111111"})
	if _, _, err := driver.Reach(ended); err == nil {
		t.Fatal("Reach answered under a context that had ended")
	}
}

// THE TEXT IS THE LIBRARY'S. heldByAnother matches the words piv-go gives SCARD_E_SHARING_VIOLATION,
// because the type that carries the code is not exported. This reads the pinned library's own
// table, so an upgrade that rewords it fails here.
func TestTheSharingViolationTextIsTheLibrarys(t *testing.T) {
	library, err := build.Import("github.com/go-piv/piv-go/v2/piv", ".", build.FindOnly)
	if err != nil {
		t.Fatalf("locate the piv-go source: %v", err)
	}
	table, err := os.ReadFile(filepath.Join(library.Dir, "pcsc_errors.go"))
	if err != nil {
		t.Fatalf("read piv-go's PC/SC error table: %v", err)
	}
	if !strings.Contains(string(table), `0x8010000B: "`+sharingViolationText+`"`) {
		t.Fatalf("piv-go no longer words SCARD_E_SHARING_VIOLATION (0x8010000B) as %q: heldByAnother would never match", sharingViolationText)
	}
}
