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

// reader is one PC/SC reader as the seams present it: its name, and either the serial of the
// YubiKey in it or the error opening it gives.
type reader struct {
	name    string
	serial  uint32
	openErr error
}

// reachOver runs Reach over the given readers, with the library replaced at its four seams.
func reachOver(t *testing.T, ctx context.Context, cardsErr error, readers ...reader) ([]string, bool, error, int) {
	t.Helper()
	previousCards, previousOpen, previousSerial, previousClose := pivCards, pivOpen, pivSerial, pivClose
	t.Cleanup(func() {
		pivCards, pivOpen, pivSerial, pivClose = previousCards, previousOpen, previousSerial, previousClose
	})
	cards := map[*piv.YubiKey]reader{}
	closedCards := 0
	pivCards = func() ([]string, error) {
		names := make([]string, 0, len(readers))
		for _, r := range readers {
			names = append(names, r.name)
		}
		return names, cardsErr
	}
	pivOpen = func(name string) (*piv.YubiKey, error) {
		for _, r := range readers {
			if r.name == name {
				if r.openErr != nil {
					return nil, r.openErr
				}
				card := &piv.YubiKey{}
				cards[card] = r
				return card, nil
			}
		}
		return nil, errors.New("no such reader")
	}
	pivSerial = func(card *piv.YubiKey) (uint32, error) { return cards[card].serial, nil }
	pivClose = func(*piv.YubiKey) error { closedCards++; return nil }
	driver, err := NewPIVDriver(map[string]string{"b-site": "22222222", "a-site": "11111111"})
	if err != nil {
		t.Fatal(err)
	}
	missing, held, err := driver.Reach(ctx)
	return missing, held, err, closedCards
}

func TestReachSaysWhichCardsAreMissingAndWhetherAReaderIsHeld(t *testing.T) {
	live := context.Background()
	sharing := errors.New("connecting to smart card: " + sharingViolationText)
	empty := errors.New("connecting to smart card: no smart card inserted")
	yubikey, hsm, plain := "Yubico YubiKey OTP+FIDO+CCID 00 00", "Nitrokey Nitrokey HSM (DENK04041440000         ) 00 00", "ACS ACR40U ICC Reader 00 00"
	both := []string{"a-site", "b-site"}
	for name, test := range map[string]struct {
		readers []reader
		missing []string
		held    bool
		closed  int
	}{
		"both cards attached and open":                       {[]reader{{yubikey, 11111111, nil}, {"Yubico YubiKey CCID 01 00", 22222222, nil}}, nil, false, 2},
		"one attached, the other unplugged":                  {[]reader{{yubikey, 22222222, nil}}, []string{"a-site"}, false, 1},
		"a YubiKey reader held by another connection":        {[]reader{{yubikey, 0, sharing}}, both, true, 0},
		"a held YubiKey reader, then an empty reader":        {[]reader{{yubikey, 0, sharing}, {plain, 0, empty}}, both, true, 0},
		"an empty reader, then a held YubiKey reader":        {[]reader{{plain, 0, empty}, {yubikey, 0, sharing}}, both, true, 0},
		"a reader named in capitals is a YubiKey's too":      {[]reader{{"YUBICO YUBIKEY CCID 00 00", 0, sharing}}, both, true, 0},
		"the HSM's reader, which the module holds by design": {[]reader{{hsm, 0, sharing}}, both, false, 0},
		"a YubiKey reader that refuses for another reason":   {[]reader{{yubikey, 0, empty}}, both, false, 0},
		"an empty reader":                   {[]reader{{plain, 0, empty}}, both, false, 0},
		"a YubiKey that is not one of ours": {[]reader{{yubikey, 99999999, nil}}, both, false, 1},
		"no reader at all":                  {nil, both, false, 0},
		"one of ours open, the other behind a held YubiKey reader": {[]reader{{yubikey, 11111111, nil}, {"Yubico YubiKey CCID 01 00", 0, sharing}}, []string{"b-site"}, true, 1},
	} {
		missing, held, err, closed := reachOver(t, live, nil, test.readers...)
		if err != nil || held != test.held || !reflect.DeepEqual(missing, test.missing) || closed != test.closed {
			t.Errorf("%s: missing=%v held=%v err=%v closed=%d; want missing=%v held=%v closed=%d", name, missing, held, err, closed, test.missing, test.held, test.closed)
		}
	}
	// the readers cannot be listed: nothing is claimed about the cards
	if _, _, err, _ := reachOver(t, live, errors.New("pcscd")); err == nil {
		t.Fatal("a reader list that could not be read was reported as an answer")
	}
	// nothing is looked at under a context that has ended, although the readers are there
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err, closed := reachOver(t, ended, nil, reader{yubikey, 11111111, nil}); err == nil || closed != 0 {
		t.Fatalf("Reach answered under a context that had ended: err=%v, %d cards opened", err, closed)
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
