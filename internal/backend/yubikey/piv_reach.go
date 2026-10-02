//go:build piv

package yubikey

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
)

// Reach looks at every reader once and says which commissioned cards could not be opened, and
// whether any reader refused because another connection holds its card.
//
// THIS BACKEND OPENS A CARD FOR EXCLUSIVE USE. A PKCS#11 module that keeps a connection to every
// card it finds (opensc-pkcs11.so does) therefore locks it out, and every request for a PIV key
// fails as unavailable with nothing naming the cause (regalia#541). The daemon asks this once at
// startup, after its own module has looked at the readers, so that the cause is named while
// someone is watching. Nothing is written and no PIN is presented.
//
// A reader that refuses cannot be asked which card it holds, so `held` is about the readers, not
// about a particular card: with a card missing and a YubiKey's reader held, that reader is the
// likely place it is.
//
// ONLY A YUBIKEY'S READER COUNTS AS HELD. Every reader is listed, the HSM's among them, and the
// PKCS#11 module holds the HSM's reader by design: counting that one would turn a YubiKey that is
// merely unplugged into "locked out" on every host that has an HSM. A reader is a YubiKey's by its
// name, as pcscd reports it.
func (driver *PIVDriver) Reach(ctx context.Context) (missing []string, held bool, err error) {
	if driver == nil || ctx.Err() != nil {
		return nil, false, ErrUnavailable
	}
	cards, err := pivCards()
	if err != nil {
		return nil, false, ErrUnavailable
	}
	present := map[string]bool{}
	for _, card := range cards {
		candidate, openErr := pivOpen(card)
		if openErr != nil {
			held = held || (heldByAnother(openErr) && yubiKeyReader(card))
			continue
		}
		if serial, serialErr := pivSerial(candidate); serialErr == nil {
			present[strconv.FormatUint(uint64(serial), 10)] = true
		}
		_ = pivClose(candidate)
	}
	for deviceID, serial := range driver.devices {
		if !present[serial] {
			missing = append(missing, deviceID)
		}
	}
	sort.Strings(missing)
	return missing, held, nil
}

// pivSerial and pivClose are seams beside pivCards and pivOpen (piv_driver_seam.go): a test cannot
// make a *piv.YubiKey that answers, so the two calls Reach makes on one are replaceable.
var (
	pivSerial = func(card *piv.YubiKey) (uint32, error) { return card.Serial() }
	pivClose  = func(card *piv.YubiKey) error { return card.Close() }
)

// heldByAnother recognises PC/SC's SCARD_E_SHARING_VIOLATION. The card library keeps the code in
// a type it does not export, so the text it gives that code is what can be matched; the test
// pins the text against the library, and a wording change fails there, not silently here.
func heldByAnother(err error) bool {
	return err != nil && strings.Contains(err.Error(), sharingViolationText)
}

// yubiKeyReader reports whether a PC/SC reader name is a YubiKey's ("Yubico YubiKey OTP+FIDO+CCID
// 00 00" and its variants).
func yubiKeyReader(name string) bool {
	return strings.Contains(strings.ToLower(name), "yubikey")
}

const sharingViolationText = "the smart card cannot be accessed because of other connections outstanding"
