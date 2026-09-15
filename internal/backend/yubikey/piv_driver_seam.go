//go:build piv

package yubikey

import "github.com/go-piv/piv-go/v2/piv"

// pivCards and pivOpen are the package's two card-discovery seams.
//
// piv-go exposes a global function pair (piv.Cards and piv.Open) that the driver
// calls directly. Without indirection, every test exercising the discovery path
// needs a physical YubiKey present — and the production guards in front of those
// calls then read as untested against a fixture that does not exist.
//
// pivCards and pivOpen name those two boundaries. The production values are
// the real functions; tests swap and restore through t.Cleanup, the same shape
// as controlplane.entropyReader (#378). Package-level seams race under
// t.Parallel, so this package contains zero t.Parallel calls; a future test
// that adds one would silently race. -race is the guard.
var pivCards = piv.Cards
var pivOpen = piv.Open
