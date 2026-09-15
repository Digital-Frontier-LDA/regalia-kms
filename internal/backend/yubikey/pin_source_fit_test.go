package yubikey_test

import (
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/yubikey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/pin"
)

// THE DAEMON'S PIN SOURCE ALREADY FITS THIS PROVIDER.
//
// internal/reachability_test.go's unwiredControls entry for this package used to say that
// wiring it "needs the PIN custody design in #20". It did not: cmd/regalia-kms builds a
// pin.LockedFileSource keyed by device rather than vendor, and that value satisfies
// yubikey.PINSource as it stands. The entry now names what actually separates this package from
// the daemon — the -tags piv build — and cites this test for the fit.
//
// THE FIT IS PINNED JOINTLY, AND WHICH GUARD FIRES DEPENDS ON THE BUILD. Under -tags piv the
// daemon's own wiring, cmd/regalia-kms/yubikey_backend_piv.go, passes the same source to
// yubikey.New and stops compiling first. Under default tags that file is not compiled — the daemon
// links yubikey_backend_stub.go — and this assertion is the only thing that notices. Default tags
// are what `go test ./...` uses, so that is the configuration this test exists for.
//
// Falsifier, measured: make a self-consistent change to the yubikey package alone — add a
// parameter to PINSource.PIN AND update provider.go's call and all four test fakes to match.
// Default build: go build ./... passes and the yubikey package fails to compile only at this file.
// -tags piv: yubikey_backend_piv.go fails to compile. (Changing the interface WITHOUT updating the
// call site and fakes breaks provider.go before this file is reached, so it tests nothing here.)
var _ yubikey.PINSource = (*pin.LockedFileSource)(nil)

func TestTheDaemonsPINSourceFitsTheYubiKeyProvider(t *testing.T) {
	var source yubikey.PINSource = (*pin.LockedFileSource)(nil)
	if source == nil {
		t.Fatal("a typed nil pointer in an interface is not a nil interface; if this fires, the premise of the check changed")
	}
}
