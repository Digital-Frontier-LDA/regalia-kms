// Package reauth names what every key provider must offer so that a token that was absent serves
// again only under a runtime lease asked for after its return (regalia-kms#72, PoC 12.4).
//
// The rule belongs to every provider that can execute a key operation, whatever the token. The
// daemon walks its providers at startup and refuses one that does not implement Provider
// (cmd/regalia-kms, requireReauthorization).
package reauth

import "context"

// Gate says whether the node holds a runtime lease it asked for after a moment, given in this
// host's CLOCK_BOOTTIME milliseconds. internal/admission.Gate is the one in the daemon.
type Gate interface {
	RequestedAfter(ctx context.Context, boottimeMs int64) bool
}

// Provider is a key provider that waits, after a token's absence and after a start of the daemon,
// for a lease asked for since. sinceMs is when this process started, on the boot clock; boottime
// reads that clock.
type Provider interface {
	RequireReauthorization(gate Gate, boottime func() (int64, error), sinceMs int64) error
}
