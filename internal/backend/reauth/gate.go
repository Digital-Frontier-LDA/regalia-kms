package reauth

import "context"

// Gate says whether the node holds a runtime lease it asked for after a moment, given in this
// host's CLOCK_BOOTTIME milliseconds. internal/admission.Gate is one.
type Gate interface {
	RequestedAfter(ctx context.Context, boottimeMs int64) bool
}
