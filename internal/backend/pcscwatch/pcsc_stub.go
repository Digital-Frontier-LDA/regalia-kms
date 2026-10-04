//go:build !piv

package pcscwatch

// System is nil in a build without PC/SC (-tags piv links libpcsclite): the watcher never runs, and a
// removable token is not served where reauthorization is required.
func System() API { return nil }
