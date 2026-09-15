// Command inventory verifies a secret-inventory document: the Regalia-side half of #33.
//
// WHAT #33 SPLITS, AND WHY THIS IS ONLY ONE HALF. The issue covers every material secret the
// company holds, across fourteen repositories, and its own scope section divides the work:
// "Regalia should define the inventory schema, custody classifications, verification rules, and
// central status. Consumer repositories and system owners supply and execute service-specific
// migration records." This tool and inventory.go are that first sentence. The inventory itself --
// the signed-off document naming every system -- is the second, and is not in this repository.
//
// So this ships the rules with no data to run them over, which is an uncomfortable shape and the
// right one: the alternative is a schema invented alongside the first inventory that has to
// describe it, and every field then means whatever the first author needed it to mean.
//
// WHAT IT REFUSES. Four refusals are the reason it exists, and each is a state that reads as
// complete while being the thing the issue is about:
//
//	a record with no owner            an unowned secret has nobody to attest to it or rotate it
//	a record with no custody          found, written down, and never assigned to a classification
//	an exception past its expiry      a time-bounded exception that nothing is timing
//	a system reference that dangles   in either direction -- see below
//
// The dangling reference is checked BOTH WAYS, and the second direction is the one that matters
// for #33's fifth acceptance criterion. A record naming an undeclared system is an obvious hole. A
// system declared with an owner and named by no record is not obvious at all: it counts as
// inventoried in every summary, while the discovery for it was never done. Silence and "holds no
// secrets" look identical, so the document has to say which.
//
// THE SUMMARY LINE IS COMPUTED, NOT WRITTEN. It goes to stderr as one line, and the word in it
// comes from Verdict(report), which reads the refusals. This is not tidiness. A sibling tool in
// this repository exited 0 on a repository where it matched zero files and printed a sentence
// asserting a property of files it had never opened, because its summary was a constant sitting on
// the success path. A constant cannot be wrong about the run it describes only if the run has one
// outcome. Here the string is derived, so there is no arrangement of code that prints VERIFIED
// beside a non-zero refusal count -- and an empty record set is itself a refusal, so the zero-file
// case cannot reach the success path at all.
//
// Exit codes follow kms/tools/guardenum: 2 for usage, 1 for a run that refused or could not read
// its input, 0 only for a verified inventory.
//
//	go run ./tools/inventory inventory.json
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: inventory <inventory.json>")
		os.Exit(2)
	}
	// ReadBounded, not os.ReadFile: the size cap belongs before the read, not after it.
	data, err := ReadBounded(os.Args[1])
	if err != nil {
		// Not routed through Report: a file that could not be read is not an inventory that
		// refused, and reporting it as one would put a readable-looking REFUSED line over a typo in
		// a path. The distinction matters when this runs in CI over a path that moved.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	report := Verify(data, time.Now())
	for _, refusal := range report.Refusals {
		fmt.Println(refusal)
	}
	fmt.Fprintf(os.Stderr, "INVENTORY=%s SYSTEMS=%d RECORDS=%d REFUSED=%d BLOCKERS=%d\n",
		Verdict(report), report.Systems, report.Records, len(report.Refusals), report.Blockers)
	if !report.OK() {
		os.Exit(1)
	}
}
