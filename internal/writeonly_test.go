package internal_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// carriers are the structs whose fields exist to carry a decision from where it is made to where it
// is enforced. A field on one of these that is written and never read is not dead weight — it is a
// decision that was made, transported, and then quietly not applied.
var carriers = map[string]string{
	"Draft":    "internal/audit",
	"Route":    "internal/registry",
	"Binding":  "internal/registry",
	"Decision": "internal/policy",
	"Request":  "internal/api",
}

// THIS LIST IS HAND-MAINTAINED AND THE TEST'S NAME USED TO OVERSTATE IT.
//
// "No carrier field is written and never read" is a claim about every carrier; what runs is a
// check of the structs named above. api.Request was a carrier from the day it existed and was not
// listed, so IdempotencyKey sat written-and-never-read in the request type of an HTTP API while
// the detector built to find that reported nothing. There is no mechanical definition of "carrier"
// available without type information, which this deliberately does not depend on, so the list stays
// manual -- but the limit is now in the name and in the failure text instead of in a comment
// nobody reaches.

// fieldsAllowedToBeWriteOnly are fields whose only job is to be serialised — they are read by
// encoding/json rather than by Go code, so the AST cannot see the read.
var fieldsAllowedToBeWriteOnly = map[string]string{
	"Draft.Timestamp":           "serialised into the event; read back by Verify through JSON",
	"Draft.LatencyMilliseconds": "serialised only",
	"Draft.DeviceID":            "serialised only",
	"Draft.Outcome":             "serialised only",
}

// A DECISION CARRIED AND NEVER READ IS A DECISION NOT APPLIED.
//
// This shape has appeared three times from three independent authors:
//
//   - context.subject was computed by the SOPS client, transmitted, length-checked, carried into
//     api.Request, and read by nothing. It was the one value that could have tied an envelope's AAD
//     to the authorised route.
//   - The purpose-policy digest was computed at startup, logged, and dropped, while the coordinator
//     was handed the REGISTRY digest under the name PolicyDigest — so every audit event answered
//     "which policy allowed this" with the wrong hash.
//   - Sources.Fencing returned an "acquired" boolean to separate "never evaluated" from "not held",
//     and render() ignored it and emitted zero for both.
//
// Each was found by reading. This finds them mechanically, for the structs where the consequence is
// a control that silently does not apply.
//
// LIMITS, because a test that overstates its reach is the thing this repository keeps finding.
//
// It sees reads of the form x.Field in non-test Go within this module, and writes of the form
// Field: value or x.Field = value. So it catches OUTBOUND carriers — structs this code builds and
// hands onward, like Draft and Route.
//
// It does NOT catch inbound ones. api.Request is populated by encoding/json, which is not a
// composite literal, so an inbound field nothing reads has zero writes by this measure and is not
// flagged. That matters: context.subject — the value that could have tied an envelope's AAD to the
// authorised route, transmitted and read by nobody — was exactly that shape, and this test would
// have missed it. Two of the three motivating instances are covered; the third is named here rather
// than implied.
//
// It also cannot see reflection, or a field consumed only by encoding/json. Those are listed above
// with a reason, because an unexplained allowlist entry reads as a statement that nothing is
// missing.
func TestNoListedCarrierFieldIsWrittenAndNeverRead(t *testing.T) {
	root := ".."
	reads := map[string]int{}
	writes := map[string]int{}
	declaredOn := map[string][]string{}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		// ERRORS ARE NOT SKIPPED. A walk that swallows them checks fewer files and still passes,
		// which is the same defect this test exists to find, in the test itself.
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return parseErr
		}

		// A selector on the left of an assignment is a WRITE, and ast.Inspect also visits it as a
		// SelectorExpr. Counting it as both meant a field only ever assigned via x.Field = value had
		// its own write bump its read count, so it could never be reported. Record the positions of
		// assignment targets and skip exactly those.
		writePositions := map[token.Pos]struct{}{}
		ast.Inspect(file, func(node ast.Node) bool {
			if assign, ok := node.(*ast.AssignStmt); ok {
				for _, lhs := range assign.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok {
						writePositions[sel.Sel.Pos()] = struct{}{}
						writes[sel.Sel.Name]++
					}
				}
			}
			return true
		})
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.KeyValueExpr:
				if key, ok := n.Key.(*ast.Ident); ok {
					writes[key.Name]++
				}
			case *ast.SelectorExpr:
				if _, isWrite := writePositions[n.Sel.Pos()]; !isWrite {
					reads[n.Sel.Name]++
				}
			case *ast.TypeSpec:
				// EVERY struct in the tree, not only the carriers. reads is keyed by bare
				// field name across the whole walk, so a field of the same name on ANY type
				// masks a carrier's -- and the collision check used to be computed from the
				// carrier list alone, which meant a mask from an unlisted type produced
				// confident silence instead of an "cannot analyse" line.
				if structType, isStruct := n.Type.(*ast.StructType); isStruct {
					for _, field := range structType.Fields.List {
						for _, name := range field.Names {
							// QUALIFIED BY DIRECTORY, because two distinct types can share a
							// name. api.Request and the SOPS adapter's Request both declare
							// IdempotencyKey; keyed by bare type name they collapse into one
							// owner, the field reads as uniquely owned, and the adapter's read
							// masks the API one -- which is the exact masking this check exists
							// to report. The collision detector needs a unique key as much as
							// the thing it is detecting collisions in.
							// ToSlash, because the suffix comparisons below are written with
							// "/" and filepath.Dir yields the platform separator. On a platform
							// where those differ the carrier-found check silently fails and
							// reports every listed carrier as missing -- a check breaking in the
							// direction of a confusing red rather than a quiet green, but still
							// a comparison between two things built different ways.
							owner := filepath.ToSlash(filepath.Dir(path)) + "." + n.Name.Name
							declaredOn[name.Name] = appendUnique(declaredOn[name.Name], owner)
						}
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) == 0 {
		t.Fatal("no selector expressions were found at all: this test is checking nothing")
	}

	// FIELD NAMES ARE NOT UNIQUE ACROSS CARRIERS, and this analysis keys on the bare name, so a read
	// of Route.PolicyID would mask Decision.PolicyID. Rather than report a false negative silently,
	// a shared name is refused outright: the analysis cannot answer for it and says so.
	if len(declaredOn) == 0 {
		t.Fatal("no struct fields were found at all: the collision analysis is checking nothing")
	}

	// EVERY LISTED CARRIER MUST HAVE BEEN FOUND.
	//
	// The list is hand-maintained, so a renamed struct or a wrong package path removes a
	// carrier from the analysis and changes nothing observable: the test still passes, and
	// it passes faster. That is the same failure the list itself just produced -- a check
	// silently covering less than its name says -- so the list is checked against the tree
	// rather than trusted.
	for structName, pkg := range carriers {
		found := false
		for _, owners := range declaredOn {
			for _, owner := range owners {
				if strings.HasSuffix(owner, "/"+strings.TrimPrefix(pkg, "internal/")+"."+structName) ||
					strings.HasSuffix(owner, pkg+"."+structName) {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("carriers lists %s in %s and the walk found no such struct: the entry is "+
				"contributing nothing and its absence is invisible", structName, pkg)
		}
	}

	var offenders, ambiguous []string
	for structName, pkg := range carriers {
		for _, field := range fieldsOf(t, strings.TrimPrefix(pkg, "internal/"), structName) {
			key := structName + "." + field
			if _, allowed := fieldsAllowedToBeWriteOnly[key]; allowed {
				continue
			}
			if len(declaredOn[field]) > 1 {
				ambiguous = append(ambiguous, key+" (shared with "+strings.Join(declaredOn[field], ", ")+")")
				continue
			}
			// A selector read count of zero, with at least one composite-literal write, is the
			// signature: something builds it and nothing consumes it.
			if reads[field] == 0 && writes[field] > 0 {
				offenders = append(offenders, key)
			}
		}
	}
	sort.Strings(offenders)
	sort.Strings(ambiguous)
	if len(ambiguous) > 0 {
		// Reported, not tolerated. A name-keyed analysis cannot separate these, and pretending it
		// can is how a detector produces confident silence.
		t.Logf("NOT ANALYSED, field name shared across carriers so a read of one masks the other: %s", strings.Join(ambiguous, ", "))
	}
	if len(offenders) > 0 {
		t.Fatalf("these carrier fields are written and never read: %s\n"+
			"A field on one of these structs exists to carry a decision from where it is made to where it is enforced. "+
			"Written and never read means the decision was made, transported, and quietly not applied. "+
			"Either consume it, remove it, or add it to fieldsAllowedToBeWriteOnly with the reason.",
			strings.Join(offenders, ", "))
	}
}

func fieldsOf(t *testing.T, dir, structName string) []string {
	t.Helper()
	var names []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			spec, ok := node.(*ast.TypeSpec)
			if !ok || spec.Name.Name != structName {
				return true
			}
			structType, ok := spec.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range structType.Fields.List {
				for _, name := range field.Names {
					if name.IsExported() {
						names = append(names, name.Name)
					}
				}
			}
			return false
		})
	}
	if len(names) == 0 {
		t.Fatalf("found no exported fields on %s in %s: this test would pass while checking nothing", structName, dir)
	}
	return names
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
