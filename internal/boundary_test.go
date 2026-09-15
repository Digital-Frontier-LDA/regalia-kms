// Package internal_test enforces the architectural invariants ADR §1 rests on.
//
// These are not style checks. The ADR's guarantee is that "the KMS is the only production
// cryptographic boundary" and that a caller "cannot select a reader, slot, backend or arbitrary
// mechanism". That guarantee is a property of the SHAPE of the code: it survives only while token
// access stays behind the backend packages and no other path can reach a device or a local
// identity. A reviewer cannot see that in a diff, so it is asserted here.
package internal_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
)

// packagesAllowedToTouchTokens are the only places a device library may be imported. Everything
// else must go through the backend interface.
var packagesAllowedToTouchTokens = []string{
	"internal/backend/nitrokey",
	"internal/backend/yubikey",
	"internal/backend/openpgp/pcsc",
}

// deviceLibraries reach hardware directly. An import of one outside the allowed packages is a
// second path to a token, which is exactly what the KMS exists to prevent.
var deviceLibraries = []string{
	"github.com/miekg/pkcs11",
	"github.com/go-piv/piv-go",
	"github.com/ebfe/scard",
	"golang.org/x/crypto/openpgp",
	// cgo. A package that calls PC/SC or PKCS#11 through C reaches the token without importing any
	// library named above, so `import "C"` counts as a device library. The OpenPGP PC/SC transport
	// (internal/backend/openpgp/pcsc) is the first package in this module to use it.
	"C",
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		directory = filepath.Dir(directory)
	}
	t.Fatal("could not locate the module root")
	return ""
}

// walkGoFiles visits every non-test Go file in the module, reporting its path relative to the root.
func walkGoFiles(t *testing.T, root string, visit func(relative string, file *ast.File)) {
	t.Helper()
	fileSet := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		// The SOPS adapter is a separate module with its own boundary; it is a CLIENT of the KMS.
		if strings.HasPrefix(relative, "adapters/") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		visit(relative, parsed)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ONLY THE BACKEND PACKAGES MAY REACH A DEVICE.
//
// If another package imports a token library it has its own path to the hardware, bypassing
// routing, policy and audit — the controls the boundary exists to apply. That is not something a
// code review reliably catches, because the import looks ordinary at the point it is added.
func TestOnlyBackendPackagesImportDeviceLibraries(t *testing.T) {
	root := moduleRoot(t)
	walkGoFiles(t, root, func(relative string, file *ast.File) {
		directory := filepath.Dir(relative)
		allowed := false
		for _, permitted := range packagesAllowedToTouchTokens {
			if directory == permitted {
				allowed = true
			}
		}
		if allowed {
			return
		}
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			for _, library := range deviceLibraries {
				if path == library || strings.HasPrefix(path, library+"/") {
					t.Errorf("%s imports the device library %s; token access must stay behind %v",
						relative, path, packagesAllowedToTouchTokens)
				}
			}
		}
	})
}

// THE OPERATION BOUNDARY MUST NOT DEPEND ON A BACKEND IMPLEMENTATION.
//
// api, operations and policy decide WHETHER something may happen; they must not know which device
// performs it, or a decision could be made differently per backend — and the "purpose-shaped, not
// device-shaped" rule would hold only by convention.
func TestDecisionPackagesDoNotImportBackendImplementations(t *testing.T) {
	root := moduleRoot(t)
	decisionPackages := []string{"internal/api", "internal/operations", "internal/policy", "internal/auth"}
	walkGoFiles(t, root, func(relative string, file *ast.File) {
		directory := filepath.Dir(relative)
		isDecision := false
		for _, decision := range decisionPackages {
			if directory == decision {
				isDecision = true
			}
		}
		if !isDecision {
			return
		}
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if strings.Contains(path, "/internal/backend/") {
				t.Errorf("%s imports the backend implementation %s; decision packages must depend on the interface only",
					relative, path)
			}
		}
	})
}

// NO PACKAGE MAY SHELL OUT.
//
// A local `gpg`, `sops` or `pkcs11-tool` invocation would be a production crypto path outside the
// KMS — the exact thing ADR §1 removes, and the exact thing that is easy to add "just for this one
// case". os/exec has no legitimate use in this service.
func TestNoPackageShellsOut(t *testing.T) {
	root := moduleRoot(t)
	walkGoFiles(t, root, func(relative string, file *ast.File) {
		for _, imported := range file.Imports {
			if strings.Trim(imported.Path.Value, `"`) == "os/exec" {
				t.Errorf("%s imports os/exec; the KMS must not invoke external cryptographic tools", relative)
			}
		}
	})
}

// THE CLIENT CONTRACT MUST NOT NAME THE OPENPGP APPLET.
//
// ADR-0001 §1: the API is purpose-shaped, not device-shaped, and a caller "cannot select a reader,
// slot, backend or arbitrary mechanism". Issue #21 turns that into a specific requirement for the
// one backend most likely to leak through it — a legacy compatibility adapter is adopted by
// callers who already speak the legacy tool's language, and the easy way to serve them is to let
// them keep speaking it. One `gpg_key_id` field, one `openpgp` format, one OPENPGP_* error code,
// and the carve-out is no longer removable: every consumer is now coupled to it, which is the
// "permanent bypass" the issue exists to prevent.
//
// The check is on NAMES a client can see — exported identifiers and the operation paths — in the
// packages that face one. It is deliberately not a repository-wide string search:
//
//   - registry and envelope carry "yubikey-openpgp" as a VALUE, because a custody manifest has to
//     name the backend a key is bound to. That is an operator artifact, not a client contract, and
//     no request ever carries it.
//   - `sops-pgp` is an allowed format name (API.md, api/README.md) and names the MATERIAL, not the
//     device. A client presenting a SOPS-encrypted data key has to say so; which card opens it is
//     the KMS's business, and the whole point of routing is that the answer can change.
//
// Falsifier: add `func OpenPGPFormat() string` to internal/api, or a /v1/operations/openpgp-unwrap
// path. Either fails here alone.
func TestNoClientContractNamesTheOpenPGPApplet(t *testing.T) {
	forbidden := []string{"openpgp", "gpg"}
	names := func(value string) string {
		lowered := strings.ToLower(value)
		for _, word := range forbidden {
			if strings.Contains(lowered, word) {
				return word
			}
		}
		return ""
	}

	for _, path := range api.OperationPaths() {
		if word := names(path); word != "" {
			t.Errorf("operation path %s names %q; a client would select a device by choosing a route", path, word)
		}
	}

	root := moduleRoot(t)
	clientFacing := []string{"internal/api", "internal/operations", "internal/policy"}
	fileSet := token.NewFileSet()
	inspected := 0
	for _, directory := range clientFacing {
		entries, err := os.ReadDir(filepath.Join(root, directory))
		if err != nil {
			t.Fatalf("reading %s: %v", directory, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			relative := filepath.Join(directory, entry.Name())
			parsed, err := parser.ParseFile(fileSet, filepath.Join(root, relative), nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", relative, err)
			}
			inspected++
			for _, declaration := range parsed.Decls {
				for _, identifier := range exportedNames(declaration) {
					if word := names(identifier); word != "" {
						t.Errorf("%s exports %s, which names %q; the client contract must not be device-shaped",
							relative, identifier, word)
					}
				}
			}
		}
	}
	if inspected == 0 {
		t.Fatal("no client-facing source file was parsed, so this test checked nothing")
	}
}

// exportedNames returns the exported identifiers a declaration introduces: functions and methods,
// types, and top-level constants and variables.
func exportedNames(declaration ast.Decl) []string {
	var found []string
	keep := func(name *ast.Ident) {
		if name != nil && name.IsExported() {
			found = append(found, name.Name)
		}
	}
	switch typed := declaration.(type) {
	case *ast.FuncDecl:
		keep(typed.Name)
	case *ast.GenDecl:
		for _, spec := range typed.Specs {
			switch specified := spec.(type) {
			case *ast.TypeSpec:
				keep(specified.Name)
				// Exported fields of an exported struct are part of the contract too: a
				// GPGKeyID field on a request type is exactly the leak this test is for.
				structure, ok := specified.Type.(*ast.StructType)
				if !ok || structure.Fields == nil {
					continue
				}
				for _, field := range structure.Fields.List {
					for _, name := range field.Names {
						keep(name)
					}
					if field.Tag != nil {
						found = append(found, field.Tag.Value)
					}
				}
			case *ast.ValueSpec:
				for _, name := range specified.Names {
					keep(name)
				}
			}
		}
	}
	return found
}
