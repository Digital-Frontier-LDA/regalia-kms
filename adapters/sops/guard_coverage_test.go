package sopsadapter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops/sopsrpc"
)

// guard_coverage_test.go closes mutation survivors in this adapter: refusal guards whose condition
// could be replaced by a constant with the whole module's suite still green.
//
// Two rules every test below follows.
//
//	ASSERT THE EXACT MESSAGE. Both ServeUnix and HTTPClient.call are runs of sequential refusals,
//	so a fixture that is bad in one way is usually bad in another and errors for a reason that has
//	nothing to do with the guard. Most of the survivors here survived because a neighbouring test
//	asserted only `err == nil`: TestServeUnixRefusesExistingPath still passes with the Lstat guard
//	deleted, because net.Listen then fails with "address already in use" instead.
//
//	ONE DETECTOR PER FIXTURE. Each fixture is built so the guard under test is the only thing that
//	can refuse it, and every table ends with a labelled ANCHOR — placed last, so a t.Fatal in it
//	cannot foreclose the falsifications above it — proving the fixture is otherwise good.
//
// FOUR SURVIVORS GET NO TEST, BECAUSE NOTHING CAN REACH THEM. Recorded here so the next reader does
// not spend an afternoon rediscovering it. Every claim below was measured, on darwin/arm64 and
// again on linux/arm64 (golang:1.26 container), not reasoned about.
//
//	randomID's `rand.Read` error check, and translate's check of randomID's error. crypto/rand.Read
//	never returns a non-nil error. On failure it calls runtime.fatal and the process dies without
//	returning: measured by assigning crypto/rand.Reader a reader that always errors, which aborted
//	with "fatal error: crypto/rand: failed to read random data (see https://go.dev/issue/66821)"
//	from crypto/rand.Read — an abort recover() does not catch, not a returned error. adapter.go
//	calls the package function rather than an injectable Reader, so there is no seam to reach even
//	that. The Go source is explicit: "It never returns an error, and always fills b entirely."
//
//	json.Marshal(body) in HTTPClient.call. operationRequest is strings and a struct of strings, and
//	encoding/json has no failure mode for those — no channel, func, cyclic or floating-point field
//	exists to fail on, and invalid UTF-8 is replaced rather than rejected (measured: marshalling a
//	struct holding "\xff\xfe\x00" and "\xed\xa0\x80" returned a nil error and each byte re-encoded as \ufffd or \u0000).
//	The one body field that can carry arbitrary bytes past validTransportRequest is Nonce, from
//	IdempotencyKey, which is length-checked and not content-checked — and it marshals.
//
//	`!info.IsDir()` on the socket's parent. Reaching it needs os.Lstat(socketPath) to report ENOENT
//	while os.Stat(filepath.Dir(socketPath)) returns a non-directory, and the kernel does not offer
//	that pair: any path that traverses a non-directory fails ENOTDIR at the Lstat, which the
//	`!os.IsNotExist(err)` arm above turns into "refusing to replace existing SOPS socket path".
//	Measured with the parent as a regular file, as a symlink to a regular file, as a FIFO and as
//	/dev/null — all four refused by the Lstat guard, "lstat ...: not a directory" — and with the
//	parent as a dangling symlink or the socket named with a trailing slash, both refused one line
//	earlier by the Stat guard, "stat the SOPS socket directory ... no such file or directory".
//	Identical on darwin and linux. TestServeUnixRefusesToTakeOverAPathItDidNotCreate and
//	TestServeUnixNamesTheSocketDirectoryItCouldNotStat pin the two guards that keep it that way.

func fixedClock() time.Time { return time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC) }

// kmsResponseJSON is a response HTTPClient.call must find completely valid: the request id it sent,
// the object id it asked about, a non-empty operation id, and a small result. extraField is spliced
// in before the closing brace so a test can add exactly one defect.
func kmsResponseJSON(requestID, objectID, extraField string) string {
	return `{"request_id":"` + requestID + `","operation_id":"018f0000-0000-7000-8000-000000000002",` +
		`"object_id":"` + objectID + `","content_type":"application/vnd.regalia.envelope+json",` +
		`"result_base64":"ZGF0YS1rZXk="` + extraField + `}`
}

// alwaysYesHandler is a KMS that accepts everything and answers with a response the client must
// find valid. Pointing a refusal fixture at it means a guard that stops refusing does not merely
// error differently further down — the call SUCCEEDS and returns key material, which is the
// failure the assertions below are written against. hits counts requests that reached it at all.
func alwaysYesHandler(hits *int64) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		atomic.AddInt64(hits, 1)
		var body map[string]any
		_ = json.NewDecoder(request.Body).Decode(&body)
		objectID, _ := body["object_id"].(string)
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = writer.Write([]byte(kmsResponseJSON(request.Header.Get("X-Request-ID"), objectID, "")))
	})
}

// TestTranslateNamesAnUnsupportedKeyTypeRatherThanABadCarrierARN pins the key-type guard in
// translate.
//
// WITHOUT THE GUARD the adapter does not crash and does not accept the request — sopsrpc's
// generated getters are nil-safe, so a nil *Key or a Key carrying no kms_key falls through to
// carrier.GetArn(), which returns "", and the caller is told "invalid Regalia carrier ARN". That is
// a diagnosis of the wrong thing: SOPS sent a key of a type this adapter does not serve (age, PGP,
// GCP, Azure, Vault all arrive as a Key with no kms_key set once the unknown fields are dropped),
// and the operator is sent to check an ARN they never wrote. Encrypt and Decrypt collapse both
// refusals to "invalid SOPS key request" so a gRPC caller gets no oracle, which means translate's
// message is the ONLY place the distinction exists — and the only place it can be pinned.
func TestTranslateNamesAnUnsupportedKeyTypeRatherThanABadCarrierARN(t *testing.T) {
	for _, test := range []struct {
		name string
		key  *sopsrpc.Key
		want string
	}{
		{"no key at all", nil, "unsupported SOPS key type"},
		{"a key that carries no kms_key", &sopsrpc.Key{}, "unsupported SOPS key type"},
		{"ANCHOR: the Regalia carrier this adapter serves", sopsKey(), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := translate(test.key, "wrap", []byte("01234567890123456789012345678901"))
			if test.want == "" {
				if err != nil {
					t.Fatalf("the anchor key was refused with %q, so every refusal above is refusing something already broken", err)
				}
				if request.ObjectID != "production-sops" {
					t.Fatalf("the anchor translated to ObjectID %q, want %q", request.ObjectID, "production-sops")
				}
				return
			}
			if err == nil {
				t.Fatalf("translate() accepted %s and produced %#v", test.name, request)
			}
			if err.Error() != test.want {
				t.Fatalf("translate() error = %q, want %q — the caller is being sent to check an ARN when the real fault is that SOPS asked for a key type this adapter does not serve", err, test.want)
			}
		})
	}
}

// TestTranslateRefusesABindingContextThatIsNotExactlyTheFourBoundFields pins the cardinality check
// on the SOPS encryption context.
//
// WITHOUT THE GUARD a context carrying the four bound fields PLUS anything else is accepted: the
// four lookups below it succeed, every pattern matches, and translate returns a Request. The extra
// entries are then dropped on the floor — they never reach the KMS and never reach the audit
// record — so an operator who writes `--encryption-context ...,tenant:acme` gets a file that
// decrypts for every tenant while their .sops.yaml says otherwise. The cardinality check is the
// only thing that refuses a context field this adapter does not bind, because the four lookups are
// by name and cannot notice a fifth.
func TestTranslateRefusesABindingContextThatIsNotExactlyTheFourBoundFields(t *testing.T) {
	for _, test := range []struct {
		name    string
		mutate  func(map[string]string)
		want    string
		wantKMS int
	}{
		{
			// The sole-detector row: every other check in translate passes on this input.
			name:   "a fifth context entry nothing in the adapter binds",
			mutate: func(context map[string]string) { context["tenant"] = "acme" },
			want:   "incomplete SOPS binding context",
		},
		{
			name:   "only three of the four bound fields",
			mutate: func(context map[string]string) { delete(context, "purpose") },
			want:   "incomplete SOPS binding context",
		},
		{
			name:    "ANCHOR: exactly the four bound fields",
			mutate:  func(map[string]string) {},
			want:    "",
			wantKMS: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := sopsKey()
			test.mutate(key.GetKmsKey().Context)

			_, err := translate(key, "wrap", []byte("01234567890123456789012345678901"))
			switch {
			case test.want == "" && err != nil:
				t.Fatalf("the anchor context was refused with %q, so every refusal above is refusing something already broken", err)
			case test.want != "" && err == nil:
				t.Fatalf("translate() accepted %s: the extra entry is silently dropped, so the file decrypts under a binding the operator did not write", test.name)
			case test.want != "" && err.Error() != test.want:
				t.Fatalf("translate() error = %q, want %q", err, test.want)
			}

			// The refusal has to happen before the KMS is consulted, not after it declines.
			client := &mockKMS{wrapResult: []byte("wrapped-envelope")}
			_, _ = New(client).Encrypt(context.Background(), &sopsrpc.EncryptRequest{Key: key, Plaintext: []byte("01234567890123456789012345678901")})
			if len(client.requests) != test.wantKMS {
				t.Fatalf("KMS was called %d time(s) for %s, want %d", len(client.requests), test.name, test.wantKMS)
			}
		})
	}
}

// TestHTTPClientCallRefusesAnUnusableClientOrRequestBeforeAnythingIsSent pins each arm of the
// preflight condition at the top of HTTPClient.call. Every fixture below is pointed at a KMS that
// says yes to everything, so an arm that stops refusing does not fail later — it completes the
// operation and hands back key material.
//
// WITHOUT EACH ARM, in order:
//
//	`client == nil` and `client.client == nil` and `client.now == nil` — the very next statements
//	dereference exactly what the arm checked, so the sidecar panics on a request instead of
//	reporting a misconfiguration.
//
//	`!validHTTPSBase(client.baseURL)` — a base URL of http:// is honoured, and the plaintext data
//	key (wrap) or the wrapped one (unwrap) goes out over an unencrypted, unauthenticated hop. The
//	plaintext server below counts that: with the arm gone it is contacted.
//
//	`!validTransportRequest(request, endpoint)` — validTransportRequest is exercised directly by
//	transport_validation_test.go, but nothing pinned that call actually consults it. With the arm
//	gone a request labelled "unwrap" is POSTed to /v1/operations/wrap, and the KMS authorises the
//	endpoint it was called on, not the label in the body.
func TestHTTPClientCallRefusesAnUnusableClientOrRequestBeforeAnythingIsSent(t *testing.T) {
	var secureHits, plaintextHits int64
	secure := httptest.NewTLSServer(alwaysYesHandler(&secureHits))
	defer secure.Close()
	plaintext := httptest.NewServer(alwaysYesHandler(&plaintextHits))
	defer plaintext.Close()

	mismatched := validRequest()
	mismatched.Operation = "unwrap" // sent through Wrap, i.e. to /v1/operations/wrap

	for _, test := range []struct {
		name    string
		client  *HTTPClient
		request Request
		anchor  bool
	}{
		{name: "a nil client", client: nil, request: validRequest()},
		{name: "a client built with no *http.Client", client: NewHTTPClient(secure.URL, nil, fixedClock), request: validRequest()},
		{name: "a client built with no clock", client: NewHTTPClient(secure.URL, secure.Client(), nil), request: validRequest()},
		{name: "a plaintext http base URL", client: NewHTTPClient(plaintext.URL, plaintext.Client(), fixedClock), request: validRequest()},
		{name: "an operation that does not match the endpoint", client: NewHTTPClient(secure.URL, secure.Client(), fixedClock), request: mismatched},
		{name: "ANCHOR: a well-formed client and request", client: NewHTTPClient(secure.URL, secure.Client(), fixedClock), request: validRequest(), anchor: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			secureBefore, plaintextBefore := atomic.LoadInt64(&secureHits), atomic.LoadInt64(&plaintextHits)
			result, err := test.client.Wrap(context.Background(), test.request)
			secureSent := atomic.LoadInt64(&secureHits) - secureBefore
			plaintextSent := atomic.LoadInt64(&plaintextHits) - plaintextBefore

			if test.anchor {
				if err != nil {
					t.Fatalf("the anchor call failed with %q, so every refusal above is refusing something already broken", err)
				}
				if string(result) != "data-key" {
					t.Fatalf("the anchor returned %q, want %q", result, "data-key")
				}
				if secureSent != 1 {
					t.Fatalf("the anchor reached the KMS %d time(s), want 1 — the counters the refusals are asserted against do not count", secureSent)
				}
				return
			}
			if err == nil {
				t.Fatalf("Wrap() with %s returned %d bytes of key material and no error", test.name, len(result))
			}
			if err.Error() != "invalid KMS client request" {
				t.Fatalf("Wrap() with %s = %q, want %q — a different message means the preflight let it through and something downstream refused instead", test.name, err, "invalid KMS client request")
			}
			if result != nil {
				t.Fatalf("Wrap() with %s refused but returned %d bytes", test.name, len(result))
			}
			if secureSent != 0 || plaintextSent != 0 {
				t.Fatalf("%s reached the KMS (%d over TLS, %d in the clear): the preflight must refuse before any byte leaves this process", test.name, secureSent, plaintextSent)
			}
		})
	}
}

// TestHTTPClientRefusesANilContextInsteadOfPanicking pins the http.NewRequestWithContext error
// check. Wrap and Unwrap are the exported KMSClient interface, so the context comes from whatever
// implements the call site — a background worker, a retry wrapper, a test double — and nothing in
// this package can stop one of them handing over a nil.
//
// MEASURED, not assumed: http.NewRequestWithContext(nil, ...) returns (nil, "net/http: nil
// Context") on both darwin/arm64 and linux/arm64. WITHOUT THE GUARD httpRequest is that nil pointer
// and the next line, httpRequest.Header.Set("Content-Type", ...), dereferences it — so a caller's
// missing context takes the whole sidecar down rather than failing one operation.
func TestHTTPClientRefusesANilContextInsteadOfPanicking(t *testing.T) {
	var hits int64
	server := httptest.NewTLSServer(alwaysYesHandler(&hits))
	defer server.Close()
	client := NewHTTPClient(server.URL, server.Client(), fixedClock)

	var missing context.Context // a caller that never threaded one through
	result, err := client.Wrap(missing, validRequest())
	if err == nil {
		t.Fatalf("Wrap() with a nil context returned %d bytes and no error", len(result))
	}
	if err.Error() != "invalid KMS client request" {
		t.Fatalf("Wrap() with a nil context = %q, want %q", err, "invalid KMS client request")
	}
	if result != nil {
		t.Fatalf("Wrap() with a nil context refused but returned %d bytes", len(result))
	}
	if sent := atomic.LoadInt64(&hits); sent != 0 {
		t.Fatalf("a nil context still reached the KMS %d time(s)", sent)
	}

	// ANCHOR, last: the same client and request with a real context must complete, so the refusal
	// above is about the context and not about the fixture.
	anchor, err := client.Wrap(context.Background(), validRequest())
	if err != nil || string(anchor) != "data-key" {
		t.Fatalf("the anchor call returned %q, %v — the refusal above is refusing something already broken", anchor, err)
	}
}

// TestHTTPClientRefusesASmuggledFieldOrATrailingDocumentInTheResponse pins the two decoder guards
// in HTTPClient.call. Both fixtures are otherwise perfect responses: the request id the client
// sent, the object id it asked about, an operation id, application/json, Cache-Control: no-store,
// and a result of a legal length. Nothing else in the function can refuse them.
//
// WITHOUT THE DECODE ERROR CHECK the unknown field is accepted. MEASURED: encoding/json with
// DisallowUnknownFields populates every field it recognises and returns the error afterwards, so
// `result` is fully filled in — decoding `{...,"smuggled":"anything"}` returned
// `json: unknown field "smuggled"` with Result already set to the decoded bytes. Dropping the check
// therefore does not fall through to the field validation below; it returns the key material and
// the strictness that makes the response schema a schema is gone.
//
// WITHOUT THE TRAILING-DOCUMENT CHECK the second document is ignored. MEASURED: the second
// Decode returns a nil error, not io.EOF, and yields the extra object. A response body is one
// document; a body that is two is a disagreement about which one is the answer, and every other
// reader of that byte stream — a proxy log, an audit sink, a future streaming client — is free to
// pick the other one.
func TestHTTPClientRefusesASmuggledFieldOrATrailingDocumentInTheResponse(t *testing.T) {
	for _, test := range []struct {
		name   string
		body   func(requestID, objectID string) string
		anchor bool
	}{
		{
			name: "a smuggled unknown field",
			body: func(requestID, objectID string) string {
				return kmsResponseJSON(requestID, objectID, `,"smuggled":"anything"`)
			},
		},
		{
			name: "a second document after the response",
			body: func(requestID, objectID string) string {
				return kmsResponseJSON(requestID, objectID, "") +
					`{"request_id":"` + requestID + `","operation_id":"018f0000-0000-7000-8000-000000000003",` +
					`"object_id":"` + objectID + `","content_type":"application/vnd.regalia.envelope+json",` +
					`"result_base64":"c2Vjb25kLWFuc3dlcg=="}`
			},
		},
		{
			name:   "ANCHOR: exactly one document with only known fields",
			anchor: true,
			body: func(requestID, objectID string) string {
				return kmsResponseJSON(requestID, objectID, "")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				var body map[string]any
				_ = json.NewDecoder(request.Body).Decode(&body)
				objectID, _ := body["object_id"].(string)
				writer.Header().Set("Content-Type", "application/json")
				writer.Header().Set("Cache-Control", "no-store")
				_, _ = writer.Write([]byte(test.body(request.Header.Get("X-Request-ID"), objectID)))
			}))
			defer server.Close()

			client := NewHTTPClient(server.URL, server.Client(), fixedClock)
			result, err := client.Wrap(context.Background(), validRequest())
			if test.anchor {
				if err != nil || string(result) != "data-key" {
					t.Fatalf("the anchor response was refused: %q, %v — every refusal above is refusing something already broken", result, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Wrap() accepted %s and returned %q", test.name, result)
			}
			if err.Error() != "KMS operation failed" {
				t.Fatalf("Wrap() with %s = %q, want %q", test.name, err, "KMS operation failed")
			}
			if result != nil {
				t.Fatalf("Wrap() refused %s but returned %d bytes", test.name, len(result))
			}
		})
	}
}

// TestServeUnixRefusesAnUnusableConfigurationBeforeTouchingTheFilesystem pins both arms of
// ServeUnix's first guard.
//
// WITHOUT `socketPath == ""` the daemon stats the PROCESS WORKING DIRECTORY as the socket's parent
// — filepath.Dir("") is "." — and then applies the group-writability rule to it, so an empty path
// in the config file is reported either as a permissions problem with a directory nobody named or,
// on Linux, gets past net.Listen entirely: measured there, net.Listen("unix", "") succeeds by
// autobinding an ABSTRACT socket, which has no filesystem entry and no permission bits at all.
//
// WITHOUT `adapter == nil` the daemon binds the socket, registers a nil KeyServiceServer and
// serves: the misconfiguration is discovered by the first client, in a handler, on a socket that
// already exists and looks healthy.
func TestServeUnixRefusesAnUnusableConfigurationBeforeTouchingTheFilesystem(t *testing.T) {
	for _, test := range []struct {
		name    string
		path    func(directory string) string
		adapter *Server
		anchor  bool
	}{
		{
			name:    "no socket path",
			path:    func(string) string { return "" },
			adapter: New(&mockKMS{}),
		},
		{
			name:    "no adapter",
			path:    func(directory string) string { return filepath.Join(directory, "no-adapter.sock") },
			adapter: nil,
		},
		{
			name:    "ANCHOR: a usable path and adapter",
			path:    func(directory string) string { return filepath.Join(directory, "anchor.sock") },
			adapter: New(&mockKMS{}),
			anchor:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := socketDir(t)
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			socket := test.path(directory)
			// Bounded, because a guard that stops refusing does not return — it serves.
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			err := ServeUnix(ctx, socket, test.adapter)

			if test.anchor {
				if err != nil {
					t.Fatalf("the anchor configuration was refused with %q, so every refusal above is refusing something already broken", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ServeUnix() with %s served for the whole context and returned no error", test.name)
			}
			if err.Error() != "invalid SOPS adapter configuration" {
				t.Fatalf("ServeUnix() with %s = %q, want %q — a different message means the guard let it through and something further down refused instead", test.name, err, "invalid SOPS adapter configuration")
			}
			if socket != "" {
				if _, statErr := os.Lstat(socket); !errors.Is(statErr, fs.ErrNotExist) {
					t.Fatalf("ServeUnix() with %s created %s: the refusal must happen before net.Listen", test.name, socket)
				}
			}
		})
	}
}

// TestServeUnixRefusesToTakeOverAPathItDidNotCreate pins the Lstat guard.
//
// TestServeUnixRefusesExistingPath already builds an occupied path and still passes with the whole
// guard deleted, because it asserts only `err == nil`: net.Listen then fails with "address already
// in use" and the file survives by luck rather than by the check. This asserts the message.
//
// WITHOUT THE GUARD the daemon takes over whatever is already at the path, and what that costs
// depends on the platform — measured on both. A live socket is refused by bind(2) with EADDRINUSE,
// which looks like a refusal from outside but is not this one. A DANGLING SYMLINK at the socket
// path is refused by bind on linux/arm64, also EADDRINUSE, and FOLLOWED on darwin/arm64: bind
// creates the adapter's socket at the link's target, so the path the operator configured and the
// path clients connect to are two different files. The message is the only place the difference
// between "this is not mine" and "this failed to bind" survives.
//
// The `err == nil` arm on its own cannot be pinned, and no test here pretends to: measured,
// os.IsNotExist(nil) is false, so `!os.IsNotExist(err)` is already true for every path that exists
// and deleting `err == nil` leaves the same refusal with the same message.
//
// The `!os.IsNotExist(err)` arm reads any stat error other than ENOENT as "the path is free". It is
// also what makes `!info.IsDir()` unreachable: with it gone, a socket path whose parent is a
// regular file gets past here and is refused four lines later by the IsDir check instead.
func TestServeUnixRefusesToTakeOverAPathItDidNotCreate(t *testing.T) {
	for _, test := range []struct {
		name   string
		build  func(t *testing.T, directory string) string
		anchor bool
	}{
		{
			name: "a regular file already at the socket path",
			build: func(t *testing.T, directory string) string {
				path := filepath.Join(directory, "occupied.sock")
				if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name: "a dangling symlink already at the socket path",
			build: func(t *testing.T, directory string) string {
				path := filepath.Join(directory, "dangling.sock")
				if err := os.Symlink(filepath.Join(directory, "nowhere"), path); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			// Lstat reports ENOTDIR here, not ENOENT: the `!os.IsNotExist(err)` arm alone.
			name: "a socket path whose parent is a regular file",
			build: func(t *testing.T, directory string) string {
				parent := filepath.Join(directory, "parent-is-a-file")
				if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(parent, "child.sock")
			},
		},
		{
			name:   "ANCHOR: a name nothing occupies",
			anchor: true,
			build: func(_ *testing.T, directory string) string {
				return filepath.Join(directory, "free.sock")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := socketDir(t)
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			socket := test.build(t, directory)
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			err := ServeUnix(ctx, socket, New(&mockKMS{}))

			if test.anchor {
				if err != nil {
					t.Fatalf("the anchor path was refused with %q, so every refusal above is refusing something already broken", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ServeUnix() bound %s and returned no error", test.name)
			}
			if err.Error() != "refusing to replace existing SOPS socket path" {
				t.Fatalf("ServeUnix() with %s = %q, want %q — a different message means this guard passed the path on and something further down objected", test.name, err, "refusing to replace existing SOPS socket path")
			}
		})
	}
}

// TestServeUnixNamesTheSocketDirectoryItCouldNotStat pins the os.Stat error check on the socket's
// parent.
//
// WITHOUT THE GUARD info is a nil os.FileInfo and the very next line calls info.IsDir() on it, so a
// socket path under a directory that is not there takes the process down with a nil pointer
// dereference instead of naming the directory. Both fixtures below get past the Lstat guard
// honestly — measured, on darwin and linux: lstat of a path under a dangling symlink reports
// ENOENT, and so does a name with a trailing slash whose parent does not exist — so this guard is
// the only thing between them and that dereference.
func TestServeUnixNamesTheSocketDirectoryItCouldNotStat(t *testing.T) {
	for _, test := range []struct {
		name   string
		build  func(t *testing.T, directory string) string
		anchor bool
	}{
		{
			name: "a parent that is a dangling symlink",
			build: func(t *testing.T, directory string) string {
				parent := filepath.Join(directory, "runtime-dir")
				if err := os.Symlink(filepath.Join(directory, "never-created"), parent); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(parent, "sops.sock")
			},
		},
		{
			// filepath.Dir of a name with a trailing slash is the name itself, which does not exist.
			name: "a socket name written with a trailing slash",
			build: func(_ *testing.T, directory string) string {
				return filepath.Join(directory, "sops.sock") + string(os.PathSeparator)
			},
		},
		{
			name:   "ANCHOR: a parent that is a real directory",
			anchor: true,
			build: func(_ *testing.T, directory string) string {
				return filepath.Join(directory, "sops.sock")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := socketDir(t)
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			socket := test.build(t, directory)
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			err := ServeUnix(ctx, socket, New(&mockKMS{}))

			if test.anchor {
				if err != nil {
					t.Fatalf("the anchor path was refused with %q, so every refusal above is refusing something already broken", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ServeUnix() accepted %s and returned no error", test.name)
			}
			if !strings.HasPrefix(err.Error(), "stat the SOPS socket directory: ") {
				t.Fatalf("ServeUnix() with %s = %q, want it to name the directory it could not stat", test.name, err)
			}
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("ServeUnix() with %s = %q, want the wrapped os.Stat error to survive so an operator can see WHY", test.name, err)
			}
		})
	}
}

// TestServeUnixReportsWhyItCouldNotBindTheSocket pins the net.Listen error check.
//
// A Unix socket address is capped by sun_path — 104 bytes on darwin, 108 on Linux — which is far
// below PATH_MAX, so a long-but-legal path passes Lstat and passes the directory checks and bind(2)
// is the first thing to refuse it. MEASURED on both platforms: "listen unix <path>: bind: invalid
// argument".
//
// WITHOUT THE GUARD listener is nil and execution continues: `defer listener.Close()` is registered
// on a nil interface, os.Chmod fails on the socket that was never created, and the deferred Close
// panics on the way out. The operator loses the one line that says the path could not be bound and
// gets a nil dereference in its place.
func TestServeUnixReportsWhyItCouldNotBindTheSocket(t *testing.T) {
	for _, test := range []struct {
		name   string
		socket func(directory string) string
		anchor bool
	}{
		{
			name: "a socket path longer than sun_path",
			socket: func(directory string) string {
				return filepath.Join(directory, strings.Repeat("n", 200)+".sock")
			},
		},
		{
			name:   "ANCHOR: the same directory with a short name",
			anchor: true,
			socket: func(directory string) string { return filepath.Join(directory, "short.sock") },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := socketDir(t)
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			err := ServeUnix(ctx, test.socket(directory), New(&mockKMS{}))

			if test.anchor {
				if err != nil {
					t.Fatalf("the anchor path was refused with %q, so the refusal above is refusing something already broken", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ServeUnix() with %s returned no error", test.name)
			}
			// The other refusals in ServeUnix are errors.New and fmt.Errorf values; only the
			// net.Listen check returns the *net.OpError, so this is the guard and nothing else.
			var operation *net.OpError
			if !errors.As(err, &operation) || operation.Op != "listen" || operation.Net != "unix" {
				t.Fatalf("ServeUnix() with %s = %q, want the bind failure from net.Listen (a *net.OpError with Op \"listen\", Net \"unix\")", test.name, err)
			}
		})
	}
}

// TestServeUnixRefusesToServeASocketItCouldNotNarrowTo0600 pins the os.Chmod error check.
//
// LINUX ONLY, AND NOT FOR CONVENIENCE. The guard needs a socket that binds successfully and then
// cannot be chmod-ed, and Go's Linux syscall layer offers exactly that: a name beginning with '@'
// is translated to a leading NUL, which is the ABSTRACT namespace — the socket exists in the
// network namespace with no filesystem entry, so os.Chmod on that name reports ENOENT. MEASURED on
// linux/arm64 (golang:1.26): net.Listen("unix", "@name") returned no error, no directory entry
// appeared, and os.Chmod returned "chmod @name: no such file or directory". MEASURED on
// darwin/arm64: '@' is an ordinary character, the listen creates a real file named "@name", and the
// Chmod succeeds — there is no reachable failure to assert, so the test skips rather than pretend.
//
// WITHOUT THE GUARD the daemon serves on that abstract socket. An abstract socket carries NO
// permission bits: every process in the network namespace may connect, and this adapter's whole
// security argument is that the socket has exactly one trust domain because it is 0600 under a
// dedicated account. The Chmod error is the only thing that notices the mode was never applied.
func TestServeUnixRefusesToServeASocketItCouldNotNarrowTo0600(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("the abstract Unix namespace, the only reachable os.Chmod failure here, is Linux-only; on %s '@' names an ordinary file and the Chmod succeeds", runtime.GOOS)
	}
	directory := socketDir(t)
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	// Relative names resolve against the working directory, which is also what filepath.Dir("@x")
	// reports as the socket's parent; chdir so that parent is this 0700 directory and not the
	// package source tree.
	t.Chdir(directory)

	abstract := "@regalia-sops-guard-test"
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := ServeUnix(ctx, abstract, New(&mockKMS{}))
	if err == nil {
		t.Fatal("ServeUnix() served on an abstract socket: it has no permission bits at all, so every process in the network namespace can ask this sidecar to unwrap data keys")
	}
	// A bind failure would read "listen unix @...: bind: ..." and would mean the fixture never got
	// as far as the Chmod; naming chmod is what makes this guard the detector.
	if !strings.Contains(err.Error(), "chmod") || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ServeUnix() = %q, want the os.Chmod failure on a socket with no filesystem entry", err)
	}

	// ANCHOR, last: a filesystem socket in the same directory, under the same working directory and
	// the same adapter, must serve and shut down cleanly.
	anchorCtx, anchorCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer anchorCancel()
	if err := ServeUnix(anchorCtx, filepath.Join(directory, "anchor.sock"), New(&mockKMS{})); err != nil {
		t.Fatalf("the anchor socket was refused with %q, so the refusal above is refusing something already broken", err)
	}
}

// signer returns a crypto.Signer for the TLS fixtures. ECDSA rather than the neighbouring tests'
// rsa.GenerateKey purely for speed: the guard under test asks whether the key implements
// crypto.Signer, which both satisfy.
func signer(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestClientTLSConfigRefusesAPrivateKeyThatIsNotASigner pins the crypto.Signer assertion.
//
// It is the whole reason the constructor takes a tls.Certificate rather than key bytes: a
// PKCS#11-backed key can only ever be a crypto.Signer, so anything else in that field is raw key
// material that someone read off disk. WITHOUT THE GUARD ClientTLSConfig returns a *tls.Config that
// looks correct and fails at handshake time instead — crypto/tls rejects the certificate on the
// first KMS call, once per connection, with a message about an unimplemented interface rather than
// about a policy the sidecar is supposed to enforce at construction.
func TestClientTLSConfigRefusesAPrivateKeyThatIsNotASigner(t *testing.T) {
	roots := x509.NewCertPool()
	for _, test := range []struct {
		name       string
		privateKey any
		anchor     bool
	}{
		{name: "raw private key bytes", privateKey: []byte("308204a30201000282010100c0ffee")},
		{name: "a PEM string", privateKey: "-----BEGIN PRIVATE KEY-----"},
		{name: "no private key at all", privateKey: nil},
		{name: "ANCHOR: a crypto.Signer", privateKey: signer(t), anchor: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate := tls.Certificate{Certificate: [][]byte{{1, 2, 3}}, PrivateKey: test.privateKey}
			config, err := ClientTLSConfig(certificate, roots, "kms.internal.example")

			if test.anchor {
				if err != nil {
					t.Fatalf("the anchor certificate was refused with %q, so every refusal above is refusing something already broken", err)
				}
				if config == nil || len(config.Certificates) != 1 {
					t.Fatalf("the anchor produced %#v", config)
				}
				return
			}
			if err == nil {
				t.Fatalf("ClientTLSConfig() accepted %s and returned %#v", test.name, config)
			}
			if err.Error() != "KMS client private key must implement crypto.Signer" {
				t.Fatalf("ClientTLSConfig() with %s = %q, want %q — a different message means an earlier check refused it and the Signer rule was never reached", test.name, err, "KMS client private key must implement crypto.Signer")
			}
			if config != nil {
				t.Fatalf("ClientTLSConfig() refused %s but returned a config: %#v", test.name, config)
			}
		})
	}
}

// TestNewMTLSHTTPClientDoesNotBuildAClientWhenTheTLSConfigIsRefused pins the error propagation from
// ClientTLSConfig.
//
// TestNewMTLSHTTPClientHasBoundedTransportAndNoProxyOrRedirect reaches the error return only
// through the timeout rule above this one, so the propagation itself was never exercised.
//
// WITHOUT THE GUARD tlsConfig is nil and the function returns an *http.Client whose
// Transport.TLSClientConfig is nil — which is not "no TLS settings", it is Go's DEFAULTS: the
// system root pool instead of the pinned Regalia roots, no client certificate, and no TLS 1.3
// floor. The sidecar would then happily connect to anything holding a publicly trusted certificate
// for that name and complete no mutual authentication at all, and the only sign would be that the
// KMS rejected it — if the thing it reached was the KMS.
func TestNewMTLSHTTPClientDoesNotBuildAClientWhenTheTLSConfigIsRefused(t *testing.T) {
	key := signer(t)
	certificate := tls.Certificate{Certificate: [][]byte{{1, 2, 3}}, PrivateKey: key}
	for _, test := range []struct {
		name        string
		certificate tls.Certificate
		roots       *x509.CertPool
		serverName  string
		want        string
	}{
		{
			name:        "no root pool",
			certificate: certificate,
			serverName:  "kms.internal.example",
			want:        "invalid KMS TLS configuration",
		},
		{
			name:        "a URL where the server name belongs",
			certificate: certificate,
			roots:       x509.NewCertPool(),
			serverName:  "https://kms.internal.example",
			want:        "invalid KMS TLS configuration",
		},
		{
			name:        "a private key that is not a signer",
			certificate: tls.Certificate{Certificate: [][]byte{{1, 2, 3}}, PrivateKey: []byte("raw bytes")},
			roots:       x509.NewCertPool(),
			serverName:  "kms.internal.example",
			want:        "KMS client private key must implement crypto.Signer",
		},
		{
			name:        "ANCHOR: a configuration ClientTLSConfig accepts",
			certificate: certificate,
			roots:       x509.NewCertPool(),
			serverName:  "kms.internal.example",
			want:        "",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A timeout the rule above this guard accepts, so the guard is the only refusal left.
			client, err := NewMTLSHTTPClient(test.certificate, test.roots, test.serverName, 15*time.Second)

			if test.want == "" {
				if err != nil {
					t.Fatalf("the anchor configuration was refused with %q, so every refusal above is refusing something already broken", err)
				}
				transport, ok := client.Transport.(*http.Transport)
				if !ok || transport.TLSClientConfig == nil {
					t.Fatalf("the anchor built a client with no TLS configuration: %#v", client)
				}
				return
			}
			if err == nil {
				t.Fatalf("NewMTLSHTTPClient() with %s returned a client: its Transport.TLSClientConfig is nil, so it would dial the KMS with the system roots and no client certificate", test.name)
			}
			if err.Error() != test.want {
				t.Fatalf("NewMTLSHTTPClient() with %s = %q, want %q", test.name, err, test.want)
			}
			if client != nil {
				t.Fatalf("NewMTLSHTTPClient() refused %s but returned %#v", test.name, client)
			}
		})
	}
}
