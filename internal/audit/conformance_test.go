package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// conformanceRig is a collector behind mutual TLS, as the shippers reach one: this repository's own
// regalia-audit-collector (OpenCollector) as the stand-in for the external service the owner picks (#351), or
// any handler a test puts in front of it.
type conformanceRig struct {
	target   ConformanceTarget
	receipts ed25519.PrivateKey
}

func newConformanceRig(t *testing.T, wrap func(http.Handler) http.Handler) conformanceRig {
	t.Helper()
	authority, clientCertificate, clientKey, serverTLS := collectorTestTLS(t)
	collector, err := OpenCollector(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { collector.Close() })
	_, receiptKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	collector.SetReceiptKey(receiptKey)
	var handler http.Handler = collector.Handler()
	if wrap != nil {
		handler = wrap(handler)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.StartTLS()
	t.Cleanup(server.Close)
	client, err := NewMTLSHTTPClient(tls.Certificate{Certificate: [][]byte{clientCertificate.Raw}, PrivateKey: clientKey}, authority, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	sink, err := NewHTTPSink(server.URL, client, 5*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	anonymous, err := NewHTTPSink(server.URL, &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: authority, ServerName: "127.0.0.1"}}}, 5*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	identity := sha256.Sum256(clientCertificate.Raw)
	return conformanceRig{target: ConformanceTarget{Sink: sink, Anonymous: anonymous, Identity: hex.EncodeToString(identity[:]),
		ReceiptKeys: []ed25519.PublicKey{receiptKey.Public().(ed25519.PublicKey)}, Site: "sitea"}, receipts: receiptKey}
}

func failed(checks []ConformanceCheck) []string {
	var out []string
	for _, c := range checks {
		if !c.Passed {
			out = append(out, c.Rule+": "+c.Detail)
		}
	}
	return out
}

func TestOurCollectorMeetsTheContract(t *testing.T) {
	rig := newConformanceRig(t, nil)
	checks, err := CheckConformance(context.Background(), rig.target)
	if err != nil {
		t.Fatal(err)
	}
	if !Conforms(checks) || len(checks) != 12 {
		t.Fatalf("%d checks; failed: %q", len(checks), failed(checks))
	}
}

// acceptsEverything is a collector that acknowledges every event it is sent, rewrites and gaps included: what a
// careless external service might do. The contract's checks must catch it.
func acceptsEverything(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/events" {
			body, _ := io.ReadAll(r.Body)
			var event Event
			if json.Unmarshal(body, &event) == nil && event.Sequence > 3 || strings.Contains(string(body), "rewritten") {
				w.Header().Set("X-Regalia-Audit-Hash", event.Hash)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		next.ServeHTTP(w, r)
	})
}

func TestACollectorThatAcceptsRewritesOrGapsDoesNotConform(t *testing.T) {
	rig := newConformanceRig(t, acceptsEverything)
	checks, err := CheckConformance(context.Background(), rig.target)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(failed(checks), "\n")
	if Conforms(checks) || !strings.Contains(got, "a DIFFERENT event at a committed sequence is refused") ||
		!strings.Contains(got, "an event out of order (a gap) is refused") {
		t.Fatalf("a collector that takes rewrites and gaps passed; failed: %q", failed(checks))
	}
}

func TestReceiptsByAKeyThatIsNotPinnedDoNotConform(t *testing.T) {
	rig := newConformanceRig(t, nil)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	rig.target.ReceiptKeys = []ed25519.PublicKey{other}
	checks, _ := CheckConformance(context.Background(), rig.target)
	got := failed(checks)
	if Conforms(checks) || len(got) != 1 || !strings.Contains(got[0], "signed ("+ReceiptDomain+") by a pinned receipt key") {
		t.Fatalf("failed: %q", got)
	}
}

func TestAnUnreachableCollectorFailsTheFirstCheckAndStops(t *testing.T) {
	rig := newConformanceRig(t, nil)
	closed, err := NewHTTPSink("https://127.0.0.1:1", rig.target.Sink.client, 2*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	rig.target.Sink = closed
	checks, _ := CheckConformance(context.Background(), rig.target)
	if len(checks) != 1 || checks[0].Passed {
		t.Fatalf("checks: %+v", checks)
	}
}
