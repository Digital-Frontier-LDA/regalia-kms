package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// handoverPKI is a client CA with two client certificates, the old and the new, and one from another CA.
type handoverPKI struct {
	roots            *x509.CertPool
	old, new, alien  *x509.Certificate
	oldKey, alienKey ed25519.PrivateKey
}

func newHandoverPKI(t *testing.T) handoverPKI {
	t.Helper()
	ca := func(name string) (*x509.Certificate, ed25519.PrivateKey) {
		public, private, _ := ed25519.GenerateKey(rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
		if err != nil {
			t.Fatal(err)
		}
		certificate, _ := x509.ParseCertificate(der)
		return certificate, private
	}
	issue := func(issuer *x509.Certificate, issuerKey ed25519.PrivateKey, name string) (*x509.Certificate, ed25519.PrivateKey) {
		public, private, _ := ed25519.GenerateKey(rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, public, issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		certificate, _ := x509.ParseCertificate(der)
		return certificate, private
	}
	root, rootKey := ca("handover-test-ca")
	other, otherKey := ca("another-ca")
	var p handoverPKI
	p.roots = x509.NewCertPool()
	p.roots.AddCert(root)
	p.old, p.oldKey = issue(root, rootKey, "sitea-shipper-2026")
	p.new, _ = issue(root, rootKey, "sitea-shipper-2027")
	p.alien, p.alienKey = issue(other, otherKey, "sitea-shipper-forged")
	return p
}

func postHandover(t *testing.T, collector *Collector, caller *x509.Certificate, old *x509.Certificate, key ed25519.PrivateKey) int {
	t.Helper()
	signature := ed25519.Sign(key, HandoverPreimage(fingerprintOf(old), fingerprintOf(caller)))
	body, _ := json.Marshal(map[string]string{"old_certificate": base64.StdEncoding.EncodeToString(old.Raw), "signature": hex.EncodeToString(signature)})
	request := httptest.NewRequest("POST", "/v1/handover", bytes.NewReader(body))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{caller}}
	recorder := httptest.NewRecorder()
	collector.Handler().ServeHTTP(recorder, request)
	return recorder.Code
}

// TestARotatedCertificateContinuesItsStreams: #291's done-when. A trail pruned through line 3 and
// shipped to line 5 under the old certificate ships on under the new one, after a hand-over, with no
// alarm: the stream, its head and its receipts continue; the old certificate is refused from then on.
func TestARotatedCertificateContinuesItsStreams(t *testing.T) {
	pki := newHandoverPKI(t)
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	collector.SetClientRoots(pki.roots)
	_, receiptKey, _ := ed25519.GenerateKey(rand.Reader)
	collector.SetReceiptKey(receiptKey)
	data := trailLines(nil, 7, "sync-pull")
	events, _ := TrailEvents("sync", data)
	for _, event := range events[:5] {
		if code := postCollectorEvent(t, collector.Handler(), pki.old, "sitea.sync", event).Code; code != 204 {
			t.Fatalf("old certificate, event %d: %d", event.Sequence, code)
		}
	}
	if code := postHandover(t, collector, pki.new, pki.old, pki.oldKey); code != 204 {
		t.Fatalf("the hand-over answered %d", code)
	}
	// the new certificate sees the old stream: its head, and the next event commits after it
	if head, hash := getCollectorPosition(t, collector.Handler(), pki.new, "sitea.sync"); head != 5 || hash != events[4].Hash {
		t.Fatalf("after the hand-over the new certificate sees head %d", head)
	}
	if code := postCollectorEvent(t, collector.Handler(), pki.new, "sitea.sync", events[5]).Code; code != 204 {
		t.Fatalf("the new certificate's next event: %d", code)
	}
	// a pruned trail (marker at line 3) ships on from the new certificate: no tamper alarm
	walker, _ := NewTrailWalker("sync", TrailStart{})
	lines := bytes.SplitAfter(data, []byte("\n"))
	for _, line := range lines[:3] {
		if _, err := walker.Next(line); err != nil {
			t.Fatal(err)
		}
	}
	sink := &handlerSink{t: t, collector: collector, certificate: pki.new, site: "sitea.sync"}
	committed, _, err := ShipTrailFrom(context.Background(), sink, "sitea.sync", "sync", walker.Last(), bytes.Join(lines[3:], nil))
	if err != nil || committed != 7 || len(sink.alarms) != 0 {
		t.Fatalf("the pruned trail after a rotation: committed %d, %v, alarms %q", committed, err, sink.alarms)
	}
	// receipts name the caller's own certificate, so the host's prune checks them against its new one
	request := httptest.NewRequest("GET", "/v1/receipt?sequence=7", nil)
	request.Header.Set("X-Regalia-Site", "sitea.sync")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{pki.new}}
	recorder := httptest.NewRecorder()
	collector.Handler().ServeHTTP(recorder, request)
	var receipt Receipt
	_ = json.Unmarshal(recorder.Body.Bytes(), &receipt)
	signature, _ := hex.DecodeString(receipt.Signature)
	if !ed25519.Verify(receiptKey.Public().(ed25519.PublicKey), ReceiptPreimage(fingerprintOf(pki.new), "sitea.sync", 7, receipt.EventHash, receipt.LineSHA256, receipt.LineChain), signature) {
		t.Fatalf("the receipt does not name the new certificate: %s", recorder.Body.String())
	}
	// the old certificate is retired: it can neither write nor read a position
	if code := postCollectorEvent(t, collector.Handler(), pki.old, "sitea.sync", events[6]).Code; code != 403 {
		t.Fatalf("the retired certificate wrote: %d", code)
	}
	// the hand-over survives a restart
	collector.Close()
	reopened, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if head, _ := getCollectorPosition(t, reopened.Handler(), pki.new, "sitea.sync"); head != 7 {
		t.Fatalf("after a restart the new certificate sees head %d", head)
	}
	if code := postCollectorEvent(t, reopened.Handler(), pki.old, "sitea.sync", events[6]).Code; code != 403 {
		t.Fatalf("after a restart the retired certificate wrote: %d", code)
	}
}

// handlerSink is a TrailSink that calls the collector's handler as a certificate would.
type handlerSink struct {
	t           *testing.T
	collector   *Collector
	certificate *x509.Certificate
	site        string
	alarms      []string
}

func (s *handlerSink) Send(_ context.Context, event Event) error {
	if code := postCollectorEvent(s.t, s.collector.Handler(), s.certificate, s.site, event).Code; code != 204 {
		return ErrSinkUnavailable
	}
	return nil
}

func (s *handlerSink) CommittedHead(context.Context, string) (uint64, string, error) {
	head, hash := getCollectorPosition(s.t, s.collector.Handler(), s.certificate, s.site)
	return head, hash, nil
}

func (s *handlerSink) ReportAlarm(_ context.Context, _ uint64, _ string, reason string) error {
	s.alarms = append(s.alarms, reason)
	return nil
}

func TestAHandoverIsRefusedUnlessItHolds(t *testing.T) {
	pki := newHandoverPKI(t)
	collector, err := OpenCollector(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	events, _ := TrailEvents("sync", trailLines(nil, 2, "sync-pull"))
	if code := postHandover(t, collector, pki.new, pki.old, pki.oldKey); code != 503 {
		t.Fatalf("with no client CA given, a hand-over answered %d", code)
	}
	collector.SetClientRoots(pki.roots)
	if code := postHandover(t, collector, pki.new, pki.old, pki.oldKey); code != 409 {
		t.Fatalf("an old certificate with no streams: %d", code)
	}
	postCollectorEvent(t, collector.Handler(), pki.old, "sitea.sync", events[0])
	for label, code := range map[string]int{
		"signed by another key":            postHandover(t, collector, pki.new, pki.old, pki.alienKey),
		"an old certificate of another CA": postHandover(t, collector, pki.new, pki.alien, pki.alienKey),
		"to itself":                        postHandover(t, collector, pki.old, pki.old, pki.oldKey),
	} {
		if code == 204 {
			t.Errorf("%s: the hand-over was taken", label)
		}
	}
	postCollectorEvent(t, collector.Handler(), pki.new, "sitea.admission", events[0]) // the new identity's own stream
	if code := postHandover(t, collector, pki.new, pki.old, pki.oldKey); code != 409 {
		t.Fatalf("a new identity with streams of its own: %d", code)
	}
}

func TestAHandoverIsTakenOnceAndTheStateHasOneHolder(t *testing.T) {
	pki := newHandoverPKI(t)
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	collector.SetClientRoots(pki.roots)
	events, _ := TrailEvents("sync", trailLines(nil, 1, "sync-pull"))
	postCollectorEvent(t, collector.Handler(), pki.old, "sitea.sync", events[0])
	if code := postHandover(t, collector, pki.new, pki.old, pki.oldKey); code != 204 {
		t.Fatal(code)
	}
	if code := postHandover(t, collector, pki.new, pki.old, pki.oldKey); code == 204 {
		t.Fatal("a replayed hand-over was taken")
	}
	if _, err := OpenCollector(stateDir); err == nil || !strings.Contains(err.Error(), "held by another collector") {
		t.Fatalf("a second holder of the state: %v", err)
	}
	if err := collector.RecordOperatorHandover(fingerprintOf(pki.new), fingerprintOf(pki.alien), ""); err == nil {
		t.Fatal("an operator hand-over without a reason was taken")
	}
	if err := collector.RecordOperatorHandover(fingerprintOf(pki.new), fingerprintOf(pki.alien), "the 2027 key was lost; replaced by ticket 42"); err != nil {
		t.Fatalf("the operator hand-over: %v", err)
	}
	if head, _ := getCollectorPosition(t, collector.Handler(), pki.alien, "sitea.sync"); head != 1 {
		t.Fatalf("after two hand-overs the third identity sees head %d", head)
	}
	collector.Close()
	if reasons := collectorAlarmReasons(t, stateDir); len(reasons) < 2 || !strings.HasPrefix(reasons[len(reasons)-1], "record: ") {
		t.Fatalf("the hand-overs are not recorded in the alarm log: %q", reasons)
	}
}
