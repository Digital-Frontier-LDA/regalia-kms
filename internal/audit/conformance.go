package audit

// CONFORMANCE: does an audit collector meet the contract the shippers rely on (deploy/baremetal/AUDIT-COLLECTOR.md)?
//
// The owner decided the collector is an EXTERNAL service (#351): each node's shippers send its trails to an outside
// service the owner chooses, so a compromised node cannot erase its own record. Any such service is checked here
// against the contract ONLY, through the same client the shippers use (HTTPSink, ShipTrail), never through its
// internals: `regalia-audit-ship conformance` runs these checks against a candidate, and the tests run them against
// this repository's own regalia-audit-collector as the stand-in.
//
// It writes to ONE fresh stream of its own, "<site>.conformance-<random>": three synthetic trail lines, the
// refusals it provokes, and one alarm. Nothing of a real trail is sent, and no real stream is touched.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ConformanceAlarmReason is the reason the conformance run's one alarm carries: a test, never a tampered trail.
const ConformanceAlarmReason = "CONFORMANCE RUN (regalia-audit-ship conformance): a test alarm on a conformance stream, not a tampered trail"

// ConformanceCheck is one rule of the contract and whether the collector met it.
type ConformanceCheck struct {
	Rule   string
	Passed bool
	Detail string
}

// ConformanceTarget is what the checks need: the shippers' own sink for this host, the same collector reached with no
// client certificate, this host's identity (SHA-256 of its client certificate's DER, hex), and the pinned receipt keys.
type ConformanceTarget struct {
	Sink        *HTTPSink
	Anonymous   *HTTPSink
	Identity    string
	ReceiptKeys []ed25519.PublicKey
	Site        string // the host's site; the stream is <site>.conformance-<random>
}

// conformanceLines are n chained trail lines as trails.py writes them (sorted keys, no spaces, ASCII, newline).
func conformanceLines(n int, event string) []byte {
	var out, previous []byte
	for seq := 1; seq <= n; seq++ {
		prev := ""
		if previous != nil {
			sum := sha256.Sum256(previous)
			prev = hex.EncodeToString(sum[:])
		}
		line := []byte(fmt.Sprintf(`{"at":%d,"event":%q,"outcome":"ALLOW","prev":%q,"seq":%d}`+"\n", 1790000000+seq, event, prev, seq))
		out = append(out, line...)
		previous = line
	}
	return out
}

// conformanceRewrite is `data` (three lines) with its THIRD line replaced by another that chains onto the same second
// line: the shape of a rewritten trail, refused only because it differs at a committed position.
func conformanceRewrite(data []byte) []byte {
	lines := bytes.SplitAfter(data, []byte("\n"))
	sum := sha256.Sum256(lines[1])
	third := []byte(fmt.Sprintf(`{"at":%d,"event":"rewritten","outcome":"DENY","prev":%q,"seq":3}`+"\n", 1790000003, hex.EncodeToString(sum[:])))
	return append(append(append([]byte(nil), lines[0]...), lines[1]...), third...)
}

// CheckConformance runs every rule in order and returns them all; an error is returned only when the checks could
// not run at all (the stream name). A collector conforms when every check passed.
func CheckConformance(ctx context.Context, target ConformanceTarget) ([]ConformanceCheck, error) {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	name := "conformance-" + hex.EncodeToString(random)
	stream := target.Site + "." + name
	if !collectorSitePattern.MatchString(stream) {
		return nil, fmt.Errorf("the stream %q is not one a collector accepts", stream)
	}
	sink := target.Sink.WithSite(stream)
	var checks []ConformanceCheck
	check := func(rule string, passed bool, detail string, args ...any) bool {
		checks = append(checks, ConformanceCheck{Rule: rule, Passed: passed, Detail: fmt.Sprintf(detail, args...)})
		return passed
	}

	// 1. reachable, with mutual TLS, and ready
	if !check("answers HEAD /v1/health/ready with 204 over mutual TLS", sink.Ready(ctx), "%s", target.Sink.baseURL) {
		return checks, nil // nothing else can be judged against a collector that does not answer
	}
	head, _, err := sink.CommittedHead(ctx, stream)
	check("GET /v1/stream-position: a fresh stream is at 0", err == nil && head == 0, "head %d, %v", head, err)

	// 2. commits what it is sent, durably acknowledged, and reports the head
	data := conformanceLines(3, "conformance")
	events, err := TrailEvents(name, data)
	if err != nil {
		return nil, err
	}
	committed, total, err := ShipTrail(ctx, sink, stream, name, data)
	check("POST /v1/events: three chained events committed, each acknowledged by X-Regalia-Audit-Hash", err == nil && committed == 3 && total == 3,
		"%d of %d, %v", committed, total, err)
	head, hash, err := sink.CommittedHead(ctx, stream)
	check("the head is the last event committed, by sequence and hash", err == nil && head == 3 && hash == events[2].Hash, "%d %s, %v", head, hash, err)

	// 3. idempotent on the same event, and never accepts another at a committed position or out of order
	check("the same event sent again is acknowledged, not appended (a lost acknowledgement is retried)",
		sink.Send(ctx, events[2]) == nil, "re-send of sequence 3")
	other, _ := TrailEvents(name, conformanceRewrite(data))
	rewrittenOK := len(other) == 3 && other[1].Hash == events[1].Hash && other[2].Hash != events[2].Hash
	check("a DIFFERENT event at a committed sequence is refused (a rewrite)", rewrittenOK && sink.Send(ctx, other[2]) != nil, "rewritten sequence 3")
	five, _ := TrailEvents(name, conformanceLines(5, "conformance"))
	check("an event out of order (a gap) is refused", len(five) == 5 && sink.Send(ctx, five[4]) != nil, "sequence 5 after 3")
	head, hash, err = sink.CommittedHead(ctx, stream)
	check("refusals leave the head where it was", err == nil && head == 3 && hash == events[2].Hash, "%d %s, %v", head, hash, err)
	// the positive control: the RIGHT next event is still taken, so the two refusals above were about their content,
	// not a collector that fails every request after the first three (regalia-kms-3e on #365)
	sendErr := errors.New("no fourth event")
	if len(five) == 5 {
		sendErr = sink.Send(ctx, five[3])
	}
	head, hash, err = sink.CommittedHead(ctx, stream)
	check("the correct next event is still committed after the refusals (they were about content)",
		sendErr == nil && err == nil && head == 4 && hash == five[3].Hash, "sequence 4: %v; head %d %s, %v", sendErr, head, hash, err)

	// 4. signs receipts with a pinned key, over exactly what it holds
	receipt, err := sink.Receipt(ctx, 3)
	chain := LineChainStart
	for _, event := range events {
		chain = LineChain(chain, trailLineHash(event.Detail))
	}
	preimage := ReceiptPreimage(target.Identity, stream, 3, events[2].Hash, trailLineHash(events[2].Detail), chain)
	signed := false
	if signature, decodeErr := hex.DecodeString(receipt.Signature); err == nil && decodeErr == nil {
		for _, key := range target.ReceiptKeys {
			signed = signed || ed25519.Verify(key, preimage, signature)
		}
	}
	check("GET /v1/receipt: a receipt for the committed head, signed ("+ReceiptDomain+") by a pinned receipt key, over this "+
		"identity, stream, event, line and line chain", err == nil && receipt.Sequence == 3 && receipt.EventHash == events[2].Hash &&
		receipt.LineChain == chain && signed, "%+v, %v", receipt, err)
	_, err = sink.Receipt(ctx, 5)
	check("no receipt for a position it does not hold", err != nil, "sequence 5")

	// 5. only an identified client
	if target.Anonymous != nil {
		_, _, err = target.Anonymous.WithSite(stream).CommittedHead(ctx, stream)
		check("a client with no certificate is refused", err != nil, "%v", err)
	}

	// 6. a client's alarm is taken. Said to be a conformance run, on the conformance stream, so whoever receives it does
	// not take it for a tampered trail (regalia-kms-3e on #365); a real one comes from ShipTrail with its own reason.
	err = sink.ReportAlarm(ctx, 4, five[3].Hash, ConformanceAlarmReason)
	check("POST /v1/alarms: a client's alarm is accepted", err == nil, "%v", err)
	return checks, nil
}

// Conforms says whether every check passed.
func Conforms(checks []ConformanceCheck) bool {
	for _, c := range checks {
		if !c.Passed {
			return false
		}
	}
	return len(checks) > 0
}
