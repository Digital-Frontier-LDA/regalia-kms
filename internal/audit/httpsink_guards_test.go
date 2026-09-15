package audit

// #237 operand sweep of the HTTP sink. httpsink.go's existing tests drive the happy path and two
// unhappy responses, and 23 of its 39 leaf operands survived being replaced with a constant. The
// rows here close the ones that are reachable and whose loss changes an OUTCOME rather than a
// message.
//
// Three of them are not redundancy at all — they are what stops a nil being dereferenced:
//
//	Send/CommittedHead/Ready each read sink.client immediately after checking sink == nil, and
//	each reads response.Body immediately after checking the transport's error. A guard whose
//	removal turns a refusal into a panic is the opposite of redundant, and a sweep reports it as
//	a survivor exactly like a redundant one, which is why each row below asserts that the call
//	RETURNED rather than that it returned something.
//
// The panics are caught and reported as assertions rather than allowed to abort the binary: a
// run containing a panic truncates the failing set, so an aborting row would hide whatever else
// the same mutation broke.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// chainedHash is a well-formed event hash — the shape auditHashPattern accepts — so a row that
// means to test something else is not refused for its hash.
const chainedHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// callingSink runs one call against a sink and reports what came back, including a panic, so the
// failure is a named assertion instead of a process abort.
func sendRecovering(sink *HTTPSink, event Event) (err error, panicked any) {
	defer func() { panicked = recover() }()
	return sink.Send(context.Background(), event), nil
}

func committedHeadRecovering(sink *HTTPSink) (sequence uint64, hash string, err error, panicked any) {
	defer func() { panicked = recover() }()
	sequence, hash, err = sink.CommittedHead(context.Background(), "sitea")
	return sequence, hash, err, nil
}

func readyRecovering(sink *HTTPSink) (ready bool, panicked any) {
	defer func() { panicked = recover() }()
	return sink.Ready(context.Background()), nil
}

// A SINK THAT WAS NEVER BUILT REFUSES; IT DOES NOT CRASH.
//
// Both shapes occur: a nil *HTTPSink is what a caller holds when construction failed and the
// error was dropped, and a zero-valued &HTTPSink{} is what a caller holds when the struct was
// assembled by hand instead of by NewHTTPSink. Every method reads sink.client one line after
// checking for them.
func TestAnUnbuiltSinkRefusesEveryCallRatherThanPanicking(t *testing.T) {
	for name, sink := range map[string]*HTTPSink{
		"a nil sink":        nil,
		"a zero-value sink": {},
	} {
		t.Run(name, func(t *testing.T) {
			err, panicked := sendRecovering(sink, Event{Hash: chainedHash})
			if panicked != nil {
				t.Errorf("Send on %s panicked (%v): the guard in front of sink.client is what turns an unbuilt sink into a refusal, and without it a misconfigured collector takes the daemon down instead of failing the shipment", name, panicked)
			} else if !errors.Is(err, ErrSinkUnavailable) {
				t.Errorf("Send on %s returned %v, want ErrSinkUnavailable: the shipper retries that class and does not handle others", name, err)
			}

			_, _, headErr, panicked := committedHeadRecovering(sink)
			if panicked != nil {
				t.Errorf("CommittedHead on %s panicked (%v)", name, panicked)
			} else if !errors.Is(headErr, ErrSinkUnavailable) {
				t.Errorf("CommittedHead on %s returned %v, want ErrSinkUnavailable", name, headErr)
			}

			ready, panicked := readyRecovering(sink)
			if panicked != nil {
				t.Errorf("Ready on %s panicked (%v)", name, panicked)
			} else if ready {
				t.Errorf("%s reported itself ready: a collector nobody can reach read as a healthy off-host copy", name)
			}
		})
	}
}

// A TRANSPORT FAILURE LEAVES NO RESPONSE TO READ.
//
// http.Client.Do returns a nil response alongside its error, and all three methods reach for
// response.Body or response.StatusCode on the next line. This is the ordinary case — the
// collector is down, which is the state the whole shipper exists to survive — so a panic here is
// not an edge.
func TestATransportFailureIsRefusedRatherThanDereferenced(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("collector unreachable")
	})}
	sink, err := NewHTTPSink("https://audit.internal", client, time.Second, "")
	if err != nil {
		t.Fatal(err)
	}

	sendErr, panicked := sendRecovering(sink, Event{Hash: chainedHash})
	if panicked != nil {
		t.Errorf("Send panicked when the transport failed (%v): Do hands back a nil response with its error and the next line reads response.Body", panicked)
	} else if !errors.Is(sendErr, ErrSinkUnavailable) {
		t.Errorf("Send returned %v for an unreachable collector, want ErrSinkUnavailable", sendErr)
	}

	_, _, headErr, panicked := committedHeadRecovering(sink)
	if panicked != nil {
		t.Errorf("CommittedHead panicked when the transport failed (%v)", panicked)
	} else if !errors.Is(headErr, ErrSinkUnavailable) {
		t.Errorf("CommittedHead returned %v for an unreachable collector, want ErrSinkUnavailable", headErr)
	}

	ready, panicked := readyRecovering(sink)
	if panicked != nil {
		t.Errorf("Ready panicked when the transport failed (%v)", panicked)
	} else if ready {
		t.Error("an unreachable collector reported ready")
	}
}

// THE HASH IS THE IDEMPOTENCY KEY, so an event whose hash is not a chained hash must not be sent
// at all. Shipping it would put an arbitrary string in the Idempotency-Key header and ask the
// collector to commit an event the local chain cannot name.
func TestSendRefusesAnEventWhoseHashIsNotAChainedHash(t *testing.T) {
	for name, hash := range map[string]string{
		"empty":               "",
		"not a digest":        "sha256:not-a-digest",
		"the wrong algorithm": "sha1:" + strings.Repeat("a", 40),
		"uppercase hex":       "sha256:" + strings.Repeat("A", 64),
		"one nibble short":    "sha256:" + strings.Repeat("a", 63),
	} {
		t.Run(name, func(t *testing.T) {
			var calls int
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{"X-Regalia-Audit-Hash": []string{hash}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			sink, err := NewHTTPSink("https://audit.internal", client, time.Second, "")
			if err != nil {
				t.Fatal(err)
			}
			// The collector double echoes whatever hash it is given, so the acknowledgement check
			// downstream is SATISFIED by this shipment. Only the guard in front of the wire can
			// refuse it, which is what makes this row about that guard.
			if err := sink.Send(context.Background(), Event{Sequence: 1, Hash: hash}); err == nil {
				t.Fatalf("an event whose hash is %s was shipped: the hash is the Idempotency-Key, so the collector is asked to commit a record the local chain cannot name", name)
			}
			if calls != 0 {
				t.Fatalf("the sink made %d request(s) before refusing: the event reached the wire, and a collector that accepts it holds an off-host record with a hash this journal never produced", calls)
			}
		})
	}
}

// A SINK WITH NO CLIENT IS NOT A SINK. NewHTTPSink dereferences the client one line after
// checking it, to copy the caller's settings, so the check is what turns a nil into a refused
// configuration instead of a crash inside the constructor.
func TestASinkBuiltWithoutAClientIsRefused(t *testing.T) {
	build := func() (sink *HTTPSink, err error, panicked any) {
		defer func() { panicked = recover() }()
		sink, err = NewHTTPSink("https://audit.internal", nil, time.Second, "")
		return sink, err, nil
	}
	sink, err, panicked := build()
	if panicked != nil {
		t.Fatalf("NewHTTPSink panicked on a nil client (%v): the constructor copies *client immediately after the check, so without it a missing transport crashes the daemon during configuration rather than being reported", panicked)
	}
	if err == nil {
		t.Fatalf("a sink was built with no HTTP client (%v): every later call would find sink.client nil and the collector would be unreachable for a reason nothing reported at startup", sink)
	}
}

// AN EVENT TOO LARGE TO SHIP MUST NOT BE SHIPPED.
//
// validateDraft caps every STRING field at 512 bytes, but VerifiedApprovers is a slice and is not
// in the list it walks, so a request carrying a large approver set marshals to an arbitrarily
// large event. The body cap is what keeps that off the wire.
func TestSendRefusesAnOversizedBody(t *testing.T) {
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{"X-Regalia-Audit-Hash": []string{chainedHash}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	sink, err := NewHTTPSink("https://audit.internal", client, time.Second, "")
	if err != nil {
		t.Fatal(err)
	}

	oversized := Event{Sequence: 1, Hash: chainedHash}
	for len(oversized.VerifiedApprovers) < 2000 {
		oversized.VerifiedApprovers = append(oversized.VerifiedApprovers, strings.Repeat("a", 64))
	}
	// PROVE THE FIXTURE: the event must actually marshal past the cap, or this row is about an
	// ordinary shipment and says nothing about the bound.
	body, err := json.Marshal(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 64<<10 {
		t.Fatalf("fixture: the event marshals to %d bytes, which is inside the %d-byte cap", len(body), 64<<10)
	}

	if err := sink.Send(context.Background(), oversized); err == nil {
		t.Fatal("an event larger than the body cap was shipped: the bound exists so one request cannot push an unbounded body at the collector, and it was not applied")
	}
	if calls != 0 {
		t.Fatalf("the sink made %d request(s) before refusing: the oversized body reached the wire", calls)
	}

	// KNOWN-GOOD: the same sink ships an ordinary event, so the refusal is the size rather than
	// a Send that refuses everything.
	if err := sink.Send(context.Background(), Event{Sequence: 1, Hash: chainedHash}); err != nil {
		t.Fatalf("an ordinary event was refused (%v), so the row above proves nothing", err)
	}
}

// A 2XX IS NOT AN ACKNOWLEDGEMENT, AND NEITHER IS A CORRECT HASH ON THE WRONG STATUS.
//
// The existing status row pairs a 202 with a missing acknowledgement header, so the header check
// refuses it and the status check never has to. This row supplies the correct acknowledgement on
// a status that is not 204, leaving the status operand as the only thing that can object.
func TestSendRequiresExactlyNoContentEvenWithACorrectAcknowledgement(t *testing.T) {
	event := Event{Sequence: 1, Hash: chainedHash}
	for name, status := range map[string]int{
		"200 OK":       http.StatusOK,
		"201 Created":  http.StatusCreated,
		"202 Accepted": http.StatusAccepted,
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"X-Regalia-Audit-Hash": []string{event.Hash}},
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			})}
			sink, err := NewHTTPSink("https://audit.internal", client, time.Second, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := sink.Send(context.Background(), event); err == nil {
				t.Fatalf("a %s carrying the right acknowledgement hash was accepted as a durable commit: the contract is 204, and every other 2xx is a collector that received the event without saying it kept it", name)
			}
		})
	}

	// KNOWN-GOOD: the same double on 204 succeeds, so the rows above are about the status rather
	// than about a Send that refuses everything.
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{"X-Regalia-Audit-Hash": []string{event.Hash}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	sink, err := NewHTTPSink("https://audit.internal", client, time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Send(context.Background(), event); err != nil {
		t.Fatalf("a 204 with the right acknowledgement was refused (%v), so the rows above prove nothing", err)
	}
}

// THE COMMITTED HEAD IS THE ONE VALUE THE HOST CANNOT AUTHOR, so an answer that is not an answer
// must be an error and never a zero. A zero reads as "the collector holds nothing", which on a
// fresh journal reconciles CLEAN — the failure is silent exactly where it matters.
func TestCommittedHeadRefusesAnAnswerItCouldNotRead(t *testing.T) {
	for name, response := range map[string]*http.Response{
		"a 500 from the collector": {StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"sequence":0,"hash":""}`))},
		"a 404 from the collector": {StatusCode: http.StatusNotFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))},
		"a body that is not JSON":  {StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("<html>proxy error</html>"))},
		"a truncated body":         {StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"sequence":5,"hash":`))},
		// THE ROW THAT ISOLATES THE DECODE ERROR. The other three are each also refused by
		// something downstream — a sticky syntax error fails the trailing-document read too, and
		// a partial object fails the shape check — so with the decode operand replaced by a
		// constant they all still refuse. An EMPTY body does not: the decode fails with io.EOF,
		// the trailing read then returns io.EOF and passes, and the zero position reads as a
		// well-formed "holds nothing". A 200 with no body would become the collector's answer.
		"a 200 with no body at all": {StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))},
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response, nil })}
			sink, err := NewHTTPSink("https://collector.test", client, time.Second, "")
			if err != nil {
				t.Fatal(err)
			}
			sequence, hash, err := sink.CommittedHead(context.Background(), "sitea")
			if err == nil {
				t.Fatalf("%s was read as a committed head of (%d, %q): an unreadable answer became 'the collector holds nothing', which reconciles clean on a fresh journal and hides that the off-host memory was never consulted", name, sequence, hash)
			}
		})
	}
}

// AND A COLLECTOR THAT GENUINELY HOLDS NOTHING IS A POSITION, NOT A REFUSAL.
//
// REFUSAL DIRECTION, which every row above is blind to: the shape check reads
// (Sequence > 0) != (Hash != "") together with a pattern check guarded on the hash being
// non-empty. Drop that guard and the pattern is applied to the empty hash, so the one answer a
// brand-new stream can give — (0, "") — is refused as impossible. Reconciliation then refuses
// every site's first startup, and no negative test notices.
func TestACollectorThatHoldsNothingIsAPositionRatherThanAnImpossibleShape(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"sequence":0,"hash":""}`))}, nil
	})}
	sink, err := NewHTTPSink("https://collector.test", client, time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	sequence, hash, err := sink.CommittedHead(context.Background(), "sitea")
	if err != nil {
		t.Fatalf("a collector reporting that it holds nothing for this stream was refused (%v): that is the only answer a stream that has never shipped can give, and refusing it turns every site's first startup into an incident", err)
	}
	if sequence != 0 || hash != "" {
		t.Fatalf("CommittedHead reported (%d, %q) for a collector holding nothing, want (0, \"\")", sequence, hash)
	}
}
