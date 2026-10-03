package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var errNoConnection = errors.New("no connection")

// The relay in front of the real client: one whole key passes; anything else (no client, nothing, part of a
// key, more than a key, no answer in time) becomes nothing, so systemd-cryptsetup asks for the recovery key.
func TestTheRelayPassesOneWholeKeyOrNothing(t *testing.T) {
	key := bytes.Repeat([]byte("k"), keyBytes)
	cases := []struct {
		name   string
		client func(*net.UnixConn) // nil: no client listening at all
		want   []byte
		said   string
	}{
		{"a whole key", func(c *net.UnixConn) { c.Write(key) }, key, ""},
		{"no client", nil, nil, "could not be reached"},
		{"nothing", func(c *net.UnixConn) {}, nil, "gave nothing"},
		{"part of a key, then a crash", func(c *net.UnixConn) { c.Write(key[:20]) }, nil, "not one whole key"},
		{"more than a key", func(c *net.UnixConn) { c.Write(append(key, 'x')) }, nil, "not one whole key"},
		{"no answer in time", func(c *net.UnixConn) { time.Sleep(2 * time.Second) }, nil, "no answer within"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			directory, err := os.MkdirTemp("", "rr")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(directory)
			core := filepath.Join(directory, "core.sock")
			if tc.client != nil {
				real, err := net.ListenUnix("unix", &net.UnixAddr{Name: core, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer real.Close()
				go func() {
					c, err := real.AcceptUnix()
					if err != nil {
						return
					}
					tc.client(c)
					c.Close()
				}()
			}
			listener, ask := socketPair(t)
			var log locked
			done := make(chan error, 1)
			go func() { done <- relay(listener, core, 300*time.Millisecond, &log) }()
			started := time.Now()
			got, err := ask()
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("the asker got %q, %v", got, err)
			}
			if took := time.Since(started); took > 1500*time.Millisecond {
				t.Fatalf("the answer took %s with a bound of 300ms", took)
			}
			listener.Close()
			if err := <-done; err != nil {
				t.Fatalf("relay ended with %v", err)
			}
			said := log.said()
			if !strings.Contains(said, tc.said) || strings.Contains(said, string(key[:8])) {
				t.Fatalf("the relay said %q", said)
			}
		})
	}
}

// The client's attempt ends within its budget, so its answer, or its nothing, reaches the relay before the
// relay's own wait runs out: a slow round of peers does not turn an unlock into a recovery prompt silently.
func TestAnAttemptEndsWithinItsBudget(t *testing.T) {
	porto := newFakePeer(t, "porto")
	paths, _ := pathsOf(t, tokensFor(porto))
	slow := func(string, time.Time) transport {
		return func([]byte) ([]byte, error) { time.Sleep(40 * time.Millisecond); return nil, errNoConnection }
	}
	var log bytes.Buffer
	boot := testSession(t) // (an RSA key: made before the clock starts)
	started := time.Now()
	_, _, _, err := deriveKey(configFor(porto), options{rounds: 100, budget: 150 * time.Millisecond}, paths, bytes.Repeat([]byte{1}, 32),
		boot, slow, noQuote, func(time.Duration) {}, &log)
	wantError(t, err, "no peer helped within 150ms")
	if took := time.Since(started); took > 400*time.Millisecond {
		t.Fatalf("the attempt took %s with a budget of 150ms", took)
	}
}

// At the edge of the budget: the last ask is cut at the budget, not 10 s later. A peer that accepts and
// never answers is asked just before the budget ends; the attempt ends at the budget.
func TestTheLastAskEndsWithTheBudget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			defer c.Close() // accepted, never answered
		}
	}()
	porto := newFakePeer(t, "porto")
	config := configFor(porto)
	config.Peers[0].Endpoint = listener.Addr().String()
	paths, _ := pathsOf(t, tokensFor(porto))
	boot := testSession(t)
	var log bytes.Buffer
	started := time.Now()
	_, _, _, err = deriveKey(config, options{rounds: 1, budget: 300 * time.Millisecond}, paths, bytes.Repeat([]byte{1}, 32), boot,
		tcpTransport, noQuote, func(time.Duration) {}, &log)
	if err == nil {
		t.Fatal("a peer that never answers gave a key")
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("the last ask ran %s past a budget of 300ms (ioTimeout alone is %s)", took, ioTimeout)
	}
	if !strings.Contains(log.String(), "the reply did not arrive") {
		t.Fatalf("the ask was not cut at the budget: %s", log.String())
	}
}
