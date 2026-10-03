package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
