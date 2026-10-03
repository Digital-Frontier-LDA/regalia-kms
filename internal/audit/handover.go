package audit

// STREAM CONTINUITY ACROSS A CLIENT CERTIFICATE ROTATION (#291).
//
// The collector keys a stream by the client certificate's fingerprint and the site. A host's audit
// client certificate is rotated (expiry, suspicion), and a new certificate would otherwise start new,
// empty streams. Once a trail has been pruned behind the old stream (#288), a restart is worse than a
// gap: the shipper sees a collector behind its prune marker and stops with a tamper alarm. So the
// stream belongs to the host, and a new certificate takes over the host's streams only by an explicit
// HAND-OVER, recorded durably, as a key rollover keeps a log's identity:
//
//   - by the old certificate (the normal rotation): POST /v1/handover over mTLS with the NEW
//     certificate, carrying the OLD certificate and the old key's signature over HandoverPreimage. The
//     old certificate must chain to the collector's client CA and must have streams; the new one must
//     have none of its own, and neither may have been handed over before;
//   - by the operator (the old key is lost): regalia-audit-collector handover -state … -old … -new …
//     -reason …, with the collector stopped (the state directory's lock).
//
// After a hand-over the new identity writes, reads positions of, and gets receipts for the old
// identity's streams (every site), and the OLD identity is RETIRED: everything it asks is refused, so
// two certificates never write one stream. Receipts still name the caller's own fingerprint, so a
// host's prune verifies them against its current certificate. Every hand-over is a line of
// handovers.jsonl (fsynced before it takes effect) and a record in the alarm log.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const (
	handoversFileName = "handovers.jsonl"
	lockFileName      = "collector.lock"
	// HandoverDomain begins every hand-over's signed bytes.
	HandoverDomain = "regalia.collector.handover/v1"
	// maxHandoverBody bounds a hand-over request: a certificate and a signature.
	maxHandoverBody = 16 << 10
)

// handover is one line of handovers.jsonl.
type handover struct {
	Old    string    `json:"old"` // the retired identity: SHA-256 of its certificate's DER, hex
	New    string    `json:"new"` // the identity that takes over its streams
	By     string    `json:"by"`  // "old-key" or "operator"
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
}

// HandoverPreimage is what the old key signs: that its streams continue under the new identity.
func HandoverPreimage(oldIdentity, newIdentity string) []byte {
	return []byte(HandoverDomain + "\n" + oldIdentity + "\n" + newIdentity)
}

// SetClientRoots gives the collector the client CA its listener verifies against, so a hand-over's old
// certificate is held to the same roots (cmd/regalia-audit-collector).
func (c *Collector) SetClientRoots(roots *x509.CertPool) { c.clientRoots = roots }

// loadHandovers reads handovers.jsonl at open. Each line must be consistent with the ones before it:
// an identity is retired at most once, and an identity that takes over has no streams of its own (it
// writes the old identity's), so a stream is never reachable through two identities.
func (c *Collector) loadHandovers() error {
	c.successor, c.predecessor = map[string]string{}, map[string]string{}
	file, err := os.Open(filepath.Join(c.stateDir, handoversFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("collector hand-overs: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		var h handover
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&h); err != nil {
			return fmt.Errorf("collector hand-overs line %d is not a hand-over: %v", line, err)
		}
		if err := c.handoverAllowedLocked(h.Old, h.New); err != nil {
			return fmt.Errorf("collector hand-overs line %d: %v — restore from backup", line, err)
		}
		c.successor[h.Old], c.predecessor[h.New] = h.New, h.Old
	}
	return scanner.Err()
}

// streamIdentityLocked is the identity whose streams `identity` writes: itself, or, after hand-overs,
// the first identity of its line. Retired identities are refused before this is asked.
func (c *Collector) streamIdentityLocked(identity string) string {
	for {
		previous, ok := c.predecessor[identity]
		if !ok {
			return identity
		}
		identity = previous
	}
}

// hasStreamsLocked reports whether the identity has streams of its own (on disk, in its own name).
func (c *Collector) hasStreamsLocked(identity string) bool {
	for _, stream := range c.streams {
		if stream.identity == identity {
			return true
		}
	}
	return false
}

// handoverAllowedLocked holds a hand-over from old to new to the rules: two well-formed, different
// identities; old not retired, and with streams (its own, or by an earlier hand-over); new never
// retired, never a successor, and without streams of its own.
func (c *Collector) handoverAllowedLocked(old, new string) error {
	switch {
	case !identityFingerprintHexPattern.MatchString(old) || !identityFingerprintHexPattern.MatchString(new) || old == new:
		return errors.New("a hand-over is between two different certificate fingerprints")
	case c.successor[old] != "":
		return fmt.Errorf("%s was already handed over to %s", old, c.successor[old])
	case c.successor[new] != "" || c.predecessor[new] != "":
		return fmt.Errorf("%s already took part in a hand-over", new)
	case c.hasStreamsLocked(new):
		return fmt.Errorf("%s has streams of its own: a hand-over would leave a stream reachable two ways", new)
	case !c.hasStreamsLocked(c.streamIdentityLocked(old)):
		return fmt.Errorf("%s has no streams to hand over", old)
	}
	return nil
}

// recordHandover writes the hand-over durably (the line fsynced, then the directory), then applies it,
// then records it in the alarm log for whoever watches the collector.
func (c *Collector) recordHandover(old, new, by, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.handoverAllowedLocked(old, new); err != nil {
		return err
	}
	encoded, err := json.Marshal(handover{Old: old, New: new, By: by, Reason: reason, At: time.Now().UTC()})
	if err != nil {
		return err
	}
	path := filepath.Join(c.stateDir, handoversFileName)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncDir(c.stateDir); err != nil {
		return err
	}
	c.successor[old], c.predecessor[new] = new, old
	record, _ := json.Marshal(collectorAlarm{Timestamp: time.Now().UTC(), Identity: new,
		Reason: fmt.Sprintf("record: %s handed over its streams to this identity (%s)%s", old, by, map[bool]string{true: ": " + reason, false: ""}[reason != ""])})
	return c.appendAlarmLocked(record)
}

// RecordOperatorHandover is the operator's hand-over, for an old certificate whose key is lost
// (cmd/regalia-audit-collector handover). The collector holding this state must not be running: the
// caller opened it, so it holds the state directory's lock.
func (c *Collector) RecordOperatorHandover(old, new, reason string) error {
	if strings.TrimSpace(reason) == "" || len(reason) > 512 || strings.IndexFunc(reason, unicode.IsControl) >= 0 {
		return errors.New("an operator hand-over needs a reason: one line, at most 512 characters")
	}
	return c.recordHandover(old, new, "operator", reason)
}

// resolveCaller is every endpoint's step after authentication: a retired identity is refused (and
// alarmed), any other is answered with the identity whose streams it writes.
func (c *Collector) resolveCaller(request *http.Request, writer http.ResponseWriter, identity, commonName, site string) (string, bool) {
	c.mu.Lock()
	successor, retired := c.successor[identity]
	streamIdentity := c.streamIdentityLocked(identity)
	c.mu.Unlock()
	if retired {
		c.reject(request, writer, http.StatusForbidden, collectorAlarm{
			Identity: identity, CommonName: commonName, Site: site,
			Reason: fmt.Sprintf("this client certificate was handed over to %s and is retired: two certificates never write one stream", successor),
		})
		return "", false
	}
	return streamIdentity, true
}

// handleHandover takes a hand-over presented by the NEW certificate (handover.go's header).
func (c *Collector) handleHandover(writer http.ResponseWriter, request *http.Request) {
	identity, commonName, authenticated := peerIdentity(request)
	if !authenticated {
		c.reject(request, writer, http.StatusUnauthorized, collectorAlarm{
			Identity: "unauthenticated",
			Reason:   "no client certificate was presented: a hand-over is accepted only from an identified client",
		})
		return
	}
	refuse := func(status int, reason string) {
		c.reject(request, writer, status, collectorAlarm{Identity: identity, CommonName: commonName, Reason: "hand-over refused: " + reason})
	}
	var body struct {
		OldCertificate string `json:"old_certificate"` // DER, base64
		Signature      string `json:"signature"`       // hex: ECDSA (ASN.1) over SHA-256, or Ed25519
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, maxHandoverBody))
	decoder.DisallowUnknownFields()
	var trailing any
	if err := decoder.Decode(&body); err != nil || !errors.Is(decoder.Decode(&trailing), io.EOF) {
		refuse(http.StatusBadRequest, "the body is not {old_certificate, signature}")
		return
	}
	der, err := base64.StdEncoding.DecodeString(body.OldCertificate)
	if err != nil {
		refuse(http.StatusBadRequest, "old_certificate is not base64 DER")
		return
	}
	old, err := x509.ParseCertificate(der)
	if err != nil {
		refuse(http.StatusBadRequest, "old_certificate is not a certificate")
		return
	}
	if c.clientRoots == nil {
		refuse(http.StatusServiceUnavailable, "this collector was given no client CA to check an old certificate against")
		return
	}
	if _, err := old.Verify(x509.VerifyOptions{Roots: c.clientRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		refuse(http.StatusForbidden, "the old certificate does not chain to the client CA: "+err.Error())
		return
	}
	digest := sha256.Sum256(old.Raw)
	oldIdentity := hex.EncodeToString(digest[:])
	signature, err := hex.DecodeString(body.Signature)
	if err != nil || !verifyHandoverSignature(old, HandoverPreimage(oldIdentity, identity), signature) {
		refuse(http.StatusForbidden, "the signature is not the old certificate's key over the hand-over")
		return
	}
	if err := c.recordHandover(oldIdentity, identity, "old-key", ""); err != nil {
		refuse(http.StatusConflict, err.Error())
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// verifyHandoverSignature checks the old key's signature, for the key types audit client certificates
// carry: ECDSA (ASN.1, over SHA-256 of the preimage) and Ed25519 (over the preimage).
func verifyHandoverSignature(certificate *x509.Certificate, preimage, signature []byte) bool {
	switch key := certificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(preimage)
		return ecdsa.VerifyASN1(key, digest[:], signature)
	case ed25519.PublicKey:
		return ed25519.Verify(key, preimage, signature)
	}
	return false
}

// Handover presents, over this sink's (new) client certificate, the old certificate and its key's
// signature over HandoverPreimage, so the collector continues the old certificate's streams under the
// new one (#291). Success is the 204.
func (sink *HTTPSink) Handover(ctx context.Context, oldCertificate, signature []byte) error {
	if sink == nil || sink.client == nil {
		return ErrSinkUnavailable
	}
	body, err := json.Marshal(map[string]string{"old_certificate": base64.StdEncoding.EncodeToString(oldCertificate), "signature": hex.EncodeToString(signature)})
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, sink.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, sink.baseURL+"/v1/handover", bytes.NewReader(body))
	if err != nil {
		return ErrSinkUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := sink.client.Do(request)
	if err != nil {
		return ErrSinkUnavailable
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("the collector refused the hand-over (%d): %s", response.StatusCode, strings.TrimSpace(string(answer)))
	}
	return nil
}
