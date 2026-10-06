package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

func TestCommandReconcilesArtifactAndReturnsReviewStatusForLostResponse(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic.svc.poc.invalid"}, DNSNames: []string{"synthetic.svc.poc.invalid"}, NotBefore: now.Add(-time.Second), NotAfter: now.Add(time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	tbs := sha256.Sum256(leaf.RawTBSCertificate)
	keyPin := "sha256:" + hex.EncodeToString(spki[:])
	streamPath := filepath.Join(dir, "collector-export.jsonl")
	recorder, err := audit.Open(streamPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"authorized", "success"} {
		draft := audit.Draft{Timestamp: now, RequestID: "018f0000-0000-7000-8000-000000000001", Principal: "spiffe://regalia/workload/synthetic", Decision: "allow", ObjectID: "synthetic-ca", Purpose: "synthetic-pki", Operation: "sign", DeviceID: "synthetic-token", Outcome: outcome, RegistryDigest: "synthetic-registry", PolicyDigest: "synthetic-policy", RBACDigest: "synthetic-rbac", X509ProfileID: "synthetic-profile", PayloadDigest: "sha256:" + hex.EncodeToString(tbs[:]), ArtifactKind: "certificate", KeyFingerprint: keyPin}
		if err := recorder.Record(context.Background(), draft, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := audit.VerifyIntegrity(streamPath)
	if err != nil {
		t.Fatal(err)
	}
	issuerPath, leafPath := filepath.Join(dir, "issuer.pem"), filepath.Join(dir, "leaf.der")
	if err := os.WriteFile(issuerPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafPath, leafDER, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-audit-stream", streamPath, "-issuer", issuerPath, "-expected-sequence", fmt.Sprint(len(events)), "-expected-hash", events[len(events)-1].Hash, "-profile", "synthetic-profile", "-object", "synthetic-ca", "-purpose", "synthetic-pki", "-key-fingerprint", keyPin}
	var output, diagnostic bytes.Buffer
	if code := run(append(append([]string{}, args...), "-artifact", leafPath), &output, &diagnostic); code != 0 {
		t.Fatalf("valid reconciliation failed: code=%d diagnostic=%s report=%s", code, &diagnostic, &output)
	}
	if !strings.Contains(output.String(), "consistent") || strings.Contains(output.String(), "synthetic.svc") {
		t.Fatal("report omitted verdict or exposed certificate identity")
	}
	output.Reset()
	diagnostic.Reset()
	if code := run(args, &output, &diagnostic); code != 1 || !strings.Contains(output.String(), "indeterminate") {
		t.Fatalf("lost artifact must require review: code=%d diagnostic=%s report=%s", code, &diagnostic, &output)
	}
	output.Reset()
	diagnostic.Reset()
	args[7] = "sha256:" + strings.Repeat("0", 64)
	if code := run(args, &output, &diagnostic); code != 2 || output.Len() != 0 {
		t.Fatal("wrong collector anchor produced a report")
	}
}

func TestInputRefusesBundlesPrivateKeysOversizeAndNamedPipes(t *testing.T) {
	dir := t.TempDir()
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	for name, data := range map[string][]byte{
		"bundle":   append(bytes.Clone(block), block...),
		"private":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}),
		"oversize": bytes.Repeat([]byte{1}, audit.MaxX509ArtifactBytes+1),
		"trailing": append(bytes.Clone(block), []byte("extra")...),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readDER(path, "CERTIFICATE"); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
	pipe := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := regularFile(pipe); err == nil {
		t.Fatal("named pipe accepted")
	}
	var output, diagnostic bytes.Buffer
	if run([]string{"-issuer", filepath.Join(dir, "private-input-name")}, &output, &diagnostic) != 2 || strings.Contains(diagnostic.String(), "private-input-name") {
		t.Fatal("invalid command exposed input path")
	}
}

func TestArgumentErrorsDoNotEchoOperatorInput(t *testing.T) {
	const privateValue = "synthetic-private-operator-input"
	tooMany := make([]string, 0, 2*(audit.MaxX509Artifacts+1))
	for i := 0; i <= audit.MaxX509Artifacts; i++ {
		tooMany = append(tooMany, "-artifact", privateValue)
	}
	for _, args := range [][]string{{"-expected-sequence", privateValue}, tooMany, {"-" + privateValue}} {
		var output, diagnostic bytes.Buffer
		if run(args, &output, &diagnostic) != 2 || output.Len() != 0 || strings.Contains(diagnostic.String(), privateValue) {
			t.Fatal("argument refusal echoed operator input")
		}
	}
	var output, diagnostic bytes.Buffer
	if run([]string{"-help"}, &output, &diagnostic) != 0 || !strings.Contains(diagnostic.String(), "expected-hash") {
		t.Fatal("help no longer explains the collector anchor")
	}
}
