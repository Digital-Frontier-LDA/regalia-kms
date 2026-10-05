package openbaopoc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	sops "github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
var repository = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
var generation = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

func (w *Wrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.configured || ctx.Err() != nil {
		return nil, errConfig
	}
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, errConfig
	}
	c := opts.WithConfigMap
	allowed := map[string]bool{"kms_url": true, "server_name": true, "ca_path": true, "certificate_path": true, "private_key_path": true, "object_id": true, "repository": true, "path": true, "environment": true, "kms_purpose": true, "timeout": true, "key_version": true, "historical_key_versions": true}
	for k, v := range c {
		if !allowed[k] || v == "" || strings.ContainsAny(v, "\r\n\x00") {
			return nil, errConfig
		}
	}
	b := binding{c["object_id"], c["repository"], c["path"], c["environment"], c["kms_purpose"], c["key_version"]}
	historical, err := historicalVersions(b.KeyVersion, c["historical_key_versions"])
	if err != nil {
		return nil, errConfig
	}
	u, err := url.Parse(c["kms_url"])
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		!identifier.MatchString(b.ObjectID) || !identifier.MatchString(b.Purpose) || !repository.MatchString(b.Repository) ||
		b.Environment != "development" || b.Path == "" || len(b.Path) > 190 || path.Clean(b.Path) != b.Path || b.Path == "." || b.Path == ".." ||
		strings.HasPrefix(b.Path, "/") || strings.HasPrefix(b.Path, "../") || strings.Contains(b.Path, "\\") ||
		(opts.WithKeyId != "" && opts.WithKeyId != keyID(b)) || len(opts.WithAad) != 0 {
		return nil, errConfig
	}
	timeout := 5 * time.Second
	if c["timeout"] != "" {
		timeout, err = time.ParseDuration(c["timeout"])
		if err != nil {
			return nil, errConfig
		}
	}
	ca, err := protectedFile(c["ca_path"], false)
	if err != nil {
		return nil, errConfig
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errConfig
	}
	certificate, err := protectedFile(c["certificate_path"], false)
	if err != nil {
		return nil, errConfig
	}
	key, err := protectedFile(c["private_key_path"], true)
	if err != nil {
		return nil, errConfig
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return nil, errConfig
	}
	httpClient, err := sops.NewMTLSHTTPClient(pair, roots, c["server_name"], timeout)
	if err != nil || ctx.Err() != nil {
		return nil, errConfig
	}
	w.client = sops.NewHTTPClient(c["kms_url"], httpClient, time.Now)
	if b.KeyVersion != "" {
		w.client = &versionedClient{base: c["kms_url"], http: httpClient, binding: b}
	}
	w.binding = b
	w.historical = historical
	w.configured = true
	return &wrapping.WrapperConfig{Metadata: map[string]string{"mode": "development-poc", "format": "regalia-poc-v" + strconv.Itoa(frameVersion(b))}}, nil
}

// No environment expansion, symlinks, special files or shared private-key permissions.
func protectedFile(name string, private bool) ([]byte, error) {
	before, err := os.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errConfig
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, errConfig
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Size() > 64<<10 ||
		after.Mode().Perm()&0o022 != 0 || (private && after.Mode().Perm()&0o077 != 0) {
		return nil, errConfig
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		clear(data)
		return nil, errConfig
	}
	return data, nil
}
