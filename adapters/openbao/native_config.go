package openbaopoc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"strings"
	"time"

	sops "github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func (w *NativeWrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.client != nil || ctx.Err() != nil {
		return nil, errConfig
	}
	opts, err := wrapping.GetOpts(options...)
	if err != nil || len(opts.WithAad) != 0 {
		return nil, errConfig
	}
	c := opts.WithConfigMap
	keys := []string{"address", "server_name", "ca_path", "cert_path", "key_path", "object_id", "kms_purpose", "environment", "timeout"}
	if len(c) != len(keys) {
		return nil, errConfig
	}
	for _, key := range keys {
		if c[key] == "" || strings.ContainsAny(c[key], "\r\n\x00") {
			return nil, errConfig
		}
	}
	b := binding{ObjectID: c["object_id"], Purpose: c["kms_purpose"], Environment: c["environment"]}
	u, err := url.Parse(c["address"])
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		!identifier.MatchString(b.ObjectID) || !identifier.MatchString(b.Purpose) || b.Environment != "development" ||
		nativeOptions(b, []wrapping.Option{wrapping.WithKeyId(opts.WithKeyId)}) != nil {
		return nil, errConfig
	}
	timeout, err := time.ParseDuration(c["timeout"])
	if err != nil || timeout < time.Second || timeout > time.Minute {
		return nil, errConfig
	}
	ca, err := protectedFile(c["ca_path"], false)
	if err != nil {
		return nil, errConfig
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errConfig
	}
	certificate, err := protectedFile(c["cert_path"], false)
	if err != nil {
		return nil, errConfig
	}
	key, err := protectedFile(c["key_path"], true)
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
	w.client = &versionedClient{base: c["address"], http: httpClient, binding: b, native: true}
	w.binding, w.timeout = b, timeout
	return &wrapping.WrapperConfig{Metadata: map[string]string{"mode": "development-poc", "format": "regalia-envelope-v2"}}, nil
}
