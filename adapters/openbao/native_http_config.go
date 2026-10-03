package openbaopoc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"time"

	sops "github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops"
)

func nativeHTTPClient(ctx context.Context, c map[string]string) (*http.Client, time.Duration, error) {
	u, err := url.Parse(c["address"])
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || c["environment"] != "development" {
		return nil, 0, errConfig
	}
	timeout, err := time.ParseDuration(c["timeout"])
	if err != nil || timeout < time.Second || timeout > time.Minute {
		return nil, 0, errConfig
	}
	ca, err := protectedFile(c["ca_path"], false)
	if err != nil {
		return nil, 0, errConfig
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, 0, errConfig
	}
	cert, err := protectedFile(c["cert_path"], false)
	if err != nil {
		return nil, 0, errConfig
	}
	key, err := protectedFile(c["key_path"], true)
	if err != nil {
		return nil, 0, errConfig
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, 0, errConfig
	}
	client, err := sops.NewMTLSHTTPClient(pair, roots, c["server_name"], timeout)
	if err != nil || ctx.Err() != nil {
		return nil, 0, errConfig
	}
	return client, timeout, nil
}
