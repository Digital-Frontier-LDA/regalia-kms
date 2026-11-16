package openbaopoc

import (
	"context"
	"strings"

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
	if !identifier.MatchString(b.ObjectID) || !identifier.MatchString(b.Purpose) || nativeOptions(b, []wrapping.Option{wrapping.WithKeyId(opts.WithKeyId)}) != nil {
		return nil, errConfig
	}
	httpClient, timeout, err := nativeHTTPClient(ctx, c)
	if err != nil {
		return nil, err
	}
	w.client = &versionedClient{base: c["address"], http: httpClient, binding: b, native: true, logger: opts.WithLogger}
	w.binding, w.timeout = b, timeout
	return &wrapping.WrapperConfig{Metadata: map[string]string{"mode": "development-poc", "format": "regalia-envelope-v2"}}, nil
}
