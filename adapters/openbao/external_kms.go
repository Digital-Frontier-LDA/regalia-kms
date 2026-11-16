package openbaopoc

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// ExternalKMS provides development-only Transit signing. It has its own
// provider configuration and mTLS identity, independent of the seal wrapper.
type ExternalKMS struct {
	kms.UnimplementedKMS
	mu                sync.RWMutex
	client            *http.Client
	base, environment string
	timeout           time.Duration
	closed            context.Context
	cancel            context.CancelFunc
	opened            bool
	logger            hclog.Logger
}

var _ kms.KMS = (*ExternalKMS)(nil)

func NewExternal() *ExternalKMS { return &ExternalKMS{} }

func strictStrings(c kms.ConfigMap, keys []string) (map[string]string, error) {
	if len(c) != len(keys) {
		return nil, errConfig
	}
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		v, ok := c[key].(string)
		if !ok || v == "" || strings.ContainsAny(v, "\r\n\x00") {
			return nil, errConfig
		}
		result[key] = v
	}
	return result, nil
}

func (p *ExternalKMS) Open(ctx context.Context, opts *kms.OpenOptions) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.opened || opts == nil || ctx.Err() != nil {
		return errConfig
	}
	c, err := strictStrings(opts.ConfigMap, []string{"address", "server_name", "ca_path", "cert_path", "key_path", "environment", "timeout"})
	if err != nil {
		return err
	}
	client, timeout, err := nativeHTTPClient(ctx, c)
	if err != nil {
		return err
	}
	// Verification is read-only. It never signs or consumes a policy nonce.
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, c["address"]+"/v1/health/ready", nil)
	if err != nil {
		return errConfig
	}
	probe := *client
	probe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := probe.Do(req)
	if err != nil {
		client.CloseIdleConnections()
		return contextError(err, "")
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4097))
	resp.Body.Close()
	if readErr != nil || resp.StatusCode != http.StatusOK || probeCtx.Err() != nil {
		client.CloseIdleConnections()
		return &APIError{Code: "DEPENDENCY_UNAVAILABLE"}
	}
	p.client, p.base, p.environment, p.timeout = client, c["address"], c["environment"], timeout
	p.closed, p.cancel = context.WithCancel(context.Background())
	p.opened = true
	p.logger = opts.Logger
	return nil
}

func (p *ExternalKMS) Close(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		p.cancel()
	}
	if p.client != nil {
		p.client.CloseIdleConnections()
	}
	return nil
}

func (p *ExternalKMS) keyContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.opened || p.closed.Err() != nil || ctx.Err() != nil {
		return nil, nil, errOperation
	}
	call, cancel := context.WithTimeout(ctx, p.timeout)
	stop := context.AfterFunc(p.closed, cancel)
	return call, func() { stop(); cancel() }, nil
}
