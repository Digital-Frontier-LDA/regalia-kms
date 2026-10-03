package openbaopoc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	sops "github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops"
)

func (c *versionedClient) nativeCall(ctx context.Context, req sops.Request, operation string, doc versionedRequest, contentType string, limit int) ([]byte, error) {
	if req.ObjectID != c.binding.ObjectID || req.Purpose != c.binding.Purpose || req.Environment != c.binding.Environment {
		return nil, errOperation
	}
	attempts := 3
	if operation == "sign" {
		attempts = 2
	}
	for attempt := 0; attempt < attempts; attempt++ {
		result, err := c.nativeAttempt(ctx, req, operation, doc, contentType, limit)
		if err == nil {
			return result, nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || !apiErr.Retryable || attempt+1 == attempts {
			return nil, err
		}
		timer := time.NewTimer(time.Duration(40*(1<<attempt)) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, contextError(ctx.Err(), req.RequestID)
		case <-timer.C:
		}
		// The prior nonce may have been consumed, including on an ambiguous
		// hardware failure. Never replay it, and never retry transport ambiguity.
		var nextErr error
		req, nextErr = request(c.binding, operation, req.Data, nil)
		if nextErr != nil {
			return nil, errOperation
		}
	}
	return nil, errOperation
}

func (c *versionedClient) nativeAttempt(ctx context.Context, req sops.Request, operation string, doc versionedRequest, contentType string, limit int) ([]byte, error) {
	protocol := &APIError{Code: "PROTOCOL_ERROR", RequestID: req.RequestID}
	if ctx.Err() != nil {
		return nil, contextError(ctx.Err(), req.RequestID)
	}
	doc.ObjectID = req.ObjectID
	if operation != "sign" {
		doc.Format = "regalia-envelope-v2"
	}
	doc.Context.Environment, doc.Context.Purpose = req.Environment, req.Purpose
	expires := time.Now().UTC().Add(time.Minute)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	doc.Context.ExpiresAt, doc.Context.Nonce = expires.Format(time.RFC3339Nano), req.IdempotencyKey
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, protocol
	}
	defer clear(encoded)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/operations/"+operation, bytes.NewReader(encoded))
	if err != nil {
		return nil, protocol
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-Request-ID", req.RequestID)
	httpReq.Header.Set("Idempotency-Key", req.IdempotencyKey)
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, contextError(err, req.RequestID)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit*2+1)))
	defer clear(data)
	if ctx.Err() != nil {
		return nil, contextError(ctx.Err(), req.RequestID)
	}
	media, _, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, contextError(err, req.RequestID)
	}
	if len(data) > limit*2 || mediaErr != nil || media != "application/json" || resp.Header.Get("Cache-Control") != "no-store" {
		return nil, protocol
	}
	return decodeAPIResponse(data, resp.StatusCode, req.RequestID, req.ObjectID, contentType, limit)
}
