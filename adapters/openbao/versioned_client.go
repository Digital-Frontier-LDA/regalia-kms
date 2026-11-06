package openbaopoc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"

	sops "github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops"
	"github.com/hashicorp/go-hclog"
)

// This client carries envelope and signing requests. The existing KMS APIs
// own generation selection, policy, custody and envelope authentication.
type versionedClient struct {
	base    string
	http    *http.Client
	binding binding
	native  bool
	logger  hclog.Logger
}

type versionedRequest struct {
	ObjectID string `json:"object_id"`
	Context  struct {
		Environment string `json:"environment"`
		Purpose     string `json:"purpose"`
		ExpiresAt   string `json:"expires_at"`
		Nonce       string `json:"nonce"`
	} `json:"context"`
	Format      string `json:"format,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Payload     []byte `json:"payload_base64,omitempty"`
	Ciphertext  []byte `json:"ciphertext_base64,omitempty"`
	Nonce       []byte `json:"nonce_base64,omitempty"`
	DataKey     []byte `json:"data_key_base64,omitempty"`
}

func (c *versionedClient) Wrap(ctx context.Context, req sops.Request) ([]byte, error) {
	if len(req.Data) != 32 {
		return nil, errOperation
	}
	result, err := c.seal(ctx, req, maxWrappedKey)
	if err != nil || !validInnerEnvelope(result, c.binding) {
		return nil, errOperation
	}
	return result, nil
}

func (c *versionedClient) seal(ctx context.Context, req sops.Request, resultLimit int) ([]byte, error) {
	key, nonce := make([]byte, 32), make([]byte, 12)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return nil, errOperation
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, errOperation
	}
	aead, err := gcm(key)
	if err != nil {
		return nil, errOperation
	}
	// This is the documented v2 content-AAD format. The server reconstructs it
	// independently, validates the ciphertext and supplies the actual KEK ref.
	aad := []byte("regalia-envelope-v2\x00" + c.binding.ObjectID + "\x00AES-256-GCM\x00" + contextDigest(c.binding))
	doc := versionedRequest{Ciphertext: aead.Seal(nil, nonce, req.Data, aad), Nonce: nonce, DataKey: key}
	result, err := c.callBounded(ctx, req, "seal-envelope", doc, "application/vnd.regalia.envelope", resultLimit)
	if err != nil {
		return nil, err
	}
	e, err := nativeEnvelope(result, c.binding)
	if err != nil || !bytes.Equal(e.Nonce, nonce) || !bytes.Equal(e.Ciphertext, doc.Ciphertext) {
		return nil, errOperation
	}
	return result, nil
}

func (c *versionedClient) Unwrap(ctx context.Context, req sops.Request) ([]byte, error) {
	// The outer wrapper has already checked the explicit generation allowlist,
	// metadata agreement and configured context before this request can be made.
	result, err := c.call(ctx, req, "release-secret", versionedRequest{Payload: req.Data}, "application/vnd.regalia.secret")
	if err != nil || len(result) != 32 {
		clear(result)
		return nil, errOperation
	}
	return result, nil
}

func (c *versionedClient) call(ctx context.Context, req sops.Request, operation string, doc versionedRequest, contentType string) ([]byte, error) {
	return c.callBounded(ctx, req, operation, doc, contentType, maxWrappedKey)
}

func (c *versionedClient) callBounded(ctx context.Context, req sops.Request, operation string, doc versionedRequest, contentType string, resultLimit int) ([]byte, error) {
	if c.native {
		return c.nativeCall(ctx, req, operation, doc, contentType, resultLimit)
	}
	if req.ObjectID != c.binding.ObjectID || req.Purpose != c.binding.Purpose || req.Environment != c.binding.Environment {
		return nil, errOperation
	}
	doc.ObjectID, doc.Format = req.ObjectID, "regalia-envelope-v2"
	doc.Context.Environment, doc.Context.Purpose = req.Environment, req.Purpose
	expires := time.Now().UTC().Add(time.Minute)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	doc.Context.ExpiresAt = expires.UTC().Format(time.RFC3339Nano)
	doc.Context.Nonce = req.IdempotencyKey
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, errOperation
	}
	defer clear(encoded)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/operations/"+operation, bytes.NewReader(encoded))
	if err != nil {
		return nil, errOperation
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-Request-ID", req.RequestID)
	httpReq.Header.Set("Idempotency-Key", req.IdempotencyKey)
	// Prevent ambient redirection from forwarding the configured client identity.
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, errOperation
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(resultLimit*2+1)))
	defer clear(data)
	mediaType, _, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || len(data) > resultLimit*2 || resp.StatusCode != http.StatusOK ||
		mediaErr != nil || mediaType != "application/json" || resp.Header.Get("Cache-Control") != "no-store" {
		return nil, errOperation
	}
	var result struct {
		RequestID   string `json:"request_id"`
		OperationID string `json:"operation_id"`
		ObjectID    string `json:"object_id"`
		ContentType string `json:"content_type"`
		Result      []byte `json:"result_base64"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&result) != nil || decoder.Decode(&extra) != io.EOF || result.RequestID != req.RequestID ||
		result.OperationID == "" || result.ObjectID != req.ObjectID || result.ContentType != contentType ||
		len(result.Result) == 0 || len(result.Result) > resultLimit || ctx.Err() != nil {
		clear(result.Result)
		return nil, errOperation
	}
	return result.Result, nil
}
