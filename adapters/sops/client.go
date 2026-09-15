package sopsadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPClient struct {
	baseURL string
	client  *http.Client
	now     func() time.Time
}

type operationContext struct {
	Environment string `json:"environment"`
	Purpose     string `json:"purpose"`
	ExpiresAt   string `json:"expires_at"`
	Nonce       string `json:"nonce"`
	Subject     string `json:"subject"`
}

type operationRequest struct {
	ObjectID         string           `json:"object_id"`
	Context          operationContext `json:"context"`
	Format           string           `json:"format"`
	PlaintextDataKey string           `json:"plaintext_data_key_base64,omitempty"`
	WrappedDataKey   string           `json:"wrapped_data_key_base64,omitempty"`
	EnvelopeAAD      string           `json:"envelope_aad_base64"`
}

type operationResponse struct {
	RequestID   string `json:"request_id"`
	OperationID string `json:"operation_id"`
	ObjectID    string `json:"object_id"`
	ContentType string `json:"content_type"`
	Result      []byte `json:"result_base64"`
}

type bindingAAD struct {
	Repository  string `json:"repository"`
	Path        string `json:"path"`
	Environment string `json:"environment"`
	Purpose     string `json:"purpose"`
}

func NewHTTPClient(baseURL string, client *http.Client, now func() time.Time) *HTTPClient {
	if client == nil {
		return &HTTPClient{baseURL: strings.TrimSuffix(baseURL, "/"), now: now}
	}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPClient{baseURL: strings.TrimSuffix(baseURL, "/"), client: &copy, now: now}
}

func (client *HTTPClient) Wrap(ctx context.Context, request Request) ([]byte, error) {
	return client.call(ctx, request, "/v1/operations/wrap")
}

func (client *HTTPClient) Unwrap(ctx context.Context, request Request) ([]byte, error) {
	return client.call(ctx, request, "/v1/operations/unwrap")
}

func (client *HTTPClient) call(ctx context.Context, request Request, endpoint string) ([]byte, error) {
	if client == nil || client.client == nil || client.now == nil || !validHTTPSBase(client.baseURL) || !validTransportRequest(request, endpoint) {
		return nil, errors.New("invalid KMS client request")
	}
	aad, err := json.Marshal(bindingAAD{Repository: request.Repository, Path: request.Path, Environment: request.Environment, Purpose: request.Purpose})
	if err != nil {
		return nil, errors.New("invalid KMS client request")
	}
	sum := sha256.Sum256(aad)
	body := operationRequest{
		ObjectID: request.ObjectID,
		Context: operationContext{
			Environment: request.Environment, Purpose: request.Purpose,
			ExpiresAt: client.now().UTC().Add(time.Minute).Format(time.RFC3339Nano), Nonce: request.IdempotencyKey,
			Subject: "sha256:" + hex.EncodeToString(sum[:]),
		},
		Format: "regalia-envelope-v2", EnvelopeAAD: base64.StdEncoding.EncodeToString(aad),
	}
	if endpoint == "/v1/operations/wrap" {
		body.PlaintextDataKey = base64.StdEncoding.EncodeToString(request.Data)
	} else {
		body.WrappedDataKey = base64.StdEncoding.EncodeToString(request.Data)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, errors.New("invalid KMS client request")
	}
	defer zero(encoded)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, errors.New("invalid KMS client request")
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("X-Request-ID", request.RequestID)
	httpRequest.Header.Set("Idempotency-Key", request.IdempotencyKey)
	response, err := client.client.Do(httpRequest)
	if err != nil {
		return nil, errors.New("KMS operation failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !jsonContentType(response.Header.Get("Content-Type")) {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, errors.New("KMS operation failed")
	}
	if endpoint == "/v1/operations/unwrap" && response.Header.Get("Cache-Control") != "no-store" {
		// Drain like the branch above. Returning without reading leaves the connection
		// unreusable, so a server that keeps omitting the header quietly accumulates idle
		// connections instead of reusing one.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, errors.New("KMS operation failed")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxCiphertextBytes+8192))
	decoder.DisallowUnknownFields()
	var result operationResponse
	if err := decoder.Decode(&result); err != nil {
		return nil, errors.New("KMS operation failed")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("KMS operation failed")
	}
	maximum := maxCiphertextBytes
	if endpoint == "/v1/operations/unwrap" {
		maximum = maxDataKeyBytes
	}
	if result.RequestID != request.RequestID || result.OperationID == "" || result.ObjectID != request.ObjectID || len(result.Result) == 0 || len(result.Result) > maximum {
		zero(result.Result)
		return nil, errors.New("KMS operation failed")
	}
	return result.Result, nil
}

func jsonContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func validHTTPSBase(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validTransportRequest(request Request, endpoint string) bool {
	if request.Operation == "" || (endpoint == "/v1/operations/wrap" && request.Operation != "wrap") || (endpoint == "/v1/operations/unwrap" && request.Operation != "unwrap") {
		return false
	}
	if !identifierPattern.MatchString(request.ObjectID) || !repositoryPattern.MatchString(request.Repository) || !safePath(request.Path) || !identifierPattern.MatchString(request.Purpose) {
		return false
	}
	if request.Environment != "production" && request.Environment != "staging" && request.Environment != "development" {
		return false
	}
	return len(request.RequestID) == 36 && len(request.IdempotencyKey) >= 16 && len(request.IdempotencyKey) <= 128 && len(request.Data) > 0
}
