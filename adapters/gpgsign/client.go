// Package gpgsign produces OpenPGP signatures whose private-key operation is the Regalia KMS
// `sign` operation. The private key never exists here: this package holds the PUBLIC key, asks the
// KMS to sign a digest over mTLS, checks the answer against that public key, and lets
// github.com/ProtonMail/go-crypto frame it as an OpenPGP packet.
package gpgsign

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// digestContentType is the only content type this adapter ever asks the KMS to sign: a digest (or,
// for RSA, the DigestInfo that carries one). A purpose policy for a release key allows exactly this.
const digestContentType = "application/vnd.regalia.digest"

// maxSignatureBytes bounds a result: RSA-4096 is 512 bytes, the largest signature the KMS returns.
const maxSignatureBytes = 512

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)

// Target names what is signed with, in the KMS's own terms: an object and the context its purpose
// policy binds. Nothing here selects a device, a slot or an algorithm (API.md).
type Target struct {
	ObjectID    string
	Environment string
	Purpose     string
}

func (target Target) valid() bool {
	if !identifierPattern.MatchString(target.ObjectID) || !identifierPattern.MatchString(target.Purpose) {
		return false
	}
	return target.Environment == "production" || target.Environment == "staging" || target.Environment == "development"
}

// KMSError is a refusal the KMS itself returned. Code is the API's error code (API.md): DENIED and
// INVALID_ARGUMENT never succeed on retry, and Retryable says so for the rest.
type KMSError struct {
	Code      string
	Status    int
	Retryable bool
}

func (failure *KMSError) Error() string {
	return fmt.Sprintf("the KMS refused the signature: %s (HTTP %d)", failure.Code, failure.Status)
}

// Client calls POST /v1/operations/sign.
type Client struct {
	baseURL string
	client  *http.Client
	now     func() time.Time
	random  io.Reader
}

// NewClient returns a client for the KMS at baseURL, which must be an HTTPS origin. client carries
// the mTLS identity. Redirects are never followed: a KMS that answers with one is not the KMS.
func NewClient(baseURL string, client *http.Client, now func() time.Time) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("the KMS URL must be an HTTPS origin")
	}
	if client == nil || now == nil {
		return nil, errors.New("the KMS client needs an HTTP client and a clock")
	}
	copy := *client
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{baseURL: strings.TrimSuffix(baseURL, "/"), client: &copy, now: now, random: rand.Reader}, nil
}

type operationContext struct {
	Environment string `json:"environment"`
	Purpose     string `json:"purpose"`
	ExpiresAt   string `json:"expires_at"`
	Nonce       string `json:"nonce"`
	Subject     string `json:"subject,omitempty"`
}

type operationRequest struct {
	ObjectID    string           `json:"object_id"`
	Context     operationContext `json:"context"`
	ContentType string           `json:"content_type"`
	Payload     string           `json:"payload_base64"`
}

type operationResponse struct {
	RequestID   string `json:"request_id"`
	OperationID string `json:"operation_id"`
	ObjectID    string `json:"object_id"`
	ContentType string `json:"content_type"`
	Result      []byte `json:"result_base64"`
}

type errorResponse struct {
	RequestID string `json:"request_id"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// Sign asks the KMS to sign payload with target's object and returns the raw signature bytes.
// subject is recorded with the request (at most 256 bytes); it says what the digest is of, and is a
// statement by this client, not something the KMS can check.
func (client *Client) Sign(ctx context.Context, target Target, payload []byte, subject string) ([]byte, error) {
	if client == nil || !target.valid() || len(payload) == 0 || len(subject) > 256 {
		return nil, errors.New("invalid KMS sign request")
	}
	entropy := make([]byte, 32)
	if _, err := io.ReadFull(client.random, entropy); err != nil {
		return nil, errors.New("no randomness for the request nonce")
	}
	// One fresh nonce per request, and it IS the idempotency key (API.md): the KMS reserves it
	// durably, so a request cannot be replayed under another key.
	nonce := hex.EncodeToString(entropy[:16])
	requestID := uuidV4(entropy[16:])
	encoded, err := json.Marshal(operationRequest{
		ObjectID: target.ObjectID,
		Context: operationContext{
			Environment: target.Environment, Purpose: target.Purpose,
			ExpiresAt: client.now().UTC().Add(time.Minute).Format(time.RFC3339Nano), Nonce: nonce, Subject: subject,
		},
		ContentType: digestContentType, Payload: base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		return nil, errors.New("invalid KMS sign request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.baseURL+"/v1/operations/sign", bytes.NewReader(encoded))
	if err != nil {
		return nil, errors.New("invalid KMS sign request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Request-ID", requestID)
	request.Header.Set("Idempotency-Key", nonce)
	response, err := client.client.Do(request)
	if err != nil {
		// The cause is a TLS or network failure. It is reported as one fixed line: the transport's
		// own text names hosts and certificates, and belongs in the operator's debugging, not in a
		// release log.
		return nil, errors.New("the KMS is unreachable or refused the connection")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	if err != nil || !jsonContentType(response.Header.Get("Content-Type")) {
		return nil, errors.New("the KMS answered with something that is not its API")
	}
	if response.StatusCode != http.StatusOK {
		var failure errorResponse
		if decodeStrict(body, &failure) != nil || failure.Code == "" {
			return nil, errors.New("the KMS answered with something that is not its API")
		}
		return nil, &KMSError{Code: failure.Code, Status: response.StatusCode, Retryable: failure.Retryable}
	}
	var result operationResponse
	if decodeStrict(body, &result) != nil {
		return nil, errors.New("the KMS answered with something that is not its API")
	}
	// The answer must be to THIS request, for THIS object, and be signature-sized. Whether it is a
	// valid signature is the caller's check, against the pinned public key.
	if result.RequestID != requestID || result.OperationID == "" || result.ObjectID != target.ObjectID ||
		len(result.Result) == 0 || len(result.Result) > maxSignatureBytes {
		return nil, errors.New("the KMS answer does not match the request")
	}
	return result.Result, nil
}

func decodeStrict(body []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(into); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("more than one JSON document")
	}
	return nil
}

func jsonContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

// uuidV4 formats 16 random bytes as an RFC 9562 version-4 UUID, which X-Request-ID must be.
func uuidV4(random []byte) string {
	value := make([]byte, 16)
	copy(value, random)
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	text := hex.EncodeToString(value)
	return text[0:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:32]
}
