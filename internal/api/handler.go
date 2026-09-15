// Package api implements the strict HTTP boundary described by api/openapi.json.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/approval"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
)

const maxRequestBytes = 1_500_000

var (
	identifierPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	requestIDPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

type OperationContext struct {
	Environment string
	Purpose     string
	ExpiresAt   time.Time
	Nonce       string
	Subject     string
}

type Request struct {
	RequestID string
	// The Idempotency-Key header is NOT carried here. It is required, and validateRequest
	// refuses a request whose header does not equal context.nonce -- that comparison is the
	// whole of its job, and it happens at the boundary. The nonce is what the policy layer
	// reserves durably, so a copy of the key on this struct would be a second name for a
	// value already present as Context.Nonce, written by the handler and read by nothing.
	// It was exactly that until this change, and the carrier detector could not see it
	// because the SOPS adapter declares a field of the same name.
	Principal   string
	ObjectID    string
	Operation   string
	Context     OperationContext
	Format      string
	ContentType string
	Data        []byte
	EnvelopeAAD []byte
	// Approvals is the raw X-Verified-Approvals header, uninterpreted. The handler
	// deliberately does not parse or validate it: the name of the field it eventually
	// feeds is VerifiedApprovers, and the verification belongs next to the key set in
	// the coordinator rather than in the layer that also decides HTTP status codes.
	// Carrying it as an opaque string keeps this layer unable to assert an approver.
	Approvals string
	// SealCiphertext, SealNonce and SealDataKey carry the assembled seal inputs: the
	// client encrypts locally, and only the data key (never the plaintext) crosses
	// the wire. Present only on seal-envelope; Data is nil there.
	SealCiphertext []byte
	SealNonce      []byte
	SealDataKey    []byte
}

type Result struct {
	OperationID string
	ContentType string
	Data        []byte
}

type Coordinator interface {
	Execute(context.Context, Request) (Result, error)
}

type Failure struct {
	Code      string
	Status    int
	Retryable bool
}

func (failure *Failure) Error() string { return "KMS operation failed" }

type Handler struct{ coordinator Coordinator }

func NewHandler(coordinator Coordinator) *Handler { return &Handler{coordinator: coordinator} }

type contextDocument struct {
	Environment string `json:"environment"`
	Purpose     string `json:"purpose"`
	ExpiresAt   string `json:"expires_at"`
	Nonce       string `json:"nonce"`
	Subject     string `json:"subject,omitempty"`
}

type requestDocument struct {
	ObjectID         string          `json:"object_id"`
	Context          contextDocument `json:"context"`
	Format           string          `json:"format,omitempty"`
	ContentType      string          `json:"content_type,omitempty"`
	Payload          string          `json:"payload_base64,omitempty"`
	PlaintextDataKey string          `json:"plaintext_data_key_base64,omitempty"`
	WrappedDataKey   string          `json:"wrapped_data_key_base64,omitempty"`
	EnvelopeAAD      string          `json:"envelope_aad_base64,omitempty"`
	SealCiphertext   string          `json:"ciphertext_base64,omitempty"`
	SealNonce        string          `json:"nonce_base64,omitempty"`
	SealDataKey      string          `json:"data_key_base64,omitempty"`
}

type resultDocument struct {
	RequestID   string `json:"request_id"`
	OperationID string `json:"operation_id"`
	ObjectID    string `json:"object_id"`
	ContentType string `json:"content_type"`
	Result      string `json:"result_base64"`
}

type errorDocument struct {
	RequestID string `json:"request_id"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// operationPaths is the ONE statement of the operation surface.
//
// This map used to be an anonymous literal inside ServeHTTP while server.Routes carried its own
// hand-written list of three paths. The two disagreed: certificate-sign, key-agreement and
// release-secret were implemented here, documented in API.md, and returned 404 because Routes
// never forwarded them. Three finished features were unreachable and every handler-level test
// passed, because those tests call the Handler directly and never traverse the router.
//
// OperationPaths exists so the router cannot hold a second opinion.
var operationPaths = map[string]string{
	"/v1/operations/sign":             "sign",
	"/v1/operations/wrap":             "wrap",
	"/v1/operations/unwrap":           "unwrap",
	"/v1/operations/certificate-sign": "certificate-sign",
	"/v1/operations/key-agreement":    "key-agreement",
	"/v1/operations/release-secret":   "release-secret",
	"/v1/operations/seal-envelope":    "seal-envelope",
}

// OperationPaths returns every path the operation handler serves, sorted.
func OperationPaths() []string {
	paths := make([]string, 0, len(operationPaths))
	for path := range operationPaths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	operation, known := operationPaths[request.URL.Path]
	if !known {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeError(writer, request.Header.Get("X-Request-ID"), "INVALID_ARGUMENT", http.StatusMethodNotAllowed, false)
		return
	}
	principal := auth.Principal(request.Context())
	if principal == "" {
		writeError(writer, request.Header.Get("X-Request-ID"), "UNAUTHENTICATED", http.StatusUnauthorized, false)
		return
	}
	requestID := request.Header.Get("X-Request-ID")
	idempotencyKey := request.Header.Get("Idempotency-Key")
	if !requestIDPattern.MatchString(requestID) || !idempotencyPattern.MatchString(idempotencyKey) || !isJSON(request.Header.Get("Content-Type")) {
		writeError(writer, requestID, "INVALID_ARGUMENT", http.StatusBadRequest, false)
		return
	}
	document, err := decodeRequest(writer, request)
	if err != nil {
		writeError(writer, requestID, "INVALID_ARGUMENT", http.StatusBadRequest, false)
		return
	}
	input, err := validateRequest(operation, principal, requestID, idempotencyKey, document)
	if err != nil {
		writeError(writer, requestID, "INVALID_ARGUMENT", http.StatusBadRequest, false)
		return
	}
	input.Approvals = request.Header.Get(approval.HeaderName)
	defer zero(input.Data)
	defer zero(input.EnvelopeAAD)
	defer zero(input.SealDataKey)
	defer zero(input.SealNonce)
	defer zero(input.SealCiphertext)
	if handler.coordinator == nil {
		writeError(writer, requestID, "DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable, true)
		return
	}
	result, err := handler.coordinator.Execute(request.Context(), input)
	if err != nil {
		var failure *Failure
		if !errors.As(err, &failure) || failure.Status < 400 || failure.Status > 599 || failure.Code == "" {
			writeError(writer, requestID, "INTERNAL", http.StatusInternalServerError, false)
			return
		}
		writeError(writer, requestID, failure.Code, failure.Status, failure.Retryable)
		return
	}
	defer zero(result.Data)
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(resultDocument{
		RequestID: requestID, OperationID: result.OperationID, ObjectID: input.ObjectID,
		ContentType: result.ContentType, Result: base64.StdEncoding.EncodeToString(result.Data),
	})
}

func decodeRequest(writer http.ResponseWriter, request *http.Request) (requestDocument, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	contents, err := io.ReadAll(request.Body)
	if err != nil {
		return requestDocument{}, err
	}
	if err := rejectDuplicateJSONKeys(contents); err != nil {
		return requestDocument{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var document requestDocument
	if err := decoder.Decode(&document); err != nil {
		return document, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return document, errors.New("request must contain exactly one JSON document")
	}
	return document, nil
}

// rejectDuplicateJSONKeys prevents ambiguous requests where different parsers or
// intermediaries select different values for the same field. encoding/json otherwise
// silently applies last-key-wins semantics.
func rejectDuplicateJSONKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch delimiter := token.(type) {
		case json.Delim:
			switch delimiter {
			case '{':
				seen := map[string]struct{}{}
				for decoder.More() {
					key, err := decoder.Token()
					if err != nil {
						return err
					}
					name, ok := key.(string)
					if !ok {
						return errors.New("invalid object key")
					}
					if _, exists := seen[name]; exists {
						return errors.New("duplicate JSON key")
					}
					seen[name] = struct{}{}
					if err := walk(); err != nil {
						return err
					}
				}
				_, err := decoder.Token()
				return err
			case '[':
				for decoder.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				_, err := decoder.Token()
				return err
			}
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain exactly one JSON document")
	}
	return nil
}

func validateRequest(operation, principal, requestID, idempotencyKey string, document requestDocument) (Request, error) {
	expiresAt, err := time.Parse(time.RFC3339Nano, document.Context.ExpiresAt)
	if err != nil || !identifierPattern.MatchString(document.ObjectID) || !identifierPattern.MatchString(document.Context.Purpose) ||
		(document.Context.Environment != "production" && document.Context.Environment != "staging" && document.Context.Environment != "development") ||
		!idempotencyPattern.MatchString(document.Context.Nonce) || document.Context.Nonce != idempotencyKey || len(document.Context.Subject) > 256 {
		return Request{}, errors.New("invalid operation context")
	}
	encoded, maximum := "", 0
	switch operation {
	case "sign":
		if document.Format != "" || document.PlaintextDataKey != "" || document.WrappedDataKey != "" || document.ContentType == "" {
			return Request{}, errors.New("invalid sign request")
		}
		encoded, maximum = document.Payload, 1<<20
	case "wrap":
		if document.Format != "regalia-envelope-v2" || document.Payload != "" || document.WrappedDataKey != "" || document.ContentType != "" {
			return Request{}, errors.New("invalid wrap request")
		}
		encoded, maximum = document.PlaintextDataKey, 4096
	case "unwrap":
		if (document.Format != "regalia-envelope-v2" && document.Format != "sops-pgp") || document.Payload != "" || document.PlaintextDataKey != "" || document.ContentType != "" {
			return Request{}, errors.New("invalid unwrap request")
		}
		encoded, maximum = document.WrappedDataKey, 48<<10
	case "certificate-sign":
		// The payload is a PKCS#10 request in DER. The caller supplies no format, no data-key
		// fields and no content type: what the certificate says is the server's decision, taken
		// from the issuing profile, so there is nothing here for the client to select.
		if document.Format != "" || document.PlaintextDataKey != "" || document.WrappedDataKey != "" || document.ContentType != "" {
			return Request{}, errors.New("invalid certificate-sign request")
		}
		encoded, maximum = document.Payload, 8<<10
	case "key-agreement":
		// The payload is the peer's PKIX public key. There is no format or content type to
		// choose: the derivation and its KDF are the server's, and the request context binds the
		// result so a derived key cannot be repurposed.
		if document.Format != "" || document.PlaintextDataKey != "" || document.WrappedDataKey != "" || document.ContentType != "" {
			return Request{}, errors.New("invalid key-agreement request")
		}
		encoded, maximum = document.Payload, 4096
	case "release-secret":
		// The payload is the envelope the caller holds. The KMS stores no secret: the value lives
		// outside the token as authenticated ciphertext, and only the data key is unwrapped on it.
		//
		// There is no envelope_aad here either. The binding context is the server's decision, taken
		// from the authorized route, exactly as the certificate profile above is: a context the
		// caller chooses proves only that the caller knows what it chose. ENVELOPE.md requires it to
		// be reconstructed by the KMS rather than accepted as a client assertion, and it was accepted
		// as one -- decoded here, passed through the coordinator, and compared with nothing.
		if document.Format != "regalia-envelope-v2" || document.PlaintextDataKey != "" || document.WrappedDataKey != "" || document.ContentType != "" || document.EnvelopeAAD != "" {
			return Request{}, errors.New("invalid release-secret request")
		}
		encoded, maximum = document.Payload, 64<<10
	case "seal-envelope":
		// The caller has already encrypted locally; the request carries the assembled parts and
		// never the plaintext. Like release-secret, there is no envelope_aad: the binding context
		// is the server's decision, taken from the authorized route — a context the caller chooses
		// proves only that the caller knows what it chose.
		if document.Format != "regalia-envelope-v2" || document.Payload != "" || document.PlaintextDataKey != "" ||
			document.WrappedDataKey != "" || document.ContentType != "" || document.EnvelopeAAD != "" {
			return Request{}, errors.New("invalid seal-envelope request")
		}
		encoded, maximum = document.SealCiphertext, (1<<20)+16
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) == 0 || len(data) > maximum {
		zero(data)
		return Request{}, errors.New("invalid operation payload")
	}
	aad, err := base64.StdEncoding.Strict().DecodeString(document.EnvelopeAAD)
	if err != nil || len(aad) > 12<<10 {
		zero(data)
		zero(aad)
		return Request{}, errors.New("invalid envelope context")
	}
	request := Request{
		RequestID: requestID, Principal: principal,
		ObjectID: document.ObjectID, Operation: operation, Context: OperationContext{
			Environment: document.Context.Environment, Purpose: document.Context.Purpose,
			ExpiresAt: expiresAt, Nonce: document.Context.Nonce, Subject: document.Context.Subject,
		}, Format: document.Format, ContentType: document.ContentType, Data: data, EnvelopeAAD: aad,
	}
	if operation == "seal-envelope" {
		// The payload decoded above is the ciphertext; the other two assembled parts
		// carry exact sizes. A 16-byte ciphertext is a GCM tag over zero bytes — there
		// is no such thing as an empty envelope. Any rejection zeroes everything decoded.
		if request.SealNonce, err = base64.StdEncoding.Strict().DecodeString(document.SealNonce); err != nil || len(request.SealNonce) != 12 {
			zero(data)
			return Request{}, errors.New("invalid seal nonce")
		}
		if request.SealDataKey, err = base64.StdEncoding.Strict().DecodeString(document.SealDataKey); err != nil || len(request.SealDataKey) != 32 {
			zero(data)
			zero(request.SealNonce)
			return Request{}, errors.New("invalid seal data key")
		}
		if len(data) < 17 {
			zero(data)
			zero(request.SealNonce)
			zero(request.SealDataKey)
			return Request{}, errors.New("invalid seal ciphertext")
		}
		request.SealCiphertext = data
		request.Data = nil
	}
	return request, nil
}

func isJSON(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func writeError(writer http.ResponseWriter, requestID, code string, status int, retryable bool) {
	if !requestIDPattern.MatchString(requestID) {
		requestID = "00000000-0000-4000-8000-000000000000"
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(errorDocument{RequestID: requestID, Code: code, Message: "request failed", Retryable: retryable})
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
