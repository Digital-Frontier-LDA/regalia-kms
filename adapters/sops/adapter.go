// Package sopsadapter translates the upstream SOPS key-service protocol into
// authenticated Regalia KMS wrap/unwrap requests. It contains no key backend.
package sopsadapter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strings"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops/sopsrpc"
)

const (
	maxDataKeyBytes    = 4096
	maxCiphertextBytes = 48 << 10
)

var (
	carrierPattern    = regexp.MustCompile(`^arn:aws:kms:regalia:000000000000:key/([a-z0-9][a-z0-9-]{2,62})$`)
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
)

type Request struct {
	Operation      string
	ObjectID       string
	Repository     string
	Path           string
	Environment    string
	Purpose        string
	RequestID      string
	IdempotencyKey string
	Data           []byte
}

type KMSClient interface {
	Wrap(context.Context, Request) ([]byte, error)
	Unwrap(context.Context, Request) ([]byte, error)
}

type Server struct {
	sopsrpc.UnimplementedKeyServiceServer
	client KMSClient
}

func New(client KMSClient) *Server { return &Server{client: client} }

func (server *Server) Encrypt(ctx context.Context, input *sopsrpc.EncryptRequest) (*sopsrpc.EncryptResponse, error) {
	request, err := translate(input.GetKey(), "wrap", input.GetPlaintext())
	if err != nil || server.client == nil || len(request.Data) == 0 || len(request.Data) > maxDataKeyBytes {
		return nil, errors.New("invalid SOPS key request")
	}
	defer zero(request.Data)
	result, err := server.client.Wrap(ctx, request)
	if err != nil || len(result) == 0 || len(result) > maxCiphertextBytes {
		zero(result)
		return nil, errors.New("KMS operation failed")
	}
	return &sopsrpc.EncryptResponse{Ciphertext: result}, nil
}

func (server *Server) Decrypt(ctx context.Context, input *sopsrpc.DecryptRequest) (*sopsrpc.DecryptResponse, error) {
	request, err := translate(input.GetKey(), "unwrap", input.GetCiphertext())
	if err != nil || server.client == nil || len(request.Data) == 0 || len(request.Data) > maxCiphertextBytes {
		return nil, errors.New("invalid SOPS key request")
	}
	defer zero(request.Data)
	result, err := server.client.Unwrap(ctx, request)
	if err != nil || len(result) == 0 || len(result) > maxDataKeyBytes {
		zero(result)
		return nil, errors.New("KMS operation failed")
	}
	return &sopsrpc.DecryptResponse{Plaintext: result}, nil
}

func translate(key *sopsrpc.Key, operation string, data []byte) (Request, error) {
	if key == nil || key.GetKmsKey() == nil {
		return Request{}, errors.New("unsupported SOPS key type")
	}
	carrier := key.GetKmsKey()
	if carrier.GetRole() != "" || carrier.GetAwsProfile() != "" {
		return Request{}, errors.New("AWS role/profile fields are forbidden")
	}
	matches := carrierPattern.FindStringSubmatch(carrier.GetArn())
	if len(matches) != 2 {
		return Request{}, errors.New("invalid Regalia carrier ARN")
	}
	values := carrier.GetContext()
	if len(values) != 4 {
		return Request{}, errors.New("incomplete SOPS binding context")
	}
	repository, filePath := values["repository"], values["path"]
	environment, purpose := values["environment"], values["purpose"]
	if !repositoryPattern.MatchString(repository) || !safePath(filePath) ||
		(environment != "production" && environment != "staging" && environment != "development") || !identifierPattern.MatchString(purpose) {
		return Request{}, errors.New("invalid SOPS binding context")
	}
	requestID, err := randomID()
	if err != nil {
		return Request{}, errors.New("request identity unavailable")
	}
	return Request{
		Operation: operation, ObjectID: matches[1], Repository: repository, Path: filePath,
		Environment: environment, Purpose: purpose, RequestID: requestID,
		IdempotencyKey: "sops-" + strings.ReplaceAll(requestID, "-", ""), Data: append([]byte(nil), data...),
	}, nil
}

func safePath(value string) bool {
	return value != "" && len(value) <= 256 && !strings.Contains(value, "\\") && !strings.HasPrefix(value, "/") &&
		path.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, "../")
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
