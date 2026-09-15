package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

func LoadFile(path string) ([]Policy, string, error) {
	// FAULT INJECTION CLASS (#334) [load.LoadFile/open]: MEASURED with this branch
	// neutralised, because the first version of this comment paraphrased the refusal and
	// got it wrong, and a review then predicted a panic that does not happen either:
	//
	// 	os.Open(missing)  -> file == nil, "no such file or directory"
	// 	file.Stat()       -> nil, "invalid argument"   (no panic; os nil-checks the receiver)
	// 	LoadFile(missing) -> "policy must be a non-writable regular file"
	//
	// The ErrInvalid satisfies the first operand of the mode guard below, so a file that is
	// not there is refused for its permissions. The ledger row asserts os.ErrNotExist
	// specifically, because a stat error is not absence.
	file, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open policy: %w", err)
	}
	defer file.Close()
	// FAULT INJECTION CLASS (#334) [load.LoadFile/stat]: the err != nil operand is §17
	// unreachable -- fstat on a descriptor Open just returned does not fail portably -- and
	// it shares one return with two operands that ARE reachable (a directory, and a group-
	// or world-writable file), both pinned by readiness_test.go. Even an inducible fault
	// could not be isolated from them. Classified in fault_injection_leaves_test.go.
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, "", errors.New("policy must be a non-writable regular file")
	}
	return Load(file)
}

const maxPolicyFileBytes = 512 << 10

type fileDocument struct {
	SchemaVersion int          `json:"schema_version"`
	Policies      []filePolicy `json:"policies"`
}

type filePolicy struct {
	ID                string            `json:"id"`
	ObjectID          string            `json:"object_id"`
	Purpose           string            `json:"purpose"`
	Environment       string            `json:"environment"`
	Operation         string            `json:"operation"`
	Algorithm         string            `json:"algorithm"`
	ContentTypes      []string          `json:"content_types"`
	MaxPayloadBytes   int64             `json:"max_payload_bytes"`
	MaxFutureSeconds  int64             `json:"max_future_seconds"`
	RequiredApprovals int               `json:"required_approvals"`
	Approvers         []string          `json:"approvers"`
	Cosmos            *fileCosmosPolicy `json:"cosmos,omitempty"`
}

type fileCosmosPolicy struct {
	ChainIDs          []string          `json:"chain_ids"`
	AccountNumbers    []uint64          `json:"account_numbers"`
	MessageTypes      []string          `json:"message_types"`
	Destinations      []string          `json:"destinations"`
	Sources           []string          `json:"sources"`
	MaxGasLimit       uint64            `json:"max_gas_limit"`
	MaxFee            map[string]uint64 `json:"max_fee"`
	MaxPerTransaction map[string]uint64 `json:"max_per_transaction"`
	MaxPerDay         map[string]uint64 `json:"max_per_day"`
}

func Load(reader io.Reader) ([]Policy, string, error) {
	// FAULT INJECTION CLASS (#334) [load.Load/read-and-cap]: two leaves, one marker. The
	// io.ReadAll branch is reached only by a failing io.Reader (the harness supplies one);
	// the size cap is reached by a payload above 512 KiB, and without it the LimitReader
	// TRUNCATES such a payload and the operator is told their JSON is malformed rather than
	// oversized. Both have ledger rows in fault_injection_leaves_test.go.
	contents, err := io.ReadAll(io.LimitReader(reader, maxPolicyFileBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read policy: %w", err)
	}
	if len(contents) > maxPolicyFileBytes {
		return nil, "", errors.New("policy exceeds 512 KiB")
	}
	var document fileDocument
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, "", fmt.Errorf("decode policy: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, "", errors.New("policy must contain exactly one JSON document")
	}
	if document.SchemaVersion != 1 || len(document.Policies) == 0 {
		return nil, "", errors.New("policy is empty or unsupported")
	}
	policies := make([]Policy, 0, len(document.Policies))
	for _, input := range document.Policies {
		if input.MaxFutureSeconds < 1 || input.MaxFutureSeconds > 3600 {
			return nil, "", errors.New("max_future_seconds must be between 1 and 3600")
		}
		output := Policy{
			ID: input.ID, ObjectID: input.ObjectID, Purpose: input.Purpose, Environment: input.Environment,
			Operation: input.Operation, Algorithm: input.Algorithm, ContentTypes: input.ContentTypes,
			MaxPayloadBytes: input.MaxPayloadBytes, MaxFuture: time.Duration(input.MaxFutureSeconds) * time.Second,
			RequiredApprovals: input.RequiredApprovals, Approvers: input.Approvers,
		}
		if input.Cosmos != nil {
			output.Cosmos = &CosmosPolicy{
				ChainIDs: input.Cosmos.ChainIDs, AccountNumbers: input.Cosmos.AccountNumbers,
				MessageTypes: input.Cosmos.MessageTypes, Destinations: input.Cosmos.Destinations,
				Sources:     input.Cosmos.Sources,
				MaxGasLimit: input.Cosmos.MaxGasLimit, MaxFee: input.Cosmos.MaxFee,
				MaxPerTransaction: input.Cosmos.MaxPerTransaction, MaxPerDay: input.Cosmos.MaxPerDay,
			}
		}
		policies = append(policies, output)
	}
	sum := sha256.Sum256(contents)
	return policies, "sha256:" + hex.EncodeToString(sum[:]), nil
}
