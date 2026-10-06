package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// The runner can return on cancellation while middleware still holds its slot.
// The worker must own its input buffers, and may publish a result only before
// the caller abandons it. Neither a late write nor input cleanup can race with
// the HTTP handler's own cleanup after Execute returns.
func (c *Coordinator) executeHardware(ctx context.Context, route registry.Route, request api.Request, contentType string) ([]byte, string, error) {
	owned := request
	owned.Data = bytes.Clone(request.Data)
	owned.EnvelopeAAD = bytes.Clone(request.EnvelopeAAD)
	owned.SealCiphertext = bytes.Clone(request.SealCiphertext)
	owned.SealNonce = bytes.Clone(request.SealNonce)
	owned.SealDataKey = bytes.Clone(request.SealDataKey)
	if request.Operation == "seal-envelope" {
		// Preserve the seal API's caller-key cleanup, now without touching the
		// independent buffer retained by a canceled but still-running worker.
		defer zero(request.SealDataKey)
	}
	clearInputs := func() {
		zero(owned.Data)
		zero(owned.EnvelopeAAD)
		zero(owned.SealCiphertext)
		zero(owned.SealNonce)
		zero(owned.SealDataKey)
	}
	var mu sync.Mutex
	var started, closed bool
	var output []byte
	var outputType string
	runErr := c.runner.Run(ctx, func(operationCtx context.Context) error {
		mu.Lock()
		if closed {
			mu.Unlock()
			return context.Canceled
		}
		started = true
		mu.Unlock()
		defer clearInputs()
		var result []byte
		var resultType string
		var operationErr error
		defer func() { zero(result) }()
		if owned.Operation == "seal-envelope" {
			result, resultType, operationErr = c.seal(operationCtx, route, owned)
		} else {
			data := owned.Data
			hardwareContentType := contentType
			if contentType == "application/vnd.cosmos.tx+protobuf" || contentType == x509TBSContentType {
				digest := sha256.Sum256(data)
				data = digest[:]
				if contentType == x509TBSContentType {
					hardwareContentType = "application/vnd.regalia.digest"
				}
			}
			result, resultType, operationErr = c.hardware.Execute(operationCtx, route, owned.Operation, owned.Format, hardwareContentType, data, owned.EnvelopeAAD)
		}
		mu.Lock()
		defer mu.Unlock()
		if !closed {
			// A provider may alias its input. The caller's result must survive
			// clearing both worker inputs and the backend result on return.
			output, outputType = bytes.Clone(result), resultType
		}
		return operationErr
	})
	mu.Lock()
	defer mu.Unlock()
	closed = true
	if !started {
		// At capacity, canceled before dispatch, or no callback invoked.
		clearInputs()
	}
	if runErr != nil {
		zero(output)
		return nil, "", runErr
	}
	return output, outputType, nil
}
