# runtime/cryptographic-operations Specification

## Purpose

Define the supported hardware operation contracts, format boundaries, and failure behavior presented to clients.

## Requirements

### Requirement: KMS-CRYPTO-001 Signature input and encoding

The KMS SHALL enforce the signing input admitted for the selected backend and algorithm. PIV Ed25519 SHALL sign a bounded message without prehashing, PIV digest signing SHALL require the declared digest size, and Nitrokey PKCS#11 secp256k1 SHALL produce a 64-byte low-S signature.

#### Scenario: PIV signing boundaries

- **WHEN** a PIV request carries an admitted digest or a 1–1024 byte Ed25519 message
- **THEN** the input is admitted under the matching signing contract

#### Scenario: Invalid signing input

- **WHEN** a PIV request carries a digest of incorrect length or an out-of-bound Ed25519 message
- **THEN** the input is refused

#### Scenario: ECDSA canonical form

- **WHEN** the token returns a valid high-S secp256k1 signature
- **THEN** the result is normalized to low-S raw r and s

### Requirement: KMS-CRYPTO-002 Context-bound agreement

Where the hardware route admits key agreement, the KMS SHALL return a 32-byte HKDF-SHA256 key bound to the supplied context and SHALL withhold the raw ECDH shared secret.

#### Scenario: Derived result

- **WHEN** the admitted token and peer key produce a shared secret
- **THEN** the response carries the context-bound derived key

#### Scenario: Context separation

- **WHEN** the same peer key is used with two different contexts
- **THEN** the derived keys differ

### Requirement: KMS-CRYPTO-003 Context-bound RSA wrapping

The Regalia RSA-OAEP wrapping format SHALL bind the wrapped key to the supplied context. Unwrapping framed data under a different context SHALL fail, and wrapping with an empty context or mismatched RSA key size SHALL fail.

#### Scenario: Matching wrap context

- **WHEN** a framed key is decrypted and opened under the original context
- **THEN** the original key bytes are recovered

#### Scenario: Context or key mismatch

- **WHEN** the context changes, the wrap context is absent or the key size disagrees with the requested algorithm
- **THEN** the operation is refused

### Requirement: KMS-CRYPTO-004 Bounded operation execution

The operation runner SHALL refuse requests at its concurrency bound, return deadline or cancellation failures, and retain an in-flight execution slot until the underlying call returns. A panic SHALL return a sanitized operation failure and restore capacity.

#### Scenario: Concurrency bound

- **WHEN** the configured number of operations is already in progress
- **THEN** an additional call receives a retryable busy result

#### Scenario: Deadline or panic

- **WHEN** the operation times out or the backend panics
- **THEN** the caller receives a classified failure without backend detail
