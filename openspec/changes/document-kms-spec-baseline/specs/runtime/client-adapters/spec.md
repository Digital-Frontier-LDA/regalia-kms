## Purpose

Define client-side operation mapping, transport boundaries, and supported interoperability claims.

## ADDED Requirements

### Requirement: KMS-ADAPTER-001 SOPS context-bound wrapping

The SOPS adapter SHALL map the admitted carrier and its exact repository, normalized relative path, environment and purpose to KMS wrap and unwrap operations. Malformed carrier input SHALL fail before a KMS call, and a different context or failed KMS unwrap SHALL return no plaintext.

#### Scenario: SOPS round trip

- **WHEN** a valid carrier encrypts and decrypts a data key under the same context
- **THEN** the returned plaintext equals the original data key

#### Scenario: Context mismatch

- **WHEN** decrypt presents a different purpose
- **THEN** the adapter returns an error and no data key

#### Scenario: Malformed carrier

- **WHEN** a required context field is missing or an extra field is supplied
- **THEN** the adapter refuses the request

#### Scenario: Local Encrypt protobuf mapping

- **WHEN** an admitted carrier is used by a client speaking the sidecar's local protobuf contract at `/KeyService/Encrypt` and the operation succeeds
- **THEN** the request carries `key` at field 1 and `plaintext` at field 2, and the response carries `ciphertext` at field 1. The local `Key` uses `kms_key` at field 1 with carrier fields `arn` 1, `role` 2, `context` 3 (entry key 1 and value 2) and `aws_profile` 4

#### Scenario: Local Decrypt protobuf mapping

- **WHEN** an admitted carrier is used by a client speaking the sidecar's local protobuf contract at `/KeyService/Decrypt` and the operation succeeds
- **THEN** the request carries `key` at field 1 and `ciphertext` at field 2, and the response carries `plaintext` at field 1. The local `Key` uses `kms_key` at field 1 with carrier fields `arn` 1, `role` 2, `context` 3 (entry key 1 and value 2) and `aws_profile` 4

#### Scenario: Encrypt maps the SOPS 3.13.3 carrier wire fields

- **WHEN** a client sends `getsops/sops v3.13.3` protobuf for the admitted KMS carrier to `/KeyService/Encrypt`
- **THEN** the unary method decodes `key` as request field 1 and `plaintext` bytes as field 2, and on success returns `ciphertext` bytes as response field 1

#### Scenario: Decrypt maps the SOPS 3.13.3 carrier wire fields

- **WHEN** a client sends `getsops/sops v3.13.3` protobuf for the admitted KMS carrier to `/KeyService/Decrypt`
- **THEN** the unary method decodes `key` as request field 1 and `ciphertext` bytes as field 2, and on success returns `plaintext` bytes as response field 1

#### Scenario: The SOPS 3.13.3 KMS carrier has matching nested tags

- **WHEN** either method receives `getsops/sops v3.13.3` wire data with only the `kms_key` alternative of `Key`
- **THEN** the wire mapping uses `kms_key` 1, then `arn` 1, `role` 2, `context` 3 with entry key 1 and value 2, and `aws_profile` 4. The adapter still refuses nonempty role or profile values

### Requirement: KMS-ADAPTER-002 Local SOPS trust domain

The SOPS service SHALL listen on a private mode-0600 Unix socket, refuse an existing entry or writable socket parent, and use a bounded TLS 1.3 client with explicit trust roots and server identity. The KMS authenticates the sidecar's workload principal for every caller sharing its socket.

#### Scenario: Private sidecar

- **WHEN** the service starts in an admissible directory at an unused path
- **THEN** the socket is mode 0600 and serves the published RPC

#### Scenario: Unsafe socket or remote trust

- **WHEN** the path exists, the parent is group-writable, or remote trust is incomplete
- **THEN** startup or transport construction refuses the invalid configuration

#### Scenario: Shared socket callers use the configured sidecar principal

- **WHEN** two callers within the same local socket trust domain submit valid Encrypt or Decrypt requests through one sidecar configured with a single accepted KMS client identity
- **THEN** each forwarded wrap or unwrap authenticates to the KMS as that sidecar's workload principal, which is also the attribution of any corresponding operation audit records

### Requirement: KMS-ADAPTER-003 GnuPG-compatible signing output

The signing adapter SHALL emit only a signature that matches the configured public key and the operation it requested from the KMS. It SHALL support detached and cleartext OpenPGP signing for its admitted algorithms and return no output on a refusal or mismatched result.

#### Scenario: Valid signatures

- **WHEN** an admitted request receives a correct signature
- **THEN** the emitted detached or cleartext signature verifies for the original content

#### Scenario: Incorrect result

- **WHEN** the response is uncorrelated or fails verification against the pinned key
- **THEN** the adapter rejects it and writes no signature

#### Scenario: Git signs a commit and tag through the configured command

- **WHEN** Git invokes the signer using its supported named detached-signature form
- **THEN** the resulting commit and tag signatures verify with GnuPG

#### Scenario: Signature publication preserves an occupied destination

- **WHEN** the signing command reaches the final publication of a detached or cleartext signature in a directory it can write, and the destination name is occupied at that instant, including by a dangling symlink
- **THEN** the command reports that the destination exists and exits unsuccessfully without replacing the entry or writing through it

### Requirement: KMS-ADAPTER-004 OpenBao conformance boundary

An OpenBao client integration SHALL qualify supported auto-unseal and External Keys behavior against the named upstream release before those capabilities are published as supported. PKI signing SHALL require KMS inspection of the certificate request.

#### Scenario: Release qualification

- **WHEN** a candidate plugin is tested with the named OpenBao release
- **THEN** the conformance tests establish the applicable use, refusal and recovery behavior before support is claimed

### Requirement: KMS-ADAPTER-005 Service identity and site commissioning evidence

A deployed SOPS integration SHALL demonstrate that the workload TLS identity and site boundary are enforced in the intended host deployment.

#### Scenario: Site commissioning

- **WHEN** the sidecar and KMS run under the target trust configuration
- **THEN** an approved workload completes an authorized operation, and disallowed access is refused at the intended boundary

### Requirement: KMS-ADAPTER-006 Signing command input validation

The GnuPG-compatible signing command SHALL reject unsupported options, incompatible modes, invalid status descriptors and untrusted deployment inputs before asking the KMS to sign.

#### Scenario: Invalid signing grammar is rejected before signing

- **WHEN** an invocation uses an unsupported option, unsupported status descriptor or conflicting command modes
- **THEN** the command refuses before asking the KMS to sign

#### Scenario: Unsafe deployment inputs fail before remote signing

- **WHEN** the signer receives writable or invalid deployment configuration or key material
- **THEN** the command refuses without contacting the KMS for a signature
