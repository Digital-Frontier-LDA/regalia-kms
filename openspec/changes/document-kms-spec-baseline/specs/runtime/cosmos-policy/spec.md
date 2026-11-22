## Purpose

Define the supported Cosmos SignDoc subset and the policy conditions for hardware signing.

## ADDED Requirements

### Requirement: KMS-COSMOS-001 Supported SignDoc and parser refusal

The KMS SHALL parse the supported Cosmos SDK SignDoc wire subset before policy and hardware. It SHALL accept MsgSend and MsgDelegate shapes, interpret an omitted account number as zero, and refuse unknown message types, wrong wire types and duplicate scalar fields.

#### Scenario: Supported document

- **WHEN** a supported SDK SignDoc carries MsgSend or MsgDelegate
- **THEN** its accounting and transaction fields are exposed to policy

#### Scenario: Default account number

- **WHEN** a proto3 document omits the zero account number
- **THEN** the parser reports zero and policy still decides whether it is allowed

#### Scenario: Malformed input

- **WHEN** the document is truncated or carries an unsupported message
- **THEN** the request is refused without hardware use

### Requirement: KMS-COSMOS-002 Transaction policy and signing input

A Cosmos signing decision SHALL enforce configured chain, account, source, destination, message-type, denomination, amount, gas and fee restrictions before reservation. An admitted operation SHALL send the SHA-256 digest of the original SignDoc bytes to hardware.

#### Scenario: Authorized transaction

- **WHEN** all applicable dimensions match including an amount exactly at an inclusive cap
- **THEN** policy admits the request and hardware receives the SignDoc digest

#### Scenario: Dimension out of bounds

- **WHEN** any required allowlist or cap fails
- **THEN** policy denies with the applicable rule before reservation

### Requirement: KMS-COSMOS-003 Sequence reservation and recovery

After the first accepted sequence of a chain-account tuple, the local policy journal SHALL admit only the next sequence for that tuple before signing. The journal does not query chain state, so commissioning requires an external observation. Recovery-only admission SHALL refuse a sequence-bearing request before route, reservation or signing.

#### Scenario: Known sequence

- **WHEN** the next sequence skips or repeats the last reservation for the same chain and account
- **THEN** policy refuses the request

#### Scenario: Separate accounts

- **WHEN** a distinct account starts at a sequence seen for another account
- **THEN** its reservation is evaluated independently

#### Scenario: Recovery admission

- **WHEN** a lone survivor has recovery-only admission
- **THEN** the sequence-bearing request performs no route lookup, reservation or hardware operation

### Requirement: KMS-COSMOS-004 Physical and live-chain qualification

A production Cosmos deployment SHALL qualify the selected token and operator-observed account state on the target chain before relying on the signing path.

#### Scenario: Production qualification

- **WHEN** an operator stages a supported hardware signer for a target chain
- **THEN** the ceremony records independently verified hardware signatures and the initial sequence under approved authority
