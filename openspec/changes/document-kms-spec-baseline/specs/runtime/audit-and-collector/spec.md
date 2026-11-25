## Purpose

Define audit durability, response gating, off-host continuity and the limits of collector evidence.

## ADDED Requirements

### Requirement: KMS-AUDIT-001 Durable result gate

A served operation SHALL obtain durable audit acknowledgement for authorization before touching hardware and for success before returning output. When required remote acknowledgement fails, the caller SHALL receive no result even when the local event is already durable.

#### Scenario: Both acknowledgements

- **WHEN** the authorization and success events are acknowledged
- **THEN** the operation result is released

#### Scenario: Authorization unavailable

- **WHEN** the pre-operation audit acknowledgement fails
- **THEN** no hardware operation occurs

#### Scenario: Success unavailable

- **WHEN** the hardware produces output but success acknowledgement fails
- **THEN** the result is withheld

### Requirement: KMS-AUDIT-002 Verifiable local event history

The KMS audit journal SHALL bind ordered events to their previous hash, retain policy and authorization identity metadata, and refuse verification of altered or missing links. Unsafe audit metadata SHALL be refused before persistence.

#### Scenario: Local verification

- **WHEN** events were recorded and remain intact
- **THEN** verification returns the ordered events and their policy identity metadata

#### Scenario: Tampering or unsafe metadata

- **WHEN** an event is altered or removed, or an event draft carries disallowed content
- **THEN** verification or recording refuses the input

#### Scenario: Unshipped local events resume in chain order

- **WHEN** remote delivery is interrupted while local events are durable and the sink becomes reachable again, including after reopening the journal
- **THEN** the shipper sends the pending events in chain order from its recorded progress

### Requirement: KMS-AUDIT-003 Collector commit and replay

The reference collector SHALL scope each stream to an authenticated certificate identity and site, durably commit before acknowledging, re-acknowledge an exact committed replay, and refuse a different history or a sequence gap without advancing the committed head.

#### Scenario: Commit and exact replay

- **WHEN** a valid next link is sent and subsequently retried after a lost acknowledgement
- **THEN** the collector commits once and returns an acknowledgement for both deliveries

#### Scenario: Divergence or write failure

- **WHEN** an event would fork the stream, arrives out of order, or cannot be durably committed
- **THEN** the event is refused and the previous committed head remains

#### Scenario: Collector listener and event handler reject missing identities

- **WHEN** a caller omits the client certificate at the TLS listener or directly invokes the event handler with no peer identity
- **THEN** the listener rejects the TLS connection, or the directly invoked handler returns HTTP 401 and creates no stream

#### Scenario: Collector reopen retains the acknowledged position

- **WHEN** the reference collector closes and reopens the same journal after acknowledging an event
- **THEN** a position read returns the same acknowledged sequence and event hash

#### Scenario: Position endpoint reports the held head

- **WHEN** the authenticated caller requests the position of its nonempty stream by site
- **THEN** the collector returns the committed sequence and hash of that stream

#### Scenario: Positions remain scoped by identity and site

- **WHEN** authenticated producers with independent streams request their position using the same or a different site header
- **THEN** the collector reports only the stream selected by the caller's resolved certificate identity and requested site

#### Scenario: An empty stream has a zero position

- **WHEN** an authenticated caller asks for the position of a stream with no committed events
- **THEN** the collector returns sequence zero and an empty hash, which the audit client reads as an empty stream rather than a commitment of prior events

### Requirement: KMS-AUDIT-004 Trail continuity, receipt and handover

The trail shipper SHALL compare local history to the collector head before appending a suffix. The collector SHALL sign receipts only for held positions on the caller's stream. A valid certificate handover SHALL preserve stream history and retire the previous credential's access.

#### Scenario: Continuation and handover

- **WHEN** the local trail extends a committed prefix and the replacement certificate proves handover authority
- **THEN** the suffix is appended and the replacement identity can continue the stream

#### Scenario: Rewritten trail or foreign receipt

- **WHEN** the local trail diverges or a caller asks for another stream's receipt
- **THEN** the shipper refuses and alarms on divergence, and the collector refuses the foreign receipt

#### Scenario: Receipt binds the held stream position

- **WHEN** a caller requests a committed sequence in its own stream and the collector has a receipt signing key
- **THEN** the receipt signature binds the authenticated identity, site, sequence, event hash, line hash and line-chain value at that position

#### Scenario: A collector without a receipt key refuses a receipt

- **WHEN** an authenticated caller requests an existing position and no receipt signing key is configured
- **THEN** the collector returns HTTP 404 and does not issue an unsigned receipt

#### Scenario: Handover rejects unsuitable proof or an occupied destination

- **WHEN** the former certificate fails verification, its key does not authorize handover to this destination, or the destination already holds a stream
- **THEN** the collector refuses the handover and does not transfer control of the streams

#### Scenario: A committed handover cannot be used again

- **WHEN** a caller replays an authorized proof after the collector accepted that exact stream handover
- **THEN** the collector refuses a second transfer

#### Scenario: A saved receipt gives no fresh collector observation

- **WHEN** a caller presents a previously issued receipt whose signature still verifies for the named stream and position
- **THEN** the receipt authenticates that commitment without a signed timestamp, expiry or request challenge. Signature validity alone establishes neither the collector's current head nor that it still holds the position

### Requirement: KMS-AUDIT-005 Production collector acceptance

A production deployment relying on off-host audit SHALL qualify its selected collector and continuity policy, including retention, receipt freshness and outage behavior, before claiming the required deployment guarantees.

#### Scenario: Reference-to-deployment acceptance

- **WHEN** the designated collector and production principals are in place
- **THEN** an authorized conformance record proves durable acknowledgement, refusal, access and continuity behavior under that deployment

### Requirement: KMS-AUDIT-006 Bounded collector alarms

The reference collector SHALL validate reported alarm payloads and SHALL apply an alarm budget independently to each authenticated identity, including a bound on flood notices within a window.

#### Scenario: Malformed alarm submission is refused

- **WHEN** an authenticated alarm submission has an empty or control-containing reason, malformed hash, unknown field, trailing document, or a reason beyond the configured size bound
- **THEN** the collector returns HTTP 400

#### Scenario: An identity exhausts its reported-alarm budget

- **WHEN** one authenticated identity exceeds its reported-alarm budget in the current window
- **THEN** the collector returns HTTP 429, records at most one flood notice for that identity during the window and leaves other identities' budgets independent

### Requirement: KMS-AUDIT-007 Collector probe and shipping commands

The reference collector SHALL answer an authenticated readiness probe. The audit shipper SHALL keep its named-trail probe read-only, fail conformance when pinned keys cannot verify collector receipts, and retry temporarily unavailable deliveries in periodic mode.

#### Scenario: Collector readiness proves authenticated reachability

- **WHEN** an authenticated caller sends HEAD to the reference collector readiness endpoint
- **THEN** the collector returns HTTP 204 without attempting a live disk commit

#### Scenario: Named trail check reads position without shipping

- **WHEN** the audit shipper check command runs with -probe and a named trail under a configured mutual-TLS identity
- **THEN** it checks collector reachability and reads and reports the named trail's committed head without posting events

#### Scenario: Reachable collector fails conformance under the wrong receipt key

- **WHEN** a reachable collector returns a receipt but its signature does not verify under any configured receipt key
- **THEN** the conformance command reports the receipt check failure and exits unsuccessfully

#### Scenario: Periodic shipping retries an unavailable collector

- **WHEN** remote delivery is temporarily unavailable during periodic audit shipping
- **THEN** the shipper retries on a later interval without reporting the undelivered events as committed
