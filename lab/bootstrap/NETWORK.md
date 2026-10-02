# Three-container WireGuard experiment

This extends the disposable IPC lab. Three containers each own a software TPM,
private peer state, and a disposable LUKS2 image. Their bridge network is internal
to this Compose project; no ports, host devices, or Docker socket are exposed.
Bootstrap HTTP binds only to a WireGuard address, and nftables permits only the
mesh UDP endpoints, bootstrap TCP over WireGuard, and local control traffic.
WireGuard source identity is checked in addition to the target's TPM attestation.

Containers initially need NET_ADMIN, SETUID and SETGID to configure their own
network namespace and drop to UID/GID 10000. The service and its software TPM run
without effective capabilities after setup. The trusted host runner can still
execute namespace administration for deliberate network-failure injection.

The trusted commissioning fixture exchanges public AK/PCR/WireGuard identities,
enrolls each target with the other two authorizers, and obtains both per-peer
contributions through actual WireGuard exchanges to create independent LUKS
slots. An independent random recovery credential is returned only to the host
runner's memory; nodes retain no plaintext copy. The runner supplies it through
stdin for a manual recovery drill. No secret enters command arguments or reports.

`lock` is a logical loss of bootstrap authorization, not an OS reboot. The next
`bootstrap` generates a new RSA session key, unseals local TPM material, contacts
the selected peers concurrently with bounded deadlines, validates the first
response, and checks the derived credential against its actual LUKS2 keyslot.
Only then does the node become an authorizer again. A lost grant requires a fresh
challenge. A late or invalid response never marks the target operational.

Only `challenge` and `authorize` are accepted over the bootstrap endpoint.
Enrollment, policy injection, logical lock, manual recovery and status are local
fixture controls on loopback. JSON bodies/responses are bounded and logs omit
requests, credentials, responses, and captured tool output.

This remains emulated evidence: common Docker host, resettable software TPMs,
unsigned fixture policy, software-held peer keys, Python memory, no initramfs,
no mapped dm-crypt filesystem, no physical reboot, no HSM or runtime leases.
It does not establish global revocation, rollback resistance, or measured boot.
The network experiment does prove encrypted cross-container transport and the
logical recovery protocol under selected network and availability failures.

The target enforces its own known requester/authorizer capabilities and requires
the challenged peer epoch to equal its local fixture epoch. A local policy update
cancels an in-flight bootstrap before activation. This deliberately fails closed
on a known mismatch; it does not fetch or authenticate updated policy.

## Observed membership freshness gap

The runner reproduces a revoked node bootstrapping through a peer when both retain
the old ACTIVE policy while the third peer knows the revocation. This assertion
confirms a limitation, not a theft-resistance acceptance criterion. It is recorded
separately as `limitations_observed.stale_target_and_authorizer_can_bootstrap`.
Current peers reject the revoked target, and a target with a current view rejects
a stale/locally revoked authorizer. No unsigned or asynchronous manifest scheme
can infer information that neither participating node has received. Production
still needs an explicit freshness/partition policy and independent external
enforcement before claiming prompt theft revocation.

## Security Findings

Membership freshness remains a production blocker: two stale participants can
authorize bootstrap after a third receives revocation. The lab reproduces this
behavior instead of counting it as successful theft protection.

## Checks Performed

The network runner exercises 67 assertions, including actual handshakes, all six
recovery directions, simultaneous two-node recovery, manual seeding of each
possible survivor, request/source binding, bounded parsing, partitions, routing
failure, lost grants, known policy/epoch mismatches, and genuine TPM policy refusal.
Input-limit tests reject an oversized declared length before sending a body and
accept a valid JSON request padded to exactly 64 KiB. The former avoids a client
write/close race when a server rejects headers while oversized bytes are still
in transit; a missing error response fails the assertion rather than raising a
harness `KeyError`.
The existing IPC and repository tests remain separate regression checks.

## Residual Risk

The Docker host and fixture controller remain trusted. Recovery material is in
host Python memory for the drill. Logical locks do not erase daemon memory or
simulate an operating-system reboot. Container and Python memory cleanup does
not establish secure zeroization, hardware custody, or resistance to root access.

## Recommendation

Use this runner for disposable software validation. Keep production bootstrap
blocked on signed policy freshness, physical measured boot, actual encrypted-root
boot, hardware device qualification, and the other gates in the architecture.

## Signed runtime experiment

The separate [cluster runner](CLUSTER.md) reuses this transport with distinct
bootstrap/runtime WireGuard keys and a bounded administrative route for signed
membership, freshness and access leases. It tests denial after old signed
freshness expires, including partitioned stale peers. This original network
runner intentionally retains the stale unsigned-policy drill; neither mode
qualifies hardware epoch protection or instantaneous global revocation.
