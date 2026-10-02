# Local peer experiment contract (version 1)

This is a disposable lab contract, not a production protocol. A separate
`peer.py --state PATH` process reads one JSON command from stdin and returns one
JSON response on stdout. Transport is private local IPC; there is no network
listener, WireGuard transport, or authenticated OS separation between roles.
The trusted lab harness commissions state, pins keys/policy, and injects policy
changes. The original IPC cases recover A through B/C; enrollment also supports
the other directed paths between A, B and C, with independent per-target secrets.

Commands use exact field sets. Duplicate fields, unknown fields, invalid types,
malformed encodings, and input above 64 KiB fail closed. Results have the shape
`{"result": {...}}`; refusals use `{"error": {"code": "INVALID_REQUEST"}}` or
`DENIED`. Internal/tool failures use `INTERNAL` and a nonzero process exit.
Raw requests, private keys, secrets, and tool output are never logged.

| Operation | Input fields | Result |
|---|---|---|
| `init` (trusted fixture commissioning) | `op`, `peer_id`, `targets` | Pinned Ed25519 public key; refuses an already commissioned state |
| `challenge` | `op`, `node_id` | Fresh nonce, challenge ID, peer ID, manifest epoch |
| `authorize` | `op`, `request`, `quote`, `signature` | Signed, session-encrypted peer contribution |

The request contains exactly `node_id`, `peer_id`, `manifest_epoch`,
`boot_session_id`, `ephemeral_public_key`, `peer_nonce`, and `challenge_id`.
Session/challenge IDs are 16 bytes encoded as lowercase hex; the nonce is 32
bytes; epoch is a positive integer. The recipient public key is hex-encoded DER
SubjectPublicKeyInfo for RSA-3072 with exponent 65537. The TPM qualification is
SHA-256 of canonical sorted JSON for this request. `quote` and `signature` carry
bounded hex-encoded outputs from tpm2-tools; clients cannot provide verifier
paths, pinned keys, or approved measurements.

`targets` maps enrolled node IDs to exact `ak_pem`/`approved_pcr` records. A peer
cannot enroll itself as a target. Release selects the AK, measurement, and
independent contribution belonging to the requested target.

The verifier checks requester bootstrap capability (ACTIVE or MAINTENANCE),
authorizer capability (ACTIVE), exact current pinned epoch, enrolled AK, fresh
server-issued nonce, challenge ownership/expiry, quote signature/qualification,
approved PCR digest, and exact quoted bank/selection (sha256 PCR 7). Challenge
state is bounded, expires after 30 seconds, and is persisted under a process
lock. An owned challenge is atomically consumed before attestation/response work;
a failed attempt or lost response requires a new challenge. This prevents two
concurrent workers from issuing grants for the same challenge.

The response contains exactly `version`, `peer_id`, `request_digest`,
`ciphertext`, and `signature`. The 32-byte contribution is encrypted with the
cryptography library's RSA-OAEP using SHA-256/MGF1-SHA256 and the label
`regalia-bootstrap-lab/v1/contribution\0 || request_digest`. The verifier signs
canonical response fields excluding `signature`, prefixed with
`regalia-bootstrap-lab/v1/response\0`, using Ed25519. These established library
operations avoid implementing an asymmetric encryption construction in the lab.

The target verifies the pinned authorizer signature and its own pending request
digest before decrypting. The first valid response consumes the boot session;
duplicate or later peer responses cannot be consumed. Invalid responses do not
consume the session. A response cannot be reused for a different ephemeral key,
peer path, or request. Local contribution plus the received peer contribution
then derives the credential for the actual disposable LUKS2 keyslot test.

Policy and epoch are trusted unsigned fixture state, not signed membership or
rollback-resistant freshness. State and signing keys are software files in
tmpfs, writable by the trusted harness/host. This proves orchestration behavior
under pinned policy; physical theft, root compromise, cross-host authorization,
lease/fencing authority, and production anti-rollback remain separate gates.
