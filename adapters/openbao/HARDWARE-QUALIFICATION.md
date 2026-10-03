# OpenBao hardware qualification record

This is the execution and evidence template for #121/#123. A software-token CI
pass does not fill this record. Run it on the nominated isolated qualification
environment with a custody operator and witness, under the existing
[PIN custody](../../PIN-CUSTODY.md), [Nitrokey qualification](../../e2e/NITROKEY-QUALIFICATION.md)
and recovery ceremony. No deployment or hardware provisioning is performed by
the plugin tests or packager.

Keep the completed record restricted. Public issues receive only artifact
versions, test outcomes and a reference to the restricted evidence. Endpoints,
principals, token serials, object inventories, recovery shares and operator
identities belong in that record, never in public CI or issue attachments.

## Entry conditions

- Record the operator, witness, isolated test environment and maintenance scope.
- Use synthetic OpenBao data and dedicated qualification objects. Do not change
  a production seal, revoke a production generation or reuse an application key.
- Record the daemon commit, plugin archive/binary SHA-256, OpenBao 2.7.1 binary
  checksum, SDK versions, hardware/firmware and custody evidence references.
- Confirm the token passes the existing provenance, identity, nonexportability,
  PIN custody and admission/fencing gates. Stop on a PIN latch or declining retry
  budget; never retry through it.
- The current plugin admits `environment=development` only. A production/staging
  environment cannot be enabled by editing the example: changing this gate needs
  reviewed software and a new qualification record.
- Commission an independent recovery token through the existing quorum ceremony
  before retiring any seal generation. Verify that recovery preserves the exact
  generation identity and authorized public-key fingerprint.
- Issue independent plugin mTLS credentials from the KMS workload CA. The KMS
  must start and renew those credentials while all OpenBao nodes are sealed.

## Witnessed sequence

| Step | Required result and evidence |
| --- | --- |
| Bootstrap | Checksum-bound plugin registration, actual mTLS, exact seal grants. Initialize once; retain recovery shares in approved custody. Record seal/release audit IDs without payloads. |
| Restart | Store a synthetic marker, seal/stop OpenBao, restart and read the same marker. No manual unseal or software fallback. |
| Outage | Stop the qualification KMS or remove its test token. Unsealed software KV stays readable; a fresh OpenBao process cannot unseal. External signing refuses. Restore admitted custody and recover. |
| Identity/grant denial | Independently issued unauthorized credentials, wrong purpose/object and removed exact grants refuse; no successful hardware operation. Seal identity cannot sign; signing identity cannot unseal. |
| Fencing | Revoke the qualification node's runtime admission through the existing mechanism. Calls refuse without another-address fallback; audit distinguishes admission denial. Restore admission under the existing rules. |
| Plugin crash | Kill only the nominated test plugin during a held, audited response. Correlate the interrupted request with KMS audit; verify respawn, fresh nonce, resumed checks and restart. Do not assume the lost call did not execute. |
| Rotation | Promote a new immutable test KEK generation, retain the predecessor as retired, keep the same plugin config. Verify stored and recovery-key rewrap and restart. |
| Snapshot recovery | Restore a pre-promotion snapshot on a fresh isolated node with independently issued credentials and the independently commissioned recovery token. Normal restore only; verify source data and original recovery-share authorization. |
| Revocation | Only after recovery evidence, revoke the disposable predecessor. Current rewrapped storage works; its old snapshot refuses. Document that revocation can destroy old snapshot recoverability. |
| Transit | Test each deployed algorithm, raw/prehashed input and pinned public-key verification; exact namespace/mount grants and revocation. Encryption and CA mappings remain refused. |
| Leakage | Restricted inspection finds no marker, recovery share, PIN, client private key or root token in plugin logs, persistent plugin state or OpenBao Raft storage. Never upload raw state. |

## Result and release gate

For each row record pass/fail, time, artifact identities, audit correlation and
restricted evidence reference. Record repeat/ambiguous operations explicitly.
The operator and witness attest the completed record; software authors cannot
substitute CI for either attestation.

The release stays blocked on any failed/unrun row, unresolved provenance or
fencing issue, missing recovery generation, missing off-host audit evidence or
missing witness. Keep the adapter development-only and the PR in draft. A future
production release also needs HA, supported upgrade/migration drills and its
reviewed rollout/rollback procedure under #123. PKI has the separate inspected
certificate/CRL signing prerequisites in #122 and is not qualified here.
