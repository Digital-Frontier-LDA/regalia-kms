# Current limitations

What Regalia KMS does **not** do yet, what has not been measured, and the risks accepted on purpose.
This file says what is true **today** on `main`. An entry is added as soon as a limitation is found,
and is removed only by the PR that closes it, which cites its number. The per-component docs carry
the detail. This is the index.

Status words: **not built** (no code yet), **not measured** (code exists, but nothing has shown it on
the real hardware or in the real setting), **accepted** (a risk taken on purpose, with its reason).

## Overall

- **Nothing has run in a ceremony or on the production hardware.** No key ceremony has been held, and
  no Shamir share set exists yet. The three production hosts (HPE DL360 Gen9 with TPM 2.0) have not run
  this software (#253). Whether their TPMs carry an EK certificate is not known (#190). Every
  three-node scenario so far runs on a software TPM (swtpm) in CI.
- **Hardware qualification is open**: Nitrokey HSM 2 for production; the Pico HSM is supported but
  not qualified ([`CONFIGURATIONS.md`](CONFIGURATIONS.md)).

## Membership, heartbeats and recovery (deploy/baremetal)

- **The authority host is being retired (#386).** Until #386 merges, `authority.py` and its units are
  still in the tree, and MEMBERSHIP-RECOVERY.md still names "the authority's" chain for the
  crash-window recovery. They are not part of the production design: heartbeats and revocations are
  signed by 2 of {the three nodes, the owner} (#199).
- **Recovery with only one surviving peer: not built.** `recover` and `reanchor` need two peer chains
  today. With one peer left, a node cannot be recovered or re-anchored. The design is decided, with the
  owner co-signing as the second source behind `--one-source` (#387, PR #395). With **both** peers gone,
  recovery is a new root ceremony, by design.
- **Accepted, once #387 lands:** a one-peer recovery cannot see a revocation that was made after the
  signing laptop last synced, if the surviving peer withholds it and the audit collector has no
  receipt for it. The owner is asked before signing ([`deploy/baremetal/MEMBERSHIP-RECOVERY.md`](deploy/baremetal/MEMBERSHIP-RECOVERY.md)).
- **TPM owner authorization: not built** (#242 step C). Every owner-authorized TPM call runs with an
  **empty** owner authorization: the anchor's define, define-time writes and undefine
  (`membership.HighWater`), the heartbeat counter's definition, recount's undefine, and the AK's
  `evictcontrol` (attest.py, enrol.py). The decided production posture sets the owner authorization,
  kept off the host in envelopes for the owner's cards. Until step C passes it in (through one channel,
  never argv), enrolment, reanchor, recount and replacement fail closed on a host whose owner
  authorization is set. Enrolment does not yet refuse a TPM whose owner or lockout authorization is
  empty.
- **Re-anchoring on a real host has three known faults, fixed in #391 (not merged):**
  - Run as root, `reanchor` writes `membership.json` as root with mode 0600, so the node's `regalia-sync`
    cannot read its own chain afterwards and the node cannot serve.
  - **Security:** `membership._exclusive` opens its lock with `O_CREAT` and no `O_NOFOLLOW`. Root
    running `reanchor`, or any Store or HighWater, in `regalia-sync`'s state directory can be made to
    open or create any file read-write through a planted symlink.
  - `reanchor`'s anchor lock (`/run/lock/regalia-highwater-<idx>.lock`) is not the services'
    (`<state>/highwater.lock`), so the two do not serialize.
- **No total-outage re-anchor rehearsal** (#391 adds it). The procedure in MEMBERSHIP-RECOVERY.md is not
  yet the total-outage one, and its example names `/var/lib/regalia/membership.json`, while the store
  is under `/var/lib/regalia-sync`.
- **Nothing advances the ESP's chain after genesis** (#377 is merged; the fix is #410). The initrd refuses an ESP
  chain below the TPM anchor, and `regalia-sync` advances the anchor on every accepted manifest, so a
  node that accepts a second manifest would boot to the recovery prompt. The fix is to write the ESP
  first and advance the anchor after it, in a root oneshot ("ESP advance", #66). It must land before
  any node takes a second manifest.
- **Rotating the system-phase PCR key: not built.** The anchor's write policy names one key, and
  PolicyOR(old, new) is deferred (#242 follow-up). Rotating that key today makes every anchor
  Unusable until each node is re-anchored.
- **Refusing a crashed node in the wrong boot phase: no end-to-end test** (#397). It is covered by unit
  tests only.
- **`recover` is a Python call, not a command** (#387). `reanchor` is a command.

## Tokens and the HSM gate (#72)

- **The physical pull-and-reinsert drill has not been run** (G3). The script is merged
  (`e2e/hsm-gate-drill.py`) and needs a person at the bench. Reader names and slot flags were checked
  on the Nitrokeys and a YubiKey. **The Pico has not been tested** for any part of G3.
- **The production daemon must be the `-tags piv` build.** No image builder ships the daemon yet
  (#61). A daemon built without it refuses to start when admission is required and a removable token
  is configured.

## The owner's and the release cards (ADR D30)

- **Not measured**: the developer-card layout has not been shown on a staging YubiKey. The layout
  is the owner key in OpenPGP SIG, owner-auth in DEC, and SSH commit signing in AUT. The three checks
  still to run are a raw Ed25519 signature from SIG through OpenSC, an OpenPGP certificate built on the
  existing card key with DEC bound to it, and git SSH signing from AUT. If the first fails, the owner key
  moves to PIV.
- **Not measured: touch-required behaviour** on the owner and release keys. It needs the owner at
  the bench.
- **Accepted:** a release card stolen together with its PIN can sign a release. Mitigations: touch is
  fixed, and three wrong PINs lock the card. Recovery is a new release key, published as a rotation.
- **Not decided:** whether the owner must also approve a release when the release specialist is
  someone else (to be settled when the company has staff). Whether a technical director gets
  recovery-only cards is awaiting the owner.

## Ceremony inputs (`manifest propose --genesis`, `enrol`, the card record, build provenance)

- **Not measured**: `propose`/`sign --genesis`, the card-record verifier and build provenance have run
  only with software keys, software TPMs and in CI.
- **Genesis node entries are not signed** (#399). `propose --genesis` cannot tell a node's
  `enrol entry` file from an edited copy. A mismatch is caught by that node's `enrol check`, but only
  after the root has signed, so the cost is redoing the genesis, not a silent acceptance. Until then the
  operator carries the files and reads the printed diff.
- **Card attestation: not built** (#400). Nothing yet produces the YubiKeys' OpenPGP attestation
  certificates (`ykman openpgp keys attest`). The card record's `attestation_sha256` values are
  placeholders in the test vectors, so "attested" has no certificate behind it anywhere yet. When it is
  built, the attestation will show the touch policy ("fixed"), the key source, the serial and the
  fingerprint. OpenPGP has **no PIN-policy attestation**, so "PIN always" stays a recorded setting.
- **The card record has no freshness check** (#403). Any record the pinned root has ever signed is
  accepted, so after a card replacement an older record would bring back the retired cards' keys. Until
  then the operator checks the printed session and time against the ceremony sheet. It must be closed
  before any card is replaced.
- **The laptop's signing record is not hash-chained** (#405), and a lost signing-record directory has
  no recovery path yet (#406). Freshness checks built on the record (#403, #408) are only as strong as
  the laptop it lives on.
- **The bench-token lists are kept by hand** (`membership.BENCH_NITROKEYS`, `BENCH_PICOS`,
  `BENCH_YUBIKEYS`). A new bench token must be added there. A test keeps the drills' staging list equal
  to it, and nothing ties it to the operators' staging registry.
- **Build provenance** hashes only the files in `REPO_FILES`. It compares the Go release by **name**
  with `go.mod`, not the toolchain binary, which the builder verifies through the Go checksum database.
  `build-initrd.sh` runs git as the checkout's owner with no global or system configuration (#384).
  `uki.py`'s own checkout is being given the same rule.

## Audit and monitoring

- The external audit collector and the monitoring service are **contracts only**
  ([`deploy/baremetal/AUDIT-COLLECTOR.md`](deploy/baremetal/AUDIT-COLLECTOR.md),
  [`deploy/baremetal/MONITORING.md`](deploy/baremetal/MONITORING.md)). The real service has not been
  chosen or deployed. The audit collector's conformance suite runs against the reference collector in
  CI. **Monitoring has no conformance command** (MONITORING.md section 5: not built).
- **Audit completeness is checked in some scenarios only.** `audit_complete` runs in the theft and
  rolling scenarios. Recovery is #402, and outage, leases and replace are not covered. The time trail
  and the update trail are never checked end to end in a three-node scenario.
- **Collector receipts carry no signed time** (#398), so a stale receipt still verifies. This matters
  for the one-peer recovery witness (#387).

## Products on the roadmap

- **No OpenBao plugin** ([`OPENBAO-COMPATIBILITY.md`](OPENBAO-COMPATIBILITY.md)).
- **No release-signing tool for the card-held release key** (planned).
- **No Kubernetes KMS provider** (planned).

## Tests

- `moved_by_sync` (the sync round that moved a node to an epoch) cannot see how many envelopes a round received:
  trail events don't carry it. A node moved other than by its sync, right after a no-op round from the same peer,
  would be credited to that peer. In the scenarios only the seed is moved otherwise, and it is never asked (#393).
- `audit_complete` judges each trail at a snapshot taken when it is called. Lines written after it are checked only
  if the collector already holds them, so a scenario must call it after the events it names (#393, #409).
