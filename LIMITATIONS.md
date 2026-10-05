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

- **The root's permissive epochs reach the cluster by hand** (#386 retired the authority host).
  An image approval, or a replacement, signed by the root on the offline laptop, is given to ONE
  running node with `deliver` (root, at its console), and the others pull it. Nothing carries them
  automatically. In the three-node scenarios, an owner-signed epoch is committed by the harness into
  the seed's store with its services stopped (`advance(signer="owner")`). On a host, the owner's
  revocation goes through `revoke.py import`, which the scenarios exercise separately
  (`revoke_by_owner`).
- **Recovery with only one surviving peer: not built.** `recover` and `reanchor` need two peer chains
  today. With one peer left, a node cannot be recovered or re-anchored. The design is decided, with the
  owner co-signing as the second source behind `--one-source` (#387, PR #395). With **both** peers gone,
  recovery is a new root ceremony, by design.
- **Accepted, once #387 lands:** a one-peer recovery cannot see a revocation that was made after the
  signing laptop last synced, if the surviving peer withholds it and the audit collector has no
  receipt for it. The owner is asked before signing ([`deploy/baremetal/MEMBERSHIP-RECOVERY.md`](deploy/baremetal/MEMBERSHIP-RECOVERY.md)).
- **TPM owner authorization: built (#242 step C), with these limits.**
  - The owner authorization crosses the TPM bus in clear when used (password sessions, #414). A discrete TPM can
    be sniffed by someone with physical access during enrolment, a re-anchor or a recount.
  - The value cannot be zeroed in Python memory. While an owner-authorized call runs, the value is readable through
    /proc by root (a memfd; `seal-hsm-pin.sh` uses a root-only file on /run).
  - No end-to-end `enrol commit` under v4 with a set owner authorization runs on a software TPM (#420). The path
    is held by unit tests and by swtpm tests of the anchor's owner calls.
  - During `enrol commit` the owner authorization is held by a process of uid regalia-sync, the network-facing
    sync daemon's user. commit refuses while another process of that uid exists. Moving the owner calls into the
    root parent is #419.
  - `enrol init` takes no owner authorization (it runs before `enrol ownerauth`). `attest.py node-init` (the lab
    CLI) keeps an empty one.
  - Rotating a set owner authorization is not built.
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
- **Genesis node identities are bound to each node's TPM, not to its hardware** (#399). `propose
  --genesis` takes each node's bundle, kept challenge and activation and proves them itself: the AK is
  in the TPM its EK names, and the AK quoted every identity field (both WireGuard keys, the signing
  key, the token serials, the SSH host key) bound to that very challenge, booted on PCR 11 the genesis
  measurements accept (system phase). What it cannot show: that the TPM is a genuine vendor TPM, which
  rests on the EK certificate or, without one, the EK Name copied by hand (#190; the DL360's TPM is
  unknown); that the node was not compromised when it enrolled (enrolment trusts the host at its own
  console); and PCR 7 is only compared across the nodes where the measurements give no expected value.
  The quote covers bundle.json as the node holds it at `activate`; the enrolment directory is checked
  to be root's (0700, trusted ancestors), and root on the node at enrolment is trusted. The PCR 11
  judgement assumes the host had finished booting (systemd-pcrphase "ready" extended) when `activate`
  ran, which a software TPM cannot show: a bench item (#297), and the refusal says to re-run once
  `systemctl is-system-running` reports running. Run only on software TPMs so far.
- **Card attestation: not built** (#400). Nothing yet produces the YubiKeys' OpenPGP attestation
  certificates (`ykman openpgp keys attest`). The card record's `attestation_sha256` values are
  placeholders in the test vectors, so "attested" has no certificate behind it anywhere yet. When it is
  built, the attestation will show the touch policy ("fixed"), the key source, the serial and the
  fingerprint. OpenPGP has **no PIN-policy attestation**, so "PIN always" stays a recorded setting.
- **Card-record freshness is per laptop** (#403, #408). A record is accepted only if it is the newest
  card record on the ceremony laptop's root signing record (`signing-record.jsonl`, in the state
  directory marked `regalia-signing-state.json`). That is newest on THIS laptop, not newest of the
  root: a Shamir root rebuilt elsewhere with a fresh state directory signs a valid "sequence 1". The
  card ceremony's `--first-card-record` makes that visible (regalia-ceremony#111). `propose --genesis`
  prints `card record N of M` with its digests, for the operator to check against the ceremony sheet.
- **Nothing writes the state-directory marker yet.** `manifest sign` refuses a directory without it and
  never writes one; the card ceremony's writer (regalia-ceremony#111) is not built. Until it lands, no
  real laptop can sign. The marker and log path is unit-tested only until the first-ceremony rehearsal.
- **The laptop's signing record is not hash-chained** (#405). A deleted line, a cut tail or a state
  directory restored from an older backup is not detected; #405 would anchor the newest card-record
  digest in the root-signed manifest. A lost state directory has no recovery path yet (#406).
- **The bench-token lists are kept by hand** (`membership.BENCH_NITROKEYS`, `BENCH_PICOS`,
  `BENCH_YUBIKEYS`). A new bench token must be added there. A test keeps the drills' staging list equal
  to it, and nothing ties it to the operators' staging registry.
- **Build provenance** hashes only the files in `REPO_FILES`. It compares the Go release by **name**
  with `go.mod`, not the toolchain binary, which the builder verifies through the Go checksum database.
  `build-initrd.sh` runs git as the checkout's owner with no global or system configuration (#384), and
  so does `uki.py`'s own checkout (#404): repo-git.sh's exact environment, no file under the signer's
  HOME. `uki.py` also refuses any untracked file but `__pycache__` bytecode, ignore rules included
  (`build-initrd.sh` to follow). The build record is unsigned; two builders' records must agree. The
  signer's clone must be writable by the signer alone: a `.pyc` planted by another writer would run.

## Audit and monitoring

- The external audit collector and the monitoring service are **contracts only**
  ([`deploy/baremetal/AUDIT-COLLECTOR.md`](deploy/baremetal/AUDIT-COLLECTOR.md),
  [`deploy/baremetal/MONITORING.md`](deploy/baremetal/MONITORING.md)). The real service has not been
  chosen or deployed. The audit collector's conformance suite runs against the reference collector in
  CI. **Monitoring has no conformance command** (MONITORING.md section 5: not built).
- **Audit completeness is checked in some scenarios only.** `audit_complete` runs in the theft, rolling and
  recovery scenarios (#402). Outage, leases and replace are not covered. The time trail and the update trail
  are never checked end to end in a three-node scenario. In recovery, "each node's change to serving" is not
  tied to a step, and the victims' not-serving lines are not checked.
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
