# Operating Regalia — where to look

This is the **entry point**, not a procedure. It tells you which document answers which
question, in the order a first-time operator needs them. It deliberately does not repeat the
content — every section points out to the doc (or spec, or test) that is the source of truth,
so there is one place to read and no copy that can drift.

Documents in this repo are linked; documents in the sibling **regalia** tracking repo are
named with the `regalia:` prefix (e.g. `regalia:doc/RUNBOOK-KMS-OPERATOR.md`), matching the
convention the other docs use.

If you are in an emergency, skip straight to `regalia:doc/RUNBOOK-KMS-INCIDENT.md`. If you are
integrating a client, go to `regalia:doc/RUNBOOK-KMS-DEVELOPER.md`. Everything else starts here.

## The 30-second model

Regalia is one Go binary that holds **no key material in software**. It fronts hardware
(SmartCard-HSM tokens, YubiKey PIV) behind a mutual-TLS API; every operation is
mTLS-authenticated, policy-checked, and written to a hash-chained audit journal that can be
shipped off-host. It fails closed: a check that cannot prove a property reports "unknown,"
not "pass." The single most important operating fact is the one the operator runbook leads
with — **every check has a claim, and the claim has limits** — so the first skill is reading
what a green light actually proves.

The two things you must know before touching anything:

- **Which site are you on, and is it the intended-active site?** Fencing exists so there is
  never two active signers. A replaced or demoted site that keeps signing is the failure the
  whole control plane is built to prevent. See [`FENCING.md`](FENCING.md).
- **You are the support contract.** There is no vendor. Cold standby has a human RTO of hours.
  That trade is stated in the [README](README.md#why-self-hosted--the-trade-stated-honestly).

## Read these first, in this order

| # | Document | The question it answers |
|---|---|---|
| 1 | [`README.md`](README.md) | What it is, what it does/doesn't do, the self-hosting trade, quick start |
| 2 | `regalia:doc/RUNBOOK-KMS-OPERATOR.md` | **The** day-to-day: start/stop, "will it start," reading a check's claim, fencing |
| 3 | [`API.md`](API.md) | The operation surface — the 7 paths, the mTLS + approval binding, the envelope |
| 4 | [`POLICY.md`](POLICY.md) | The purpose-bound policy contract — who may do what, to which object, for which purpose |
| 5 | `regalia:doc/RUNBOOK-KMS-INCIDENT.md` | What to do when something is wrong |

If you operate the Cosmos wallet specifically, add [`COSMOS-SUPPORT.md`](COSMOS-SUPPORT.md)
(the exact wire contract, the sign-mode and fee-field refusals, and sequence recovery) and
`regalia:doc/HSM-KMS-DEPLOYMENT.md`.

## Find the right document by job

| You want to… | Read |
|---|---|
| Start/stop the daemon, confirm it will start | `regalia:doc/RUNBOOK-KMS-OPERATOR.md` |
| Understand an API call or an error code | [`API.md`](API.md) |
| Change who may sign what | [`POLICY.md`](POLICY.md), [`config/REGISTRY.md`](config/REGISTRY.md) |
| Add or retire a key / object | `regalia:doc/RUNBOOK-KMS-NODE-MOVE.md`, `regalia:doc/RUNBOOK-CUSTODIAN-ROTATION.md` |
| Read or ship the audit trail | [`AUDIT.md`](AUDIT.md), `regalia:doc/AUDIT-COLLECTOR-OPERATIONS.md`, `regalia:doc/AUDIT-COLLECTOR-RECONCILIATION.md` |
| Reason about the active/passive site | [`FENCING.md`](FENCING.md) |
| Handle a lost or exposed PIN | [`PIN-CUSTODY.md`](PIN-CUSTODY.md), `regalia:doc/RUNBOOK-KMS-INCIDENT.md` |
| Recover from site loss | `regalia:doc/RUNBOOK-DISASTER-RECOVERY.md`, `regalia:doc/SUCCESSION-AND-INCAPACITY.md` |
| Run or interpret a fault drill | `regalia:doc/RUNBOOK-KMS-FAULT-DRILLS.md` |
| Configure SOPS decryption | [`SOPS-TRANSPORT.md`](SOPS-TRANSPORT.md), `regalia:doc/SOPS-HSM.md` |
| Set up or read metrics/alerts | [`OBSERVABILITY.md`](OBSERVABILITY.md) |
| Verify a sealed control-plane export | `regalia:doc/CONTROL-PLANE-EXPORT.md` |
| Understand the envelope (wrap/release) | [`ENVELOPE.md`](ENVELOPE.md) |
| Understand mTLS client identity | [`IDENTITY.md`](IDENTITY.md) |
| Qualify the hardware backend | `regalia:doc/RUNBOOK-NITROKEY-GATE.md`, `regalia:doc/CI-HARDWARE-RUNNER.md` |
| Threat-model a change | [`SECURITY.md`](SECURITY.md), `regalia:doc/HSM-THREAT-MODEL.md` |

## The three things that will brick a site

Stated up front because the cost of missing them is total, not degraded:

1. **Two active signers.** Fencing (`ErrEpoch`, the activation lease) exists to make this
   impossible. If you are about to bring up a second site on the same account, you are
   about to cause the worst failure class. [`FENCING.md`](FENCING.md).
2. **A journal that opens against a mark nobody read.** The policy-state and audit journals
   are hash-chained with high-water sidecars; a truncated or rewritten journal is refused at
   open, and an unreadable mark must not resolve to "position 0." The high-water mark catches a
   journal truncated behind its own mark. It does not catch a journal restored together with its
   sidecar from the same older backup: both positions then agree, local verification accepts the
   pair, and replay is possible. Never restore the pair from a backup without an independent
   record of the last position. [`POLICY.md`](POLICY.md) and the
   policy-state-journal spec in the tracking repo (`regalia:openspec/specs/policy-state-journal/spec.md`).
3. **Acting on a check's strong reading.** A green `-check-config` did not touch the token; a
   present metric is the last measurement, not now. The operator runbook names each limit.
   The habit to build is "what does this check *not* prove?"
   `regalia:doc/RUNBOOK-KMS-OPERATOR.md`.

## How the docs, spec, and tests stay honest together

This repo provides three checks so a doc cannot silently promise what the code does not do.
None of them runs in this repo's CI (CI runs only their own unit tests); each is run by hand:

- **Spec → test.** Every OpenSpec scenario must be claimed by a test via a
  `// spec: <capability>/<scenario>` comment; [`tools/spectrace`](tools/spectrace) fails on
  an orphan scenario (a promise no test holds) or a dangling link (a test guarding a sentence
  that was removed). **It is not yet enforced in CI**, and scenarios without a test exist today:
  run it by hand, and do not read a green CI run as proof that every scenario has a test.
- **Change → code.** When an OpenSpec change is archived,
  [`tools/specarchive`](tools/specarchive) verifies every file/symbol named in its Impact
  section still exists — so a change cannot point at code that moved. It is run by hand at
  archive time, not in CI.
- **Doc → proof.** [`tools/docassert`](tools/docassert) flags a doc line that asserts a
  safety guarantee ("SHALL", "is refused") with no adjacent spec/test link, so an unlinked
  claim is visible rather than trusted. **It is manual and opt-in, not a CI gate**: by default
  it only reports, and it exits 1 on an unlinked line only when run with `-fail`.

The specs live in the sibling **regalia** tracking repo under `regalia:openspec/specs/`; the
five capabilities are `cosmos-authinfo-parser`, `cosmos-fee-policy`,
`cosmos-signing-contract`, `policy-state-journal`, and `ceremony-yubikey-identity`.

## Status

**Pre-production / pre-1.0.** Neither the software nor its test suite is complete: some spec
scenarios have no test yet (run `tools/spectrace` to list them), and production hardware
qualification (Nitrokey HSM 2) is open. Use it for development, testing, and
staging; do not protect production keys with it yet. See the
[README status note](README.md) at the top of the README.
