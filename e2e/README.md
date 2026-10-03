# KMS PicoHSM and local E2E entry point

This layer intentionally reuses the existing ceremony test estate instead of
duplicating its device selection, DevAut, PIN retry, signing, recovery, JUnit,
and transcript logic.

```sh
# Default: build the established Debian emulator image and run its full suite
# (including the real SoftHSM PKCS#11 route and wizard dress rehearsal), plus
# every KMS Go package under the race detector.
e2e/run.sh

# Disposable Debian VM, using the existing full native emulator battery.
e2e/run.sh --mode native-vm

# Attached PicoHSM2: existing non-destructive identity/health/signature gate.
e2e/run.sh --mode pico-gate

# Destructive provisioning/recovery battery; two explicit interlocks.
REGALIA_ALLOW_DESTRUCTIVE_PICO=YES HSM_CI_SERIAL=ESP... \
  e2e/run.sh --mode pico-nightly
```

`--plan` prints the exact commands without executing them. The default can
never wipe a card. Pico targeting, PIN retry protection, DevAut checks, output
redaction, and evidence retention remain owned by `hsm-staging-ci.sh`.

The ephemeral SoftHSM test sends an authenticated signing request through the
HTTP handler, RBAC, registry and health selection, semantic policy and replay
journal, mandatory remote audit, bounded executor, backend manager, Nitrokey
provider, and concrete PKCS#11 driver. It also tests the driver directly. The
same phase runs real SOPS 3.13 encryption/decryption through the private Unix
adapter, TLS 1.3 mutual authentication, the complete policy path, context-bound
RSA wrap/unwrap, and four correlated allow/success audit events. All keys and
certificates are ephemeral fixtures. The
same driver loads OpenSC for PicoHSM2 and Nitrokey, but production enablement
still requires a real implementation of the mandatory per-session DevAut
challenge and `openSecureChannel`; the repository currently has only a DevAut
certificate reader. The driver refuses construction without both probes.

The optional `cosmos-simapp-smoke.sh` starts a reviewed, locally supplied
Cosmos SDK `simd` binary and checks its RPC health. It intentionally does not
claim transaction acceptance; the binary must be supplied with
`REGALIA_COSMOS_SIMD_BIN` so a broken upstream `latest` image cannot silently
become test evidence.

`cosmos-simapp-tx.sh` uses the same disposable node to submit and query a real
`MsgSend`. It proves chain acceptance with the SDK's test keyring; it is not
evidence that the KMS hardware signed that transaction.

`cosmos-simapp-kms-tx.sh` is the arm that is. Against the same kind of disposable node, the
transaction is built by cosmpy's generated protobuf bindings (`cosmos_kms_tx.py`, never an encoder
in this repository), signed by the KMS path — the production SignDoc parser, the production policy
engine and the concrete PKCS#11 provider with low-S — over a secp256k1 key on a SoftHSM token, and
broadcast. The KMS keeps one durable policy journal for the whole run, as the daemon does, so the
account sequence, the daily quota and the fencing epoch carry from one request to the next.

It then checks, against the live chain, that a KMS-signed `MsgSend` is committed and moves the
balances by exactly the amount and fee, and that each of these fails for its own reason:

| Case | Refused by the KMS | Rejected by the node when another KMS signs it anyway |
|---|---|---|
| the committed `TxRaw` replayed | | code 19 |
| another chain id | rule `cosmos-chain` | code 4 |
| a destination outside the policy | rule `cosmos-destination` | |
| a skipped or reused account sequence | rule `sequence` | code 32 |
| another account number | rule `cosmos-account` | code 4 |
| a fee or gas limit over the cap | rule `cosmos-fee`, `cosmos-gas` | |
| a gas limit the chain cannot run in | | code 11 |
| several messages: one disallowed destination, or a sum over the per-transaction cap | rule `cosmos-destination`, `cosmos-amount` | |
| a memo, or a truncated SignDoc | the parser (`signdoc`) | |
| a send that would cross the daily quota | rule `quota` | |
| the superseded epoch after a promotion | rule `epoch` | |

"Another KMS" is the same code with an empty journal and, where needed, a policy that allows what
this one refuses: it shows what the node does when only the node is left to refuse. Two allowed
`MsgSend`s in one transaction, a send at the same sequence after a quota refusal, and the promoted
epoch's next sequence are each committed. The run ends by comparing the chain's own sequence and
the KMS balance with the sum of what was committed. Needs `REGALIA_COSMOS_SIMD_BIN` and `REGALIA_COSMOS_PYTHON` (a
Python with `cosmpy` and `cryptography`). Evidence class: **emulated** — the token is SoftHSM.

Every `run.sh` mode declares what CLASS of evidence its arms produce, and the run
prints them together at the end — `software` (Go and host tooling, no token),
`emulated` (SoftHSM or the ceremony emulator standing in for hardware), or
`physical` (a real token). A SoftHSM pass and a Nitrokey pass look identical in a
log and mean entirely different things, and the qualification record is assembled
by people reading these logs. A run that produced nothing physical says so; a run
that FAILED says its list is not evidence at all, because a trap that prints
"EVIDENCE PRODUCED" after the run aborted is a record of things that did not
happen.
Select it through `e2e/run.sh --mode cosmos-devnet` when the reviewed binary is
available.

The SoftHSM token is disposable: each run generates a fresh random SO-PIN and
user PIN in memory, uses them only for provisioning and the child test
processes, and removes the token directory on exit. These are not staging-card
credentials. Physical Cosmos qualification must use the separately gated
`cosmos-hardware-sign-verify.sh` path with an operator-supplied credential and
registry-selected token/object; it must never inherit or guess the SoftHSM PIN.

## Real cards on a shared bench

Every script here that drives a real card through OpenSC shows OpenSC only the cards it names and
presents a PIN only behind a serial check (`e2e/lib/bench_cards.sh`, regalia-kms#174):

- `bench_isolate <conf> <module> <serial>…` writes an OpenSC configuration that ignores every other
  reader (by reader name, so it holds when readers are renumbered) and exports `OPENSC_CONF`. Readers
  off the bus at that moment are not in the snapshot; `HSM_IGNORE_READERS` (default `Yubico`) is always
  ignored as well.
- `bench_gate <serial> [slot]` before every command that presents a PIN, the SO-PIN, or initialises a
  card: exactly the isolated cards are visible and the serial is in exactly one slot (that slot, if
  given). Under `sudo` the configuration is carried with `env OPENSC_CONF=…`, and into a systemd unit
  with `--setenv`.
- `tests/test_e2e_card_isolation.py` fails on a real-card script without the isolation, or with a PIN
  line not behind a gate. SoftHSM-only scripts are exempt; a script with both kinds marks its emulated
  lines with `# emulated token: no real card`.

OpenSC ignores a reader whose name CONTAINS an `ignored_readers` entry (a substring match): that is
why overlapping reader names are refused, and why `ignored_readers = " "` ignores every reader.
