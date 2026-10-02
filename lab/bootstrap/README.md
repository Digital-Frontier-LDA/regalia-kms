# Disposable bootstrap lab

Run from the repository root:

```sh
bash lab/bootstrap/run.sh
```

The runner chooses the Docker daemon's native architecture (arm64 on Apple Silicon)
and writes sanitized evidence to `lab/bootstrap/.artifacts/report.json`.
Override `REGALIA_LAB_PLATFORM=linux/amd64` to test the other architecture.
The Debian 13 base image is pinned by multi-architecture digest. Package versions
are recorded in the report; apt repositories are not snapshot-pinned.

Runners first check the [image input inventory](../../deploy/images/README.md) and
write `.artifacts/image-inputs.json`. The current base has **digest integrity only**;
publisher-signature authentication is unverified. These explicitly recorded
development fixtures cannot be promoted to appliance images. New Dockerfile or
Compose image references fail the inventory gate until their policy is reviewed.
The host inventory requires PyYAML 6.0.3 (pinned in `harness-requirements.txt`).

The lab is a non-root, network-disabled container with all capabilities dropped,
a read-only root filesystem, and temporary memory-backed scratch storage.
Only the evidence directory is mounted. It has no access to hardware devices,
host disks, existing KMS credentials, or the Docker socket. Generated test state
is discarded when the container exits.

Evidence class: **emulated**. This lab prepares software experiments for
regalia-kms #65–#69. Containers do not exercise UEFI, the real TPM measurement
chain, initramfs networking, dm-crypt mapping, or physical HSM authentication.

## Experiments

Two independent `swtpm` instances use Unix sockets inside the container. Separate
B/C verifier subprocesses use pinned lab AK and measurement policy, issue fresh
challenges, and release signed contributions encrypted to a boot-session key.
The current runner executes 121 checks, including 46 signed-membership scenarios.

| Area | What the lab exercises |
|---|---|
| Attestation | Fresh challenge; enrolled AK; replay and wrong-AK rejection; altered message, signature, and PCR values |
| Session binding | SHA-256 qualification binds node ID, manifest epoch, boot session, ephemeral public key, and peer nonce |
| Boot state | Current PCR values verify; an authentic quote for a modified PCR is rejected against approved values |
| TPM sealing | WireGuard private key and a separate local contribution unseal under PCR policy; empty password and foreign TPM fail |
| State change | Extending PCR 7 blocks fresh unsealing of both sealed secrets |
| LUKS2 | HKDF-derived local + B or local + C credentials authenticate independent slots in a disposable real LUKS2 header |
| Missing/wrong factors | Either factor alone, an incorrect factor, or a substituted peer path is refused |
| Path removal | Removing the B slot invalidates that credential while C still authenticates |
| Peer release | Separate B/C workers verify fresh quotes/current fixture policy and return Ed25519-signed RSA-OAEP contributions |
| Response handling | Wrong recipient, forged/altered responses, cross-session replay, duplicates, and late second-peer responses are rejected |
| State and concurrency | State capability checks, epoch advancement, expiry, bounded pending challenges, and exactly one grant from racing workers |
| Input boundary | Strict types/fields/hex, duplicate JSON keys, malformed/oversized input, and client filesystem-path substitution are refused |
| Signed membership | Pinned root/revocation roles; signature and cluster binding; chained epochs; conflicting updates; pending-request revocation; measurement-policy enforcement |
| Software rollback limitation | Restoring an entire verifier state file permits a previously revoked bootstrap; recorded as a limitation, not theft-resistance acceptance |

`cryptsetup open --test-passphrase` checks actual LUKS2 keyslot credentials
without creating a device-mapper mapping or mounting a filesystem. It does not
prove that a machine can boot its encrypted root. Contributions are generated
and retained in separate software verifier state in tmpfs, and the received
session-encrypted values supply the actual LUKS credential derivation. Transport
is local stdin/stdout IPC in one trusted container, not remote bootstrap over
WireGuard. Original scenarios use unsigned fixture policy; the additional
[signed membership scenarios](MEMBERSHIP.md) verify root/revocation signatures
and apply those policies in the actual verifier. Neither mode proves global
policy freshness, rollback-resistant storage, or production revocation. The
state-file restore drill records `membership_state_rollback_is_possible` in
`limitations_observed`. Runtime leases and software HSM service gating are exercised by the separate
cluster runner below. Physical-node recovery remains separate work.
Read the [local peer contract](PROTOCOL.md) for the request/response and challenge
lifecycle. Verifier signing keys are software test fixtures, not KMS service keys.

PCR 7 is chosen solely to exercise the software TPM API. No claim is made that
PCR 7 measures the kernel/initramfs. A real measurement survey and boot-package
decision remain #65 and #57. Changing a PCR blocks *future* unsealing; the harness
still holds values unsealed before the change. It deliberately uses these
cached values for the LUKS experiment, illustrating why boot gates alone cannot
enforce runtime revocation.

The LUKS PBKDF2 iteration count is deliberately small for disposable random lab
credentials. It is not a production commissioning default. Python orchestration
does not guarantee locked memory or destruction of immutable secret buffers.
Read [the lab threat model and secret inventory](THREAT-MODEL.md).

## Evidence and reruns

A successful run exits zero and writes an `emulated` report containing overall
status, each check, timestamp, architecture, Debian/package versions, Git commit,
image ID, and SHA-256 of each lab source file. A failed assertion/tool invocation exits
nonzero and writes a failed report when the harness starts. A Docker build failure
does not produce new experiment evidence; check report timestamps. Each rerun
replaces the latest report; copy it elsewhere to retain previous evidence.
No quotes, secret bytes, keys, TPM state, or disk images leave temporary storage.

The `bootstrap-lab` CI job runs this same entry point on Linux. It is software
evidence only, and a failed assertion or missing tool fails the job.

Run another architecture explicitly:

```sh
REGALIA_LAB_PLATFORM=linux/amd64 bash lab/bootstrap/run.sh
```

The task-specific platform takes precedence over an ambient
`DOCKER_DEFAULT_PLATFORM`; the runner does not change the caller's environment.
Both architectures use the same pinned Debian image index. Apt security updates
can change package versions on a fresh build; preserve the report and image ID
when comparing runs. Rebuild the image deliberately to pick up apt updates.

Native runs use swtpm's additional `kill` seccomp policy. Under architecture
translation (for example amd64 on this arm64 Docker VM), that filter fails to
install; the runner selects swtpm `action=none`. Docker's container restrictions
still apply. The daemon architecture and chosen swtpm mode are recorded in the
report. `REGALIA_LAB_SWTPM_SECCOMP=kill` can require the additional filter even for
a translated run; an unsupported filter then fails the run rather than silently
falling back. See [swtpm's documented seccomp option](https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm.pod).

## Additional software labs

The [three-container WireGuard experiment](NETWORK.md) now extends these IPC
checks with 67 assertions covering actual encrypted cross-container transport,
all six recovery paths,
simultaneous recovery, total-outage/manual recovery, and network-failure tests.

```sh
bash lab/bootstrap/run-network.sh
```

This separate runner uses NET_ADMIN only inside its own container namespaces,
drops service privileges, and removes its project resources after the run. It
writes sanitized `network-report.json` evidence. Its stale-policy scenario
explicitly reproduces an unresolved revocation-freshness risk.

The [encrypted-root guest experiment](VM.md) uses an amd64 Debian kernel, QEMU
TPM frontend, early WireGuard, actual dm-crypt mapping, ext4, and `switch_root`.
It writes a separate `vm-report.json` with guest stages and public PCR values.
Its modified-initramfs scenario tests a boot measurement coverage limit rather
than qualifying PCR 7 as a production policy.

```sh
bash lab/bootstrap/run-vm.sh
```

## Signed policy, runtime leases, PKCS#11 and chaos

The [cluster experiment](CLUSTER.md) implements all four software follow-ups on
three isolated nodes with separate kernel WireGuard identities for bootstrap and
runtime. It generates disposable keys using the real SoftHSM PKCS#11 module.

```sh
bash lab/bootstrap/run-cluster.sh
# Reproduce another fault schedule; defaults are seed 20261002 and 36 actions.
REGALIA_CHAOS_SEED=20261003 REGALIA_CHAOS_STEPS=36 bash lab/bootstrap/run-cluster.sh
```

The wrapper installs pinned host dependencies into an isolated ignored venv.
It writes `lab/bootstrap/.artifacts/cluster-report.json` with source hashes,
package versions, platform, image ID, every assertion, fault seed/actions and
cleanup status. CI runs both seeds and retains sanitized reports for 14 days.
Each schedule covers all 13 fault families before adding random repetitions;
cryptographic keys and nonces always use operating-system randomness.
Do not run the network, guest and cluster runners concurrently on one Docker
daemon: they reserve the same disposable laboratory subnet.

| Experiment | Software evidence |
|---|---|
| Signed network policy | Six recovery paths under signed policy; interrupted/idempotent delivery; chained catch-up; state restrictions; stale-peer denial after signed freshness expires |
| Runtime leases | Automatic renewal through either peer; expiry and running-node revocation; signed request/response binding; concurrent/replayed challenges; clock faults; independent client rejection, including a genuine unauthorized signature |
| Software service gate | Actual RSA key generation/signing through PKCS#11; non-extractable/sensitive attributes; real logout/wrong-PIN errors; token removal/reinsertion; fresh authorization before reauthentication |
| Randomized faults | Seeded partitions, lost responses, one/two/three-node authorization loss, revocation, policy forks, malformed requests, clock faults, token removal, freshness expiry and actual software-TPM PCR changes |

The online freshness signer is a lab design experiment that adds an independent
availability dependency and trusted-time assumption. It bounds stale-policy
acceptance; it does not make revocation instantaneous. Local policy/generation
files and software tokens remain cloneable. The runtime leases authorize this
test service and preserve the independent single-signer contract in
[`FENCING.md`](../../FENCING.md).

Production qualification still requires:

1. Qualify complete Debian boot packaging and the DL360 measurement chain. The
   small emulated BusyBox root is software-path evidence, not an appliance build.
2. Transfer signed cluster policy into the actual encrypted-root guest path and
   choose production freshness/time/partition policy. Qualify a rollback-resistant
   high-water store; keep service signing fencing independent.
3. Qualify native/cross-vendor PKA and wrapped-key recovery on designated physical
   lab HSMs. This container does not initialize or touch attached tokens.

Tool references: [tpm2_quote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_quote.1/),
[tpm2_checkquote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/),
[policy-based unsealing](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_unseal.1/),
and [cryptsetup source/documentation](https://gitlab.com/cryptsetup/cryptsetup).
Response primitives: [RSA-OAEP](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
and [Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).


## Bounded extended runs

```sh
python3 -m lab.bootstrap.soak --rounds 2 --steps 128 --seed 20261002 \
  --output lab/bootstrap/.artifacts/soak
```

The controller requires 1–8 rounds and 13–256 faults per round, with a two-hour
maximum per round. It preserves each schedule/report/log separately and checks
complete fault coverage, every assertion and cleanup. Reports cannot be replaced
by an earlier passing run. Each round has its own random Compose project and
report path; timeout cleanup is confined to that project. Runs still reserve the
laboratory subnet and must be serialized on a Docker daemon. The manual
`Bounded cluster soak` workflow runs the same controller with pinned actions.

Longer runs exposed `TPM_RC_LOCKOUT` after unorderly software-TPM starts. The
default PIN-less AK was DA-protected. The revised lab AK remains restricted,
fixed to its TPM/parent under TPM object rules; its explicit template adds `noDA`.
Software-TPM state remains copyable and supplies no physical possession guarantee.
Policy-only sealed contributions also use `noDA`, with `userwithauth` absent.
Actual enrolled attributes are read back and checked. TPM commands and restarts
are serialized, and diagnostic reports contain tool names/status codes only.

`lab/bootstrap/tpm_soak.py` performs 100 concurrent quote/replay checks, PCR
refusals, unorderly restarts and two contribution checks. It deliberately locks
the disposable DA-protected storage parent and proves bootstrap still works
while that parent continues to refuse. No global DA budget, recovery interval
or lockout state is cleared or relaxed. Empty-password bypass remains refused.
CI repeats this experiment inside an isolated container. No real TPM or PIN
protected key is touched; physical firmware/object-policy qualification remains
required.

See [runtime mTLS evidence](RUNTIME-MTLS.md) for the separate external gateway
experiment using the actual Go authentication middleware.

See [extended soak evidence](SOAK-VALIDATION.md) for the completed 256-fault run.
