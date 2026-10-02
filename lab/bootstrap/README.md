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
`limitations_observed`. Runtime leases, HSMs, and physical-node recovery remain separate work.
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

## Next slices

Additional experiments can run on the development machine:

| Experiment | Software validation to add |
|---|---|
| Signed network policy | Commission authority pins on all three peers; deliver signed updates over a separate administrative contract; test interrupted/conflicting delivery and explicit freshness/partition policy |
| Runtime leases | Expiry, renewal through either peer, running-node revocation, clock faults and external client rejection; preserve independent service-signing fencing |
| Software service gate | Reuse the existing [SoftHSM battery](../../e2e/README.md) to connect bootstrap authorization to PKCS#11 service readiness, token removal and reauthentication; native vendor PKA remains a hardware gate |
| Randomized faults | Seeded partition, response-loss, reboot, policy-conflict and parser-corruption schedules; retain the seed and assert recovery or an explicit closed state |

These are follow-up experiments, not completed acceptance criteria.

Production qualification still requires:

1. Qualify complete Debian boot packaging and the DL360 measurement chain. The
   small emulated BusyBox root is software-path evidence, not an appliance build.
2. Extend signed membership into network/guest commissioning and design
   revocation freshness before claiming safe unattended bootstrap. Qualify a
   rollback-resistant high-water store; keep service signing fencing independent.
3. Qualify native/cross-vendor PKA and wrapped-key recovery on designated physical
   lab HSMs. This container does not initialize or touch attached tokens.

Tool references: [tpm2_quote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_quote.1/),
[tpm2_checkquote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/),
[policy-based unsealing](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_unseal.1/),
and [cryptsetup source/documentation](https://gitlab.com/cryptsetup/cryptsetup).
Response primitives: [RSA-OAEP](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)
and [Ed25519](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/).
