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
regalia-kms #65–#67. Containers do not exercise UEFI, the real TPM measurement
chain, initramfs networking, dm-crypt mapping, or physical HSM authentication.

## Experiments

Two independent `swtpm` instances use Unix sockets inside the container. A pinned
lab AK public key is used by the offline `tpm2_checkquote` verifier.

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

`cryptsetup open --test-passphrase` checks actual LUKS2 keyslot credentials
without creating a device-mapper mapping or mounting a filesystem. It does not
prove that a machine can boot its encrypted root. Peer contributions are random
local test fixtures, not responses from a remote bootstrap server. A bound
ephemeral key is exercised in the quote, but response encryption is not yet
implemented. There is no signed membership, policy freshness, revocation,
runtime lease, HSM, or physical-node recovery implementation here.

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
image ID, and SHA-256 of the exact harness. A failed assertion/tool invocation exits
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

## Next slices

1. Add session-encrypted contributions from an independently running verifier
   with explicit requester/authorizer policy and transport authentication.
2. Prepare a Debian VM/physical-node initramfs lab for actual early networking
   and encrypted-root boot, then run the DL360 PCR survey.
3. Integrate signed membership and revocation freshness before claiming safe
   unattended bootstrap. Keep service signing fencing independent.
4. Qualify native/cross-vendor PKA and wrapped-key recovery on designated physical
   lab HSMs. This container does not initialize or touch attached tokens.

Tool references: [tpm2_quote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_quote.1/),
[tpm2_checkquote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/),
[policy-based unsealing](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_unseal.1/),
and [cryptsetup source/documentation](https://gitlab.com/cryptsetup/cryptsetup).
