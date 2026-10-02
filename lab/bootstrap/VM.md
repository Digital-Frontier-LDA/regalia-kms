# Emulated encrypted-root boot

```sh
bash lab/bootstrap/run-vm.sh
```

This runs the WireGuard recovery suite, then boots an amd64 Debian kernel in QEMU
TCG inside node A's container. The guest has a QEMU TPM TIS frontend connected to
that node's disposable swtpm state, a virtio disk backed by its private LUKS image,
and userspace networking. No host disks, TPM, virtualization devices, Docker
socket, or published ports are passed through. There is no KVM requirement.

The runner selects amd64 to match the production servers. On Apple Silicon this
adds Docker architecture translation. Debian's arm64 kernel in the initial
experiment lacked the TIS driver for the selected QEMU device; that attempt
failed before qualification. This runner does not qualify an arm64 boot chain.

## Boot and commissioning

The public initramfs contains the required kernel modules, tools, linked shared
libraries, OpenSSL providers, Python modules, and public peer policy fixtures.
It contains no recovery credential, WireGuard private key, local disk factor,
peer contribution, or peer signing key. The initializer loads drivers and
networking before the encrypted root is opened.

An initial guest survey captures actual firmware PCR 7 and leaves the disk closed.
QEMU/SeaBIOS measurements differ from the zero-valued IPC fixture. A trusted local
commissioning control temporarily keeps the two previously unsealed local values
in daemon memory, creates a trial PCR policy with `tpm2_createpolicy -f`, and
reseals the same values to the observed guest state. It also updates the peers'
approved measurement fixtures. This preserves the original LUKS factors and is
explicitly a disposable commissioning procedure, not an online production API.
Cached commissioning references are dropped after resealing; Python does not
guarantee erasure of the underlying memory.

The host-side A WireGuard interface is disabled so it cannot compete with the
guest's endpoint. Each guest starts from a cold QEMU process and restarts the
software TPM backend while retaining its permanent state. Persistent AK/storage
and sealed-object identity must survive. The guest unseals its boot WireGuard key
and local contribution through `/dev/tpmrm0`, establishes the actual WireGuard
tunnel, binds a fresh recipient key/challenge into its TPM quote, verifies the
signed response, and pipes the derived credential directly into cryptsetup.

The first authorized boot creates a minimal ext4 root in the mapped encrypted
volume. Later boots mount that existing filesystem and use `switch_root` into
its static BusyBox init. A sentinel is printed only from that root's init after
checking its disk marker. The initializer never prints credential bytes.

## Validation

The guest scenarios cover firmware measurement survey, cold encrypted-root boots
through B and C, refusal without an ACTIVE peer, restoration after one manual
peer recovery, current revocation refusal, and genuine TPM policy refusal after
PCR modification. Failure scenarios require a closed mapper plus the specific
peer-denial or TPM-policy marker; dependency/tool failures cannot count as a
successful security refusal. Raw guest logs are discarded. Evidence retains only
fixed stage markers, public PCR values, known loader/emulator diagnostics, package
versions, kernel name, source hashes and outcome in `.artifacts/vm-report.json`.

The resources are removed by the same project cleanup as the network suite.
Temporary boot images and encrypted disks remain inside container tmpfs. The
host controller retains disposable recovery credentials only in memory for its
drills. A Docker build failure can leave older evidence; check timestamps/status.

## Security Findings

PCR 7 alone does not bind this guest's initramfs. The runner deliberately adds an
executed line to the initializer and attempts the same disk bootstrap. A modified
initializer that executes and boots under the same approved PCR value reproduces
an unqualified boot measurement profile. It is recorded separately as
`limitations_observed.guest_pcr7_does_not_bind_initramfs`, not counted as a boot
integrity acceptance criterion. The stale membership gap from the network suite
also remains unresolved.

## Checks Performed

QEMU executes a real guest kernel, TPM driver, WireGuard interface, cryptsetup
mapping, ext4 mount and root transition. Positive boots must include peer
authorization, disk-open and encrypted-root markers. Refused boots must omit
disk-open and encrypted-root markers and include the specific refusal.

## Residual Risk

This is a small custom experimental initramfs and BusyBox root, not a complete
Debian appliance, production UKI, or qualified DL360 boot chain. QEMU, swtpm,
container host, controller and commissioning controls are trusted. Software TPM
state is cloneable and rollbackable. The currently selected PCR cannot prove
that early code is approved. HSM authentication, service readiness, leases,
physical theft resistance and production recovery ceremonies are not exercised.

## Recommendation

Use this as evidence for the early networking and peer-assisted disk orchestration
gates. Keep production authorization blocked on comprehensive measured boot and
signed membership freshness. Survey actual DL360 firmware/boot packaging and
qualify devices before choosing production PCR policies.

References: [QEMU TPM devices](https://www.qemu.org/docs/master/specs/tpm.html)
and [TPM trial PCR policies](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_createpolicy.1/).
