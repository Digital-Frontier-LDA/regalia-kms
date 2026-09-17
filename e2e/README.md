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
Select it through `e2e/run.sh --mode cosmos-devnet` when the reviewed binary is
available.

The SoftHSM token is disposable: each run generates a fresh random SO-PIN and
user PIN in memory, uses them only for provisioning and the child test
processes, and removes the token directory on exit. These are not staging-card
credentials. Physical Cosmos qualification must use the separately gated
`cosmos-hardware-sign-verify.sh` path with an operator-supplied credential and
registry-selected token/object; it must never inherit or guess the SoftHSM PIN.
