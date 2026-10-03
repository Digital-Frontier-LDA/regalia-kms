# Extended software cluster validation — 2026-10-02

The native Linux arm64 Docker mesh completed **256 seeded fault steps**, all
13 fault families and **1,320 assertions** in 1,477.764 seconds. Seed: `20261002`.
Maximum observed fault duration: 9.44 seconds. The full run includes real kernel
WireGuard, cryptsetup, swtpm and SoftHSM PKCS#11 operations, external signed-lease
verification, underlay isolation controls and cleanup. All three nodes finished
healthy and the run's private Compose resources were removed.

| Fault family | Occurrences |
|---|---:|
| `policy_conflict` | 19 |
| `authority_expiry` | 29 |
| `lost_response` | 15 |
| `total_outage` | 25 |
| `single_reboot` | 15 |
| `revoke` | 22 |
| `two_reboot` | 25 |
| `clock` | 17 |
| `bootstrap_partition` | 19 |
| `runtime_partition` | 17 |
| `pcr_fault` | 15 |
| `token` | 19 |
| `parser` | 19 |

Evidence is under `lab/bootstrap/.artifacts/soak-20261002-256-noda/`.
Cluster report SHA-256:
`8f32ea7472958096b1ba69054c2a0d512bd1c367d1d37fda56fc7af31ed8cc6d`.
Soak report SHA-256:
`8e980db4b80132921fe211912215024f2abe5a034fcade39dc6ffa150caedc09`.

This used an unsigned cached development image
`sha256:cff1e97ea3f72c5f205a1e0914915f6fc2c5572f62dd697f769083a71151d90f`
and readonly frozen source overrides, verified in every container. The report
records base commit `de60ca9282a9e900d7b64f279ba21823920ac5e5`, the
individual source hashes and override hashes. The NoDA change was present as a
development override; this is not a pristine image from the final branch commit
or publisher authentication. The runner's path/hash is recorded separately.

## Repeated restart defect and fix

An earlier extended run failed at step 95. Repeated unorderly software-TPM
restarts after using a dictionary-attack-protected attestation key exhausted the
TPM's global dictionary-attack budget (TPM_RC_LOCKOUT `0x921`). Serializing TPM
commands alone did not fix it. The lab now creates its attestation key and
policy-only sealed bootstrap objects with explicit `noda` attributes, verifies
the actual TPM public attributes, and retains PCR/fresh-nonce authentication.
The sealed objects do not permit a user-password bypass. No global lockout reset,
budget relaxation or HSM/PIN-protected key change is made.

A separate disposable TPM test deliberately locked a protected storage parent,
then completed **100** restart/quote/replay/PCR/sealed-key cycles. The parent
remained locked afterwards, with its configured dictionary-attack budget and
recovery intervals unchanged. Native local validation and fresh CI both passed.
The native IPC experiment also passed 121 assertions. The longer mesh run then
crossed its previously failing steps and completed all 256 faults.

[CI run 37061145535](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37061145535)
passed both short cluster seeds, the 100-cycle stress test and all 33 functional
jobs. Its fresh appliance scan alone remains blocked by High/Critical findings.
The retry added to device positive controls issues fresh authorization/challenges
under the existing short TTL; negative controls still require denial without
extending leases or clock tolerance.

## Remaining qualification

This is software-emulator evidence. It does not establish DL360 measured-boot
coverage, physical TPM persistence/rollback protection, physical HSM public-key
authentication or wrapped-key portability, production custody/reconciliation,
commissioned disk encryption, or safe production release admission. Longer
manual CI soak rounds are available through `cluster-soak.yml`; this checkpoint
is one roughly 25-minute run, not a multi-day soak.
