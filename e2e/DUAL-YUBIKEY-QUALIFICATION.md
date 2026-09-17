# Dual physical YubiKey Gen-5 qualification

This runbook is deliberately opt-in and destructive only where marked. It qualifies two
simultaneously connected YubiKey 5 devices for unattended PIV use; emulator results do not
substitute for this evidence.

## Preflight (read-only)

1. Connect both keys and record `ykman list --serials`.
2. Run `ykman --device SERIAL piv info` for each key. Record model, firmware, PIN retries,
   and the commissioned slots. Refuse the run if either key reports default PIN, PUK, or
   management key material.
3. Set `REGALIA_YK_SERIAL_A` and `REGALIA_YK_SERIAL_B` to the two recorded serials.

## Commissioning (approved ceremony only)

On each key, generate or import the approved PIV key in slot 9A (and 9C when signing is
required), with PIN policy `once` or `always` and touch policy `never`. Record the public
fingerprint and serial in the signed custody manifest. Never place PINs in the repository,
shell history, CI variables, or test output.

## Qualification

Run from the repository root:

```sh
set -eo pipefail
REGALIA_YK_SERIAL_A=... REGALIA_YK_SERIAL_B=... \
  go -C kms test -tags piv ./internal/integration \
  -run TestTwoPhysicalYubiKeysAreIndependentlyAddressable -count=1
```

The test opens both physical devices at once, proves serial/identity separation, reads PIN
retry state, and requires the commissioned slot to report a non-presence PIN policy and
`touch_policy=never`.

## Required evidence extensions

The qualification record must attach results for each row, with timestamps and serials:

| Property | Physical evidence |
|---|---|
| Identity separation | Both sessions open concurrently; each reports its pinned serial |
| Independent PIN handling | Correct PIN succeeds on each; wrong PIN on A changes only A's retry count |
| Failover | Remove A; operation routed to B succeeds; A's route refuses while absent |
| Revocation/rotation | Revoke/rotate A in the reviewed manifest; A refuses and B remains usable |
| Unplug/reinsert | Unplug and reinsert each key; rediscovery requires the original serial |
| Ceremony | Execute the approved two-key ceremony and retain signed transcript |
| Presence policy | Slot policy is `never` on both keys; no touch prompt is used |

Each destructive row requires a separate operator approval and a before/after device-state
record. Do not infer a pass from a skipped test or from a single-key run.

## Staging observation (2026-09-12)

Two YubiKey 5C NFC devices (firmware 5.4.3) were connected simultaneously and qualified with
the test above. Both reported ECCP256 keys in slots 9A and 9C, management keys protected by PIN,
and the test completed successfully for identity separation, independent PIN authentication,
and independent slot-9C signatures. PIN values are intentionally not recorded here.

The service-level staging test also exercised manifest failover and revocation/rotation: an
active route on A signed, a revoked A route refused without silently using standby, and a
rotated manifest promoted B, which signed with B's separate PIN. The test is
`TestTwoPhysicalYubiKeysServiceFailoverAndRevocation` (build tag `piv`).

The physical age ceremony was executed after an approved PIV reset on both staging cards. The
real `age-plugin-yubikey --generate --serial SERIAL --pin-policy once --touch-policy never`
command generated a distinct identity on each serial and reported `PIN policy: Once` and
`Touch policy: Never` for both. The PIV 9A/9C KMS slots were then reprovisioned with the same
non-presence policy and the qualification rerun successfully. Public recipients and PIN values
are intentionally not recorded here.

## Power-cycle observation (2026-09-12)

Using the staging USB hub's port-power control, the key on the controlled port disappeared from
`ykman list --serials` while the other key remained available. Restoring port power made the
same pinned serial re-enumerate, and the dual qualification passed again. An earlier cycle on
this hub required a physical unplug/reinsert; both outcomes are retained as evidence that the
daemon must treat disappearance as unavailable and rediscover by serial after recovery.
