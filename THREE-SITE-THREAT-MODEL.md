# Three-site KMS: threat model and invariants (Phase 0, #60)

**Status: proposal under evaluation (#59).** This document defines what the three-site design must
withstand before any production bootstrap code is written. It does not change a current contract:
until a phase's evidence and a recorded decision exist, [PIN-CUSTODY.md](PIN-CUSTODY.md) (static,
TPM-sealed user PINs, no runtime PKA), [FENCING.md](FENCING.md) (one independent activation
signer) and `deploy/baremetal/` (single-site commissioning, TPM-only disk unlock as the interim
baseline) remain authoritative. The secrets and their lifecycles are in
[THREE-SITE-SECRETS.md](THREE-SITE-SECRETS.md).

## The goal, stated as invariants

**Availability.**
- **A1.** Any one node that reboots is restored, unattended, by either healthy ACTIVE peer.
- **A2.** Any two nodes that reboot are restored by the remaining healthy ACTIVE node.
- **A3.** A total outage (all three down) is restored by one manual recovery at one node, after which
  A1/A2 restore the rest.
- **A4.** No single provider, datacenter, network path or device failure stops the cluster from
  serving (one serving site at a time under fencing; the others are standby).

**Security.**
- **S1.** No single location holds what unlocks a node's disk: the node's TPM contribution and one
  authorized peer's contribution are both required. Local possession of the hardware is not enough.
- **S2.** Eligibility is defined separately for the two roles, from the current signed membership:
  - **to receive** a peer contribution (be unlocked): ACTIVE or MAINTENANCE;
  - **to authorize** (give a contribution): ACTIVE only.
  DRAINING, QUARANTINED, RETIRED and REVOKED_STOLEN nodes neither receive nor authorize.
- **S3.** A captured bootstrap exchange cannot be replayed: every contribution is bound to one boot
  session's fresh ephemeral key and the peer's nonce.
- **S4.** Unlocking a disk grants nothing else: serving needs a fencing lease from the independent
  authority (FENCING.md); key use needs the HSM's own authorization; neither is a bootstrap result.
- **S5.** Long-term service private keys never leave hardware; no online bundle carries an SO PIN,
  a YubiKey PUK or management key, a membership-root key or a recovery credential.
- **S6.** Every security decision (quote verdicts, contributions issued or denied, manifests,
  revocations, recoveries) leaves an off-node, tamper-evident audit record without secrets.

## Failure domains

| Domain | What compromising it gives | What still holds |
|---|---|---|
| One server, powered off, stolen | Its disks, TPM, HSM (if attached), WG-BOOT key sealed in the TPM | S1: no peer contribution once revoked or once away from the datacenter networks (peers accept WG-BOOT only from the declared datacenter addresses); HSM keys need the HSM PIN, sealed to that TPM's measured boot |
| One server, running, root compromised | Its unlocked disk, its HSM session, its WG-SERVICE identity | S4: no activation lease unless it is the fenced active site; S5: no exportable key; revocation (#69) and lease expiry (#74) bound the window; detection is the audit trail and attestation drift |
| One datacenter (physical) | Every server in it; staff cannot open the locked drawers (custody plan) | Other sites; chassis-intrusion and access logs as detection |
| One provider (two sites may share provider X) | Both of its sites' power, network and remote hands: **one administrative failure domain** | The site at provider Y; A3 manual recovery |
| Network partition | Peers cannot reach each other or the revocation authority | Fail closed: a peer whose membership is older than the freshness bound authorizes nothing (design question 1); serving continues only under a valid lease |
| A malicious or compromised peer | It can refuse to help (availability) or try to help the wrong node | The alternate peer path (A1); it holds only its own contribution, never a whole unlock credential (S1); it cannot mint membership (offline root) |
| Stale membership on one peer | It may still help a node revoked elsewhere | Freshness bound (question 1); revocation is restrictive-only and propagates to every reachable peer |
| Rollback of a node's disk or TPM state | Old manifest, old epoch | Highest accepted epoch kept outside restorable disk state (TPM NV), checked at every decision |
| TPM (vendor bug, fTPM, physical attack) | Sealed local secrets on that node | S1 still needs a peer contribution; measured-boot claims are only as good as #65's real PCR mapping |
| HSM model or batch (Nitrokey batch defect seen on one unit; Pico disclosure GHSA-wq3w-g2fj-q2jq) | Availability of that device kind; for Pico, key protection is unqualified | Heterogeneous fleet only after #62–#64; until then production stays Nitrokey (decision record) |
| YubiKey | Its PIV/OpenPGP keys if the PIN leaks | PIN retry counters; admin credentials never online (S5) |
| Administrator (single owner) | Everything the owner can authorize | Offline membership root under ceremony custody; independent witness triggers (governance) |
| Package repository / firmware supply chain | Code on the node | Signed packages and pinned versions, signed firmware (HPE SPP), measured boot + IMA attestation (#65); rolling CURRENT/NEXT policies (#75) |
| Bootstrap protocol implementation (pre-root code in initramfs) | Everything it handles before root exists | Small, audited code (#67 gate 3), established libraries only, no custom primitives |

## Attacker cases the phases must test

1. **Intact powered-off theft.** The thief has the whole server and can power it anywhere. Claim
   available *before* revocation reaches a peer: the stolen node can unlock only if it reaches a peer
   over WG-BOOT **from a declared datacenter address** and that peer still lists it ACTIVE within its
   freshness bound. Away from its datacenter it gets nothing. Inside its datacenter (an insider),
   detection (access logs, chassis intrusion) must trigger revocation before the freshness bound
   lapses, so the claim is time-bounded and must be stated with the bound (#69).
2. **Running root compromise.** Out of scope for cooperative enforcement after unlock; bounded by
   fencing leases, short-lived service certificates, revocation, measured-boot reattestation and
   audit (#74). Stated limit, not a solved problem.
3. **Malicious peer.** Can deny service (handled by the other path) and can attempt to authorize a
   revoked node only if its own manifest is stale (freshness bound) or it is itself compromised
   (then: one contribution only, never a whole credential).
4. **Stale membership.** Covered by epochs, TPM-anchored highest-epoch, the freshness bound and
   restrictive-only revocation.
5. **Rollback.** Disk snapshots, old TPM NV contents, old manifests and old boot images: refused by
   the epoch anchor (#68) and by retiring old measured policies (#75).
6. **Independent provider or site failure.** A4 and A3; two sites at one provider are one domain.

## The Phase 0 design questions, answered (to be confirmed by the phases)

**1. Freshness of restrictive membership updates under partition.** A newer manifest proves only
*ordering*, not that no restrictive update happened since. Freshness therefore comes from a
**heartbeat** the revocation authority signs: it carries the current manifest epoch, a monotonic
sequence number, an issue time and an **expiry** (proposed: 24 hours after issue). A peer authorizes a
bootstrap only while it holds an unexpired heartbeat for its manifest's epoch, and it checks:
- the expiry against **authenticated time** (NTS-authenticated NTP, with the TPM clock as a monotonic
  floor between syncs). FENCING.md already requires authenticated time for the same reason: an
  attacker who controls the clock can make an old proof look current;
- the sequence against the highest one it has accepted, kept in **TPM NV** outside restorable disk
  state, so a captured older heartbeat cannot be replayed after a rollback.
Without authenticated time, or past the expiry, the peer fails closed: availability yields to
security, and A3 covers the gap. The bound is the explicit trade; its value is set in #69.

**2. The powered-off theft claim before revocation.** As case 1: denied away from the datacenter
networks; inside them, bounded by detection plus the heartbeat expiry (question 1). Not "immediately
global", and only as strong as the peers' authenticated time.

**3. Bootstrap eligibility versus service signing authority.** Different capabilities with different
issuers. ACTIVE (or MAINTENANCE) membership makes a node *eligible to be unlocked*; ACTIVE makes a
peer *eligible to authorize*; neither makes a node a signer. Serving needs the fencing authority's
lease (FENCING.md: one independent signer, no overlapping sites); key use needs the HSM's own
authorization. Peer runtime leases (#74) must not become a second activation authority.

## Device profiles and their assurance

| Profile | Devices | Measured boot / attestation | Local secret | Key protection | Status |
|---|---|---|---|---|---|
| A | TPM2 + Nitrokey HSM 2 + YubiKey | Yes (TPM quotes, #65) | TPM-sealed | Nitrokey, qualified | Production candidate (current fleet) |
| B | TPM2 + PicoHSM | Yes | TPM-sealed | Pico, **unqualified**; open disclosure | Lab only until #62–#64 and a decision |
| C | Bootstrap YubiKey + Nitrokey + operational YubiKey | **No TPM: no measured boot, no quote** | YubiKey-held, presence-based only | Nitrokey | Needs an explicit alternative-assurance decision |
| D | Bootstrap YubiKey + PicoHSM | No | YubiKey-held | Pico, unqualified | Lab only |

A TPM-free profile does not inherit measured-boot properties: a YubiKey can hold a secret but
cannot attest what code asked for it. It also has nowhere to seal an unattended PIN (the user PIN and
the YubiKey PIN are TPM-sealed systemd credentials today), so **profiles C and D cannot meet the
unattended-availability invariants A1 and A2**: unlocking them needs an operator, or a non-TPM PIN
mechanism that a separate decision would have to define and justify. Hardware equivalence is never
assumed.

## Lab baseline (recorded 2026-10-01)

| Item | State |
|---|---|
| Nitrokey HSM 2 DENK0404144 (staging) | attached; firmware 4.1, hardware 24.13; PKCS#11 contract 14/0 (#62) |
| Nitrokey HSM 2 DENK0404380, DENK0404547 (staging) | on the bench, not attached |
| PicoHSM staging units (ESP2202E14A, ESP41D722E2) | not attached; firmware under disclosure GHSA-wq3w-g2fj-q2jq |
| YubiKeys 36345471, 36344616, 35718625 (staging) | not attached |
| ACS ACR40U (SLE-4442) | attached; validated (regalia#43) |
| HPE DL360 Gen9 ×3 with TPM 2.0 | **not delivered** (expected mid-October): every TPM, PCR, initramfs and LUKS phase on real hardware waits for them |
| Software | Debian 13, OpenSC 0.26.1, pcscd 2.3.3, libccid 1.6.2, OpenSSL 3.5.1, cryptsetup 2.7.5, nftables 1.1.3, swtpm (kernel vTPM via tpm_vtpm_proxy for harness work) |

Invariants under test are A1–A4 and S1–S6 above. Evidence format: each phase records device serials,
firmware and software versions, the exact commands, positive and negative outcomes, sanitized logs
and stated limits on its issue; harness evidence (swtpm, SoftHSM, network namespaces) is labelled as
such.

## Lab and evidence (to be filled per phase)

Each phase records: device serials (staging only for destructive work), firmware and software
versions, the exact commands, positive and negative outcomes, sanitized logs and stated limits, on
its issue. Software and emulation (swtpm, network namespaces) are harness evidence; they never
substitute for the physical qualification a phase names.
