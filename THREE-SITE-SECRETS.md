# Three-site KMS: secret inventory and lifecycles (Phase 0, #60)

Every secret the three-site design (#59) uses, each with all eight lifecycle fields and a custody
role; "n/a" always carries its reason. Companion to [THREE-SITE-THREAT-MODEL.md](THREE-SITE-THREAT-MODEL.md).
*Existing* secrets are in use today; *proposed* ones belong to a phase and do not exist until it lands.

Custody roles: **Owner** (the principal, sole shareholder); **Technical director** (reaches the
datacenter tokens, never the PINs); **Shareholders** (k-of-n case holders); **Node** (the machine,
no human); **Fencing authority** (the independent activation signer, FENCING.md).

## Disk unlock (Phases 6, 7, 11)

| Secret | Generated | Stored | Exportable | Authorized use | Rotation | Revocation | Recovery | Custody |
|---|---|---|---|---|---|---|---|---|
| **LUKS2 volume key** (per node; LUKS existing, this use proposed) | `cryptsetup luksFormat`, on the node | at rest only wrapped in keyslots; **in kernel memory while the volume is open**, as for any dm-crypt key | yes, to anyone holding a valid keyslot credential (`--dump-volume-key`) or root on the running node: the credentials and the running node are what protect it | dm-crypt for the root filesystem | `cryptsetup reencrypt` on suspected exposure | n/a: a volume key is replaced, not revoked | through the recovery keyslot | Node |
| **Local TPM contribution** (per node, proposed) | 256-bit random, on the node at enrollment | sealed in its TPM under the measured-boot policy (#65) | no (`fixedTPM`) | one HKDF input for each of the node's peer-path keyslots | with a measured-policy change (#75) or node replacement | TPM clear / node retirement | not recoverable by design; the recovery keyslot covers its loss | Node |
| **Peer contribution `P→T`** (one per target T and peer P, six in all; proposed) | 256-bit random, by P for T at enrollment | inside P's own encrypted root, so a powered-off P yields nothing | only through the bootstrap protocol, encrypted to T's freshly attested ephemeral key, when T may receive (threat model S2) | `credential = HKDF-SHA256(local_T ‖ P→T, info = "regalia/luks/v1/<T>/<P>/<path epoch>")` opens the `P→T` keyslot; neither input alone opens anything | per pair: new contribution, new keyslot, old keyslot killed | kill the pair's keyslot on T; P drops contributions for a revoked T | re-enroll the pair | Node (P) |
| **Recovery keyslot credential** (per node, proposed) | ≥128-bit passphrase, offline, at enrollment | on paper in the Owner's safe (own sealed envelope); escrowed encrypted to the breakglass recipient | only by its custodian; the escrow copy needs k shares | a total outage (A3), or a node with no healthy peer: unlock one node, then A1/A2 | after every use | kill the keyslot | the escrow copy, through k shares (ADR-0002 D19) | Owner |

## Attestation and networking (Phases 5, 6)

| Secret | Generated | Stored | Exportable | Authorized use | Rotation | Revocation | Recovery | Custody |
|---|---|---|---|---|---|---|---|---|
| **Endorsement key (EK)** (existing) | by the TPM manufacturer | in the TPM | no | anchors the attestation key; its certificate is recorded at intake | n/a: permanent to the TPM | node retirement (manifest) | n/a: replaced with the node | Node |
| **Attestation key (AK)** (proposed) | in the TPM, restricted signing key, bound to the EK by credential activation | in the TPM (persistent handle) | no (`fixedTPM`) | quotes binding node ID, manifest epoch, boot session, ephemeral key and peer nonce (S3) | node replacement, or a new enrollment | manifest (each node's AK is listed) | re-create and re-enroll through the membership root | Node |
| **WG-BOOT key pair** (per node, proposed) | in the initramfs build at enrollment | private half sealed to the TPM under the boot policy | no (sealed) | the peer bootstrap endpoints only, before root; removed after boot | with each boot-policy change (#75) | manifest + peers' WireGuard peer lists | re-enroll | Node |
| **WG-SERVICE key pair** (per node, proposed) | on the node | in the encrypted root | yes to root on the running node (it is a file); protected by disk encryption at rest | the service plane after boot (peer traffic, optional admin SSH) | yearly, or on suspicion | manifest + peer lists | re-enroll | Node |
| **Boot-session ephemeral key** (per boot, proposed) | in the initramfs, per boot | RAM only | no: destroyed with the bootstrap buffers after unlock | receiving the encrypted peer contributions for that one boot | every boot | n/a: it never outlives the boot | n/a: a new boot makes a new one | Node |
| **TPM-held mTLS server key** (proposed, ADR-0002 D21 point 3) | in the TPM | in the TPM | no (`fixedTPM`) | the KMS server's TLS identity, certified only after attestation | with each certificate renewal or on suspicion | certificate expiry (short-lived) and revocation | re-create and re-certify | Node |

## Membership and authority (Phases 8, 9, 14)

| Secret | Generated | Stored | Exportable | Authorized use | Rotation | Revocation | Recovery | Custody |
|---|---|---|---|---|---|---|---|---|
| **Membership root key** (Ed25519, proposed) | offline, in a ceremony-grade session | offline; its backup wrapped under the ceremony roots (D19) | only as that wrapped backup | every *permissive* transition: enroll, replace, change identities, restore trust | rare, by a signed hand-over manifest | a hand-over manifest from a new root, distributed out of band | from the wrapped backup with k shares | Owner (offline) |
| **Revocation authority key** (Ed25519, proposed) | on a separate host, or as an HSM key | that host or HSM | no if HSM-held; otherwise only by its host's administrator | *restrictive* transitions (QUARANTINED, RETIRED, REVOKED_STOLEN) and freshness heartbeats; cannot enroll or activate | yearly, or on suspicion, by a root-signed manifest | a root-signed manifest naming its successor | a new key, named by the root | Owner |
| **Highest accepted epoch and heartbeat sequence** (state, proposed) | by each node as it accepts manifests and heartbeats | TPM NV (counter / extend index), outside restorable disk state | n/a: not secret, but integrity-critical | refusing rollback and replayed heartbeats | n/a: monotonic | n/a: monotonic state is not revoked | node replacement resets it, through re-enrollment | Node |
| **Fencing authority key** (Ed25519, existing, FENCING.md) | by `regalia-fence` | on its independently administered host | only by that host's administrator | activation leases, never overlapping across sites | per FENCING.md | per FENCING.md | per FENCING.md | Fencing authority |
| **Commissioning evidence key** (ECDSA P-256, existing) | offline | offline | by its custodian only | signing each node's commissioning evidence; trusted by recorded fingerprint | on suspicion, with a new recorded fingerprint | replace the recorded fingerprint | a new key and fingerprint | Owner |

## Hardware credentials (existing; Phases 2–4, 12, 13 may change the user-PIN rows)

| Secret | Generated | Stored | Exportable | Authorized use | Rotation | Revocation | Recovery | Custody |
|---|---|---|---|---|---|---|---|---|
| **HSM user PIN** | at the ceremony (generated, or chosen and checked) | PIN card (Owner's safe); TPM-sealed systemd credential per host; MAC-authenticated escrow to breakglass | by the Owner (card); not from a host (TPM-sealed) | unattended HSM login (ADR-0002 D4: no runtime PKA unless #63 changes it) | after an unexplained card opening, or on suspicion: change on the card, re-seal, new escrow | change it (the old value stops working) | escrow (newest verified), else the tier-0 payload, through k shares | Owner |
| **HSM SO-PIN** | at the ceremony | tier-0 payload only | only through k shares | HSM administration at the ceremony | at a re-initialisation | n/a: changed only by re-initialising | the payload, through k shares | Shareholders |
| **YubiKey PIV PIN** | at the ceremony | as the HSM user PIN (TPM-sealed on hosts with a TPM) | as the HSM user PIN | unattended YubiKey use on TPM profiles; profiles C/D cannot hold it unattended (threat model) | as the HSM user PIN | change it | as the HSM user PIN | Owner |
| **YubiKey PUK and management key** | at the ceremony | tier-0 payload only | only through k shares | unblock and administration | at a re-provisioning | n/a: changed only by re-provisioning | the payload, through k shares | Shareholders |
| **DKEK and its k-of-n shares** | at the ceremony | shares in the sealed cases | only by assembling k shares | restoring HSM keys | at a new ceremony (D19 avoids it) | n/a: a DKEK is replaced, not revoked | k shares | Shareholders |
| **KMS service private keys** | in the HSM | in the HSM; backups DKEK-wrapped (D19) | no (never-extractable; #62); only as DKEK-wrapped blobs | KMS operations | per key policy | KMS key revocation (policy) | from the wrapped backup with the DKEK | Node (HSM) |
| **Breakglass key, escrow MAC key, PIN escrow files** | at the ceremony / at each escrow | shares; payload; the repository (ciphertext + MAC) | only through k shares (the escrow MAC key is also on the PIN card) | SOPS recovery; authenticating escrows | breakglass: by the staged swap; MAC key: payload re-issue | as for rotation | k shares | Shareholders / Owner |

## Service trust (Phase 14)

**Service TLS certificates**: short-lived, issued to the TPM-held mTLS key above after attestation;
expiry is a control in itself. **Peer runtime leases**: proposed in #74; issued by an independent
authority, never self-issued by bootstrap peers (ADR-0002 D23).

## Open items this inventory leaves to the phases

- The heartbeat expiry and the authenticated-time source (#69).
- The exact PCR set for the local TPM contribution and the WG-BOOT key (#65).
- Per-node (proposed) or per-cluster recovery keyslot (one envelope, larger blast radius).
- A non-TPM PIN mechanism for profiles C/D, if they are ever needed unattended (needs its own decision).
