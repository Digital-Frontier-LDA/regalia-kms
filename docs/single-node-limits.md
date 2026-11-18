# Regalia KMS: the limits of a single-node deployment

Version: regalia.single-node-limits/v2

This is the text an operator acknowledges at a single-node genesis (regalia-kms-dx7). The genesis
tool prints it and records the SHA-256 of this file's bytes in the root-signed membership manifest,
as topology.single_node_limits_sha256. One changed character changes that digest, so this file is
never edited in place: a change is a new version, with a new version line. It is plain ASCII text.

The table states the single-node design (docs/design/single-node.md). It does not say what is built:
LIMITATIONS.md, section "Single-node deployments", does. The "3 nodes" column is the three-node
design (ADR-0002 D32); LIMITATIONS.md says what of it is built.

The node count is chosen at genesis and signed into the manifest. It is never inferred from how many
nodes answer: a node alone in a three-node manifest is a three-node cluster in an outage. A one-node
deployment becomes a three-node one only through a new genesis.

Words used:
- supported: the guarantee holds as it does on three nodes;
- degraded: it works, with the consequence named;
- not supported: the guarantee does not exist on one node.

| Feature or guarantee | 1 node | 3 nodes | Consequence with 1 node |
|---|---|---|---|
| Signing and decryption (stateless operations) | supported | supported | One HSM per node holds the keys either way |
| Stateful operations (approval spend-once, Cosmos sequence, key state) | degraded | supported | Committed to a single-member etcd on one disk, with no replica: a lost disk loses the latest spends. A restore raises the state epoch, and the audit collector detects a re-spend; it does not prevent one. Refused while no audit collector is configured |
| Activation (who may serve) | degraded | supported | The node activates itself (1 of 1): no second signer can refuse a root-compromised node |
| Activation after a crash during a grant | degraded | supported | A crash between the activation counter's raise and the grant record's write stops every activation, the same site's included, until the owner restores the floor (regalia-kms-dx7.24). 3 nodes: a co-signer names the last grant |
| Runtime lease (a revoked or cut-off node stops within 30 s) | degraded | supported | Self-issued: it still binds the measured boot and the current state, but nobody outside the node can withhold it |
| Survives the loss of a node | not supported | supported | Any node failure, reboot or maintenance is a full outage of the KMS |
| Survives a site, provider or network-path outage | not supported | supported | One site is a single failure domain |
| Unattended reboot | not supported | supported | Every boot needs the owner's card, or the disk recovery key. A power cut means downtime until the owner acts |
| Theft of a powered-off node | supported | supported | The disk opens only with the owner's contribution (3 nodes: a peer's), so a stolen box does not unlock |
| Theft of a running node (hot theft) | degraded | supported | No peer stops leasing it: it serves until it loses power or the owner's revocation is imported on that node, so a revocation does not reach a stolen node that is no longer reachable |
| Root compromise of the node | not supported | degraded | The node is its only signer (3 nodes: no lease without two co-signers) |
| Retiring an old signed boot image | supported | supported | The owner's unlock tool refuses an image the manifest no longer lists (3 nodes: the peers) |
| Revocation | degraded | supported | The owner alone revokes. Revoking or quarantining the only node stops the KMS |
| Heartbeats | degraded | supported | Self-signed: they prove only the node's own freshness, with no peer bound to stop helping a revoked node |
| Rolling measured-boot update | degraded | supported | Each reboot is a planned outage, with the owner present to judge the new image |
| Site advance (PCR 12) | degraded | supported | The same: a planned outage, and the owner judges the new site configuration |
| Rollback protection of the membership (TPM anchor) | supported | supported | The TPM counter and record work on one node |
| Re-anchor after anchor damage | degraded | supported | From the owner's copy of the chain, cross-checked against the audit collector, instead of two independent nodes. A compromised owner laptop can roll the node back, but not below what the collector saw. A compromised laptop and a compromised collector together are not bounded |
| Recovery after a total outage | degraded | supported | One owner-attended boot. There is no rest of the cluster to restore from, and anchor damage is the re-anchor row above |
| Lone-survivor mode, fencing, take-over, rejoin | not supported | supported | Nothing to survive or fence: each is refused, naming the profile |
| Cross-node detection (fleet alerts, a withheld chain) | not supported | supported | No fleet to compare with. Replaced by comparison with the audit collector |
| Audit trail | supported | supported | The external audit collector is mandatory: it is the only witness besides the owner |
| Operation approvals (m-of-n card holders) | supported | supported | Not bound to nodes. An approval names the one node, with no failover |
| Key backup and restore (DKEK, Shamir) | supported | supported | Unchanged. With no peer, a restore onto a replacement node is the recovery path |
| Latency of stateful operations | supported | supported | No majority round trip: faster than 3 nodes |

## The owner's decisions (2026-11-18)

- Q1. Who gives the second half of the disk key at boot? The owner's card, at every boot: reboots
  are attended. A TPM-only unlock is not offered, and an external unlock witness is not built.
- Q2. Heartbeats: self-signed by the node (threshold 1 of the node). The owner does not co-sign them.
- Q3. Changing size in place (1 to 3, 3 to 1): not in this version; a new genesis. 1 to 3 in place
  may come later as its own root-signed step; 3 to 1 in place never.
- Q4. The external audit collector is mandatory: stateful operations are refused without one.
- Q5. After anchor damage: re-anchor from the owner's chain, cross-checked against the collector,
  not a new genesis. A collector that saw a higher epoch, or does not answer, is a refusal.
- Q6. The owner's two cards are kept, unchanged: they hold the owner's unlock contribution, and one
  lost card must not strand the node.
- Q7. Hot theft (a running stolen node serves until it loses power): accepted, and documented here.

With no peer to restore from, the recovery path is the backup: a timed restore of the DKEK backup
and the owner cards onto a fresh node is part of the single-node production gate, and its measured
time is the single-node recovery time objective.
