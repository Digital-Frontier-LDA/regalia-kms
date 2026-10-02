# Updating the kernel on the three KMS hosts

The whole procedure for a Debian kernel (or boot image) update on the three-site KMS, start to finish,
with what each step needs and **whether it can be run today**. It cannot, end to end: the decisions and
the checks exist, are tested on software TPMs and have an operator command; signing with the root key,
and several pieces of the boot path, do not. Each step says which. The gaps are tracked in #156.

Read this before the first update is attempted on real hosts, and update it when a gap closes.

## Why a kernel update is not `apt upgrade` here

A KMS host comes up unattended only because its peers help it: a peer unlocks a node only if the node's
TPM quote matches a boot image the peer currently accepts. Which images are accepted is fixed by the
**root-signed membership manifest** (through the measurement document it commits to;
`deploy/baremetal/measurements.py`). So:

- a host that boots a kernel nobody approved **does not come back**;
- approving a kernel is a decision signed by the **offline root key**, and so is retiring the old one;
- the three hosts must not be down together, or nobody is left to unlock anybody.

## What it costs: two root-key signatures per update

| Manifest | Says | Signed by |
|---|---|---|
| N+1 "approve" | the current image **and** the new one are accepted | root key |
| N+2 "retire" | only the new one is accepted | root key |

The revocation key cannot sign either: it may only take trust away from a node, never change which
images are accepted. That is deliberate. An approved image is one the peers will unlock, so whoever can
approve an image can get a disk unlocked.

Both manifests can be signed **in one root-key session**, and the second kept back until the rollout is
healthy. If a revocation is published in between, the second no longer chains to the current manifest and
must be signed again.

**Decision for the owner (open):** routine Debian security updates each need a root-key session under
this design. The alternatives, none built:

1. *Keep it root-only* (today). One session per update, two signatures. Simple; the root key is used
   more often than for membership changes alone.
2. *A separate image-approval key*, named by the root in the manifest, allowed to change the accepted
   images and nothing else. Fewer root-key sessions, but that key can get a disk unlocked for an image
   of its choosing, so it needs custody close to the root's.
3. *Update less often*: batch kernel updates, and use the emergency path (below) when a fix cannot wait.

Until this is decided, plan for option 1.

## Who and what is needed

| Role | Needs |
|---|---|
| Build operator | the build host, the PCR-signing key (signs the image's expected PCR 11), each host's PCR survey |
| Root-key holder | the offline root key, in a ceremony-grade session; the two documents to sign, checked |
| Host operator | root on each KMS host, one at a time; console access if a host does not come back |
| Recovery | each host's disk recovery key card and the PIN card, in case a host must be opened by hand |

## The procedure

Status column: **exists** = a tested function or tool on `main`; **manual** = can be done by hand today
with the named tools; **NOT BUILT** = no way to do it yet.

### 0. Before starting

| # | Step | Status |
|---|---|---|
| 0.1 | All three hosts are ACTIVE, serving, and hold runtime leases from both peers. Do not start an update with a host down: take it out first with a manifest that quarantines it (the revocation key can sign that) | lease and heartbeat logic **exists** (`lease.py`, `heartbeat.py`); a status command for the operator is **NOT BUILT** |
| 0.2 | `host_probe.py` passes on each host | **exists**; it currently fails by design on every host (#135), which blocks production, not a rehearsal |
| 0.3 | Each host's recovery key card and the PIN card are at hand | **manual** (PIN-CUSTODY.md) |

### 1. Build the new image and predict what it will measure

| # | Step | Status |
|---|---|---|
| 1.1 | Build the new kernel as a Unified Kernel Image (UKI): `python3 -m deploy.baremetal.uki build …` writes the unsigned image and its **build record** (the SHA-256 of every input, every measured section and the image, and the PCR 11 it will measure in each phase). The same inputs give the same bytes: build it twice, on two machines, and compare the records | the tool **exists** (`deploy/baremetal/uki.py`; in CI with Debian 13's own tools, `e2e/uki-build.sh`). **NOT BUILT**: the inputs. The initrd with the unlock client is #66 and must hold nothing per host; pinning the kernel, microcode and stub packages is not done |
| 1.2 | Predict its PCR 11 **in the two phases a host is judged in**: the build record's `pcr11.initrd` (what the host measures when it asks for its disk) and `pcr11.system` (when it asks for a lease). The tool computes them from the built image and refuses to write a record if this machine's `systemd-measure` disagrees | **exists**; a software TPM that measures the image's sections reaches both values (`e2e/uki-build.sh`). Not shown by a boot |
| 1.3 | Sign, on the offline signing machine: `python3 -m deploy.baremetal.uki sign …`. It builds the image again from the same inputs (a third build, which must give the record's hash), signs PCR 11 with **two keys, one per phase** (the initrd-phase key for the local unlock share, the system-phase key for the HSM PIN, so neither secret opens in the other's phase), and signs the file for Secure Boot with a third. The keys are in a PKCS#11 token (`--key-source engine:pkcs11`); no option takes a PIN | the command **exists**, shown with test keys in a software token. **NOT BUILT**: the three keys, their ceremony and their cards (design on #57: generated on the ceremony machine, backed up under the break-glass key, imported into two YubiKeys); nothing has run with a hardware token |
| 1.3a | Before installing an image on a host: `python3 -m deploy.baremetal.uki verify --image … --record …` (the image is the record's, both PCR signatures verify, the Secure Boot signature verifies) | **exists** |
| 1.4 | For each host, write its new accepted set: its TPM firmware version, its PCR values, and the new PCR 11 **per phase** (`"phases": {"initrd": {"11": …}, "system": {"11": …}}`, the two values of step 1.2). The other PCRs come from that host's own survey (`pcr_survey.py snapshot`, `classify`). `python3 -m deploy.baremetal.uki set --record … --label … --tpm-firmware-version … --pcrs HOST.json` prints the set | the set **exists** (`uki set`, `attest.py`, `measurements.py`); survey **exists**; assembling the whole document is **NOT BUILT** (hand-written JSON today) |
| 1.5 | Write the CURRENT + NEXT measurement document: for every host, its current set, then the new one **listed last** | format and checks **exist** (`measurements.validate`); no authoring tool |

### 2. Approve: the root signs "both are accepted"

| # | Step | Status |
|---|---|---|
| 2.1 | Check the step: `python3 -m deploy.baremetal.rollout transition --old CURRENT.json --new BOTH.json` must answer `approve`. It refuses a renamed set, a changed label, a dropped host, two steps in one document | **exists** |
| 2.2 | **Compare the document with each host's PCR survey by eye.** No check can tell an unapproved image entered under an approved name | **manual**, and it is the control |
| 2.2a | **Review what the image's initrd does to open the root disk**: its own `etc/crypttab`, its `etc/cmdline.d`, and the unlock client's units and socket. The initrd must take the key from the unlock client's socket and from nowhere else. This is checked on the image, before it is approved, because it cannot be checked afterwards: once a host has booted, nothing on it shows what the initrd held (measured, #135). `host_probe.py` reads the root's `/etc/crypttab` and the kernel command line only | **NOT BUILT**: needs the UKI (#57), whose PCR 11 then covers the initrd; no command lists an image's unlock configuration yet |
| 2.3 | Compute the document's version from the file in hand, at signing time: `python3 -m deploy.baremetal.rollout version --measurements BOTH.json` | **exists** |
| 2.4 | Write manifest N+1, unsigned: `python3 -m deploy.baremetal.rollout propose --membership CHAIN.json --root-key HEX --old CURRENT.json --new BOTH.json`. It prints the current manifest with `epoch + 1`, `prev_digest`, and `policy_version` set to that version, and signs nothing | writing the proposal **exists**; signing it is step 2.6 |
| 2.5 | In the same session, write and sign manifest N+2 for the NEXT-only document (step 5), and keep it back | as 2.4 |
| 2.6 | Sign with the offline root key | **NOT BUILT**: the root key is "proposed" (THREE-SITE-SECRETS.md); no ceremony generates it and no tool signs with it |
| 2.7 | Bring manifest N+1 and the document to all three hosts; each commits the manifest (its TPM epoch counter rises) and rebuilds its attestation policy from the document | commit **exists** (`membership.Store`), exchange between nodes **exists** (`convergence.py`); installing the document and reloading the policy on a running host is **NOT BUILT** |
| 2.8 | Check that all three hold epoch N+1: on each host, `python3 -m deploy.baremetal.rollout epoch --membership CHAIN.json --root-key HEX --tpm-index 0x…` (the TPM epoch counter is read, never advanced; a chain that is not the one the TPM recorded is refused), and compare the three answers | **exists**, one host at a time; nothing collects the three |

### 3. Update the hosts, one at a time, in the order of their node IDs

For each host, in order:

| # | Step | Status |
|---|---|---|
| 3.1 | Install the new UKI beside the current one; the current one stays the fallback entry | **manual** (`kernel-install`, `bootctl`); not rehearsed on these hosts |
| 3.2 | Ask whether this host may reboot now: `python3 -m deploy.baremetal.rollout may-reboot …` (the manifest, the document, this node, the image it runs, its boot session, its verifier state, its leases). It refuses unless an update is approved for this host, the hosts before it are back on the new image, and both peers have vouched for this boot in the last five minutes | **exists** as a command; where the leases, the boot session and authenticated time come from on a running host is **NOT BUILT** (the lease service of #74 holds them) |
| 3.3 | Reboot into the new image | **manual** |
| 3.4 | The host is unlocked by a peer and the KMS serves again, with nobody present. The peer accepts the unlock request only from the image's initrd phase, and the lease request only once the host has booted | the peer's decision **exists** (`replacement.may_unlock`, `unlock.py`); the boot-time client that asks for it is **NOT BUILT** (#66, #67 in progress). Today the disk unlocks from the local TPM alone (#135) |
| 3.5 | **Wait until the host is back and serving before touching the next one.** `may_reboot` alone is not the interlock: for up to five minutes after a host falls back or goes down, the next one may still be told it can go | the limit is stated and tested (`rollout.py`, LIMITS) |
| 3.6 | If the new image does not boot: the boot loader falls back to the current image by itself, and the host is unlocked as before, because both are accepted | systemd-boot boot counting: **manual**, not rehearsed; the acceptance of both **exists** |
| 3.7 | If it boots but its peers refuse it, the prediction in step 1 was wrong: boot the current image, fix the document, and repeat step 2 with a new manifest | **manual** |

### 4. Check the rollout is complete

| # | Step | Status |
|---|---|---|
| 4.1 | Collect each host's attestation state file and ask `python3 -m deploy.baremetal.rollout retire-ready … --state a=A.json --state b=B.json --state c=C.json`. It needs every host's file and refuses unless every host was last seen **up** on the new image by every peer that has seen it (a host seen only in its initrd, where it asks for its disk, does not count) | **exists**; collecting the files is **manual** |
| 4.2 | Let the cluster run on the new image for the agreed time before retiring the old one. Until step 5 the old image is the fallback | **manual**; the time is not decided |

### 5. Retire: the root signs "only the new one"

| # | Step | Status |
|---|---|---|
| 5.1 | Check the step: `python3 -m deploy.baremetal.rollout transition --old BOTH.json --new NEXT.json` must answer `retire`. `abandon` means the document drops the NEW image instead: the wrong half. `python3 -m deploy.baremetal.rollout propose …` then prints manifest N+2, unsigned | **exists** |
| 5.2 | Release manifest N+2 (signed in step 2.5, or sign it now); every host commits it | as 2.4 to 2.7 |
| 5.3 | From now on a host booted into the old image gets no unlock and no lease. A lease issued just before runs out within five minutes | **exists**; shown on three software TPMs (`e2e/rolling-policy-swtpm.sh`) |
| 5.4 | Remove the old UKI from each host | **manual** |

**After step 5 there is no automatic fallback.** If the new image then breaks, the root signs again:
either the next update, or a document that re-approves the old image.

## If something goes wrong

| Situation | What to do | Status |
|---|---|---|
| A host does not come back, before step 5 | boot the current image from the boot menu; it is still accepted | **manual** |
| A host does not come back and no peer will unlock it | open its disk with its recovery key at the console (PIN-CUSTODY.md, "The disk recovery key") | **exists** (`recovery-key.sh`) |
| A host is down and must not hold the others up | a manifest that sets it QUARANTINED; the revocation key may sign it. The others then update without it | rule **exists**; signing tool **NOT BUILT** |
| The CURRENT image is found compromised | the emergency path: one manifest whose document drops it on every host at once (`python3 -m deploy.baremetal.rollout propose … --emergency`). Every host still running it is locked out until it boots the new image. Root key | writing the proposal **exists**; signing it does not |
| All three hosts are down | total-outage recovery: PIN-CUSTODY.md and the recovery keys | **manual** |

## What has been shown, and where

- **On three software TPMs, in CI** (`e2e/rolling-policy-swtpm.sh`): an unapproved image is refused; both
  images are accepted during the rollout; only one node is told it may reboot at a time; a failed image
  falls back and is still unlocked; retirement is refused until every node is on the new image; after
  it, the old image gets no unlock and no lease; a peer's membership restored from before the
  retirement refuses to load.
- **On one software TPM** (`e2e/pcr-signed-policy-swtpm.sh`): a PIN sealed once opens under the new
  image with no reseal, and does not open without the host key.
- **On no physical machine.** Nothing here has run on a DL360, a physical TPM, a real UKI or a real
  reboot. The hardware checklist is on #65.

## What is missing before this can be run (#156)

1. The root key: its generation ceremony, its custody, and a tool that writes and signs a manifest.
2. ~~One operator command for the checks~~: built, `python3 -m deploy.baremetal.rollout` (`version`, `transition`, `epoch`,
   `propose`, `may-reboot`, `retire-ready`, `check-replacement`). It reads and proposes; it signs nothing.
   Still missing around it: where a running host's leases, boot session and authenticated time come
   from for `may-reboot`, and collecting the three hosts' answers in one place.
3. Installing a measurement document on a running host and reloading its attestation policy.
4. For the image (#57): the build, its record, the signing command and the verification exist
   (`deploy/baremetal/uki.py`). Still missing: the initrd without per-host files (#66); pinned kernel,
   microcode and stub packages; the three signing keys, their ceremony and cards; Secure Boot enrolment
   of our certificate on each host; a first boot of such an image; and a stated way to list what an
   image's initrd uses to open the root disk (step 2.2a).
5. The boot-time unlock client, so that a peer is actually needed to open the disk (#66, #67, #135).
6. A rehearsal on the three DL360s (#65), including the boot loader's automatic fallback.
7. The owner's decision on who approves an image (above).
