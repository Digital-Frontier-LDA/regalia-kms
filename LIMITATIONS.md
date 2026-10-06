# Current limitations

What Regalia KMS does **not** do yet, what has not been measured, and the risks accepted on purpose.
This file says what is true **today** on `main`. An entry is added as soon as a limitation is found,
and is removed only by the PR that closes it, which cites its number. The per-component docs carry
the detail. This is the index.

Status words: **not built** (no code yet), **not measured** (code exists, but nothing has shown it on
the real hardware or in the real setting), **accepted** (a risk taken on purpose, with its reason).

## Overall

- **Nothing has run in a ceremony or on the production hardware.** No key ceremony has been held, and
  no Shamir share set exists yet. The three production hosts (HPE DL360 Gen9 with TPM 2.0) have not run
  this software (#253). Whether their TPMs carry an EK certificate is not known (#190). Every
  three-node scenario so far runs on a software TPM (swtpm) in CI.
- **Hardware qualification is open**: Nitrokey HSM 2 for production; the Pico HSM is supported but
  not qualified ([`CONFIGURATIONS.md`](CONFIGURATIONS.md)).

## Membership, heartbeats and recovery (deploy/baremetal)

- **The root's permissive epochs reach the cluster by hand** (#386 retired the authority host).
  An image approval, or a replacement, signed by the root on the offline laptop, is given to ONE
  running node with `deliver` (root, at its console), and the others pull it. Nothing carries them
  automatically. In the three-node scenarios, an owner-signed epoch is committed by the harness into
  the seed's store with its services stopped (`advance(signer="owner")`). On a host, the owner's
  revocation goes through `revoke.py import`, which the scenarios exercise separately
  (`revoke_by_owner`).
- **The lone survivor (ADR-0002 D32 item 6): the owner's authorization and directive only** (#432 item (e);
  `deploy/baremetal/survivor.py`, `owner.py sign-survivor` and `sign-directive`). Built:
  - one owner authorization, held only at the quarantine epoch (any new epoch ends it), with every other server stopped
    and the owner's typed fencing attestation, for at most 7 days;
  - the owner's directive, which only disables a key: never enables one and never destroys one (d9: one stolen owner
    token must not destroy keys irreversibly with no approver able to intervene);
  - the survivor's append-only store of the signed directives it applied. Each is verified before it is written, and
    a corrupt file refuses every key.
  - **the owner's one-server decision (2026-10-05): scope `full`.** Stateful operations continue on the lone survivor from
    the owner's attestation plus 900 s plus 60 s (every request the fenced far side could have spent has expired), plus
    600 s more when the fence is only typed rather than an iLO power readback.
  Not built yet:
  - the full scope's machinery:
    - the fence on real iLOs. `deploy/baremetal/fence.py` (`owner.py fence`) exists. It runs from the owner's machine
      on the management network, never a node, and does, in order:
      1. TLS pinned to each iLO's certificate before any credential is sent;
      2. refuses an account with more than login and power/reset;
      3. matches the box's serial and UUID to the commissioning inventory;
      4. ForceOff;
      5. reads Off twice, at least 10 s apart.

      It records the power-restore policy, and `sign-survivor` checks the evidence against the same inventory. It is
      tested against a local Redfish stand-in over real TLS, never an iLO 4. Not yet:
      - the commissioning step that records each iLO's certificate, serial and UUID in the inventory;
      - the fence-only iLO accounts. Whether iLO 4 lets such an account read its own Accounts record, which the
        fence's privilege check reads, is unmeasured. If it does not, every correct account is refused and the fence is
        the typed fallback;
      - the credentials encrypted to the owner cards' decryption keys (the tool reads them decrypted, from a pipe);
      - whether a management VPN reaches all three sites' iLOs is the owner's to say. Without it, the fence is the owner
        at each iLO in turn, or the typed fallback;
      - anyone with an iLO's power right, or a power-restore policy of "always on" after a power cut, can turn a fenced
        server back on. It then holds an older epoch and its peers halt it (G4, not built yet). The evidence records
        the policy; nothing enforces it;
    - the take-over on a real host. `deploy/baremetal/takeover.py` exists: a graceful etcd stop, the revision
      check, force-new-cluster through a /run drop-in, then the state-epoch entry (`opstate.verify_state_epoch`) as
      its first write, and the drop-in read back gone. It is tested on a scripted host and, in CI, against a real
      etcd 3.6.15 with systemctl played by the test. Not yet:
      - regalia-etcd.service (#484), so it has never run under systemd;
      - the take-over has never signed with a real TPM signing key;
      - nothing reads the entry in Go (the cache's verify, regalia-kms-ed's), so `applied.json`'s `state_epoch` stays 0;
      - the daemon's rule that a stateful operation in recovery needs the store at the authorization's own epoch;
      - an arrival-time freshness check on the entry. A replaced signing key can still sign an entry dated before the
        replacement, inside the owner's authorization window;
    - the rejoin on a real host. `deploy/baremetal/rejoin.py` exists. A returning node comes back one at a time as an
      etcd learner (admit, join, promote, finish), and its old data directory is kept, renamed, with its revision and
      db SHA-256. It is tested on a scripted host and, in CI, against a real etcd 3.6.15. That test plays systemctl,
      and localhost URLs stand in for the mesh URLs. Not yet:
      - the divergent tail is kept but nothing reads it: the reconciliation of its spends (RECOVERY-RECONCILIATION.md)
        and its shipment to the external audit collector are not built;
      - regalia-etcd.service (#484): never run under systemd;
      - etcd promotes a learner at 90% of the leader's index, so the survivor's commits can wait briefly after a
        promotion while the newcomer catches up;
      - from the first returner's promotion until the second's, the cluster is two voting members. Losing either stops
        every commit until the other returner is promoted, or another take-over. Admitting both as learners before
        either promotion (etcd's --max-learners 2) would shorten that window; it is not done;
    - the survivor trail (G6). takeover.py and rejoin.py write each step to /var/log/regalia/survivor.jsonl, shipped by
      regalia-audit-ship@survivor. Each step writes a REQUEST before it acts, then ALLOW (the cluster, the revisions, the
      state epoch, the divergent tail's digest) or DENY. Not yet:
      - the collector does not compare a take-over's state epoch with the leases the nodes ask for afterwards;
      - the fence runs off the nodes and writes no trail. Its evidence lives only in the signed authorization;
      - a step that finished but whose ALLOW could not be written (a full disk) says "DONE" and exits 3. It is never
        to be re-run (a take-over's force would run twice), and the operator writes the line by hand. Nothing writes
        it later by itself;
    - the daemon's halts (a peer heard below the quarantine epoch);
    - approvals naming their spending node (1e).
    Until they land, `full` is a recorded intent the daemon does not act on;
  - the survivor's admission mode: recovery only with no unexpired normal lease, left at the first normal lease;
  - the daemon serving stateless operations only in that mode, and refusing keys under a directive (ed);
  - installing the authorization on the node;
  - the majority committing a directive as a key-state change on its return;
  - the cap coming from the manifest's `recovery_authorization_max_s` (#459, stacked on #438; it is a constant here).
  **Accepted** (D28.6 amendment 5, D32.6):
  - A false fencing attestation holds for the authorization's life. While it holds, the survivor uses key state that
    may be up to that old, except what a directive disabled.
  - The directives live on the survivor alone until the majority returns. If its disk is lost, they are lost there, so
    the owner keeps every directive file the tool wrote and gives them again to a rebuilt survivor and to the majority.
- **etcd's configuration from the manifest: the renderer only** (#432, ADR-0002 D32; `deploy/baremetal/etcdconf.py`).
  Built:
  - who is a member (the manifest's ACTIVE, MAINTENANCE and DRAINING nodes);
  - each member's certificate bound once by the signing key the manifest pins for it (no CA). The latest binding that
    verifies wins, and a rendered one is never gone back on;
  - the timings from the measured p99 round trip (a commissioning failure above 500 ms);
  - the configuration and a check of each of its settings:
    - clients over the unix socket only, with no client TLS, which etcd ignores on a socket (d9, measured). The client
      boundary is the socket's group;
    - peers on the mesh over TLS 1.3, with certificates both ways, the key from the unit's credentials, and trust that is
      the rendered bundle only;
    - periodic compaction (1 h) and an explicit 2 GiB quota;
    - the corruption checks (feature gates).
  Not built yet:
  - enrolment making the peer and server keys (into `systemd-creds`), the self-signed certificates and the binding;
  - the bindings travelling by sync;
  - defragmentation and the alerts on the backend's size and the corruption checks;
  - a run of the rendered configuration under the image's etcd. The feature-gate names are v3.6's and are to be
    confirmed there (d9's `e2e/etcd-unit-sandbox.sh`);
  - writing the files, and the reconciler that adds or removes a running member after a root-signed epoch;
  - where the measured round trip comes from (an input today).
  **Accepted:** a member re-enrolled on the same TPM keeps its signing key, so an older binding still verifies. Renderers
  that have seen the newer one refuse to go back, but a renderer starting fresh takes the newest binding it is shown.
- **The shared operational state, `opstate/v1`: format only** (#432, ADR-0002 D32; `deploy/baremetal/opstate.py`,
  `tests/vectors/opstate-v1.json`). Built:
  - the entries (spend, sequence, quota, key-state), the etcd key each lives under, their verification, each kind's
    transition rule, and one Reserve's transaction rule, as a library with a vector for the Go side.
  Not built yet:
  - nothing writes or reads etcd: the daemon's transactions and watch cache are regalia-kms-ed's;
  - nothing yet writes the session entries (`sessions/<node>/<boot_id>/<key>`, signed by the node's signing key at each
    daemon start), nor the spend's approvals into the signer's audit line, which the collector re-verifies against
    `approvals_sha256` (`check_approvals`); the daemon calls `may_sign` at sign (ed);
  - the D25 approver sets are the caller's, not yet read from the policy;
  - garbage collection by hour-bucketed etcd leases.
  - the etcd role that grants the daemons put, never delete, under `/regalia/v1/` (ed's daemon). Until it exists, a
    client of the etcd socket could delete a key. A reader that has seen a key-state refuses its absence, but a reader
    starting fresh cannot tell a deleted key from a new one.
  **Accepted:**
  - etcd isn't Byzantine-tolerant. A member with root can withhold entries or serve old ones. It cannot forge an
    entry, because every entry carries its own signatures. A whole-cluster rollback is caught by the revision in the
    signed heartbeats (planned, #432).
  - A transaction that loses a race is retried at most three times, one round trip each, then refused.
  - A request stays spendable at most 900 s after it is spent (`MAX_REQUEST_LIFE_S`, enforced on every spend). A lone
    survivor's full scope waits that long, plus 60 s, from the owner's attestation that the others are fenced, so
    nothing the far side spent before it was fenced can be spent again (regalia-kms-1e).
  - A spend's key is collected by an etcd lease of `(expires_at - at) + 60 s`, on the etcd leader's clock. A leader whose
    clock runs more than 60 s ahead of the signer's could collect it before the request expires, and the nonce could
    then be spent again. Authenticated time (NTS) on every server bounds that, and `may_sign` refuses a request that
    expires within 60 s.
  - A node's session key vouches only until the node's signing key is replaced (its window ends at the replacing
    manifest's issued_at). A node still running the old key between then and its adoption of the new epoch writes
    nothing that verifies. That fails closed.
  - An entry's `at` is judged on arrival (`fresh`, within 60 s of the reader's clock). A reader that only lists
    entries later can't tell a backdated entry inside a session's window; the collector judges `at` against when it
    saw the entry's create revision.
  - Session entries are never deleted, so every old spend stays verifiable. They are about 300 bytes each, one per
    daemon start.
  - Quota days are UTC days.
- **Activation by quorum: partly built** (#432). D28.6 as first written (2 of {a, b, c, owner}) is
  refined by #432; see the ADR. Built (step 1, `deploy/baremetal/activation.py`): the activation lease,
  its verification under the current manifest's `activation_signers`, each node's grant record and
  signer, and the co-signer's and proposer's checks, as a library with unit tests. **Nothing issues or
  enforces an activation in the running system yet:** no `nv_activation` index is defined at
  enrolment, sync has no activation ops, there is no `owner.py sign-activation`, and the Go Gate still
  takes `regalia-fence`'s single key. By the rule, a new cluster's first activation waits about 11 minutes
  (`RECOVERY_WAIT_S`): every node starts with no grant record, so each is busy for that long after it
  starts. Expected at first bring-up, not a fault. **The runtime lease (`lease.py`) is the one serving lease under D32: 30 s, renewed at a third (every 10 s)**, issued by **one** peer over the subject's re-attested TPM. A node cut off from both peers stops within 30 s, less the 5 s admission margin. Each renewal is a re-attestation and a quote on two TPMs (no NV write), so a node's TPM does one or two quotes every 10 s. While renewals fail they back off 2 s doubling to 10 s, so a healed node is serving again within about 10 s. Each connection of a renewal may take `admission.RENEW_TIMEOUT` (3 s), so a round with both peers silent ends within 12 s, before the margin (3e's #473 finding: about 110 s at sync's 10 s deadline). Serving stops at `serve_until` on the daemon's own clock whatever the lease service is doing. A lapse watcher beside the rounds writes "not serving" to the file and the trail within half a second of the bound, even while a round waits on a peer (#486). A peer that needs more than 3 s per ask (a slow TPM, a congested link) is treated as silent. A peer whose authenticated time is more than 5 s fast issues leases the others refuse (`FUTURE_SKEW`). It does not yet carry `state_revision` or the session key (95's v2, #432). Runtime leases are issued by **one** active peer, and `regalia-fence` is still
  the authority for which site signs ([`FENCING.md`](FENCING.md)).
  **Accepted in the design:**
  - The normal path is 2 of the 3 nodes, which always overlap. ({a, b} and {c, owner} share no signer.)
  - Activation by the owner plus one node is a recovery step behind three conditions, and every renewal
    on that path repeats all three:
    1. a quarantine epoch for the other nodes;
    2. a typed hard-fencing attestation, which holds until the fenced nodes hold that epoch;
    3. a wait counted from the latest lease expiry any record shows, plus the skew margin.
  - The owner alone never activates.
  - Two active sites remain possible only if a fencing attestation is false when it is made, or if an
    operator rejoins a fenced node before it holds the quarantine epoch.
  - **Availability cost:** with one node dead and not yet quarantined, an unplanned reboot of a second
    node stops lease renewals until the owner quarantines the dead one, because of the boot rule. An
    alert after a set number of minutes unreachable prompts the owner.
- **Recovery with only one surviving peer: built (#387), not measured.** `recover apply --one-source`
  and `reanchor --one-source` take one peer's chain and a short-lived statement that the owner signs off
  the nodes (`owner.py sign-recovery`). They are unit-tested only: no three-node scenario runs the one-source path yet (#391 rehearsed
  the total-outage re-anchor; the one-source case follows this PR), and nothing has run with a real YubiKey or on
  a DL360 TPM. With **both** peers gone, recovery is a new
  root ceremony, by design.
- **Accepted:** a one-peer recovery cannot see a revocation that two nodes signed after the signing
  laptop's last record if the surviving peer withholds it and the audit collector holds no receipt
  for it (`no collector` typed). Only the operator's answer guards it. A stale collector export still
  verifies (#398). A node whose own tunnel is down cannot tell a dead peer from an unreachable one.
  ([`deploy/baremetal/MEMBERSHIP-RECOVERY.md`](deploy/baremetal/MEMBERSHIP-RECOVERY.md), "One other
  node and the owner".)
- **Under a v4 chain the anchor is written by policy only (#242 B3), with these limits.** An owner-written counter
  or slot is Unusable under a v4 tip. load, commit, restore and the ESP advance all judge it by the tip of the chain
  they hold, fetch or anchor, and refuse it before the disk or the ESP is written. The Go initrd reader
  (`membership.Anchored`) judges alike, by the tip of the chain it reads, held to the same vectors.
  - **A node whose anchor is owner-written stops advancing under v4 until it is re-anchored by policy.** Such an
    anchor is a lab node's, or one laid down before B2b. sync refuses the next chain, and the ESP advance reports
    `regalia_esp_advance_ok 0`. The repair is `reanchor` (MEMBERSHIP-RECOVERY.md), which needs two peer chains,
    or one and the owner's statement (`--one-source`, above).
  - **The v3 → v4 step is refused on such a node, with nothing moved.** This concerns lab nodes only: production
    starts at a v4 genesis, and every v4 enrolment defines its anchor by policy (#419), so no production node has an
    owner-written anchor. A lab fleet moving to v4 is re-anchored by policy node by node first; no tool checks the
    whole fleet's layout beforehand (not needed for production: regalia-kms-24 and 95, 2026-10-05), and each node's
    refusal names the fix.
  - Under a v1–v3 (lab) chain both layouts still read, by design: lab images write with the owner authorization.
  - Anyone holding the owner authorization can still undefine the indices. That is a denial (Unusable), which a
    re-anchor repairs; it cannot write them under v4.
- **TPM owner authorization: built (#242 step C), with these limits.**
  - On the TPM bus (#414, measured): the owner authorization itself is never sent. Owner calls use tpm2-tools'
    own HMAC sessions. Setting it uses a session salted to the enrolled EK (its Name checked) with parameter
    encryption. The proof is an owner createprimary. Residual: an owner call's own parameters (NV attributes and
    policies, record epochs and digests, none secret) cross in clear, because tpm2-tools' automatic sessions are
    unsalted. A bus probe on the DL360 sees those, not the value.
  - The value cannot be zeroed in Python memory. While an owner-authorized call runs, the value is readable through
    /proc by root (a memfd; `seal-hsm-pin.sh` uses a root-only file on /run).
  - `enrol commit` under v4 with a set owner authorization runs on a software TPM (#420, `InitOnSwtpm`), from
    `enrol ownerauth`'s salted set to epoch 1. Its regalia-sync steps run in-process there, not through `runuser`
    as that user (that needs root and the user, a CI e2e).
  - Under v4 the owner authorization never enters a process of regalia-sync (#419): `enrol commit` makes every
    owner-authorized definition itself, as root, and its regalia-sync steps commit by policy. With a lab chain
    (v1–v3, owner-written) the value is still handed to them (a memfd, refused while another process of that uid
    runs). Under v4 the node is fresh at its sync's first pull (10–60 s after enrolment), not at once: the heartbeat
    counter is defined one below the highest heartbeat the root parent verified.
  - `enrol init` takes no owner authorization (it runs before `enrol ownerauth`). `attest.py node-init` (the lab
    CLI) keeps an empty one.
  - Rotating a set owner authorization is not built.
  - **Break-glass custody is decided, not yet produced** (owner, 2026-10-05; 24 on rc#111). One binary SOPS file per
    node, `ownerauth-<node>.bg.sops`, replaces the ceremony's `.bg.age` envelope. It is encrypted to the post-quantum
    "ownerauth-recovery" identity in offline-keys' D28 key map, under the same SLIP-39 shares. That is
    regalia-ceremony#111's change; until it lands, the ceremony writes `.bg.age`. The record keeps `bg_sha256` as that
    file's digest, so `ownerauth.verify` is unchanged. The drill's check (`python3 -Es -m deploy.baremetal.ownerauth check`)
    is built. With sops 3.13.1, age 1.3.2 and the test vector it was run by hand without a TPM: the post-quantum
    recipient (an mlkem768x25519 stanza) decrypts byte for byte, and another node's value is refused. That hand run
    split the key with ssss as a stand-in for offline-keys' opening, which rc#111 is building.
- **The total-outage re-anchor is rehearsed on software TPMs only** (#391, `e2e/three-node-reanchor.py`). It covers one
  kind of damage, uses cryptsetup and a pty rather than a console, and doesn't run the operator's source checks.
  The one-peer and both-peers-destroyed cases aren't rehearsed (MEMBERSHIP-RECOVERY.md, "What the rehearsal does
  not show").
- **The ESP advance (#410, #66): what it does not cover.** `regalia-sync` no longer moves the TPM anchor;
  the root oneshot `regalia-esp-advance` writes the published chain to the ESP, then anchors it.
  - **Not measured** on a host: shown by unit tests, a real-systemd e2e on a plain `/efi` directory, the
    three-node fixture (an ESP directory per node) and QEMU boots 10-12, whose ESP the test writes.
  - Only the chain is written. A site change (the measured `regalia.site.cred`) still needs enrolment.
  - Until a run succeeds the node acts on a chain ahead of its anchor, and rollback protection stands at
    the anchor's epoch. `RegaliaMembershipAnchorBehind` and `RegaliaEspAdvanceFailing` warn after 15 min;
    an operator fixes the ESP and restarts the unit (deploy/baremetal/README.md §7). Nothing repairs it alone.
  - A compromised `regalia-sync` that stops publishing is not caught by that node's own alerts (the
    advance never runs, and sync's file can say anything). It is caught ACROSS the nodes:
    `RegaliaMembershipBehindFleet` (its held epoch) and `RegaliaAnchorBehindFleet` (its anchor, as root
    reads it) warn after 30 min below the highest epoch its peers hold (a node whose metrics flap away more often
    than that resets the `for:` and never fires; the `*MetricsMissing` rules see a file that stays away). **Accepted:** that needs the peers'
    metrics to be scraped together (one job per cluster) and at least one honest peer ahead; a node retired
    or revoked lags by design and must leave the scrape.
  - Its run is in the journal and its metrics, not in a hash-chained trail (#278).
  - An anchor read the TPM refuses says only "cannot read 8 bytes from NV index …": `HighWater._read8` drops
    `tpm2_nvread`'s error text, so an operator diagnosing it gets no TPM reason (#450; the text is pinned by
    `highwater-v1.json` in both languages, so its fix regenerates that vector).
  - Its anchor lock is its own (`/run/regalia-esp-advance/`), distinct from enrolment's. `reanchor` (#391) refuses
    while `regalia-esp-advance` (or its path unit, sync or admission) runs, by `systemctl is-active`, and holds the
    advance's lock for its whole run. On a machine with no `systemctl` it skips the unit check, and the three-node
    rehearsal can't show it (its units have other names): unit tests only. When the advance's RuntimeDirectory is not
    there, no lock is taken: a `regalia-esp-advance.service` an operator starts by hand during the re-anchor would run
    unserialized (the unit check refuses one that already runs). Enrolment takes neither: run it only with the node's
    units stopped.
  - `reanchor` writes the ESP before the anchor (#391), as the advance does, but does not try the initrd's render first
    as the advance does (`boot_renderable`): a chain this node could not boot under is written and anchored without
    that warning.
  - **Accepted:** enrolment (`enrol commit`) still anchors epoch 1 before it writes the ESP: its render
    verifies the chain against the anchor, so the order is not cheap to swap. A crash in between leaves no
    chain on the ESP. The next boot's render then fails and the console asks for the recovery key, as it
    does at every boot until `enrol paths` has enrolled the peers' paths. Not stranding, two tooled ways
    out: re-run `enrol commit`, which resumes from its journal (the anchor step is a no-op on a chain
    already held, and the rendered files are replaced); or let `regalia-esp-advance` run at boot, which
    writes the published chain to the ESP.
- **The ESP advance's trigger is edge-triggered.** `regalia-esp-advance.path` uses `PathChanged=`, and systemd folds
  a publication that lands during a run into that run, starting nothing afterwards. `esp_advance_settled` (#471)
  therefore re-reads the published chain after each run and runs again while it changed (at most 5 runs, then a
  refusal that the unit's `Restart=` retries). A publication that lands between a run's last read and its exit is the
  remaining window: the next publication, or the unit's next start, catches it up. `RegaliaMembershipAnchorBehind`
  warns if that window ever holds for 15 minutes.
- **One transient TPM error fails an anchor read.** `HighWater` reads the anchor's NV indices with one
  `tpm2_nvread` each and refuses on any failure, with no retry inside the tool. The services' units restart
  (the ESP advance every 15 s; sync and admission on their own schedules) and the next run reads again. CI's
  three-node fixture showed it intermittently on its shared software TPMs (#448). Since this change the tool's own
  error text goes to the journal; if it names a transient TPM code (`TPM_RC_RETRY`, `TPM_RC_YIELDED`,
  `TPM_RC_TESTING`, a busy socket), a small bounded retry on those codes alone is the next step. The refusal's own
  text still carries no TPM reason (#450).
- **Rotating the system-phase PCR key: not built.** The anchor's write policy names one key, and
  PolicyOR(old, new) is deferred (#242 follow-up). Rotating that key today makes every anchor
  Unusable until each node is re-anchored.
- **The operational state (ADR-0002 D32, #432): watched by the daemon, not yet enforced.** When
  `operational_state_endpoint`, `operational_state_dir` and `session_key_dir` are configured, the daemon
  (`internal/opstate`):
  - watches the local etcd member through its unix socket;
  - publishes the revision it has applied (`/run/regalia-state/applied.json`);
  - makes a session key at each start and publishes its public half (`/run/regalia-kms/session-key.json`).

  Not done yet:
  - The state gate (`opstate.StateGate`: the lease names this daemon's session key and cluster, the cache has
    applied the lease's `state_revision`, the last confirmation is within one lease) is built and tested but
    **not wired into the fence**. It joins once the serving lease (runtime lease v2, regalia-kms-95) carries
    those fields.
  - The entries aren't verified in Go yet (`opstate-v1`), and spends, high-water marks and key state aren't
    committed through etcd. The policy journal is still the per-node file (`policy.FileState`).
  - The daemon's unit doesn't yet join `regalia-etcd-client`, the group that may open etcd's socket. That
    group arrives with #484's sysusers, and naming it before then would stop the unit from starting.
  - The lone survivor's stateless serving under the owner's authorization (D32 item 6) has no gate path yet.
  - The session key's private half lives in the Go heap. It is never written, but it isn't locked against
    swap: the hosts are expected to run without swap, and nothing checks that.
  - **`applied.json`'s `state_epoch` is always 0 for now.** The signed `/regalia/v1/state-epoch` entry
    (`opstate.verify_state_epoch`) isn't verified by the cache yet. Until it is, a survivor's history after `--force-new-cluster` can't
    be told from the lost tail by this field.
  - **Once the runtime lease v2 (#489) is in, production must set the three settings.** Without them the
    daemon writes neither file, so its node requests no lease and stops serving.
  - **Restoring etcd from a snapshot moves its revision back.** The cache refuses a store that went backwards
    and publishes nothing, so the file goes stale. Every issuer's revision floor refuses too (#489). Both
    fail closed. The recovery step after a restore is to restart `regalia-kms` and `regalia-sync` on every
    node: a fresh cache, a fresh floor, then one lease of fail-closed. It belongs in the etcd recovery runbook
    when that is written.

## Tokens and the HSM gate (#72)

- **The physical pull-and-reinsert drill has not been run** (G3). The script is merged
  (`e2e/hsm-gate-drill.py`) and needs a person at the bench. Reader names and slot flags were checked
  on the Nitrokeys and a YubiKey. **The Pico has not been tested** for any part of G3.
- **The production daemon must be the `-tags piv` build.** No image builder ships the daemon yet
  (#61). A daemon built without it refuses to start when admission is required and a removable token
  is configured.

## The owner's and the release cards (ADR D30)

- **Not measured**: the developer-card layout has not been shown on a staging YubiKey. The layout
  is the owner key in OpenPGP SIG, owner-auth in DEC, and SSH commit signing in AUT. The three checks
  still to run are a raw Ed25519 signature from SIG through OpenSC, an OpenPGP certificate built on the
  existing card key with DEC bound to it, and git SSH signing from AUT. If the first fails, the owner key
  moves to PIV.
- **Not measured: touch-required behaviour** on the owner and release keys. It needs the owner at
  the bench.
- **Accepted:** a release card stolen together with its PIN can sign a release. Mitigations: touch is
  fixed, and three wrong PINs lock the card. Recovery is a new release key, published as a rotation.
- **Not decided:** whether the owner must also approve a release when the release specialist is
  someone else (to be settled when the company has staff). Whether a technical director gets
  recovery-only cards is awaiting the owner.

## Ceremony inputs (`manifest propose --genesis`, `enrol`, the card record, build provenance)

- **Not measured**: `propose`/`sign --genesis`, the card-record verifier and build provenance have run
  only with software keys, software TPMs and in CI.
- **Genesis node identities are bound to each node's TPM, not to its hardware** (#399). `propose
  --genesis` takes each node's bundle, kept challenge and activation and proves them itself: the AK is
  in the TPM its EK names, and the AK quoted every identity field (both WireGuard keys, the signing
  key, the token serials, the SSH host key) bound to that very challenge, booted on PCR 11 the genesis
  measurements accept (system phase). What it cannot show: that the TPM is a genuine vendor TPM, which
  rests on the EK certificate or, without one, the EK Name copied by hand (#190; the DL360's TPM is
  unknown); that the node was not compromised when it enrolled (enrolment trusts the host at its own
  console); and PCR 7 is only compared across the nodes where the measurements give no expected value.
  The quote covers bundle.json as the node holds it at `activate`; the enrolment directory is checked
  to be root's (0700, trusted ancestors), and root on the node at enrolment is trusted. The PCR 11
  judgement assumes the host had finished booting (systemd-pcrphase "ready" extended) when `activate`
  ran, which a software TPM cannot show: a bench item (#297), and the refusal says to re-run once
  `systemctl is-system-running` reports running. Run only on software TPMs so far.
- **Card attestation: not built** (#400). Nothing yet produces the YubiKeys' OpenPGP attestation
  certificates (`ykman openpgp keys attest`). The card record's `attestation_sha256` values are
  placeholders in the test vectors, so "attested" has no certificate behind it anywhere yet. When it is
  built, the attestation will show the touch policy ("fixed"), the key source, the serial and the
  fingerprint. OpenPGP has **no PIN-policy attestation**, so "PIN always" stays a recorded setting.
- **Card-record freshness is per laptop** (#403, #408). A record is accepted only if it is the newest
  card record on the ceremony laptop's root signing record (`signing-record.jsonl`, in the state
  directory marked `regalia-signing-state.json`). That is newest on THIS laptop, not newest of the
  root: a Shamir root rebuilt elsewhere with a fresh state directory signs a valid "sequence 1". The
  card ceremony's `--first-card-record` makes that visible (regalia-ceremony#111). `propose --genesis`
  prints `card record N of M` with its digests, for the operator to check against the ceremony sheet.
- **Nothing writes the state-directory marker yet.** `manifest sign` refuses a directory without it and
  never writes one; the card ceremony's writer (regalia-ceremony#111) is not built. Until it lands, no
  real laptop can sign. The marker and log path is unit-tested only until the first-ceremony rehearsal.
- **The laptop's signing record is not hash-chained** (#405). A deleted line, a cut tail or a state
  directory restored from an older backup is not detected; #405 would anchor the newest card-record
  digest in the root-signed manifest. A lost state directory has no recovery path yet (#406).
- **The bench-token lists are kept by hand** (`membership.BENCH_NITROKEYS`, `BENCH_PICOS`,
  `BENCH_YUBIKEYS`). A new bench token must be added there. A test keeps the drills' staging list equal
  to it, and nothing ties it to the operators' staging registry.
- **Build provenance** hashes only the files in `REPO_FILES`. It compares the Go release by **name**
  with `go.mod`, not the toolchain binary, which the builder verifies through the Go checksum database.
  `build-initrd.sh` runs git as the checkout's owner with no global or system configuration (#384), and
  so does `uki.py`'s own checkout (#404): repo-git.sh's exact environment, no file under the signer's
  HOME. `uki.py` also refuses any untracked file but `__pycache__` bytecode, ignore rules included
  (`build-initrd.sh` to follow). The build record is unsigned; two builders' records must agree. The
  signer's clone must be writable by the signer alone: a `.pyc` planted by another writer would run.

## Audit and monitoring

- The external audit collector and the monitoring service are **contracts only**
  ([`deploy/baremetal/AUDIT-COLLECTOR.md`](deploy/baremetal/AUDIT-COLLECTOR.md),
  [`deploy/baremetal/MONITORING.md`](deploy/baremetal/MONITORING.md)). The real service has not been
  chosen or deployed. The audit collector's conformance suite runs against the reference collector in
  CI. **Monitoring has no conformance command** (MONITORING.md section 5: not built).
- **Audit completeness is checked in some scenarios only.** `audit_complete` runs in the theft, rolling and
  recovery scenarios (#402). Outage, leases and replace are not covered. The time trail and the update trail
  are never checked end to end in a three-node scenario. In recovery, "each node's change to serving" is not
  tied to a step, and the victims' not-serving lines are not checked.
- **`regalia-sync`'s journal is a summary; the trail is the record** (#470). Each pull round now writes one
  line per peer to the journal: an epoch applied, nothing newer, `DENY <event> from <peer>: <reason>` (the
  trail's reason, word for word), or the peer did not answer, with the error class. Each peer's line is
  rate-bounded: it is written when the outcome changes, and the same outcome repeats at most every 15 minutes.
  What the journal does not say:
  - A refused round names only its last DENY. If a round applies an epoch and the heartbeat after it is then
    refused, the line says `DENY sync-heartbeat`, and the new epoch shows up in the next round's line.
  - A taken heartbeat is not reported, and neither is its freshness.
  - Unlock, enrolment and beat-sign answers given to peers are not reported.
  - A DENY that repeats inside the 15-minute window is written once. Repeats are matched with digit runs
    ignored, so a reason that carries a count, a time or a sequence doesn't write a line every round. A DENY
    whose reason differs only in its numbers therefore stays hidden for up to 15 minutes.
  - The journal lines aren't hash-chained or shipped. Anyone who can write the journal can edit or drop
    them. The trail is the evidence.

  For any of these, read the trail. In the three-node fixture, `advance()` prints the puller's trail when a
  node doesn't take an epoch (#469).
- **Collector receipts carry no signed time** (#398), so a stale receipt still verifies. This matters
  for the one-peer recovery witness (#387).

## Products on the roadmap

- **No OpenBao plugin** ([`OPENBAO-COMPATIBILITY.md`](OPENBAO-COMPATIBILITY.md)).
- **No release-signing tool for the card-held release key** (planned).
- **No Kubernetes KMS provider** (planned).

## Tests

- `moved_by_sync` (the sync round that moved a node to an epoch) cannot see how many envelopes a round received:
  trail events don't carry it. A node moved other than by its sync, right after a no-op round from the same peer,
  would be credited to that peer. In the scenarios only the seed is moved otherwise, and it is never asked (#393).
- `audit_complete` judges each trail at a snapshot taken when it is called. Lines written after it are checked only
  if the collector already holds them, so a scenario must call it after the events it names (#393, #409).
- The initrd builds verify every package against snapshot.debian.org, and one dropped connection fails the whole
  build: `debverify` doesn't retry a fetch. That fails closed, but it turned main red once (8eb35a6) with no code
  at fault. Retrying fetch errors only, never a verification failure, is #425.
- three-node-outage's step 5 (a node without authenticated time signs nothing) allows **one** signature in flight
  across the switch: a's Proposer reads the authenticated time once per step, so a signature it began before the
  read saw the switch is legitimate. The check is by position in a's trail: after a's first refusal for want of time,
  no signature as proposer or co-signer, and at most one between the switch and that refusal.
