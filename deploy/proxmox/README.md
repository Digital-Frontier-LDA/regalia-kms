# Proxmox KMS VM provisioning and commissioning

`provision.py` targets Proxmox VE 9 and renders a deterministic, secret-free Proxmox plan from a strict
site configuration. It creates only a full q35/OVMF QEMU VM, fixes CPU and
memory, disables ballooning and hotplug, imports a SHA-256-pinned Debian 12 cloud image,
enables the Proxmox firewall, and passes one entire vfio-bound PCIe USB
controller through to the guest. It has no `usbN` or LXC path. The VM disk must
live on the configured native-encrypted ZFS dataset; apply mode checks that its
encryption root exists and its key is loaded before creating the VM.

Copy `site.example.json`, replace every example value, independently verify the
Debian image digest, record the SHA-256 fingerprint of the commissioned
evidence authority's P-256 public key, and review the rendered plan before applying it:

```sh
openssl pkey -pubin -in commissioning-evidence-p256.pem -outform DER | sha256sum
```

The resulting lowercase 64-hex digest is
`controls.commissioning_evidence_public_key_sha256`. Site config schema v2
requires it; a placeholder or a key supplied only at verification time is not
a trust anchor.

```sh
python3 deploy/proxmox/provision.py site-example.json > site-example.plan.json
sudo python3 deploy/proxmox/provision.py site-example.json \
  --output site-example.applied-plan.json --apply --confirm-site site-a
```

Apply mode refuses an existing VMID rather than mutating it. Before creating a
VM it checks that it is running as root on the named Proxmox node, the image
digest matches, Proxmox VE 9 and its datacenter firewall are active, the configured controller has the expected PCI vendor/device
ID, the IOMMU group contains exactly one function, the controller is bound to
`vfio-pci`, and the bootstrap credential is an Ed25519 public key. It then
disables and unmerges Linux KSM host-wide with a persistent systemd unit.
`disable_host_ksm` is deliberately an explicit site-owner acceptance because
KSM is a host-wide control and may increase memory consumption for other VMs.

The generated VM firewall is default-deny in both directions. It permits only:

- the versioned mTLS KMS port from configured client and monitoring CIDRs;
- SSH from the separate administrative CIDRs;
- audit TLS and NTP egress to exact configured destinations.

The plan does not contain PINs, private keys, recovery material, client private
credentials, or a DKEK. Cloud-init receives only a short-lived public SSH key.
After the guest role is applied and production credentials are delivered via
the documented runtime mechanism, remove the bootstrap key and disable the
cloud-init account. Proxmox root remains a privileged threat actor and serial
console access is treated as a Proxmox-admin path, not a security boundary.
ZFS encryption protects powered-off media and discarded drives, not a guest
from Proxmox root or a storage administrator while the dataset is unlocked.

If a command fails after `qm create`, the provisioner stops the partial VM and
leaves it for inspection; it never silently deletes evidence or retries against
a different target. Correct the cause, destroy the unused partial VM through a
reviewed operator action, and provision a fresh VMID.

The `no-backup` and `no-ha` tags are warnings, not enforcement. The VM must also
be absent from every backup/replication/HA selection, and the operator roles
must lack snapshot, backup, migration, and monitor access outside their duties.
Those external cluster controls are intentionally re-checked below rather than
claimed by the guest or by a tag.

## Continuous policy guard

Install the host-side guard immediately after provisioning and before any KMS
credential is delivered to the guest:

```sh
sudo python3 -m deploy.proxmox.install_policy_guard site-example.json \
  --confirm-vmid 410
systemctl status regalia-proxmox-policy@410.timer
```

Every 15 seconds the root-owned timer queries the live Proxmox API. It checks
the VM's current node, config, pending values, snapshots, runtime/QMP state,
HA resources, replication jobs, and every backup job. Backup membership is
resolved through Proxmox's `included_volumes` endpoint, including `all` and
pool selectors; the guard does not attempt to duplicate those selection rules.
Disabled definitions are still drift because enabling one later must not turn
into a single-click custody bypass.

Any violation disables VM autostart and, if running, requests an immediate
stop with lock override. An incomplete or malformed API response receives the
same quarantine treatment because the guard can no longer prove the boundary.
The latest canonical result is written mode 0600 to
`/var/lib/regalia-proxmox-policy/VMID.json` and every invocation is also logged
to the journal. Alert on either a failed unit or a result where `compliant` is
false. Do not automatically re-enable autostart: remove the prohibited state,
run the guard without `--enforce-stop`, obtain security approval, then restore
`onboot=1` explicitly.

This is a detection-and-quarantine control, not an authorization boundary
against Proxmox root. A privileged administrator can disable the timer, and a
backup/snapshot operation may begin and finish within the polling interval.
Production therefore also requires separation of duties and removal of
`VM.Backup`, `VM.Snapshot`, `VM.Migrate`, and equivalent root access from
ordinary platform operators. Emergency root remains a trusted, audited role.
The guard materially reduces exposure and makes drift fail closed; it does not
make a hostile hypervisor safe.

## Commissioning evidence

`verify.py` schema v4 is the fail-closed repository gate for the binding architecture in
`doc/HSM-KMS-DEPLOYMENT.md`. Feed it a JSON evidence document assembled from current `pvesh`/`qm`,
cluster HA/replication/backup configuration, IOMMU inspection, and an in-guest commissioning run.
The example is synthetic and can only test the validator; it is never production evidence.

```sh
python3 -m deploy.proxmox.verify deploy/proxmox/evidence.example.json \
  --allow-unsigned-example

# Production evidence: signature is P-256 ECDSA over the exact JSON bytes.
python3 -m deploy.proxmox.verify evidence-site-a.json \
  --signature evidence-site-a.sig.der \
  --public-key commissioning-evidence-p256.pem \
  --site-config site-example.json
```

**Schema v4 adds `guest.credential_tpm2_pcrs`**: the TPM2 PCR indices the unattended PIN
credentials were sealed to with `systemd-creds encrypt --tpm2-pcrs=…` (`PIN-CUSTODY.md`). It must
be a non-empty list of distinct integers 0–23. Choosing the set is a commissioning decision for each
site; the example's `[7]` is there only so the synthetic example validates, and is not a
recommendation. What the verifier proves is that a policy was chosen, is well-formed, and is signed
with the rest of the evidence. **It does not prove the blob on the guest is sealed to that set** —
that is a property of a file inside the guest, which this verifier never reads.

Production captures MUST be signed outside the KMS guest by the commissioning evidence authority,
include the raw command transcript and tool versions, and be less than 24 hours old when a site is
enabled. The verifier requires an actual P-256 key, matches its DER fingerprint
to the reviewed site config, and binds the evidence site, node, and VMID to that
same config before checking the signature. Run this from the trusted ceremony
checkout; a site config copied from the host under examination is not independent evidence.
Run the gate again after a Proxmox upgrade, VM config change, controller move, token change,
restore, or failover. A skip is a failure.

Provisioning is not commissioning. Before enabling a site, apply the KMS guest
Ansible role, reboot, then capture and verify all of the following:

1. `pveversion`, `qm config VMID --current`, `qm pending VMID`,
   `qm listsnapshot VMID`, cluster firewall state, HA resources, replication
   jobs, every backup job or pool selection, the enabled policy timer, and the
   SHA-256 digest of its latest clean result;
2. `/sys/kernel/mm/ksm/run` and `pages_shared` both reading zero, IOMMU group
   membership, `vfio-pci` binding, and the physical-port label;
3. from the guest, systemd hardening, no swap/hibernate/core dump, no DKEK or
   recovery files, unprivileged service ownership, token serial plus
   cryptographic-identity readiness, and the TPM2 PCR set the PIN credentials
   were sealed to;
4. from client, monitoring, admin, and unauthorized network zones, positive and
   negative port tests matching the generated firewall; an accepted TCP socket
   on 8443 must still reject a caller without a valid client certificate;
5. a cold reboot, controller removal/re-attach, wrong-token substitution, and
   stale-site fencing check.

Sanitize the transcript, have the commissioning evidence authority sign it
outside the guest, populate the evidence JSON, and run `verify.py`. Physical
port identity, administrator separation, negative network paths, and cluster
job selection cannot be honestly inferred by `provision.py`; missing evidence
keeps the site out of production.

Measure the guest's memory and credential controls **inside the guest** before signing
(regalia#49). The evidence's `guest` section is otherwise a set of typed booleans, and a signature
over a false claim still verifies. `guest_probe.py` reads the guest itself:
- core limits: the unit's `LimitCORE`, `fs.suid_dumpable` and systemd-coredump storage;
- hibernation: `resume=`, the masked sleep targets or `sleep.conf`;
- active swap: must be zram or dm-crypt;
- the unit's user and `NoNewPrivileges`;
- token client tools, and every process connected to pcscd, identified by its binary.

With `--evidence` it exits 1 when the evidence claims a control the guest does not have. Keep its
JSON in the signed transcript:

```sh
sudo python3 deploy/proxmox/guest_probe.py --evidence evidence.json
```

It cannot see `runtime_credentials_excluded_from_backup`, which belongs to the host's backup jobs,
or `credential_tpm2_pcrs`, which is inside the sealed blob. It reports both as *attested, not
measured*.

Run the network matrix from a host in each named zone. `--source-ip` is bound on
the socket so a routing default cannot silently test through a different
interface. Preserve the four JSON lines in the signed transcript:

```sh
python3 deploy/proxmox/network_probe.py site-example.json --role client --source-ip 198.51.100.20
python3 deploy/proxmox/network_probe.py site-example.json --role monitoring --source-ip 203.0.113.128
python3 deploy/proxmox/network_probe.py site-example.json --role admin --source-ip 203.0.113.4
python3 deploy/proxmox/network_probe.py site-example.json --role unauthorized --source-ip 203.0.113.66
```

The `unauthorized` source address must lie outside EVERY role CIDR in the site file — here outside
`198.51.100.0/24` (clients), `203.0.113.0/28` (admin), `203.0.113.128/32` (monitoring) and the
audit sinks. The line above used `198.51.100.20`, which is a CLIENT address: the firewall accepts
it on 8443 exactly as configured, the probe reports `expected=closed, observed=open` and exits 1,
and a correct firewall reads as a failed one. Change this address with the site file, not from
memory.

The probe establishes firewall reachability only. On the allowed KMS path also
send a request without a client certificate and require the TLS handshake or
request to fail; then repeat with the commissioned client identity and require
only its authorized operation to succeed.

The required evidence states that VM-level snapshots/backups and replication are absent. Durable
KMS control-plane data is exported separately as integrity-protected, encrypted application data;
runtime credentials, vTPM state, memory, swap, core dumps, PINs, plaintext outputs, and token state
are excluded. Rebuild recovers credentials through the witnessed custody procedure rather than by
restoring a machine image containing operational authority.

That exporter and its offline inspection exist: `regalia-kms --export-control-plane` (on the
guest), `--inspect-export` and `--scan-tree` (from the ceremony checkout), with custody defined
in `doc/CONTROL-PLANE-EXPORT.md`. Until the physical drill has been run at a real site, #49
remains open — and until then, still do not configure any Proxmox VM backup as a substitute:
the guard will quarantine the guest.
