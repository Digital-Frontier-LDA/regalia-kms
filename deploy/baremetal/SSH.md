# SSH to a KMS node: which host it is, and who may log in (#143)

SSH is for administrators, from the admin zone the host firewall declares (`admin_cidrs`,
`firewall.py`). Nodes do not SSH to each other: node-to-node traffic is WireGuard and mTLS.

Two questions, answered separately.

| Question | Answer | Trust comes from |
|---|---|---|
| Is this host the node I meant? | The node's Ed25519 host key is pinned in the membership manifest (`ssh_host_pub`, schema v2) | The offline membership root |
| May this person log in? | A short-lived user certificate from one user CA, for a key held in a FIDO token | The user CA key, held in a FIDO token |

## 1. The host: a key pinned in the manifest

Each node has one SSH host key, Ed25519, and its public half is the node's `ssh_host_pub` in the
manifest (`membership.py`). It is an identity like the EK name or the WireGuard keys:

- no two nodes, and no two roles, share one;
- only a root-signed manifest can set or change it; a revocation key cannot;
- a retired or stolen node keeps it as a tombstone, so the key is never accepted for a node again.

An administrator does not learn host keys from the first connection. `ssh_trust.py` writes a
`known_hosts` file from the manifest:

```sh
python3 -Es -m deploy.baremetal.ssh_trust --chain chain.json --root-key "$ROOT_KEY_HEX" --at-least-epoch 7 \
    --known-hosts ~/.ssh/regalia_known_hosts --addresses addresses.json --ssh-config ~/.ssh/regalia_config
ssh -F ~/.ssh/regalia_config a
```

- **The name is the node ID.** Each key is filed under its node ID and the generated `ssh_config`
  sets `HostKeyAlias <node_id>`. The key that answers at an address is checked against the node the
  administrator named. A node cannot answer for another one.
- **Retired keys are `@revoked`** for every name. A node that is not in the manifest has no line and
  is refused (`StrictHostKeyChecking yes`).
- **The file is used alone:** `GlobalKnownHostsFile /dev/null`, `UpdateHostKeys no`. A host cannot
  add a key to it.
- **Rollback.** A workstation has no TPM anchor. `--at-least-epoch` is the lowest epoch the
  administrator accepts (the last one they saw, or that of the revocation they are acting on); an
  older chain is refused. There is no default.
- `addresses.json` is `{"a": "192.0.2.10", ...}`. The manifest holds no addresses, and none is
  trusted: a wrong address reaches a host whose key does not match the name.

**Not chosen: a certificate authority per node.** A node's own CA, held in its TPM, could sign
short-lived host certificates and allow rotating the host key without a new manifest. It would add a
second key type (a TPM holds ECDSA, not Ed25519), a second manifest field, and a renewal service on
every node. A host key changes rarely, and a root-signed manifest is the mechanism that already
changes every other node identity. If rotation without a manifest is wanted later, the CA key is a
new field; `ssh_host_pub` stays what it is.

## 2. The person: one user CA, short-lived certificates

`sshd-regalia-kms.conf.example` is the whole server side. What it enforces:

- **Certificates only.** `AuthorizedKeysFile none`, `PubkeyAcceptedAlgorithms` lists only the
  certificate algorithm, passwords and keyboard-interactive are off. A plain public key is refused
  before it is looked at.
- **Hardware on both sides.** The administrator's key and the CA key are FIDO token keys
  (`sk-ssh-ed25519@openssh.com`). `CASignatureAlgorithms` accepts no other CA signature, so a
  certificate signed by a key in a file is not accepted, whoever holds that file.
- **Principals.** A certificate names who it is for; `/etc/ssh/regalia-principals/<account>` lists
  which principals may log in as that account. An account without a file accepts nobody. Root does
  not log in.
- **Revocation.** `RevokedKeys` is a key revocation list. The lifetime below is the main control;
  the list is for the hours in between.

Recorded choices. They follow common practice (HashiCorp Vault's SSH CA, Teleport, `step-ca`) and
are the owner's to change:

| Choice | Value | Why |
|---|---|---|
| Where the user CA key lives | A FIDO2 resident key on a YubiKey kept for this purpose, made with `-O verify-required` (PIN and touch for every signature) | Cannot be copied; every certificate costs a touch |
| Certificate lifetime | 12 hours | One working session; a lost laptop's certificate is dead by the next day |
| Principals | The administrator's own name, one per person | The log says who, not "admin" |
| Source address | The admin CIDRs, written into the certificate | A certificate copied elsewhere is refused by sshd, not only by the firewall |
| Serial number | One per certificate, recorded | What the revocation list names |

```sh
# once, with the CA token: the CA key. ca.pub goes to every node as /etc/ssh/regalia-user-ca.pub
ssh-keygen -t ed25519-sk -O resident -O verify-required -O application=ssh:regalia-user-ca -C regalia-user-ca -f ca

# once per administrator, with their own token
ssh-keygen -t ed25519-sk -O verify-required -C jonathan -f id_regalia

# each session: a certificate for 12 hours
ssh-keygen -s ca -I jonathan-2026-10-02 -n jonathan -V +12h -z 42 \
    -O clear -O permit-pty -O source-address=203.0.113.0/28 id_regalia.pub

# revoke certificate 42 before it expires; the file goes to every node as /etc/ssh/regalia-revoked-keys
ssh-keygen -k -f regalia-revoked-keys -s ca.pub -z 1 revoked.spec    # revoked.spec holds "serial: 42"; add -u to extend an existing list
```

**Single owner.** Today one person holds the CA token and logs in. The CA then gives expiry,
revocation and a touch per certificate; it does not separate two people. When staff or an investor
arrive (ADR-0002 D8, the same triggers as the ceremony witness), the CA token goes to someone who is
not the administrator being certified.

## What is tested, and what is not

- `tests/test_baremetal_ssh_trust.py` checks the generated files against OpenSSH itself
  (`ssh-keygen -F`, `ssh -G`) and, where `sshd` is installed, runs a real `sshd` on the example
  configuration: a certificate from the CA logs in to the node it names; the same host under another
  node's name, a retired node's key, a plain key, a certificate from another CA, an expired or revoked
  certificate, and a principal the account does not list are all refused. `e2e/ssh-trust-sshd.sh` runs
  that in CI, where a skip is a failure.
- **Not tested: the FIDO path.** No token is used in CI, so the test widens the two `sk-` lines to
  the software algorithms. That `sshd` refuses a software-key certificate under the example as
  written is tested; a login with real tokens is a bench drill still to run.
- **Not done here:** `host_probe.py` does not yet measure sshd (the host key on disk equals the
  manifest's `ssh_host_pub`; this configuration is the one loaded). Nothing installs these files. The
  user CA's public key reaches a node at commissioning; it is not in the manifest.
