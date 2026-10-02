# SSH to a KMS node: which host it is, and who may log in (#143)

SSH is for administrators, from the admin zone the host firewall declares (`admin_cidrs`,
`firewall.py`). Nodes do not SSH to each other: node-to-node traffic is WireGuard and mTLS.

Two questions, answered separately.

| Question | Answer | Trust comes from |
|---|---|---|
| Is this host the node I meant? | The node's Ed25519 host key is pinned in the membership manifest (`ssh_host_pub`, schema v2) | The offline membership root |
| May this person log in? | A short-lived user certificate from the admin user CA, for a key held in a FIDO token | The admin CA's keys, on two FIDO tokens |

Three things are called "CA" around here. They are different, and only one of them exists in this design:

| | What it is | Used for logging in to a KMS node? |
|---|---|---|
| **A CA per node** | Does not exist. A node has a host KEY, pinned in the manifest; that already says which node it is | n/a |
| **The admin user CA** (section 2) | Two hardware tokens, outside the KMS | **Yes, and nothing else is** |
| **A company-wide CA inside the KMS** | Not built. Its key would live in the HSMs, replicated across the three hosts, and sign SSH certificates for the company's other machines (the OpenBao track, #529) | **No.** If the CA that lets an administrator into a KMS host lived inside the KMS, nobody could get a certificate to repair the KMS while it is down, and a compromise of the KMS's signing API would become a shell on the KMS hosts |

## 1. The host: a key pinned in the manifest

Each node has one SSH host key, Ed25519, and its public half is the node's `ssh_host_pub` in the
manifest (`membership.py`). It is an identity like the EK name or the WireGuard keys:

- no two nodes, and no two roles, share one;
- only a root-signed manifest can set or change it; a revocation key cannot;
- a retired or stolen node keeps it as a tombstone, so the key is never accepted for a node again.

An administrator does not learn host keys from the first connection. `ssh_trust.py` writes a
`known_hosts` file from the manifest:

```sh
python3 -Es -m deploy.baremetal.ssh_trust --chain chain.json --root-key "$ROOT_KEY_HEX" --at-least-epoch "$EXPECTED_EPOCH" \
    --known-hosts ~/.ssh/regalia_known_hosts --addresses addresses.json --ssh-config ~/.ssh/regalia_config
ssh -F ~/.ssh/regalia_config a
```

`$EXPECTED_EPOCH` is the epoch you expect to be current, looked up each time (the last signing record,
or the revocation you are acting on). Do not reuse the number from a previous command.

- **The name is the node ID.** Each key is filed under its node ID and the generated `ssh_config`
  sets `HostKeyAlias <node_id>`. The key that answers at an address is checked against the node the
  administrator named. A node cannot answer for another one.
- **Retired keys are `@revoked`** for every name. A node that is not in the manifest has no line and
  is refused (`StrictHostKeyChecking yes`).
- **The file is used alone, for every name:** `GlobalKnownHostsFile /dev/null`, `UpdateHostKeys no`,
  set per node and again in a closing `Host *`. A retired node, a node left out of `addresses.json`,
  or a bare IP address has no block of its own; without the catch-all, ssh would use its defaults for
  it (your own `known_hosts`, a trust-on-first-use prompt), exactly when a node has just been revoked.
- **Use it with `ssh -F` only. Never `Include` it** from `~/.ssh/config`: its `Host *` would then
  apply to every host you connect to.
- **Rollback.** A workstation has no TPM anchor. `--at-least-epoch` is the lowest epoch the
  administrator accepts; an older chain is refused. There is no default. The program also never goes
  back by itself: the file in place records the epoch and manifest it came from, and a chain that ends
  below it, or does not hold that manifest at that epoch, does not replace it. A file in the way that
  the program did not write is not replaced either. **That file is the program's only memory.** If you
  move it away or delete it, `--at-least-epoch` is the only floor again, even if a newer generated
  `ssh_config` still points at the path.
- `addresses.json` is `{"a": "192.0.2.10", ...}`. The manifest holds no addresses, and none is
  trusted: a wrong address reaches a host whose key does not match the name.

**Not chosen: a certificate authority per node.** A node's own CA, held in its TPM, could sign
short-lived host certificates and allow rotating the host key without a new manifest. It would add a
second key type (a TPM holds ECDSA, not Ed25519), a second manifest field, and a renewal service on
every node. A host key changes rarely, and a root-signed manifest is the mechanism that already
changes every other node identity. If rotation without a manifest is wanted later, the CA key is a
new field; `ssh_host_pub` stays what it is.

## 2. The person: the admin user CA, short-lived certificates

`sshd-regalia-kms.conf.example` is the whole server side. What it enforces:

- **Certificates only.** `AuthorizedKeysFile none`, `PubkeyAcceptedAlgorithms` lists only the
  certificate algorithm, passwords and keyboard-interactive are off. A plain public key is refused
  before it is looked at.
- **Hardware on both sides.** The administrator's key and the CA keys are FIDO token keys
  (`sk-ssh-ed25519@openssh.com`). `CASignatureAlgorithms` accepts no other CA signature, so a
  certificate signed by a key in a file is not accepted, whoever holds that file.
- **Touch and PIN at every login, required by the server.** `PubkeyAuthOptions touch-required
  verify-required`. Making the key with `-O verify-required` is not enough by itself: that is a flag on
  the key, and without the server line a certificate carrying `no-touch-required` logs in with no
  touch, and a key made without the flag logs in with no PIN.
- **Two CA tokens.** A FIDO key cannot be copied or backed up, so the CA is two tokens, each with its
  own key, and every node lists both public keys in `TrustedUserCAKeys`. Either can issue. With one
  token only, losing it would end every login within one certificate lifetime and leave the physical
  console as the only way in.
- **Principals.** A certificate names who it is for; `/etc/ssh/regalia-principals/<account>` lists
  which principals may log in as that account. An account without a file accepts nobody. Root does
  not log in.
- **Revocation.** `RevokedKeys` is a key revocation list. The lifetime below is the main control;
  the list is for the hours in between.

Recorded choices. They follow common practice (HashiCorp Vault's SSH CA, Teleport, `step-ca`) and
are the owner's to change:

| Choice | Value | Why |
|---|---|---|
| Where the admin CA keys live | Two YubiKeys kept for this purpose, each with its own FIDO2 resident key made with `-O verify-required` (PIN and touch for every signature); kept in two places | Cannot be copied, so there are two; every certificate costs a touch |
| Certificate lifetime | 12 hours | One working session; a lost laptop's certificate is dead by the next day |
| Principals | The administrator's own name, one per person | The log says who, not "admin" |
| Source address | The admin CIDRs, written into the certificate | A certificate copied elsewhere is refused by sshd, not only by the firewall |
| Serial number | One per certificate, recorded | What the revocation list names |

```sh
# once, with each of the two CA tokens in turn: a CA key on each
ssh-keygen -t ed25519-sk -O resident -O verify-required -O application=ssh:regalia-user-ca -C regalia-user-ca-1 -f ca1
ssh-keygen -t ed25519-sk -O resident -O verify-required -O application=ssh:regalia-user-ca -C regalia-user-ca-2 -f ca2
cat ca1.pub ca2.pub > regalia-user-ca.pub      # goes to every node as /etc/ssh/regalia-user-ca.pub

# once per administrator, with their own token ("alice" stands for the administrator's name)
ssh-keygen -t ed25519-sk -O verify-required -C alice -f id_regalia

# each session: a certificate for 12 hours, from either CA token
ssh-keygen -s ca1 -I alice-2026-10-02 -n alice -V +12h -z 42 \
    -O clear -O permit-pty -O source-address=203.0.113.0/28 id_regalia.pub
```

**Revoking a certificate before it expires.** The list goes to every node as
`/etc/ssh/regalia-revoked-keys`. Serial numbers belong to the CA that signed: `-s` names it. The spec
file holds one line, `serial: 42`.

```sh
# THE FIRST revocation ever: without -u. The file on the nodes is empty until then, and -u refuses an empty file.
ssh-keygen -k -f regalia-revoked-keys -s ca1.pub -z 1 revoked-42.spec

# EVERY LATER revocation, for either CA: WITH -u. Without it the list is REPLACED, and certificate 42 is good again.
ssh-keygen -k -u -f regalia-revoked-keys -s ca1.pub -z 2 revoked-43.spec
ssh-keygen -k -u -f regalia-revoked-keys -s ca2.pub -z 3 revoked-ca2-7.spec

# before sending it out: what the list holds, and that a given certificate is on it
ssh-keygen -Q -l -f regalia-revoked-keys
ssh-keygen -Q -f regalia-revoked-keys id_regalia-cert.pub
```

**A CA token is lost.** Issue from the other. Take the lost token's line out of
`/etc/ssh/regalia-user-ca.pub` on every node: from then on no new login with its certificates is
accepted (sessions already open go on until they end). Make a key on a new token and add its line.
Until the new token is enrolled there is one CA token again: do it the same day.

**Single owner.** Today one person holds both CA tokens and logs in. The CA then gives expiry,
revocation and a touch per certificate; it does not separate two people. When staff or an investor
arrive (ADR-0002 D8, the same triggers as the ceremony witness), a CA token goes to someone who is
not the administrator being certified.

## What is tested, and what is not

- `tests/test_baremetal_ssh_trust.py` checks the generated files against OpenSSH itself
  (`ssh-keygen -F`, `ssh -G`) and, where `sshd` is installed, runs a real `sshd` on the example
  configuration: a certificate from either CA logs in to the node it names; the same host under
  another node's name, a retired or stolen node's key under any name or address, a plain key, a
  certificate from a third CA or from a CA taken out of the file, an expired or revoked certificate, and
  a principal the account does not list are all refused; the server offers `publickey` and nothing
  else. `e2e/ssh-trust-sshd.sh` runs that in CI, where a skip is a failure.
- **Not tested: the FIDO path.** No token is used in CI, so the test widens the two `sk-` lines to
  the software algorithms. That `sshd` refuses a software-key certificate under the example as
  written is tested; a login with real tokens is a bench drill still to run. In particular
  `PubkeyAuthOptions touch-required verify-required` is only checked as loaded (`sshd -T`): it has no
  effect on software keys, so what it refuses has to be shown with tokens.
- **Not tested: a `Match` block or an earlier drop-in on a real host.** The example's header says what
  can defeat it; `host_probe.py` will have to measure the effective configuration with `sshd -T -C`.
- **Not done here:** `host_probe.py` does not yet measure sshd (the host key on disk equals the
  manifest's `ssh_host_pub`; this configuration is the one loaded). Nothing installs these files. The
  user CA's public key reaches a node at commissioning; it is not in the manifest.
