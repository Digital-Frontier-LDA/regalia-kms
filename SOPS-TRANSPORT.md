# SOPS adapter transport boundary

Decision: run the SOPS key-service adapter as a **local sidecar**, never as a
network service.

```text
SOPS process -> mode-0600 Unix socket -> adapter -> TLS 1.3 mTLS -> KMS API
```

The upstream SOPS RPC protocol has no client authentication. The sidecar
therefore creates a fresh Unix socket owned by its service identity, refuses to
replace any existing filesystem entry, applies message and concurrency limits,
and must not listen on TCP. SOPS must disable its built-in key service and name
only this socket.

## The sidecar is a trusted multiplexer: the journal records it, not the caller

The identity evaluated by KMS RBAC and policy, and recorded in the audit journal, is the
**sidecar's**. It is not the identity of whatever invoked SOPS, and the adapter propagates none.

That is sound because the socket has exactly one trust domain, and the modes gate different things:
`connect(2)` needs write on the **socket**, so `0600` under a dedicated `regalia-sops` account is
what makes the domain single; `unlink(2)` needs write on the **directory**, so a non-writable
`RuntimeDirectory` is what stops the socket being replaced by someone else's listener. `0700` adds
that other accounts cannot enumerate it. Three things keep it true rather than conventional — `ServeUnix` refuses to
start on a group- or world-writable socket directory, `test_sidecar_socket_lives_inside_the_runtime_directory_it_is_protected_by`
pins the socket into the directory that protects it, and `test_no_two_units_share_a_runtime_directory`
and `test_units_do_not_share_a_service_account` keep the boundary from being shared away.

**What that does not buy:** within the domain, every caller is still one principal. If two things on
that host legitimately use the same sidecar, the journal shows one identity for both and nothing
reports that the distinction was lost. Enforcing the boundary makes the identity *honest*; it does
not make the record answer "who". Answering that needs the daemon to accept a delegated identity
from a workload, which is a trust grant it does not currently make — see issue #104.

The adapter's network client presents a workload certificate to the sole KMS
HTTPS endpoint. Its URI SAN is the identity evaluated by KMS RBAC and policy;
the adapter does not accept a caller-supplied identity header. Repository,
normalized file path, environment, and purpose travel as authenticated request
context, but they do not replace the certificate identity.

`ClientTLSConfig` requires TLS 1.3, an explicit KMS server name, explicit trust
roots, and a client private key implementing `crypto.Signer`. The production
executable obtains a short-lived workload identity from protected runtime credential files; the
example service uses a TPM-sealed systemd credential and a workload agent or hardware signer is
preferred. A persistent plaintext PEM key is prohibited. It must not use ambient proxy settings, disable certificate
verification, or follow redirects. The HTTP client has bounded connect,
handshake, response-header, and whole-operation timeouts.

At the Proxmox boundary, expose only the main KMS HTTPS port to approved source
networks. Do not expose the sidecar socket through a shared mount, forwarded
Unix socket, TCP proxy, or container boundary. Host firewall and guest firewall
rules are both required; their concrete deployment remains part of issues #25
and #46.

Current tests prove that missing client transport inputs are rejected, the
sidecar uses a private Unix socket, malformed/wrong-environment/wrong-key
requests never reach the KMS client, and KMS errors return no plaintext. A live
certificate-chain handshake and firewall probe remain required before #19 can
close.
