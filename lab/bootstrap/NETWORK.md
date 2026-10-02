# Three-container WireGuard experiment

This extends the disposable IPC lab. Three containers each own a software TPM,
private peer state, and a disposable LUKS2 image. Their bridge network is internal
to this Compose project; no ports, host devices, or Docker socket are exposed.
Bootstrap HTTP binds only to a WireGuard address, and nftables permits only the
mesh UDP endpoints, bootstrap TCP over WireGuard, and local control traffic.
WireGuard source identity is checked in addition to the target's TPM attestation.

Containers initially need NET_ADMIN, SETUID and SETGID to configure their own
network namespace and drop to UID/GID 10000. The service and its software TPM run
without effective capabilities after setup. The trusted host runner can still
execute namespace administration for deliberate network-failure injection.

The trusted commissioning fixture exchanges public AK/PCR/WireGuard identities,
enrolls each target with the other two authorizers, and obtains both per-peer
contributions through actual WireGuard exchanges to create independent LUKS
slots. An independent random recovery credential is returned only to the host
runner's memory; nodes retain no plaintext copy. The runner supplies it through
stdin for a manual recovery drill. No secret enters command arguments or reports.

`lock` is a logical loss of bootstrap authorization, not an OS reboot. The next
`bootstrap` generates a new RSA session key, unseals local TPM material, contacts
the selected peers concurrently with bounded deadlines, validates the first
response, and checks the derived credential against its actual LUKS2 keyslot.
Only then does the node become an authorizer again. A lost grant requires a fresh
challenge. A late or invalid response never marks the target operational.

Only `challenge` and `authorize` are accepted over the bootstrap endpoint.
Enrollment, policy injection, logical lock, manual recovery and status are local
fixture controls on loopback. JSON bodies/responses are bounded and logs omit
requests, credentials, responses, and captured tool output.

This remains emulated evidence: common Docker host, resettable software TPMs,
unsigned fixture policy, software-held peer keys, Python memory, no initramfs,
no mapped dm-crypt filesystem, no physical reboot, no HSM or runtime leases.
It does not establish global revocation, rollback resistance, or measured boot.
The network experiment does prove encrypted cross-container transport and the
logical recovery protocol under selected network and availability failures.
