# Offline collector role loading

`audit.LoadCollectorRole(role, trail, now)` loads one role from the fixed `/var/lib/regalia-etc/regalia/collector-v1/active.json` selector and the v1 descriptor's generation roots. The daemon supplies an empty trail and uses the site stream. The shipper supplies the member selected by its trusted registry and uses the full site.trail stream. The API checks this member and full name. The caller remains responsible for the actual registry inventory and expected node and site.

The reader walks from the filesystem root with relative descriptor opens. It checks each opened directory and file for the root UID and absence of group/world write access. It refuses symlinks, nonregular files, hardlinks, repeated opened device/inode identities, and any other-user permission bits on the selected private key. Every open uses nonblocking and close-on-exec. Material is read through the descriptor that passed the checks. An initial size check and a bounded read enforce these limits:

| File | Maximum |
| --- | --- |
| Descriptor | 16 KiB |
| Selected client certificate | 128 KiB |
| Selected client private key | 64 KiB |
| Collector CA bundle | 256 KiB |
| Receipt keys | 64 KiB |

C1 parsing rules apply to the selected keypair, leaf validity, CA, receipt keys and first decoded certificate PEM block. The same loaded role bytes supply the actual proxy-free mTLS transport, HTTPS sink and public binding. Construction is offline. The binding contains identifiers, public content digests and certificate validity bounds. The loader does not expose key material or private digests, and fixed public error categories omit underlying file and parser diagnostics. Legacy file-based C1 callers retain their existing behavior and size policy.

Root must keep published generation files immutable during use. Descriptor-relative reads bind each individual file, with no atomic cross-file snapshot or continuing credential validity guarantee. The loader does not open the other role's files, prove its configuration, or validate effective service ACLs. No daemon or shipper entrypoint uses this API yet. Canonical selector/legacy integration, service startup and restart, safe publication, and the request gate require separate work.
