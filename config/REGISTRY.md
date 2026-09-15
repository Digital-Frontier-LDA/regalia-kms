# Registry change and rotation workflow

The custody manifest is both the organization inventory and the KMS routing source. Do not create a
second device-routing file. The daemon selects only an `active` binding whose `site` exactly matches
its configured site; it does not try a standby device, another site, another backend, or software.

## Register or rotate an object

1. Open a change that adds the planned binding and its public fingerprint or non-secret key check.
   Never add a PIN, management key, wrapped secret, Shamir share, private key or recovery phrase.
2. Run the Python manifest tests and Go registry tests. Confirm that the declared backend supports
   the algorithm and every requested operation. YubiKey PIV entries must use a current supported
   generation, `pin_policy` of `once` or `always`, and `touch_policy: never` for unattended use.
3. Require review from both the object owner and a security/custody reviewer. A new algorithm,
   backend, purpose, recovery exception, or cross-site active role also requires an ADR/threat-model
   review as specified by `doc/ADR-0001-CENTRALIZED-KMS.md`.
4. Provision and attest the new hardware through the ceremony workflow. Change its manifest state
   from `planned` to `qualified` only after the public fingerprint/key check matches ceremony output.
5. In one reviewed change, make exactly one binding per serving site `active` and demote the old
   binding to `standby` or `retired`. Ambiguous active bindings make daemon startup fail.
6. Deploy the immutable reviewed manifest, restart the KMS, and reconcile the logged registry
   SHA-256 digest with the reviewed artifact. Readiness must recover without a fallback route.
7. Exercise a non-destructive operation, verify the off-host audit record, then update rotation and
   drill metadata. Destroy retired token objects only through a separately approved ceremony.

Registry history is the reviewed Git history. The daemon logs the content digest and site at load;
issue #9 will include that digest in the off-host audit chain. Files must be regular and not group- or
world-writable. A missing active local binding or an unhealthy assigned device fails closed.
