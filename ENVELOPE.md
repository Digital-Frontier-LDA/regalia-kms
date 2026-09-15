# Hardware-rooted envelope format v2

Regalia envelope v2 protects an opaque value with a fresh random 256-bit AES data-encryption key
(DEK). AES-256-GCM encrypts the value; a named hardware backend wraps the DEK using a non-exportable
key-encryption key (KEK). There is no software wrapper implementation or fallback route.

Version 2 replaced version 1 in #206. The wrapped data-key frame changed from `RGK\x01` to `RGK\x02`,
with a 4-byte big-endian length, so that it is self-delimiting against PKCS#11 modules whose
`C_UnwrapKey` does not strip RFC 5649 padding. The change is wire-incompatible in both directions,
so the envelope `version` and the `regalia-envelope-v2` format label moved together.

The strict JSON envelope contains `version`, logical `object_id`, hardware `kek` backend/ID/version,
`algorithm`, SHA-256 `context_digest`, UTC `created_at`, nonce, authenticated ciphertext and wrapped
DEK. Go's JSON encoding represents the three byte strings as base64. Unknown fields, trailing JSON,
unsupported versions/backends, oversized values and malformed metadata are rejected.

The object's own `algorithm` in the custody manifest is `opaque`: an API token is not a key, and it
is the only value the capability matrix admits for `release-secret`. The KEK that protects it is a
real key, so each binding names it with `kek_algorithm` (`rsa2048`, `rsa3072` or `rsa4096`) and that
is what reaches the token for the data-key unwrap. A binding that omits it, or names a key the
backend cannot unwrap with, is refused at load rather than at the first release.

Each binding also names `kek_version`, the generation of the key in that slot, and the envelope's
own `kek` reference is checked against the route on every release: backend, object and version must
all be the ones the route holds. This is what makes rotation mean anything. `Rewrap` changes only
the wrapped DEK, so before this the version was a label that selected nothing — every version routed
to the same slot, and an envelope wrapped under a superseded key opened on the key that replaced it.

**The envelope's version chooses the route; it does not merely agree with it.** Release resolves the
binding that holds the generation the envelope names, and accepts a `retired` one. Seal keeps taking
the active, standby or qualified binding, so a retired KEK opens what it sealed and wraps nothing
new — those two eligibility sets are `registry.UnwrapAllows` and `registry.SealAllows`, deliberately
different and deliberately functions rather than exported maps.

The alternative, which this replaced, was to resolve every release against the *active* binding and
refuse any envelope naming another generation until it was rewrapped. That made rotation retroactive
and destructive. **The KMS does not store envelopes** — it hands them to callers, who put them in
repositories, config stores, CI secrets and backups — so "rewrap everything before retiring" asks
the daemon to enumerate ciphertexts it has never held. Worse, a backup taken before a rotation
contains envelopes naming the retired generation, and under active-only resolution those are
unopenable forever: the routine rotation, not the incident, is what destroys the recovery path. See
#84.

So rotating a KEK means installing the new key, adding its binding as `active`, and moving the old
binding to `retired` — not rewrapping anything.

**The new key must be new key material, not the old key under a new `kek_version`.** This is worth
saying because the mistake is reachable: `doc/REQUIREMENTS.md` records that a wiped card re-imports
from its seed to the same key, so a ceremony that restores rather than generates produces a
`kek_version` 2 byte-identical to `kek_version` 1. The label would move and nothing would have
rotated. (These are KEK generations throughout, not the envelope format version in this document's
title, which is 2.)

The format survives that mistake without hiding it. The wrap AAD binds the KEK's version alongside
its backend and ID, so a data key wrapped under `kek_version` 2 does not unwrap under `kek_version`
1 even when the two hold the same bytes.

**To be clear about which envelopes this affects, because it is easy to read as the opposite of the
paragraph above.** An envelope sealed correctly under `kek_version` 1 — that label over a data key
actually wrapped by that key — opens exactly as before; that is what `retired` is for. What fails is
a MISMATCH: a label and a wrapped key from different generations, which is what a relabel-only
"rotation" produces the moment anything rewraps. Nothing that was sealed correctly stops opening.

That is a containment property, not a substitute for generating a key: an attacker holding the
re-imported key holds both generations, and no AAD helps with that. Rewrapping is then an optional refresh that moves an
individual envelope onto the current generation; it is what lets a retired binding eventually be
removed, and until it is served that removal is an operator decision about how old an envelope the
system is still willing to open.

`retired` means "no longer wraps", not "no longer opens". A KEK that must refuse even to unwrap — a
compromised predecessor — is a different state, and this manifest does not have one yet; widening
`retired` to mean it would silently turn every ordinary rotation into a key-compromise response.

**An envelope may be given a maximum age.** `rotation.envelope_max_age_days` on the object bounds
how old an envelope may be when it is released, measured from its own `created_at`. This is a
different bound from `maximum_age_days`, which is measured from `last_rotated` and governs the
*key*: an object rotated exactly on schedule can still be releasing envelopes sealed years ago,
which is how `created_at` came to be authenticated and compared to nothing.

**Absent means unbounded, and that is the default deliberately.** A lifetime bound is the one
control here that causes an outage by working correctly — every envelope past the bound stops
opening at once, on a clock nobody was watching — so deployments opt in. The refusal is recorded as
`envelope-expired` rather than as a routing denial, because the fix is to re-seal the envelope and
an operator should not be searching RBAC for a grant nobody removed. The bound bites when the age
is *greater* than it, so an envelope on its last day still opens.

The age is read from the envelope header before the AEAD can be verified, for the same reason the
KEK version is: verification needs the data key that this routing exists to fetch. It cannot be
gamed in the useful direction — backdating `created_at` expires your own envelope sooner, and
post-dating it produces a header the hardware wrap AAD no longer authenticates, so the unwrap
fails.

Content AEAD authenticates version, object, algorithm and context digest. Creation time is
authenticated by the hardware wrap instead, not by the content AEAD: the offline seal path
cannot know the server's stamp before encrypting, so binding the content to a timestamp the
client did not provide would force the server either to re-stamp or to refuse. Tampering with
`created_at` still breaks the unwrap, so it remains authenticated -- by the other of the two
AADs. Hardware
wrapping additionally binds backend, KEK ID and KEK version.

The context is reconstructed by the KMS and is never accepted from the client. For `release-secret`
it is `envelope.ReleaseContext`—a canonical, versioned, NUL-separated serialization of the object,
purpose and environment taken from the authorized route, all three of which come from the custody
manifest rather than the request. `release-secret` therefore rejects `envelope_aad_base64` outright.
Sealing must derive the context the same way, through the same function.

This was previously an opaque client assertion: the caller sent the context, the KMS compared it to
nothing, and the digest proved only that whoever held the envelope knew the string it was sealed
with. An envelope sealed for one purpose and environment opened under a request declaring another,
because the caller supplied both halves and they agreed with each other.

`wrap`, `unwrap` and `key-agreement` still take a caller-supplied `envelope_aad_base64`; for SOPS it
carries repository identity, normalized file path, environment and purpose. Those are client facts
the KMS has no independent source for, so that context binds the ciphertext to what the client
declared and nothing more. It is not an authorization control, and the release path no longer
depends on one.

The envelope format caps plaintext at 1 MiB, but a released secret is bounded by the API long before
that: `release-secret` accepts an envelope of at most 64 KiB, so the largest secret this path can
carry is roughly 48 KiB once base64 and the envelope's own metadata are counted. Unwrap exposes the
plaintext only inside a callback and zeroes that buffer and the DEK immediately afterward, including
error returns. This is best effort: Go, kernels, TLS stacks and
hardware middleware may copy memory. The KMS VM therefore disables swap/hibernation/snapshots and
must apply short request deadlines, response `no-store`, bounded concurrency and process isolation.

`Rewrap` first authenticates the existing ciphertext, unwraps the DEK through the old hardware key,
and wraps it under a new hardware KEK without changing content ciphertext. Sealing is now served:
`POST /v1/operations/seal-envelope` produces an envelope under policy, RBAC and audit like every
other operation, taking the caller-assembled ciphertext, nonce and data key and never the
plaintext. `Rewrap` itself still has no caller. That no longer blocks rotation — release resolves
retired generations, so a rotation is a manifest change and envelopes keep opening — but it does mean
there is no served way to move an existing envelope onto the current KEK, and therefore no way to
retire a binding out of the manifest entirely while envelopes under it may still exist. Backup/restore consists of
the encrypted envelopes plus Shamir-protected KEK material imported into independently commissioned
hardware. Recovery verification must prove a replacement token with the restored KEK can open a test
envelope before retiring the old token. Production enablement remains blocked until that physical
ceremony passes; the unit test uses two simulated devices solely to prove format portability.

## A KEK is only hardware-rooted if the token says so

#6 requires that production KEKs be non-exportable hardware keys with no software fallback. Until
now nothing asked the token. Measured against SoftHSM: a 2048-bit RSA key generated with `openssl`
on the host and imported with `CKA_EXTRACTABLE` set wrapped a data key in 256 bytes, and was
indistinguishable at every layer above the driver from the key the token generated. The daemon
called the resulting envelope hardware-rooted. It was a file in a token-shaped box.

Two guards now ask, at the two points where the question can be afforded:

| path | attribute | object | why there |
|---|---|---|---|
| `wrap` | `CKA_LOCAL` | public key | wrap never logs in — it needs only the public key — and public objects are readable logged out |
| `unwrap` | `CKA_SENSITIVE`, `CKA_EXTRACTABLE` | private key | private objects are invisible to a logged-out session, and this path has already logged in |

They are not redundant: `CKA_LOCAL` says the pair was born on the token, `CKA_EXTRACTABLE` says it
can still be taken out, and a key can be either without being both. The imported key in the e2e
fixture is `sensitive` — checking only `CKA_SENSITIVE` lets it straight through, which is what the
falsification of that guard demonstrates. Both refusals latch the device, with `kek-exportable` and
`kek-not-token-generated` kept distinct because they send an operator to different remedies.

**This conflicts with restore, and the conflict is unresolved.** A KEK imported into a replacement
token — the paragraph above, DKEK-protected material in independently commissioned hardware — was
by definition not generated there, so `CKA_LOCAL` is false and the `wrap` guard refuses it.
Releasing still works, because that path asks only whether the key can be extracted. Production
restore is already blocked pending the physical ceremony above, so this refuses nothing that works
today. The refusal names itself rather than surfacing as a bare "unavailable", so whoever runs that
ceremony can find it.

**The SoftHSM answer does not carry to an SC-HSM, and the question is wider than restore (#447).**
The guard's "generated reports local, imported does not" was verified against SoftHSM only. On
2026-09-14 the guard itself ran logged out against the staging Pico HSM through `opensc-pkcs11`. A pair
generated on the card and a DKEK-imported pair were **both** refused: `CKA_LOCAL` was present and
false on both public keys. Logged in, the imported *private* key reports `local` although its
plaintext existed on a host. Under D1 this Pico measurement informs no production decision. The
Nitrokey HSM 2 sits behind the same OpenSC driver, so the same result is plausible and still
unmeasured. If it holds there, `wrap` refuses every production KEK, not only restored ones, and
on-token provenance has to come from the device's own attestation rather than a PKCS#11 attribute.
Repeating that probe on the Nitrokey is the first step, before any design change.

Compared with direct token signing, envelope release necessarily places plaintext and a DEK in KMS
RAM for a bounded time. Policy and audit must record this weaker custody class without recording the
value. Consumers must not persist release responses and should request the narrowest secret possible.
