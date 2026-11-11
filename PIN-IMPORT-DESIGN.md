# PIN import by TPM2_Import to an ECC P-256 key (regalia-kms#671, Option B)

Status: implemented on software TPMs (swtpm) only. **Not yet run on any physical TPM.** Until
`e2e/slb9665-pin-import-poc.sh` has run on the SLB9665 and passed, the typed PIN (Option C below)
stays the commissioning path for that module.

Decision: the owner, 2026-11-07, relayed by the Daintree global assistant (session
932bc46910191e2c-d7). #671 is Option B: ECC P-256, TPM-native. The requirement on the PIN-import key
is "at least 128-bit security", not literally RSA-3072.

## Why it changed

`seal-hsm-pin.sh --init-import-key` made an RSA-3072 decryption key, and step 0 of the ceremony
encrypted the PIN to it with RSA-OAEP (SHA-256). The DL360 Gen9's Infineon SLB9665 (firmware 5.62)
has no RSA-3072. `tpm2_testparms` on it: rsa2048 and ecc256 are supported, rsa3072, rsa4096 and
ecc384 are not. So the import key could not be made on it (`Esys_Create(0x2C4)`), and the PIN had to
be typed.

P-256 is one of the two key types the TCG PC Client Platform TPM Profile requires of every module
(the other is RSA-2048), which is why the SLB9665 has it. RSA-2048 (about 112-bit) is below the
requirement.

## The construction: TPM2 duplication, not a new scheme

Nothing new is built here. The PIN travels as a **TPM2 duplication blob**: the format the TPM 2.0
Library specification defines for moving an object to a new parent (Part 1, "Protected Storage" and
"Duplication"; Part 3, TPM2_Duplicate and TPM2_Import). It is made by `tpm2_duplicate` from
tpm2-tools and opened by the TPM's own TPM2_Import. There is no ECIES, ECDH+KDF+AEAD or other
construction of our own.

What the tool does with the parent's public key, offline, as the TPM would:

1. a fresh ephemeral P-256 key; ECDH with the parent's point; the **seed** is
   KDFe(SHA-256, Z, "DUPLICATE", ephemeral x, parent x). The ephemeral point is the
   `TPM2B_ENCRYPTED_SECRET` in the blob;
2. the **outer wrap**: the sealed object's sensitive area is encrypted with
   AES-128-CFB, key KDFa(SHA-256, seed, "STORAGE", the object's Name), and an HMAC-SHA-256, key
   KDFa(SHA-256, seed, "INTEGRITY"), covers the encrypted area and the object's Name;
3. TPM2_Import, on the host, recovers the seed with the parent's private key (which never leaves
   the TPM), checks the HMAC, decrypts, and re-wraps the object under the parent. TPM2_Load loads
   it, and TPM2_Unseal returns the PIN.

### Security level

ECC P-256 (about 128-bit), AES-128 (128-bit), SHA-256 and HMAC-SHA-256 (at least 128-bit): **about
128-bit overall**. That meets the requirement and matches RSA-3072 (also about 128-bit). The import
key is generated in the TPM (`sensitiveDataOrigin`) and is `fixedTPM|fixedParent`, as before.

### Outer wrap only (the owner's decision, 2026-11-07)

The original brief asked for "an outer seed + inner wrap". The owner decided on 2026-11-07 that the
blob uses the **outer wrap only**, for these reasons:

- The inner wrap's key (`encryptionKey`) is a **clear parameter** of TPM2_Import. If it travelled in
  the blob, it would add no confidentiality: whoever holds the blob would hold the key. It adds
  something only if it reaches the host by another channel (a second hand-carried secret), which
  would bring back the typing this path exists to remove.
- Integrity is already given by the outer HMAC, which binds the encrypted area to the object's
  Name (its public area). An inner integrity value would repeat it.
- tpm2-tools 5.7 cannot make an inner wrap when it duplicates an external object (`-o` is refused
  with `-k`; measured 2026-11-07). An inner wrap would need code of our own, which the brief rules out.

Decided: outer wrap only. An inner wrap would be reconsidered only together with a separate channel
for its key.

## The import key (the parent)

`seal-hsm-pin.sh --init-import-key`, under the owner hierarchy (with `--ownerauth-stdin` where the
owner authorization is set, #242):

| | |
|---|---|
| transient primary | ECC P-256, AES-128-CFB, `restricted\|decrypt\|fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|noda` (unchanged) |
| persisted child at `0x81000101` | **ECC P-256 (NIST), nameAlg SHA-256, AES-128-CFB, scheme NULL, KDF NULL** |
| its attributes | `fixedtpm\|fixedparent\|sensitivedataorigin\|userwithauth\|restricted\|decrypt\|noda` (`0x00030472`) |
| its authorization | empty (no value to guess) |

**restricted|decrypt: both are kept, since TPM2_Import needs them.** The parent of TPM2_Import must be
a storage key: a restricted decryption key with a symmetric algorithm (the reference
implementation's `ObjectIsStorage`; anything else is `TPM_RC_TYPE`). The symmetric algorithm
(AES-128-CFB) is the cipher of the outer wrap. `restricted` also narrows what the key can do: a
restricted key cannot be used with TPM2_ECDH_ZGen, so nobody on the host can use it as an ECDH
oracle. It only takes objects into this TPM. The RSA key it replaces could decrypt any ciphertext
for anyone on the host.

**A child, not a persisted primary.** A primary is a function of the owner seed and its template, so
re-creating it gives the same key. The child is random, so `--replace-import-key` gives a different
key (the e2e checks this), as before.

**`noda`** on the key and its primary, as before (#57): no authorization value to guess, and without
`noda` every power cut after a use would count a dictionary-attack try. The sealed object is `noda`
too, for the same reason (`e2e/tpm-lockout-swtpm.sh` section 4, with a control that counts).

**The hand-copied fingerprint is unchanged**: SHA-256 of the key's DER SubjectPublicKeyInfo, as
`--init-import-key` prints it, `host.pin_import_key_sha256` records it, and `host_probe.py` and the
ceremony check it. For P-256 the SPKI is 91 bytes: a fixed 26-byte prefix, `04`, X, Y.

## The sealed object (made at the ceremony)

A keyedhash object holding the PIN's bytes exactly (no newline): nameAlg SHA-256, scheme NULL,
attributes `userwithauth|noda` (no `sign`/`decrypt`, or TPM2_Unseal refuses it), empty authPolicy
and authorization. `fixedTPM`, `fixedParent` and `sensitiveDataOrigin` are clear, as they must be for
an object made outside the TPM and duplicated. Its public `unique` is H(seedValue || PIN) with a
random 32-byte seedValue made by tpm2_duplicate. So the public area does **not** reveal SHA-256(PIN),
which a 10-digit PIN could not survive. Measured: two blobs of one PIN have different `unique`s, and
neither is sha256(PIN).

## The ceremony side (regalia-ceremony step 0, `pin_blob_for`)

Offline, no TPM:

1. read the host's public key (PEM) once into the RAM workdir as DER, and refuse unless the typed
   prefix (at least 16 hex) matches its SHA-256 (as before);
2. refuse unless it is an uncompressed P-256 SPKI (the fixed prefix, 91 bytes);
3. **build the parent's TPM2B_PUBLIC from the pinned template and the verified X and Y**, and
   never read a template from the medium. The fingerprint covers the point only. A substituted
   template file could keep the real point and change the wrap (for example a NULL symmetric
   algorithm), so the template comes from the ceremony's own code. The e2e checks it byte for byte
   against the TPM's `tpm2_readpublic -f tss`;
4. write the PIN to a 0600 file in the RAM workdir (tpm2_duplicate seeks its input, so a pipe will
   not do), run `tpm2_duplicate --tcti none -U parent -G keyedhash -k pin -a 'userwithauth|noda'`,
   and remove the PIN file at once;
5. write the v2 blob (below), and remove the intermediates.

This adds a ceremony-laptop dependency: **tpm2-tools (`tpm2_duplicate`), with no TPM**. It is not
yet in the ceremony's offline package set (open question).

## Blob format v2

```
"regalia-pin-blob v2 tpm2-import nist-p256 sha256=" <64 lowercase hex> "\n"     (114 bytes)
TPM2B_PUBLIC            the sealed object's public area        (tpm2_duplicate -u)
TPM2B_PRIVATE           its duplicate (outer-wrapped)          (tpm2_duplicate -r)
TPM2B_ENCRYPTED_SECRET  the seed: the ephemeral P-256 point     (tpm2_duplicate -s)
```

Each part carries its own 2-byte big-endian size, and nothing may follow the third. A blob is
about 320 bytes. The hex in the header is the fingerprint of the import key the blob was made for.
It is a **label**, so a blob for another host gets a clear message before the TPM is asked. It is
not a security check: a relabelled blob is refused by TPM2_Import (the e2e checks this).

`seal-hsm-pin.sh --from-blob` refuses, before any card is looked at:

| input | result |
|---|---|
| no `regalia-pin-blob v` header, 384 or 256 bytes | "looks like an RSA-OAEP PIN blob (format 1, before regalia-kms#671) … make a new blob at ceremony step 0 … or type the PIN from the PIN card" |
| no header, any other size | "not a PIN blob" |
| `regalia-pin-blob vN` with N ≠ 2 | "a PIN blob of format vN, which this seal-hsm-pin.sh does not read" |
| over 4096 bytes, malformed header, truncated, trailing bytes | refused, with what is wrong |
| label ≠ this TPM's import key fingerprint | "was made for the import key sha256 X; this TPM's key … is Y" |
| TPM2_Import fails (altered, or relabelled) | "the TPM could not import …" |
| load or unseal fails | refused |

Format 1 (RSA-OAEP) had no header. It is recognised by its size alone and only to give the message
above. It is never decrypted.

## The host side

`seal-hsm-pin.sh --from-blob`: TPM2_Import (parent: the key at the import handle), TPM2_Load,
TPM2_Unseal. The PIN goes only into a shell variable. Transient objects are flushed, and the raw
`/dev/tpm0` is refused (no resource manager), as `--init-import-key` already did. **Every check
after that is unchanged**: card serial, full counter, PIN tested on the card, sealed (host key +
TPM2), read back, installed. A wrong or foreign blob fails before the card is touched.

**Owner authorization.** TPM2_Import and TPM2_Load authorize the **parent object** (USER role: its
empty authorization, `userwithauth`), not a hierarchy. `--from-blob` therefore needs **no owner
authorization**, even where it is set (the e2e checks this on a TPM whose owner authorization is
set). Only `--init-import-key` needs it, for TPM2_CreatePrimary and TPM2_EvictControl under the owner
hierarchy, and it already takes it with `--ownerauth-stdin` (#242).

**Threat model, unchanged.** Anyone who holds a blob AND can send commands to that host's TPM can
unseal its PIN, just as anyone with the RSA blob could ask the old key to decrypt it. The blob is
safe on any medium because only that TPM opens it. Anyone with the public key can make a blob, as
before: the card test then refuses a wrong PIN.

## host_probe

- `pin_import_key_present` requires exactly the template above: type, curve, nameAlg, symmetric
  algorithm, mode and key size, scheme, KDF, and the seven attributes. The fingerprint check is
  unchanged. An RSA-3072 key at the handle (every host commissioned before #671) fails, even with its
  recorded fingerprint.
- `tpm_algorithms` (a report, not a control, and not in the evidence schema): `tpm2_testparms`
  rsa2048, rsa3072, ecc256, ecc384, in every run. `host_probe.py --tpm-algorithms` prints only that
  and exits 0 when ecc256 is accepted. Run it before commissioning and before the ceremony.

## Migration

A host commissioned with the RSA-3072 key must run `--init-import-key --replace-import-key` (a new
fingerprint by hand, new evidence), and its PINs need new v2 blobs, or typing. Old blobs are
refused with the message above.

## Option C: the interim

Until Option B has passed on the SLB9665 itself (`e2e/slb9665-pin-import-poc.sh`, written, **not
run**), commissioning on that module types the PIN from the sealed PIN card (seal-hsm-pin.sh without
`--from-blob`; PIN-CUSTODY.md). That path is unchanged.

## Not covered here

- **TPM2_Certify of the import key by the EK-bound AK** (ADR-0002 D21 point 2): required, and **not
  yet built**. It is regalia-kms#702. Today only `signkey.py` certifies a key (the #199 signing key);
  the import key is trusted by the hand-copied fingerprint alone. No host is commissioned on this
  path until #702 lands.
- The SLB9665's TPM2_PT_MAX_AUTH_FAIL of 31 (not 32) from #671 is not addressed here.
