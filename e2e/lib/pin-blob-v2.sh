# shellcheck shell=bash
# pin-blob-v2.sh — sourced by the e2e scripts: make a v2 PIN blob the way regalia-ceremony step 0 does
# (qubes/scripts/ceremony.sh pin_blob_for), offline, with no TPM: tpm2_duplicate --tcti none.
# Format and reasoning: PIN-IMPORT-DESIGN.md. This copy exists so the e2e can make blobs without a
# ceremony checkout; the two must stay byte-compatible (the e2e checks the parent public area it builds
# against the TPM's own, byte for byte).
#
#   pin_blob_v2 <import public key, PEM> <out.blob> <work dir>    the PIN on standard input
#   pin_parent_tpm2b <import public key, PEM> <out>                the parent's TPM2B_PUBLIC, from the
#                                                                   pinned template and the key's point

# The DER SubjectPublicKeyInfo of an uncompressed P-256 point: these 26 bytes, 04, X (32), Y (32).
PIN_P256_SPKI_PREFIX=3059301306072a8648ce3d020106082a8648ce3d030107034200
# The import key's template, as seal-hsm-pin.sh --init-import-key creates it, marshalled up to the point:
# type ECC, nameAlg SHA-256, attributes fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|
# restricted|decrypt (0x00030472), empty authPolicy, symmetric AES-128-CFB, scheme NULL, curve NIST P-256,
# kdf NULL. The size (0x005a, 90) is that of the whole TPMT_PUBLIC with a 32-byte X and Y.
PIN_PARENT_TEMPLATE=005a0023000b000304720000000600800043001000030010
PIN_BLOB_HEADER="regalia-pin-blob v2 tpm2-import nist-p256 sha256="

pin_hex_to_bin(){ printf '%b' "$(sed 's/../\\x&/g' <<< "$1")"; }

pin_parent_tpm2b(){
  local hex
  hex="$(openssl pkey -pubin -in "$1" -outform der 2>/dev/null | od -An -tx1 -v | tr -d ' \n')" || return 1
  [ "${#hex}" = 182 ] && [ "${hex:0:54}" = "${PIN_P256_SPKI_PREFIX}04" ] || { echo "pin-blob: $1 is not a P-256 public key" >&2; return 1; }
  pin_hex_to_bin "${PIN_PARENT_TEMPLATE}0020${hex:54:64}0020${hex:118:64}" > "$2"
}

pin_blob_v2(){
  local pem="$1" out="$2" d="$3" fp
  rm -f "$out"
  fp="$(openssl pkey -pubin -in "$pem" -outform der 2>/dev/null | sha256sum | cut -d' ' -f1)" || return 1
  pin_parent_tpm2b "$pem" "$d/parent.tpm2b" || return 1
  # tpm2_duplicate seeks its input, so the PIN is a file (the caller's private directory), removed at once
  (umask 077; cat > "$d/pin")
  tpm2_duplicate --tcti none -U "$d/parent.tpm2b" -G keyedhash -k "$d/pin" -a 'userwithauth|noda' \
    -u "$d/obj.pub" -r "$d/obj.dpriv" -s "$d/obj.seed" >/dev/null 2>&1; local rc=$?
  rm -f "$d/pin"
  [ "$rc" = 0 ] || { echo "pin-blob: tpm2_duplicate failed" >&2; return 1; }
  { printf '%s%s\n' "$PIN_BLOB_HEADER" "$fp"; cat "$d/obj.pub" "$d/obj.dpriv" "$d/obj.seed"; } > "$out"
  rm -f "$d/obj.pub" "$d/obj.dpriv" "$d/obj.seed" "$d/parent.tpm2b"
}
