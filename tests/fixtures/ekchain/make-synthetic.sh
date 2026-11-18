#!/usr/bin/env bash
# The synthetic chains tests/test_baremetal_ekchain.py verifies (regalia-kms-x6x). Run from this directory with
# OpenSSL >= 3.4 (for -not_before/-not_after); the outputs are committed, so the tests need no key and no newer
# OpenSSL. The keys are throwaway and are deleted at the end.
#
# The shape copies the first DL360's chain (regalia#595): an EK certificate issued 2017-10-07, valid to 2032,
# by a manufacturing CA whose certificate exists twice under ONE key: as issued in 2017 and as re-issued in 2023
# (what the EK's AIA URL serves today). Beside it, the things intake must refuse: a root with the right name and
# the wrong key, and a CA with CA 029's name and another key.
#
#   root.pem          synthetic root, 2013-07-26 .. 2043-07-25
#   root-other.pem    the same subject as root.pem, another key (the "wrong root")
#   ica-2017.pem      the CA as issued 2017-08-21 .. 2037-08-21, key K
#   ica-2023.pem      the CA re-issued 2023-02-08 .. 2043-02-08, the same key K and subject
#   ica-other.pem     the CA's subject, another key, issued by root.pem (the "swapped CA")
#   ek.pem            an EK-shaped leaf (empty subject, critical SAN), 2017-10-07 .. 2032-10-07, signed by K,
#                     for the public key of swtpm's default-template RSA EK (swtpm-ek-rsa.pem)
#   ek-other.pem      the same leaf shape for the same key, signed by the other CA key
set -euo pipefail
umask 077
k=$(mktemp -d)
trap 'rm -rf "$k"' EXIT

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$k/$1.key" 2>/dev/null; }
ca_ext="basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid"
printf '%s\n' "$ca_ext" > "$k/ca.ext"
printf '%s\n' "$ca_ext" | sed 's/CA:TRUE/CA:TRUE,pathlen:0/' > "$k/ica.ext"
cat > "$k/ek.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,keyEncipherment
subjectAltName=critical,dirName:tpm_san
extendedKeyUsage=2.23.133.8.1
authorityKeyIdentifier=keyid
[tpm_san]
0.2.23.133.2.1=id:49465800
EOF
# (the "0." is OpenSSL config syntax for a repeatable field; the attribute is 2.23.133.2.1, tcg-at-tpmManufacturer)

root_dn="/C=XX/O=Synthetic/OU=Devices/CN=Synthetic Root CA"
ica_dn="/C=XX/O=Synthetic/OU=TPM2.0/CN=Synthetic Manufacturing CA 029"

key root; key root-other; key ica; key ica-other
for r in root root-other; do
  openssl req -new -key "$k/$r.key" -subj "$root_dn" -out "$k/$r.csr"
  openssl x509 -req -in "$k/$r.csr" -key "$k/$r.key" -sha256 -not_before 20130726000000Z -not_after 20430725235959Z \
    -extfile "$k/ca.ext" -set_serial 1 -out "$r.pem" 2>/dev/null
done
ica() {  # name key not_before not_after serial
  openssl req -new -key "$k/$2.key" -subj "$ica_dn" -out "$k/$1.csr"
  openssl x509 -req -in "$k/$1.csr" -CA root.pem -CAkey "$k/root.key" -sha256 -not_before "$3" -not_after "$4" \
    -set_serial "$5" -extfile "$k/ica.ext" -out "$1.pem" 2>/dev/null
}
ica ica-2017 ica 20170821124921Z 20370821124921Z 4371
ica ica-2023 ica 20230208153927Z 20430208153927Z 9002
ica ica-other ica-other 20230208153927Z 20430208153927Z 9003
leaf() {  # name ca-cert ca-key
  openssl req -new -key "$k/ica.key" -subj "/" -out "$k/leaf.csr" 2>/dev/null
  openssl x509 -req -in "$k/leaf.csr" -force_pubkey swtpm-ek-rsa.pem -CA "$2" -CAkey "$k/$3.key" -sha256 \
    -not_before 20171007103841Z -not_after 20321007103841Z -set_serial 7001 -extfile "$k/ek.ext" -out "$1.pem" 2>/dev/null
}
leaf ek ica-2023.pem ica
leaf ek-other ica-other.pem ica-other
