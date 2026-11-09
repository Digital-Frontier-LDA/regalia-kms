# shellcheck shell=bash
# import-key-cert.sh — sourced by the e2e scripts that run seal-hsm-pin.sh --init-import-key, which (#702) needs the
# node's EK and AK in the TPM and a verifier's credential to them (deploy/baremetal/importkey.py).
#
#   ikc_ready <TCTI> <dir>    on that TPM: the EK and AK as enrol init makes them (attest.py node-init: 0x81010001,
#                             0x81010002; <dir>/ek.pub, <dir>/ak.pub), then the verifier's challenge, with no TPM
#                             (<dir>/cred.bin, <dir>/keep.json) and the EK's Name, as intake records it (<dir>/ek.name)
# Needs $HERE (the repository root).

ikc_ready(){
  local tcti="$1" d="$2"
  mkdir -p "$d" || return 1
  TPM2TOOLS_TCTI="$tcti" python3 -Es "$HERE/deploy/baremetal/attest.py" node-init --out "$d" >/dev/null 2>&1 \
    || { echo "import-key-cert: attest.py node-init failed on $tcti" >&2; return 1; }
  (cd "$HERE" && python3 -Es -m deploy.baremetal.importkey challenge --ek-public "$d/ek.pub" --ak-public "$d/ak.pub" \
    --credential "$d/cred.bin" --keep "$d/keep.json") >/dev/null \
    || { echo "import-key-cert: importkey challenge failed for $d" >&2; return 1; }
  python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["ek_name"])' "$d/keep.json" > "$d/ek.name"
}
