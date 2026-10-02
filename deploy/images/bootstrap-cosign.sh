#!/bin/sh
# Reviewed verifier bootstrap pin. Publisher proofs for scanner downloads are
# verified by this binary; the repository pin is the initial trust anchor.
set -eu
umask 077
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ]
[ "$#" = 1 ] && [ ! -e "$1" ]
cosign_stage=$(mktemp)
trap 'rm -f "$cosign_stage"' EXIT HUP INT TERM
curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
  https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign-linux-amd64 -o "$cosign_stage"
printf '%s  %s\n' c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74 "$cosign_stage" | sha256sum --check --strict
install -m 0700 "$cosign_stage" "$1"
