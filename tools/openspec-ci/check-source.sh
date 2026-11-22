#!/usr/bin/env bash
set -euo pipefail

workspace="$(cd "$GITHUB_WORKSPACE" && pwd -P)"
case "$1" in
    reserve|verify) domain=product ;;
    reserve-tooling|verify-tooling) domain=tooling ;;
    *) domain= ;;
esac
source_path="$workspace/.openspec-${domain}-source"

fail() {
    printf 'OpenSpec source preparation: %s\n' "$1" >&2
    exit 1
}

# Ignore caller-supplied Git configuration and forbid lazy object fetches.
local_git() (
    for key in $(compgen -e GIT_); do unset "$key"; done
    export GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0
    export GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=
    git "$@"
)

case "$1" in
    reserve|reserve-tooling)
        if [[ -e "$source_path" || -L "$source_path" ]]; then
            fail "reserved ${domain} source directory already exists"
        fi
        ;;
    verify|verify-tooling)
        revision="$2"
        tree="$3"
        [[ -d "$workspace/.git" && -d "$source_path/.git" && ! -L "$source_path" && ! -L "$source_path/.git" ]] ||
            fail "missing separate ${domain} Git checkout"
        primary_head="$(local_git -C "$workspace" rev-parse --verify HEAD)" || fail "primary checkout HEAD differs from workflow revision"
        [[ "$primary_head" == "$GITHUB_SHA" ]] ||
            fail "primary checkout HEAD differs from workflow revision"
        source_root="$(local_git -C "$source_path" rev-parse --show-toplevel)" || fail "${domain} source does not resolve to a separate Git checkout"
        [[ "$source_root" == "$source_path" ]] ||
            fail "${domain} source does not resolve to a separate Git checkout"
        source_head="$(local_git -C "$source_path" rev-parse --verify HEAD)" || fail "${domain} checkout HEAD differs from the required revision"
        [[ "$source_head" == "$revision" ]] ||
            fail "${domain} checkout HEAD differs from the required revision"
        kind="$(local_git -C "$source_path" cat-file -t "$revision")" || fail "required ${domain} object is not a locally available commit"
        [[ "$kind" == commit ]] ||
            fail "required ${domain} object is not a locally available commit"
        source_tree="$(local_git -C "$source_path" rev-parse --verify "$revision^{tree}")" || fail "${domain} commit tree does not match the required tree"
        [[ "$source_tree" == "$tree" ]] ||
            fail "${domain} commit tree does not match the required tree"
        printf 'OpenSpec source preflight passed at %s, tree %s\n' "$revision" "$tree"
        ;;
    *)
        fail "expected reserve or verify for product or tooling"
        ;;
esac
