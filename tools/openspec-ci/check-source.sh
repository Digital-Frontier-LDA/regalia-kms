#!/usr/bin/env bash
set -euo pipefail

workspace="$(cd "$GITHUB_WORKSPACE" && pwd -P)"
product="$workspace/.openspec-product-source"

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
    reserve)
        if [[ -e "$product" || -L "$product" ]]; then
            fail "reserved product source directory already exists"
        fi
        ;;
    verify)
        revision="$2"
        tree="$3"
        [[ -d "$workspace/.git" && -d "$product/.git" && ! -L "$product" && ! -L "$product/.git" ]] ||
            fail "missing separate product Git checkout"
        primary_head="$(local_git -C "$workspace" rev-parse --verify HEAD)" || fail "primary checkout HEAD differs from workflow revision"
        [[ "$primary_head" == "$GITHUB_SHA" ]] ||
            fail "primary checkout HEAD differs from workflow revision"
        product_root="$(local_git -C "$product" rev-parse --show-toplevel)" || fail "product source does not resolve to a separate Git checkout"
        [[ "$product_root" == "$product" ]] ||
            fail "product source does not resolve to a separate Git checkout"
        product_head="$(local_git -C "$product" rev-parse --verify HEAD)" || fail "product checkout HEAD differs from the required revision"
        [[ "$product_head" == "$revision" ]] ||
            fail "product checkout HEAD differs from the required revision"
        kind="$(local_git -C "$product" cat-file -t "$revision")" || fail "required product object is not a locally available commit"
        [[ "$kind" == commit ]] ||
            fail "required product object is not a locally available commit"
        product_tree="$(local_git -C "$product" rev-parse --verify "$revision^{tree}")" || fail "product commit tree does not match the required tree"
        [[ "$product_tree" == "$tree" ]] ||
            fail "product commit tree does not match the required tree"
        printf 'OpenSpec source preflight passed at %s, tree %s\n' "$revision" "$tree"
        ;;
    *)
        fail "expected reserve or verify"
        ;;
esac
