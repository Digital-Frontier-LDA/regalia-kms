# shellcheck shell=bash
# repo-git.sh — sourced by build-initrd.sh: read the checkout with git, never letting the checkout run a command
# as root (#382).
#
# build-initrd.sh runs as root (mmdebstrap), on a checkout that is normally another user's clone. The checkout's
# own configuration can make git run commands: a clean filter that `git status` runs on files whose stat data
# changed, textconv, fsmonitor, hooks, includes pulling in more of the same. Two rules:
#   1. git runs as the checkout's OWNER (setpriv, a cleared environment, no supplementary groups, no new
#      privileges), never as root, so anything the checkout makes git run has only that user's rights;
#   2. a checkout whose own configuration holds anything a plain clone does not write is refused before git reads
#      its tree at all (repo_git_check): an ALLOWLIST, the same as uki.py's CLONE_CONFIG (#374, a test holds the two
#      equal), so no filter, textconv, merge driver, fsmonitor, hook, pager, editor, include, alias or credential
#      helper can be defined, and a .gitattributes alone then names no command.
# The global and system configurations are not read (GIT_CONFIG_GLOBAL=/dev/null, GIT_CONFIG_NOSYSTEM=1).
#
#   REPO=/path/to/checkout; . repo-git.sh; repo_git_check || exit; repo_git rev-parse HEAD

# what a clone writes into its own configuration, and nothing else (uki.py CLONE_CONFIG; names as git prints them)
REPO_GIT_ALLOWED='core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|symlinks)|extensions\.(objectformat|worktreeconfig)|user\.(name|email)|gc\.auto|remote\.[^[:space:]]+\.(url|pushurl|fetch|tagopt|prune|promisor|partialclonefilter)|branch\.[^[:space:]]+\.(remote|merge|rebase|pushremote)'

repo_git_uid(){
  # the uid git runs as: the checkout's owner when root reads another user's checkout, else this process's
  local uid; uid="$(stat -c %u "$REPO")"
  if [ "$(id -u)" = 0 ] && [ "$uid" != 0 ]; then echo "$uid"; else id -u; fi
}

repo_git(){
  local uid gid
  uid="$(stat -c %u "$REPO")" gid="$(stat -c %g "$REPO")"
  if [ "$(id -u)" = 0 ] && [ "$uid" != 0 ]; then
    setpriv --reuid="$uid" --regid="$gid" --clear-groups --no-new-privs -- \
      env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      git -c core.fsmonitor=false -c core.hooksPath=/dev/null --no-optional-locks -C "$REPO" "$@"
  else
    env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      git -c safe.directory="$REPO" -c core.fsmonitor=false -c core.hooksPath=/dev/null --no-optional-locks -C "$REPO" "$@"
  fi
}

# Refuse (return 1, saying why) a checkout whose own configuration (local and worktree scopes, includes followed)
# sets any name outside REPO_GIT_ALLOWED. Listing the configuration runs nothing: it only prints names.
repo_git_check(){
  local listed bad
  # scope NUL name NUL, pairs; turned into "scope<TAB>name" lines in the pipe (a shell variable cannot hold a NUL)
  listed="$(set -o pipefail; repo_git config --list --includes --name-only --show-scope -z | tr '\0\n' '\n\t' | paste - -)" || {
    echo "build-initrd: the checkout's git configuration cannot be read (#382)" >&2; return 1; }
  bad="$(printf '%s\n' "$listed" | awk -F'\t' '$1 == "local" || $1 == "worktree" { print $2 }' \
         | grep -Evx "$REPO_GIT_ALLOWED" | sort -u | tr '\n' ' ')"
  if [ -n "$bad" ]; then
    echo "build-initrd: the checkout's git configuration sets ${bad% }, which a clone does not: build from a fresh clone (#382)" >&2
    return 1
  fi
}
