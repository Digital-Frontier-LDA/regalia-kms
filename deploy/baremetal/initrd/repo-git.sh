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

repo_git_owner(){
  # whom git runs as when root reads the checkout: root ONLY when both the working tree's top and .git are root's;
  # otherwise the top's owner if it is not root, else .git's. Whoever owns the top can replace the entry .git at any
  # moment, so they must never get a root git (regalia-kms-1e: a swap between this stat and git opening .git/config
  # would hand root another user's configuration). A CI container's checkout (top the runner's, .git written by
  # root) is read as the runner: read-only, --no-optional-locks, and safe.directory for the root-owned .git.
  local fmt="${1:-%u}" top
  top="$(stat -c %u "$REPO")"
  if [ "$top" != 0 ]; then stat -c "$fmt" "$REPO"; else stat -c "$fmt" "$REPO/.git"; fi
}

repo_git_uid(){
  # the uid git runs as: the repository's owner when root reads another user's repository, else this process's
  local uid; uid="$(repo_git_owner)"
  if [ "$(id -u)" = 0 ] && [ "$uid" != 0 ]; then echo "$uid"; else id -u; fi
}

repo_git_root_safe(){
  # Before git runs AS ROOT (the top and .git both root's): no one but root can replace an entry on the way to
  # .git/config (#390, regalia-kms-1e). Every directory from / down to the checkout's real path, and .git, is
  # root's and not writable by group or others; a sticky directory (like /tmp) is allowed, since only its entry's
  # owner can rename that entry, and the entry below it is then required to be root's. Returns 1, saying which.
  # (regalia-kms-1e's read of #394) $REPO must already be its own real path: git -C, safe.directory and every read of
  # the builder use $REPO, so a symlinked component would be checked resolved and then followed again, retargeted.
  local path dir info uid mode loose strict=""
  path="$(realpath -e "$REPO")" || { echo "build-initrd: $REPO cannot be resolved" >&2; return 1; }
  if [ "$path" != "$REPO" ]; then
    echo "build-initrd: $REPO is not its own real path ($path): a symlinked component could be retargeted under root's git (#390)" >&2; return 1
  fi
  # .git a real directory: a gitfile or a link would send git to a gitdir (and its commondir) never checked here
  if ! _rg_is_real_dir "$path/.git"; then
    echo "build-initrd: $path/.git is not a directory of its own (a gitfile or a link): root's git would read elsewhere (#390)" >&2; return 1
  fi
  # .git and the top: root's, no group or other write, sticky or not (a sticky directory still lets others CREATE
  # entries, and git reads files that may not exist yet: commondir, config.worktree). Strict ancestors: sticky allowed,
  # since the entry below each exists and is required to be root's, and the sticky bit stops its rename.
  while IFS= read -r dir; do
    info="$(_rg_owner_mode "$dir")" || return 1
    uid="${info% *}" mode="${info#* }"
    if [ "$uid" != 0 ]; then
      echo "build-initrd: $dir is not root's (uid $uid): another user could replace what root's git reads (#390)" >&2; return 1
    fi
    if (( (8#$mode & 8#022) != 0 )) && { [ -z "$strict" ] || (( (8#$mode & 8#1000) == 0 )); }; then
      echo "build-initrd: $dir is writable by group or others (mode $mode): another user could replace what root's git reads (#390)" >&2; return 1
    fi
    [ "$dir" = "$path" ] && strict=yes                 # everything after the top is a strict ancestor
  done < <(printf '%s\n' "$path/.git" "$path"; d="$path"; while [ "$d" != / ]; do d="$(dirname "$d")"; printf '%s\n' "$d"; done)
  # what .git holds, two levels down (config, config.worktree, commondir, info/attributes, hooks...): root's, and not
  # writable by group or others (tar -x or cp -a as root keep other owners and modes)
  loose="$(_rg_loose_inside "$path/.git")"
  if [ -n "$loose" ]; then
    echo "build-initrd: $loose (in .git) is not root's or is writable by group or others: it could be rewritten under root's git (#390)" >&2; return 1
  fi
}

# the filesystem questions repo_git_root_safe asks, one function each (a test stubs them: root-owned fixtures need sudo)
_rg_owner_mode(){ stat -c '%u %a' "$1"; }
_rg_is_real_dir(){ [ -d "$1" ] && [ ! -L "$1" ]; }
_rg_loose_inside(){ find "$1" -maxdepth 2 \( ! -user 0 -o -perm /022 \) -print -quit 2>/dev/null || echo "$1 (find failed)"; }   # fails closed

repo_git(){
  local uid gid
  uid="$(repo_git_owner %u)" gid="$(repo_git_owner %g)"
  if [ "$(id -u)" = 0 ] && [ "$uid" = 0 ]; then
    repo_git_root_safe || return 1
  fi
  if [ "$(id -u)" = 0 ] && [ "$uid" != 0 ]; then
    # safe.directory: the working tree's top may still belong to someone else (its contents are compared, never run)
    setpriv --reuid="$uid" --regid="$gid" --clear-groups --no-new-privs -- \
      env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      git -c safe.directory="$REPO" -c core.fsmonitor=false -c core.hooksPath=/dev/null --no-optional-locks -C "$REPO" "$@"
  else
    env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      git -c safe.directory="$REPO" -c core.fsmonitor=false -c core.hooksPath=/dev/null --no-optional-locks -C "$REPO" "$@"
  fi
}

# Refuse (return 1, saying why) a checkout that is not exactly its commit: a change to a tracked file, or ANY untracked
# file, listed with NO exclude rule (#404): a .gitignore, .git/info/exclude or an ignore file must not hide a file the
# build reads. `go build` compiles every .go file of a package directory, tracked or not, and this builder runs the
# checkout's Python AS ROOT (the root check, uki.py, debverify.py), so an untracked __pycache__/*.pyc whose recorded
# source mtime and size match would run as root in place of the reviewed source. Unlike the signer's check (uki.py
# Checkout.clean, which runs as the signer and allows bytecode), no bytecode is allowed here. A git that fails is
# never read as clean.
repo_git_clean(){
  local changed others
  changed="$(repo_git status --porcelain --untracked-files=all)" || {
    echo "build-initrd: git status failed on the checkout: it is not read as clean" >&2; return 1; }
  if [ -n "$changed" ]; then
    echo "build-initrd: the checkout has changes or untracked files: build from a clean clone at the agreed commit" >&2
    printf '%s\n' "$changed" | head -5 | sed 's/^/  /' >&2; return 1
  fi
  others="$(set -o pipefail; repo_git ls-files -z --others | tr '\0' '\n')" || {
    echo "build-initrd: git ls-files failed on the checkout: it is not read as clean" >&2; return 1; }
  if [ -n "$others" ]; then
    echo "build-initrd: the checkout holds untracked files that an ignore rule hides (bytecode included: the build runs the" \
         "checkout's Python as root): build from a fresh clone, or remove them (git clean -xdn lists them)" >&2
    printf '%s\n' "$others" | head -5 | sed 's/^/  /' >&2; return 1
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
