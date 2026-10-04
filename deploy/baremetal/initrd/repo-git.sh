# shellcheck shell=bash
# repo-git.sh — sourced by build-initrd.sh: read the checkout with git, never letting the checkout run a command
# as root (#382).
#
# build-initrd.sh runs as root (mmdebstrap), on a checkout that is normally another user's clone. The checkout's
# own configuration can make git run commands: a clean filter that `git status` runs on files whose stat data
# changed, textconv, fsmonitor, hooks, includes pulling in more of the same. Two rules:
#   1. git runs as the checkout's OWNER (setpriv, a cleared environment, no supplementary groups, no new
#      privileges), never as root, so anything the checkout makes git run has only that user's rights;
#   2. a checkout whose local configuration or .gitattributes could make git run anything is refused before git
#      reads its tree at all (repo_git_check), so nothing of it runs in the first place.
# The global and system configurations are not read (GIT_CONFIG_GLOBAL=/dev/null, GIT_CONFIG_NOSYSTEM=1).
#
#   REPO=/path/to/checkout; . repo-git.sh; repo_git_check || exit; repo_git rev-parse HEAD

# configuration keys (lower case, as `git config --list` prints them) that name a command or pull in more config
REPO_GIT_REFUSED='^(filter\.|diff\.[^=]*\.(textconv|command)=|merge\.[^=]*\.driver=|core\.(fsmonitor|hookspath|sshcommand|pager|editor|askpass|gitproxy|attributesfile|excludesfile)=|include\.|includeif\.|credential\.|alias\.|uploadpack\.|receive\.|sequence\.editor=|gpg\.|pager\.)'

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

# Refuse (return 1, saying why) a checkout whose local configuration or tracked .gitattributes could make git run a
# command. Reading the configuration runs nothing: --list only prints it.
repo_git_check(){
  local bad attrs
  bad="$(repo_git config --local --no-includes --list 2>/dev/null | tr '[:upper:]' '[:lower:]' | grep -E "$REPO_GIT_REFUSED" | cut -d= -f1 | sort -u | tr '\n' ' ')"
  if [ -n "$bad" ]; then
    echo "build-initrd: the checkout's own git configuration could run a command ($bad): build from a clone without it (#382)" >&2
    return 1
  fi
  attrs="$(find "$REPO" -name .gitattributes -not -path "$REPO/.git/*" -type f -exec grep -lE '(^|[[:space:]])-?(filter|diff|merge)(=|[[:space:]]|$)' {} + 2>/dev/null | sed "s|^$REPO/||" | tr '\n' ' ')"
  if [ -n "$attrs" ]; then
    echo "build-initrd: .gitattributes names a filter, diff or merge driver ($attrs): build from a clone without it (#382)" >&2
    return 1
  fi
  if [ -e "$REPO/.git/info/attributes" ] && grep -qE '(filter|diff|merge)' "$REPO/.git/info/attributes"; then
    echo "build-initrd: .git/info/attributes names a filter, diff or merge driver: build from a clone without it (#382)" >&2
    return 1
  fi
}
