#!/usr/bin/env bash
set -euo pipefail

[[ "$(uname -sm)" == "Linux x86_64" ]] || { echo 'OpenSpec requires the pinned Linux x64 Node archive' >&2; exit 1; }
runtime="$RUNNER_TEMP/openspec-ci"
tools="$GITHUB_WORKSPACE/tools/openspec-ci"
node_archive="$runtime/node-v24.22.3-linux-x64.tar.xz"
node="$runtime/node/bin/node"
npm="$runtime/node/lib/node_modules/npm/bin/npm-cli.js"

mkdir "$runtime"
mkdir "$runtime/cache" "$runtime/config" "$runtime/npm-cache"
curl -fsSL --proto '=https' --proto-redir '=https' --max-time 120 \
    https://nodejs.org/dist/v24.22.3/node-v24.22.3-linux-x64.tar.xz -o "$node_archive"
printf '%s  %s\n' 4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb "$node_archive" |
    sha256sum --check --strict
python3 -BEs -m tarfile -e "$node_archive" "$runtime" --filter data
mv "$runtime/node-v24.22.3-linux-x64" "$runtime/node"
node_version="$("$node" --version)"
[[ "$node_version" == v24.22.3 ]] || { echo 'OpenSpec Node version mismatch' >&2; exit 1; }

for key in $(compgen -e NPM_CONFIG_) $(compgen -e npm_config_); do unset "$key"; done
export NPM_CONFIG_USERCONFIG="$runtime/npm-userconfig" NPM_CONFIG_GLOBALCONFIG="$runtime/npm-globalconfig"
export NPM_CONFIG_CACHE="$runtime/npm-cache" NPM_CONFIG_UPDATE_NOTIFIER=false
export OPENSPEC_TELEMETRY=0 DO_NOT_TRACK=1 XDG_CACHE_HOME="$runtime/cache" XDG_CONFIG_HOME="$runtime/config"
: > "$NPM_CONFIG_USERCONFIG"
: > "$NPM_CONFIG_GLOBALCONFIG"

npm_version="$("$node" "$npm" --version)"
[[ "$npm_version" == 11.19.1 ]] || { echo 'OpenSpec npm version mismatch' >&2; exit 1; }
cp "$tools/package.json" "$tools/package-lock.json" "$runtime/"
cd "$runtime"
"$node" "$tools/check-lock.cjs" package.json package-lock.json
"$node" "$npm" ci --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/
openspec_version="$("$node" node_modules/@fission-ai/openspec/bin/openspec.js --version)"
[[ "$openspec_version" == 2.1.1 ]] ||
    { echo 'OpenSpec CLI version mismatch' >&2; exit 1; }
printf 'OpenSpec toolchain ready: Node v24.22.3, npm 11.19.1, OpenSpec 2.1.1\n'
