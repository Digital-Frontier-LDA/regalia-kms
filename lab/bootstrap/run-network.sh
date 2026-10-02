#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p .artifacts
export REGALIA_LAB_COMMIT="$(git rev-parse HEAD)"
export REGALIA_LAB_DAEMON_PLATFORM="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')"
export REGALIA_LAB_PLATFORM="${REGALIA_LAB_PLATFORM:-$REGALIA_LAB_DAEMON_PLATFORM}"
if [[ "$REGALIA_LAB_PLATFORM" != "$REGALIA_LAB_DAEMON_PLATFORM" ]]; then
  export REGALIA_LAB_SWTPM_SECCOMP="${REGALIA_LAB_SWTPM_SECCOMP:-none}"
else
  export REGALIA_LAB_SWTPM_SECCOMP="${REGALIA_LAB_SWTPM_SECCOMP:-kill}"
fi
env -u DOCKER_DEFAULT_PLATFORM docker compose --file compose.network.yaml build
export REGALIA_LAB_IMAGE_ID="$(docker image inspect regalia-bootstrap-mesh:dev --format '{{.Id}}')"
env -u DOCKER_DEFAULT_PLATFORM python3 mesh.py
