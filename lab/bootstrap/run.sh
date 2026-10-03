#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p .artifacts
python3 -Es ../../deploy/images/inventory.py > .artifacts/image-inputs.json
export REGALIA_LAB_UID="$(id -u)" REGALIA_LAB_GID="$(id -g)"
export REGALIA_LAB_COMMIT="$(git rev-parse HEAD)"
export REGALIA_LAB_DAEMON_PLATFORM="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')"
export REGALIA_LAB_PLATFORM="${REGALIA_LAB_PLATFORM:-$REGALIA_LAB_DAEMON_PLATFORM}"
# swtpm's extra syscall filter cannot be installed by amd64 translation on this
# arm64 Docker VM. Docker's own sandbox is still applied to the whole container.
if [[ "$REGALIA_LAB_PLATFORM" != "$REGALIA_LAB_DAEMON_PLATFORM" ]]; then
  export REGALIA_LAB_SWTPM_SECCOMP="${REGALIA_LAB_SWTPM_SECCOMP:-none}"
else
  export REGALIA_LAB_SWTPM_SECCOMP="${REGALIA_LAB_SWTPM_SECCOMP:-kill}"
fi
# The task-specific platform is authoritative even when the developer's shell
# forces unrelated projects to amd64 through DOCKER_DEFAULT_PLATFORM.
env -u DOCKER_DEFAULT_PLATFORM docker compose build
export REGALIA_LAB_IMAGE_ID="$(docker image inspect regalia-bootstrap-lab:dev --format '{{.Id}}')"
env -u DOCKER_DEFAULT_PLATFORM docker compose run --rm lab
