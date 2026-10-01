#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p .artifacts
export REGALIA_LAB_UID="$(id -u)" REGALIA_LAB_GID="$(id -g)"
export REGALIA_LAB_COMMIT="$(git rev-parse HEAD)"
export REGALIA_LAB_PLATFORM="${REGALIA_LAB_PLATFORM:-$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')}"
# The task-specific platform is authoritative even when the developer's shell
# forces unrelated projects to amd64 through DOCKER_DEFAULT_PLATFORM.
env -u DOCKER_DEFAULT_PLATFORM docker compose build
env -u DOCKER_DEFAULT_PLATFORM docker compose run --rm lab
