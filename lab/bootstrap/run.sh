#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p .artifacts
export REGALIA_LAB_UID="$(id -u)" REGALIA_LAB_GID="$(id -g)"
export REGALIA_LAB_COMMIT="$(git rev-parse HEAD)"
export REGALIA_LAB_PLATFORM="${REGALIA_LAB_PLATFORM:-$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')}"
docker compose build
docker compose run --rm lab
