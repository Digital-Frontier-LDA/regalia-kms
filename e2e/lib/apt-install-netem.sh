#!/usr/bin/env bash
# apt-install-netem.sh PACKAGE… — install PACKAGE… with apt, plus the running kernel's linux-modules-extra only when the
# kernel's base modules lack sch_netem, then check that netem is there (regalia-1ur).
#
# The hosted runner's kernel can be ahead of the archive's linux-modules-extra: 7.0.0-1017-azure on ubuntu-24.04 since
# 2026-10-21, for which apt has no linux-modules-extra package. Installing it unconditionally fails the job before any
# test runs (#609's three-node-wan, run 40506387532). ci.yml's wg-boot-netns and node-units.yml's jobs share this one
# step, so the two cannot drift apart again. It prints the kernel and where netem came from; when neither the base
# modules nor an installable extra package has it, it fails here, naming the kernel, rather than in the loss case.
set -euo pipefail
[ "$#" -gt 0 ] || { echo "usage: apt-install-netem.sh PACKAGE…" >&2; exit 2; }
kernel="$(uname -r)"
sudo apt-get update -qq
extra=()
if base="$(modinfo -F filename sch_netem 2>/dev/null)" && [ -n "$base" ]; then
  echo "kernel $kernel: sch_netem in the base modules ($base)"
else
  extra=("linux-modules-extra-$kernel")
  echo "kernel $kernel: sch_netem not in the base modules, installing ${extra[0]}"
fi
# ${extra[@]+…}: an empty array is unbound under set -u in bash before 4.4 (macOS has 3.2)
rc=0
sudo apt-get install -y -qq --no-install-recommends "$@" ${extra[@]+"${extra[@]}"} || rc=$?
[ "$rc" -eq 0 ] || { echo "kernel $kernel: apt-get install failed (exit $rc)${extra[0]+, with ${extra[0]} asked for}" >&2; exit "$rc"; }
where="$(modinfo -F filename sch_netem 2>/dev/null)" || where=""
[ -n "$where" ] || { echo "kernel $kernel: sch_netem is still missing after the install" >&2; exit 1; }
echo "kernel $kernel: sch_netem is $where"
