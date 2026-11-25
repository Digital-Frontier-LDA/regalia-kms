# OpenSpec reference checks in build-test

The workflow reserves `.openspec-product-source` at the tail of build-test.
The pinned checkout action prepares a separate, shallow checkout of the
literal product commit in that directory with credential persistence disabled.
`check-source.sh verify` checks the expected commit, its type and tree, and
the primary workspace HEAD. Preflight and the checker require local Git
objects and disable replacement objects, prompts, lazy fetch and transports.
A missing object fails the job. The primary workspace supplies the OpenSpec
snapshot and its candidate-test and external-cache data.

The job uses Python 3.14.7 and a checksum-pinned Linux x64 Node 24.22.3
archive with bundled npm 11.19.1. The npm v3 lock pins OpenSpec 2.1.1
and YAML 2.9.1 for YAML 1.2 workflow parsing. The install uses task-local
config and cache directories and disables npm lifecycle scripts.

The last step runs strict OpenSpec validation, the focused Python and YAML
wiring tests, and the reference checker. Any failed phase fails build-test.
The checker JSON must report integrity and the expected product revision and
tree. Verification authority remains unassessed and coverage remains open.
