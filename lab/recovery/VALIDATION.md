# Recovery matrix checkpoint — 2026-10-02

Real cryptsetup 2.7.5 on native Debian arm64, using disposable 32 MiB regular-file
LUKS2 fixtures. The Docker tools image is unsigned development infrastructure;
its identifier and exact report/script hashes are in [validation-summary.json](validation-summary.json).
The container used `--init`, no capabilities, no new privileges, a read-only
source mount, and private temporary storage. No host disks, keys or TPM were used.

| Target | Reached scenarios | Finding cases | Retry still needs repair | False unchanged claims |
|---|---:|---:|---:|---:|
| main `098ec6d` | 152 / 152 | 46 | 46 | 7 |
| proposed #170 `2fda5946beb51b9de0322d019182fba0a00da749` | 582 / 582 | 174 | 68 | 0 |

Both runs completed **with findings** and exited 1. Neither grants release
admission. The proposed script has more command/cleanup paths; comparing raw
finding totals between scripts is not a regression ranking.

Every scenario preserved normal boot access through the installer key and, for
replacement, at least one old/new recovery key. This checks a generic unlock,
in addition to explicitly selecting individual slots; an ignored slot cannot
count as a working normal boot path. Every explicit laboratory reconciliation
ended with one normal-priority recovery mapping and preserved installer access.
The laboratory operator has all disposable keys. Its repair is not a production
custody decision or permission to delete operational slots.

The matrix covers failure before/after each cryptsetup call, TERM after, KILL
before/after, closed stderr, and interruptions in cleanup following each single
command failure. It does not cover arbitrary libcryptsetup sector writes,
recursive combinations of failures, physical power loss, or hardware custody.
The existing script and #170 were observed without modification. #175's custody
and production reconciliation redesign remains open.

Full reports are retained locally in `/tmp/regalia-recovery-evidence/main-final.json`
and `pr170-final.json`, with hashes recorded in the summary. CI uploads its own
full report even when findings fail the job. Findings must remain visible.

## Merged-script checkpoint

After #170 merged, main `55b8600` was observed with real cryptsetup 2.7.5:
**622/622 scenarios reached**, 172 finding cases, all ordinary unlock paths and
explicit laboratory repairs preserved. This supersedes earlier results as the
current-main observation; historical reports remain tied to their original
script versions. Exact report SHA-256: `d9a9e37f8ca54dfaa82e8512aabccdb5328e8a290e55f7cd52eaa50ad5dd3148`.
Script SHA-256: `47e08272c808863fff8b524faa5146620e3375db7af5810ffa20aacb6e77afab`.

The larger merged script has additional command paths. CI allowed 30 minutes (75 since the per-sync faults of #175)
for complete coverage; incomplete runs and findings still fail.

## #175 checkpoint (2026-10-03)

The script rewritten for #175, run against the extended matrix on cryptsetup 2.7.5 (Debian 13 amd64,
file-backed images, no root). **Passed: 337/337 scenarios reached, 0 findings.** It covers every call
× fail before/after, TERM after and KILL before/after, plus closed stderr, the header-writing calls
after each single failure, and every header sync × KILL, TERM and EIO:

| Mode | Syncs per call |
|---|---|
| enrol | `luksAddKey` 3, `token import` 2 |
| replace | `luksAddKey` 3, `token import` 2, `luksKillSlot` 3, `token remove` 2 |

In 81 cases the header right after the fault was changed and not clean. Each is recorded as an
observation, and the identical retry ended clean in every one. In every case the printed `STATE`
was the header's.

An earlier run found one case: replace, `luksKillSlot`, sync 1, KILL. luksKillSlot wipes the key
material before it updates the metadata, and the retry refused the listed but spent keyslot. That
is fixed in the script and covered by a unit test.

Script SHA-256: `676c5ada5d44b8fffb0724eccfd2bf8c71fa441059a2d79732b2dfc9d342cb1b`. Report SHA-256:
`628e99169a93d7f9843f2e60360598d8d5a064cbaaa28c3a2bb0cce99031781b`. The run took 61 minutes on two
CPUs.

**Superseded by d9's read of #236 (same day).** The 337/337 run above predates:
- the expected-key check (a retry must leave the right key, not only a clean shape);
- the TPM stand-in;
- level 2 (faults in the run that resumes each unfinished header);
- proof that every sync fault fired;
- `recovery-reconcile.py` as the repair.

Under all of them, one replace shard (1/8) on cryptsetup 2.7.5 passed 110/110: 24 level-1 cases and 86 level-2 cases, 0 findings, every fault proven fired. Its first run caught a harness defect, now fixed: observing an image let cryptsetup repair a stale secondary header before the run (see README, "Observing never touches a run's image"). The full result is CI's merged report of 2 modes × 8 shards on cryptsetup 2.7.0, recorded on #236.
