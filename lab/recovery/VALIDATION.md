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
