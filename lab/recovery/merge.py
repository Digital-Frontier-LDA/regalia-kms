"""Merge the sharded matrix reports (#175) and check them as one run.

Fails unless: every expected shard of every mode is present and passed, all shards of a mode agree
on the level-1 total, the full scenario list and the sync table (one script, one cryptsetup), and the
scenarios they ran are disjoint and together exactly that list. Prints the merged summary.
"""
import argparse
import json
from pathlib import Path


def merge(paths, shards, modes=('enrol', 'replace')):
    reports = [json.loads(Path(p).read_text()) for p in paths]
    problems, summary = [], {'modes': {}, 'cryptsetup': sorted({r.get('cryptsetup') for r in reports}),
                             'script_sha256': sorted({r.get('script_sha256') for r in reports})}
    if len(summary['script_sha256']) != 1: problems.append('the shards ran different scripts')
    if len(summary['cryptsetup']) != 1: problems.append('the shards ran different cryptsetup versions')
    for mode in modes:
        mine = [r for r in reports if mode in r.get('first_level_total', {})]
        seen = sorted(r.get('shard') for r in mine)
        expected = ['%d/%d' % (i, shards) for i in range(1, shards + 1)]
        if seen != expected: problems.append('%s: shards %s, expected %s' % (mode, seen, expected))
        totals = {r['first_level_total'][mode] for r in mine}
        tables = {json.dumps(r.get('syncs', {}).get(mode), sort_keys=True) for r in mine}
        if len(totals) != 1: problems.append('%s: the shards disagree on the level-1 total: %s' % (mode, sorted(totals)))
        if len(tables) != 1: problems.append('%s: the shards disagree on the sync table' % mode)
        # Which scenarios ran, not only how many (d9): disjoint per shard, and together the full list.
        full = {json.dumps(r.get('first_level_all_ids', {}).get(mode)) for r in mine}
        if len(full) != 1: problems.append('%s: the shards disagree on the full scenario list' % mode)
        ran = [i for r in mine for i in r.get('first_level_ids', {}).get(mode, [])]
        if len(ran) != len(set(ran)): problems.append('%s: a scenario ran in more than one shard' % mode)
        expected_ids = set(json.loads(next(iter(full))) or []) if len(full) == 1 else set()
        if set(ran) != expected_ids:
            problems.append('%s: %d scenarios not run, %d run that are not in the list' % (mode, len(expected_ids - set(ran)), len(set(ran) - expected_ids)))
        executed = sum(r.get('first_level_executed', {}).get(mode, 0) for r in mine)
        total = next(iter(totals)) if totals else None
        if executed != total: problems.append('%s: level 1 ran %d of %s scenarios' % (mode, executed, total))
        failed = [r.get('shard') for r in mine if r.get('status') != 'passed']
        if failed: problems.append('%s: shards %s did not pass' % (mode, failed))
        syncs = json.loads(next(iter(tables))) if len(tables) == 1 else None
        if not syncs or any(not counts or min(counts) < 1 for counts in syncs.values()):
            problems.append('%s: no header sync was counted for a header-writing call: %s' % (mode, syncs))
        summary['modes'][mode] = {
            'level1_total': total, 'level1_executed': executed,
            'level2_executed': sum(r.get('second_level_executed', {}).get(mode, 0) for r in mine),
            'level2_baselines': sum(r.get('second_level_baselines', {}).get(mode, 0) for r in mine),
            'findings': sum(r.get('finding_cases', 0) for r in mine), 'syncs': syncs,
            'observations': sum(r.get('observations', {}).get('header_needs_reconciliation', 0) for r in mine)}
    summary['status'] = 'passed' if not problems else 'failed'
    summary['problems'] = problems
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shards', type=int, required=True)
    parser.add_argument('reports', nargs='+')
    args = parser.parse_args()
    summary = merge(args.reports, args.shards)
    print(json.dumps(summary, indent=2))
    if summary['status'] != 'passed': raise SystemExit(1)


if __name__ == '__main__':
    main()
