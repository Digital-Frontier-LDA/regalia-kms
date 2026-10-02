"""Run bounded cluster fault rounds and preserve each complete evidence report."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def summarize(report, seed, steps):
    from chaos_cases import schedule, KINDS
    expected = schedule(seed, steps)
    actions = report.get('chaos', {}).get('actions', [])
    if (report.get('status') != 'passed' or report.get('cleanup') != 'passed'
            or report.get('chaos', {}).get('seed') != seed
            or report.get('chaos', {}).get('steps') != steps or len(actions) != steps
            or not report.get('checks') or any(x.get('status') != 'passed' for x in report['checks'])):
        raise ValueError('cluster did not finish every check, fault, and cleanup')
    for index, (actual, planned) in enumerate(zip(actions, expected), 1):
        if (actual.get('status') != 'passed' or actual.get('step') != index
                or any(actual.get(key) != value for key, value in planned.items())):
            raise ValueError('fault evidence does not match the requested schedule')
    counts = Counter(action['kind'] for action in actions)
    if set(counts) != set(KINDS):
        raise ValueError('fault coverage is incomplete')
    return {'checks': len(report['checks']), 'faults': steps, 'coverage': dict(counts),
            'max_fault_seconds': max(x.get('elapsed_seconds', 0) for x in actions)}


def run(output, rounds, steps, seed, runner=None, timeout=7200):
    # Validate all work bounds before creating output or starting Docker.
    from chaos_cases import schedule
    if not 1 <= rounds <= 8 or not 60 <= timeout <= 7200:
        raise ValueError('round count or timeout outside lab bounds')
    for index in range(rounds):
        schedule(seed + index, steps)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    command = ['bash', str(HERE / 'run-cluster.sh')] if runner is None else [sys.executable, str(runner.resolve())]
    summary = {'schema': 'regalia.cluster-soak/v1', 'status': 'failed', 'rounds': [],
               'evidence_class': 'emulated-cluster', 'production_approved': False,
               'runner': command, 'runner_sha256': hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest()}
    started = time.monotonic()
    try:
        for index in range(rounds):
            current = seed + index
            destination = output / f'round-{index + 1:02d}'
            destination.mkdir()
            report_path = destination.resolve() / 'cluster-report.json'
            project = 'regalia-bootstrap-soak-' + os.urandom(8).hex()
            environment = dict(os.environ, REGALIA_CHAOS_SEED=str(current), REGALIA_CHAOS_STEPS=str(steps),
                               REGALIA_CLUSTER_REPORT=str(report_path), REGALIA_LAB_PROJECT=project)
            with (destination / 'console.log').open('wb') as console:
                process = subprocess.Popen(command, cwd=HERE.parents[1], env=environment,
                                           stdout=console, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=45)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    # Cleanup is confined to this round's random Compose project.
                    subprocess.run(['docker','compose','--project-name',project,'--file',
                                    str(HERE/'compose.network.yaml'),'down','--volumes','--remove-orphans'],
                                   env=environment, stdout=console, stderr=subprocess.STDOUT, timeout=45)
                    raise ValueError('round exceeded its time bound; cleanup attempted and failure retained')
            if report_path.exists():
                data = report_path.read_bytes()
                (destination / 'cluster-report.json').write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
            else:
                raise ValueError('cluster produced no report')
            item = {'seed': current, 'report_sha256': digest, 'exit_code': process.returncode, 'project': project}
            summary['rounds'].append(item)
            if process.returncode:
                raise ValueError('cluster command failed; retained evidence is not a passing round')
            item.update(summarize(json.loads(data), current, steps))
            print(f'Round {index + 1}: {steps} faults passed', flush=True)
        summary['status'] = 'passed'
    finally:
        summary['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'soak-report.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--steps', type=int, default=128)
    parser.add_argument('--seed', type=int, default=20261002)
    parser.add_argument('--timeout', type=int, default=7200)
    parser.add_argument('--runner', type=Path, help='explicit trusted development wrapper; its hash is recorded')
    args = parser.parse_args()
    try:
        print(json.dumps(run(**vars(args)), indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'FAILED: {error}\n')


if __name__ == '__main__':
    main()
