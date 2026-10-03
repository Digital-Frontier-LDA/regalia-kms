"""Run the repository's lab commands with an isolated Python interpreter."""
import sys

COMMANDS = {
    'appliance-build': 'lab.appliance.build',
    'appliance-probe': 'lab.appliance.probe',
    'appliance-scan': 'lab.appliance.scan_build',
    'appliance-scan-docker': 'lab.appliance.scan_docker',
    'appliance-collect': 'lab.appliance.collect',
    'bootstrap-soak': 'lab.bootstrap.soak',
}

def main():
    if not sys.flags.isolated:
        sys.exit('REFUSED: use python3 -I tools/lab_cli.py COMMAND ...')
    import pathlib
    import runpy
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        sys.exit('Usage: python3 -I tools/lab_cli.py {' + ','.join(sorted(COMMANDS)) + '} ...')
    # The physical repository is trusted code. Append it after standard libraries
    # and installed dependencies; never use cwd, PYTHONPATH or an argv path.
    root = pathlib.Path(__file__).resolve().parents[1]
    sys.path.append(str(root))
    module = COMMANDS[sys.argv[1]]
    sys.argv = [module, *sys.argv[2:]]
    runpy.run_module(module, run_name='__main__')


if __name__ == '__main__':
    main()
