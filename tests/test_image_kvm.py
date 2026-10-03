"""A QEMU zero exit is insufficient: preflight must confirm initialized KVM."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = (ROOT / 'lab/appliance/ci-kvm.sh').read_text().split("-- python3 -I - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
# This producer emulates QMP only. It cannot qualify an actual KVM host.
PRODUCER = '''import json,os,pathlib,socket,sys
pathlib.Path(os.environ['REGALIA_PROBE_PID']).write_text(str(os.getpid()))
mode=os.environ['REGALIA_PROBE_CASE']
if mode=='early_exit': sys.exit(0)
path=sys.argv[sys.argv.index('-qmp')+1].split(',')[0][5:]
with socket.socket(socket.AF_UNIX) as server:
 server.bind(path);server.listen(1)
 connection,_=server.accept()
 with connection,connection.makefile('rwb') as stream:
  stream.write(b'{"QMP":{}}\\n');stream.flush()
  while True:
   line=stream.readline()
   if not line: break
   command=json.loads(line)['execute']
   with open(os.environ['REGALIA_PROBE_COMMANDS'],'a') as record: record.write(command+'\\n')
   values={'qmp_capabilities':{},'query-kvm':{'enabled':mode!='disabled','present':True},
           'query-cpus-fast':[] if mode=='no_cpu' else [{'cpu-index':0}],
           'query-status':{'status':'running' if mode=='running' else 'prelaunch'},'quit':{}}
   result={'error':{'class':'GenericError'}} if mode=='error' else {'return':values[command]}
   stream.write(json.dumps(result).encode()+b'\\n');stream.flush()
   if command=='quit': break
'''


class KVMPreflightTests(unittest.TestCase):
    def probe(self, mode, optimize=False):
        with tempfile.TemporaryDirectory(prefix='regalia-kvm-test-') as directory:
            folder = Path(directory)
            executable = folder / 'qemu-system-x86_64'
            executable.write_text('#!' + sys.executable + '\n' + PRODUCER)
            executable.chmod(0o700)
            pid, commands = folder / 'child.pid', folder / 'commands'
            env = dict(os.environ, PATH=str(folder) + os.pathsep + os.environ['PATH'],
                       REGALIA_PROBE_CASE=mode, REGALIA_PROBE_PID=str(pid),
                       REGALIA_PROBE_COMMANDS=str(commands))
            # Only the device-access predicate is simulated; the real child,
            # Unix socket, QMP sequence and cleanup run unchanged.
            code = "import os\nos.access=lambda path,mode: True\n" + PROBE
            args = [sys.executable] + (['-O'] if optimize else []) + ['-c', code]
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)
            if pid.exists():
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pid.read_text()), 0)
            observed = commands.read_text().splitlines() if commands.exists() else []
            return result, observed

    def test_initialized_paused_kvm_cpu_and_clean_shutdown_succeed(self):
        result, commands = self.probe('ok')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(commands, ['qmp_capabilities', 'query-kvm', 'query-cpus-fast', 'query-status', 'quit'])

    def test_zero_exit_before_kvm_initialization_is_refused(self):
        result, _ = self.probe('early_exit')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('before KVM initialization', result.stderr)

    def test_disabled_kvm_is_refused_even_with_python_optimization(self):
        result, commands = self.probe('disabled', optimize=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('KVM is not active', result.stderr)
        self.assertNotIn('quit', commands)

    def test_missing_cpu_running_machine_and_qmp_error_are_refused(self):
        for mode in ['no_cpu', 'running', 'error']:
            with self.subTest(mode=mode):
                result, _ = self.probe(mode)
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
