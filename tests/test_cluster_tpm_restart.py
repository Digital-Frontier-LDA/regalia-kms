"""A cold emulator restart must wait for outstanding quote/unseal commands."""
from pathlib import Path
import subprocess
import importlib.util
import tempfile
import threading
import unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('regalia_tpm_fixture', Path(__file__).resolve().parents[1]/'lab/bootstrap/lab.py')
tpm_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tpm_module)
TPM = tpm_module.TPM


class TPMRestart(unittest.TestCase):
    def test_restart_waits_for_command_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            tpm=TPM(Path(directory),'test')
            running, finish, closed=threading.Event(),threading.Event(),threading.Event()
            errors=[]
            def tool(*args,**kwargs):
                running.set()
                if not finish.wait(3): raise TimeoutError('fixture never released')
                return subprocess.CompletedProcess(args,0,b'',b'')
            def invoke():
                try: tpm.call('tpm2_quote')
                except BaseException as error: errors.append(error)
            with patch.object(tpm_module,'run',side_effect=tool),patch.object(tpm,'close',side_effect=closed.set),patch.object(tpm,'start'):
                first=threading.Thread(target=invoke);first.start()
                self.assertTrue(running.wait(1))
                second=threading.Thread(target=tpm.restart);second.start()
                self.assertFalse(closed.wait(.1),'restart interrupted the live command')
                finish.set();first.join(2);second.join(2)
                self.assertFalse(first.is_alive());self.assertFalse(second.is_alive())
                self.assertTrue(closed.is_set());self.assertEqual(errors,[])
