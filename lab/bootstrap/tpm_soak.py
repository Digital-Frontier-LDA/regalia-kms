"""Prove policy-bound TPM bootstrap remains available after repeated unorderly starts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
from concurrent.futures import ThreadPoolExecutor
import yaml
from lab import TPM, tpm_refused, verify_quote


def exercise(cycles):
    if not 4 <= cycles <= 256:
        raise ValueError('cycle count outside lab bounds')
    report={'schema':'regalia.tpm-restart-soak/v1','status':'failed','production_approved':False,
            'evidence_class':'emulated','cycles_completed':0,
            'source_sha256':hashlib.sha256(Path(__file__).with_name('lab.py').read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix='regalia-tpm-soak-') as directory:
        tpm=TPM(Path(directory),'restart')
        def counters():
            values=yaml.safe_load(tpm.call('tpm2_getcap','properties-variable').stdout)
            return {key:values[key] for key in ('TPM2_PT_LOCKOUT_COUNTER','TPM2_PT_MAX_AUTH_FAIL',
                                               'TPM2_PT_LOCKOUT_INTERVAL','TPM2_PT_LOCKOUT_RECOVERY')}
        try:
            tpm.start();tpm.prepare_storage()
            wireguard,local=os.urandom(45),os.urandom(32)
            tpm.seal('wg',wireguard,'0x81010004');tpm.seal('local',local,'0x81010005')
            report['initial_counters']=counters()
            # Deliberately fault this disposable DA-protected storage parent.
            # This proves bootstrap still works while GLOBAL DA enforcement is
            # active; no reset, enlarged budget, or timer change can hide it.
            maximum = report['initial_counters']['TPM2_PT_MAX_AUTH_FAIL']
            if not 1 <= maximum <= 16: raise RuntimeError('unexpected fixture DA budget')
            for _ in range(maximum):
                refusal = tpm.call('tpm2_load','-C','0x81010003','-P','hex:01020304',
                    '-u',tpm.root/'wg.pub','-r',tpm.root/'wg.priv','-c',tpm.root/'denied.ctx',
                    required=False)
                tpm_refused(refusal,0x98E,expected_exit=3)
            report['locked_counters'] = counters()
            if report['locked_counters']['TPM2_PT_LOCKOUT_COUNTER'] < maximum:
                raise RuntimeError('fixture did not enter DA lockout')
            for index in range(cycles):
                challenges=[os.urandom(32),os.urandom(32)]
                with ThreadPoolExecutor(max_workers=2) as pool:
                    jobs=[pool.submit(tpm.quote,value,f'quote-{index}-{n}') for n,value in enumerate(challenges)]
                    for job,challenge in zip(jobs,challenges):
                        paths=job.result()
                        if not verify_quote(tpm.root/'ak.pem',paths,challenge,tpm.root/'approved.pcr'):
                            raise RuntimeError('fresh quote did not verify against the enrolled identity and PCRs')
                        if verify_quote(tpm.root/'ak.pem',paths,os.urandom(32)):
                            raise RuntimeError('replayed quote accepted under a different challenge')
                        for path in paths:path.unlink()
                tpm.call('tpm2_pcrextend','7:sha256='+os.urandom(32).hex())
                tpm_refused(tpm.unseal('0x81010004'),0x99D)
                # Deliberately no TPM2_Shutdown: this models an unorderly restart.
                tpm.restart()
                if tpm.unseal('0x81010004').stdout != wireguard or tpm.unseal('0x81010005').stdout != local:
                    raise RuntimeError('bootstrap contributions changed after a cold restart')
                tpm_refused(tpm.call('tpm2_unseal','-c','0x81010005',required=False),0x12F)
                report['cycles_completed']=index+1
            # A DA-protected object must still refuse, while noDA quotes and
            # PCR-only unsealing have succeeded for every preceding cycle.
            refusal = tpm.call('tpm2_load','-C','0x81010003','-u',tpm.root/'wg.pub',
                '-r',tpm.root/'wg.priv','-c',tpm.root/'denied.ctx',required=False)
            tpm_refused(refusal,0x921)
            final=counters();report['final_counters']=final
            initial=report['initial_counters']
            if (final['TPM2_PT_LOCKOUT_COUNTER'] < final['TPM2_PT_MAX_AUTH_FAIL']
                    or any(final[key] != initial[key] for key in initial if key != 'TPM2_PT_LOCKOUT_COUNTER')):
                raise RuntimeError('DA threshold was not exercised or global protections changed')
            report.update(status='passed',ak_attributes=tpm.ak_attributes,sealed_object_attributes=tpm.sealed_attributes)
        except Exception as error:
            report["failure_class"] = type(error).__name__
            report["tpm_failures"] = list(tpm.failures)
        finally:
            tpm.close()
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cycles',type=int,default=100)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    report=exercise(args.cycles)
    if args.output:args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if report["status"] != "passed": raise SystemExit(1)

if __name__=='__main__':main()
