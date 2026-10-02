"""Apply explicit fixture card selections to every interrupted legacy operation.

This is a laboratory custodian oracle with all fixture cards. No production
slot/card selection policy is inferred from these fixtures.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def run(script, reconciler, output):
    original=script.read_bytes(); repair_source=reconciler.read_bytes()
    observer=load('observer',Path(__file__).with_name('matrix.py'))
    with tempfile.TemporaryDirectory(prefix='regalia-operator-proof-') as temp:
        root=Path(temp);legacy=root/'legacy.sh';legacy.write_bytes(original)
        tool=root/'reconcile.py';tool.write_bytes(repair_source)
        repair=load('repair',tool)
        def selected(executable,image,values,state):
            repair.CRYPTSETUP=executable
            candidates=state['opens_slots']['new'] or state['opens_slots']['old']
            if not candidates:return False
            keep=candidates[0]
            kept=values['new'] if state['opens_slots']['new'] else values['old']
            retired=[];cards=[]
            for slot in state['keyslots']:
                if slot in ('0',keep):continue
                named=[name for name in ('old','new') if slot in state['opens_slots'][name]]
                if not named:raise ValueError('fixture custodian cannot prove requested retirement')
                retired.append(slot);cards.append(values[named[0]])
            repair.reconcile(image,keep,retired,kept,cards)
            after=observer.observe(executable,image,values)
            return (observer.clean_recovery(after) and after['opens_boot']['installer']
                    and (after['opens_boot']['old'] or after['opens_boot']['new']))
        observer.reconcile_fixture=selected
        observed=observer.run(legacy,output)
    result={'schema':'regalia.explicit-operator-matrix/v1','status':'passed',
            'reconciler_sha256':hashlib.sha256(repair_source).hexdigest(),
            'legacy_sha256':hashlib.sha256(original).hexdigest(),
            'legacy_report_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
            'legacy_status':observed['status'],'legacy_finding_cases':observed['finding_cases'],
            'scenarios':observed['cases_executed'],'fault_points_reached':observed['fault_points_reached'],
            'all_explicit_repairs_clean':all(c['fixture_reconciliation_clean'] for c in observed['cases']),
            'all_unlock_paths_preserved':all(c['unlock_available'] for c in observed['cases']),
            'production_approved':False,'release_admissible':False}
    if not result['all_explicit_repairs_clean'] or not result['all_unlock_paths_preserved']:
        raise ValueError('fixture reconciliation not proven')
    output.with_name(output.stem+'-operator-summary.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script',type=Path,required=True)
    parser.add_argument('--reconciler',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(run(**vars(args)),indent=2))
