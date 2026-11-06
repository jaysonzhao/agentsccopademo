import json, os, subprocess, sys
from pathlib import Path
out=Path(os.environ['OPENCLAW_OUT']); cases=json.loads((out/'demos/catalog.json').read_text())
layer=sys.argv[1] if len(sys.argv)>1 else 'all'
assert layer in {'scc','gatekeeper','all'}
constraint=os.environ['OPENCLAW_NS']+'-baseline'
for case in cases:
    if layer!='all' and case['layer']!=layer: continue
    r=subprocess.run(['oc','create','--dry-run=server','-f',str(out/'demos'/case['file']),'-o','name'],capture_output=True,text=True)
    evidence=r.stderr+r.stdout
    if case['expected']=='allow':
        passed=r.returncode==0
    elif case['layer']=='gatekeeper':
        passed=(r.returncode!=0 and 'admission webhook' in evidence and constraint in evidence and case['reason'] in evidence)
    else:
        passed=(r.returncode!=0 and ('security context constraint' in evidence.lower() or 'unable to validate against any' in evidence.lower()))
    print(('PASS' if passed else 'FAIL'),case['name'],case['expected'])
    (out/'demos'/(case['name']+'.evidence.txt')).write_text(evidence)
    if not passed:
        print(evidence); sys.exit('Stop: an unexpected failure is not a successful denial test')
print('Admission demonstration complete; no test pods were created')
