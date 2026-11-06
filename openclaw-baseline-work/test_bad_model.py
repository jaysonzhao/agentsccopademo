import json, subprocess, time
from pathlib import Path

ns='openclaw-baseline'
pod=subprocess.check_output(['oc','-n',ns,'get','pods','-l','app=openclaw','-o','jsonpath={.items[0].metadata.name}'],text=True).strip()
model='minimax/baseline-does-not-exist-'+str(int(time.time()))
cmd=['oc','-n',ns,'exec',pod,'-c','gateway','--','node','/app/dist/index.js','agent',
     '--agent','main','--model',model,'--session-id','bad-model-'+str(int(time.time())),
     '--message','Reply OK. Do not use tools.','--timeout','120','--json']
try:
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=180)
except subprocess.TimeoutExpired:
    print('BLOCKED P08: CLI timed out')
    Path('provider-bad-model.evidence.txt').write_text('BLOCKED P08: CLI timed out; no raw output saved.\n')
    raise SystemExit(2)
combined=(r.stdout+'\n'+r.stderr).lower()
needles=('unknown model','model not found','model unavailable','not in catalog','unavailable model','cannot resolve model','invalid model')
passed=r.returncode!=0 and any(s in combined for s in needles)
if passed:
    Path('provider-bad-model.evidence.txt').write_text('PASS P08: nonexistent model override returned a nonzero result with an explicit model-selection error. Raw output suppressed.\n')
    print('PASS P08 bad model rejected for an explicit model-selection reason')
else:
    status='BLOCKED' if ('sccexecrestrictions' in combined or 'timeout' in combined or 'unable to connect' in combined) else 'FAIL'
    Path('provider-bad-model.evidence.txt').write_text(f'{status} P08: did not observe an explicit model-selection rejection; return code {r.returncode}. Raw output suppressed.\n')
    print(f'{status} P08: no explicit model-selection rejection observed; raw output suppressed')
    raise SystemExit(1)
