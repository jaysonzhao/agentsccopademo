import {spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
const [provider, model, agent='main']=process.argv.slice(2);
if(!provider || !model) throw new Error('Provide provider and served model ID');
const ref=provider+'/'+model;
function run(args, json=true) {
  const r=spawnSync(process.execPath,['/app/dist/index.js',...args],
    {encoding:'utf8',timeout:180000,maxBuffer:8*1024*1024,env:process.env});
  if(r.error || r.status!==0) throw new Error('OpenClaw '+args[0]+' failed; inspect privately for auth, pairing, model, timeout, or state errors');
  if(!json) return;
  try {return JSON.parse(r.stdout);} catch {throw new Error('Expected OpenClaw JSON; inspect the image/version privately');}
}
function requireTest(ok,name) {if(!ok) throw new Error('FAIL '+name); console.log('PASS '+name);}
requireTest(Boolean(process.env.OPENCLAW_MODEL_API_KEY),'P01 Secret is injected (value hidden)');
run(['config','validate'],false); console.log('PASS P02 OpenClaw config validation');
const catalog=run(['models','list','--provider',provider,'--json']);
requireTest((catalog.models??[]).some(m=>m.key===ref),'P03 model appears in OpenClaw catalog');
const status=run(['models','status','--agent',agent,'--json']);
requireTest(status.resolvedDefault===ref,'P04 expected effective primary model');
const nonce='OPENCLAW_PROVIDER_OK_'+randomUUID();
const turn=run(['agent','--agent',agent,'--model',ref,'--session-id','baseline-'+randomUUID(),
  '--message','Reply with exactly '+nonce+'. Do not use tools.','--timeout','120','--json']);
const result=turn.result??turn, meta=result.meta??{}, actual=meta.agentMeta??{};
requireTest(['ok','completed'].includes(turn.status) && turn.ok!==false && !meta.error && !meta.aborted,
  'P05 Gateway turn completed');
requireTest(actual.provider===provider && actual.model===model,'P06 actual provider/model match');
const reply=(result.payloads??[]).map(p=>p.text??'').join('\n');
requireTest(reply.includes(nonce),'P07 real model reply contains fresh test marker');
console.log('Verified through OpenClaw Gateway:',ref);
