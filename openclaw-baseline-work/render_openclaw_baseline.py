import copy, json, os, re, subprocess
from pathlib import Path
import yaml

ns = os.environ['OPENCLAW_NS']
host = os.environ['OPENCLAW_ROUTE_HOST']
storage = os.environ['OPENCLAW_STORAGE_CLASS']
src = Path(os.environ['OPENCLAW_SOURCE'])/'agents/openclaw/deployment/manifests'
out = Path(os.environ['OPENCLAW_OUT'])
pin = '45c37a7ae223ebbf02626ae54ad43ab8a3bacb2f'
assert subprocess.check_output(['git','-C',os.environ['OPENCLAW_SOURCE'],'rev-parse','HEAD'],text=True).strip() == pin
assert re.fullmatch(r'[a-z0-9](?:[-a-z0-9]*[a-z0-9])?',ns) and len(ns) < 45
assert re.fullmatch(r'[a-z0-9][a-z0-9.-]+[a-z0-9]',host)
assert storage and not out.exists(), 'Use a fresh output directory; do not overwrite a reviewed deployment'
out.mkdir(parents=True)
sa = 'openclaw-agent'
scc_name = ns+'-restricted'
def load(name): return yaml.safe_load((src/name).read_text())
def dump(name, docs):
    (out/name).write_text(yaml.safe_dump_all(docs,sort_keys=False))
def resource(api,kind,name,spec=None):
    d={'apiVersion':api,'kind':kind,'metadata':{'name':name,'namespace':ns}}
    if spec is not None: d['spec']=spec
    return d

d=load('04-deployment.yaml'); d['metadata']['namespace']=ns
p=d['spec']['template']; ps=p['spec']
p['metadata'].setdefault('annotations',{})['openshift.io/required-scc']=scc_name
ps.update(serviceAccountName=sa,automountServiceAccountToken=True,enableServiceLinks=False,
          hostNetwork=False,hostPID=False,hostIPC=False,shareProcessNamespace=False)
ps['securityContext']={'runAsNonRoot':True,'seccompProfile':{'type':'RuntimeDefault'},'fsGroupChangePolicy':'OnRootMismatch'}
security={'privileged':False,'runAsNonRoot':True,'allowPrivilegeEscalation':False,
          'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']},'seccompProfile':{'type':'RuntimeDefault'}}
base=json.loads(Path(os.environ['OPENCLAW_BASE_SCC_JSON']).read_text())
if base.get('userNamespaceLevel')=='RequirePodLevel': ps['hostUsers']=False
for c in ps['initContainers']+ps['containers']:
    c['securityContext']=copy.deepcopy(security)
    c.setdefault('volumeMounts',[]).append({'name':'tmp','mountPath':'/tmp'})
    for m in c['volumeMounts']:
        if m['name']=='config': m['readOnly']=True
    c['resources']=({'requests':{'cpu':'50m','memory':'64Mi','ephemeral-storage':'64Mi'},
                     'limits':{'cpu':'100m','memory':'256Mi','ephemeral-storage':'256Mi'}} if c['name']=='init-config' else
                    {'requests':{'cpu':'500m','memory':'1Gi','ephemeral-storage':'256Mi'},
                     'limits':{'cpu':'2','memory':'4Gi','ephemeral-storage':'1Gi'}})
init=ps['initContainers'][0]
assert init['name']=='init-config' and 'Config exists, keeping it' in init['command'][-1]
init['command'][-1]='umask 077\n'+init['command'][-1]+'\nchmod 700 /home/node/.openclaw\n'
gateway=ps['containers'][0]; assert gateway['name']=='gateway'
assert gateway['args']==['node','/app/dist/index.js','gateway','run']
gateway['args'] += ['--allow-unconfigured','--auth','token']
gateway['env']=[e for e in gateway['env'] if e['name']!='VLLM_API_KEY']
gateway['envFrom']=[{'secretRef':{'name':'openclaw-secrets'}}]
gateway['env'] += [{'name':'XDG_CACHE_HOME','value':'/home/node/.cache'}, {'name':'TMPDIR','value':'/tmp'}]
ps['volumes'].append({'name':'tmp','emptyDir':{'sizeLimit':'256Mi'}})
images=sorted({c['image'] for c in ps['containers']+ps['initContainers']})
assert all(re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}',i) for i in images)
config={'gateway':{'port':18789,'bind':'lan','mode':'local','auth':{'mode':'token'},
         'controlUi':{'allowedOrigins':['https://'+host,'http://localhost:18789','http://127.0.0.1:18789']}},
        'channels':{},'agents':{'defaults':{'workspace':'/home/node/.openclaw/workspace','sandbox':{'mode':'off'}},
                                 'entries':{'main':{'tools':{'alsoAllow':['exec','read','write','edit','apply_patch']}}}},
        'tools':{'profile':'full','deny':['group:plugins'],
                 'exec':{'mode':'ask','host':'gateway','strictInlineEval':True},
                 'elevated':{'enabled':False},'fs':{'workspaceOnly':True}}}
cm=load('02-configmap.yaml'); cm['metadata']['namespace']=ns; cm['data']['openclaw.json']=json.dumps(config,indent=2)+'\n'
pvc=load('03-pvc.yaml'); pvc['metadata']['namespace']=ns; pvc['spec']['storageClassName']=storage
svc=load('05-service.yaml'); svc['metadata']['namespace']=ns
route=load('06-route.yaml'); route['metadata']['namespace']=ns; route['spec']['host']=host
account=resource('v1','ServiceAccount',sa); account['automountServiceAccountToken']=True
net=resource('networking.k8s.io/v1','NetworkPolicy','openclaw-open-network',
             {'podSelector':{'matchLabels':{'app':'openclaw'}},'policyTypes':['Ingress','Egress'],'ingress':[{}],'egress':[{}]})
dump('app.yaml',[account,cm,pvc,d,svc,route,net]); dump('deployment.yaml',[d])
assert base['runAsUser']['type']=='MustRunAsRange' and base['seLinuxContext']['type']=='MustRunAs'
base['metadata']={'name':scc_name}; base.pop('status',None)
base.update(users=[],groups=[],priority=None,allowPrivilegedContainer=False,allowPrivilegeEscalation=False,
            defaultAllowPrivilegeEscalation=False,readOnlyRootFilesystem=True,allowHostDirVolumePlugin=False,
            allowHostNetwork=False,allowHostPorts=False,allowHostPID=False,allowHostIPC=False,
            allowedCapabilities=[],defaultAddCapabilities=[],requiredDropCapabilities=['ALL'],seccompProfiles=['runtime/default'],
            volumes=['configMap','secret','emptyDir','persistentVolumeClaim','downwardAPI','projected'],allowedUnsafeSysctls=[])
dump('scc.yaml',[base])
role=resource('rbac.authorization.k8s.io/v1','Role','use-openclaw-scc')
role['rules']=[{'apiGroups':['security.openshift.io'],'resources':['securitycontextconstraints'],'resourceNames':[scc_name],'verbs':['use']}]
binding=resource('rbac.authorization.k8s.io/v1','RoleBinding','use-openclaw-scc')
binding['roleRef']={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'use-openclaw-scc'}
binding['subjects']=[{'kind':'ServiceAccount','name':sa,'namespace':ns}]
dump('scc-access.yaml',[role,binding])
template={'apiVersion':'templates.gatekeeper.sh/v1','kind':'ConstraintTemplate','metadata':{'name':'openclawbaseline'},
 'spec':{'crd':{'spec':{'names':{'kind':'OpenClawBaseline'},'validation':{'openAPIV3Schema':{
 'type':'object','required':['images','serviceAccount','scc'],'properties':{'images':{'type':'array','minItems':1,'items':{'type':'string'}},
 'serviceAccount':{'type':'string'},'scc':{'type':'string'}}}}}},
 'targets':[{'target':'admission.k8s.gatekeeper.sh','rego':Path('openclaw-baseline.rego').read_text()}]}}
constraint={'apiVersion':'constraints.gatekeeper.sh/v1beta1','kind':'OpenClawBaseline','metadata':{'name':ns+'-baseline'},
 'spec':{'enforcementAction':'dryrun','match':{'scope':'Namespaced','namespaces':[ns],'kinds':[
 {'apiGroups':[''],'kinds':['Pod','PodTemplate','ReplicationController','Service']},
 {'apiGroups':['apps'],'kinds':['Deployment','StatefulSet','DaemonSet','ReplicaSet']},
 {'apiGroups':['batch'],'kinds':['Job','CronJob']},{'apiGroups':['route.openshift.io'],'kinds':['Route']}]},
 'parameters':{'images':images,'serviceAccount':sa,'scc':scc_name}}}
dump('template.yaml',[template]); dump('constraint-dryrun.yaml',[constraint])
constraint['spec']['enforcementAction']='deny'; dump('constraint-deny.yaml',[constraint])
(out/'source-record.json').write_text(json.dumps({'starter_commit':pin,'images':images,'namespace':ns,'scc':scc_name},indent=2))
print('Rendered nonsecret manifests into',out)
