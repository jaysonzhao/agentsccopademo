import copy, json, os
from pathlib import Path
import yaml
out=Path(os.environ['OPENCLAW_OUT'])
app=yaml.safe_load((out/'deployment.yaml').read_text()); ns=app['metadata']['namespace']
demo=out/'demos'; demo.mkdir(exist_ok=True)
catalog=[]
def save(name,obj,expected,layer,reason):
    filename=name+'.yaml'; (demo/filename).write_text(yaml.safe_dump(obj,sort_keys=False))
    catalog.append({'name':name,'file':filename,'expected':expected,'layer':layer,'reason':reason})
def gcase(name,change,reason):
    d=copy.deepcopy(app); d['metadata']['name']='demo-'+name
    change(d,d['spec']['template']['spec'])
    save('gk-'+name,d,'deny','gatekeeper',reason)
positive=copy.deepcopy(app); positive['metadata']['name']='demo-gk-positive'
save('gk-positive',positive,'allow','gatekeeper','valid Deployment')
gcase('tag',lambda d,p:p['containers'][0].update(image='ghcr.io/openclaw/openclaw:latest'),'approved digest')
gcase('other-digest',lambda d,p:p['containers'][0].update(image='ghcr.io/openclaw/openclaw@sha256:'+'0'*64),'approved digest')
gcase('missing-limit',lambda d,p:p['containers'][0]['resources']['limits'].pop('memory'),'limits.memory')
gcase('writable-root',lambda d,p:p['containers'][0]['securityContext'].update(readOnlyRootFilesystem=False),'readOnlyRootFilesystem')
gcase('wrong-sa',lambda d,p:p.update(serviceAccountName='default'),'dedicated workload service account')
gcase('missing-scc',lambda d,p:d['spec']['template']['metadata']['annotations'].pop('openshift.io/required-scc'),'dedicated SCC')
gcase('init-capability',lambda d,p:p['initContainers'][0]['securityContext']['capabilities'].update(add=['SYS_ADMIN']),'added capabilities')
gcase('two-replicas',lambda d,p:d['spec'].update(replicas=2),'exactly one')
gcase('share-process',lambda d,p:p.update(shareProcessNamespace=True),'shareProcessNamespace')
gcase('projected-configmap',lambda d,p:p['volumes'].append({'name':'unsafe-config','projected':{'sources':[{'configMap':{'name':'unrelated-config'}}]}}),'unapproved projected ConfigMap')
gcase('sidecar',lambda d,p:p['containers'].append({'name':'unsafe-sidecar','image':p['containers'][0]['image'],'command':['sleep','3600']}),'unsafe-sidecar')
gcase('other-secret',lambda d,p:p['containers'][0]['envFrom'].append({'secretRef':{'name':'unrelated-credentials'}}),'envFrom Secret')
gcase('bad-mount',lambda d,p:p['containers'][0]['volumeMounts'][0].update(mountPath='/etc'),'unapproved path')
# A dedicated namespace isolates SCC admission tests from this Gatekeeper constraint.
testns=ns+'-scc-demo'
pod={'apiVersion':'v1','kind':'Pod','metadata':copy.deepcopy(app['spec']['template']['metadata']),
     'spec':copy.deepcopy(app['spec']['template']['spec'])}
pod['metadata'].update(name='scc-positive',namespace=testns)
save('scc-positive',pod,'allow','scc','valid Pod admission; dry-run does not schedule it')
def scase(name,change):
    d=copy.deepcopy(pod); d['metadata']['name']='scc-'+name; change(d['spec'])
    save('scc-'+name,d,'deny','scc','SCC must reject')
scase('host-port',lambda p:p['containers'][0].setdefault('ports',[]).append({'containerPort':8080,'hostPort':8080}))
scase('privileged',lambda p:p['containers'][0]['securityContext'].update(privileged=True))
scase('host-network',lambda p:p.update(hostNetwork=True))
scase('host-path',lambda p:p['volumes'].append({'name':'host-root','hostPath':{'path':'/'}}))
scase('writable-root',lambda p:p['containers'][0]['securityContext'].update(readOnlyRootFilesystem=False))
scase('capability',lambda p:p['containers'][0]['securityContext']['capabilities'].update(add=['SYS_ADMIN']))
scase('init-escalation',lambda p:p['initContainers'][0]['securityContext'].update(allowPrivilegeEscalation=True))
account={'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'openclaw-agent','namespace':testns},'automountServiceAccountToken':False}
access=list(yaml.safe_load_all((out/'scc-access.yaml').read_text()))
for d in access:
    d['metadata']['namespace']=testns
    for s in d.get('subjects',[]): s['namespace']=testns
(demo/'scc-setup.yaml').write_text(yaml.safe_dump_all([account]+access,sort_keys=False))
constraint=yaml.safe_load((out/'constraint-deny.yaml').read_text())
suite={'apiVersion':'test.gatekeeper.sh/v1alpha1','kind':'Suite','metadata':{'name':'openclaw-baseline'},'tests':[{
 'name':'openclaw-controls','template':'../template.yaml','constraint':'../constraint-deny.yaml',
 'cases':[{'name':c['name'],'object':c['file'],'assertions':[{'violations':'no' if c['expected']=='allow' else 'yes'}]}
          for c in catalog if c['layer']=='gatekeeper']}]}
(demo/'suite.yaml').write_text(yaml.safe_dump(suite,sort_keys=False))
(demo/'catalog.json').write_text(json.dumps(catalog,indent=2))
print('Generated',len(catalog),'admission cases; SCC demo namespace:',testns)
