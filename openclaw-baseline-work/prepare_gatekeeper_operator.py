import json, os
from pathlib import Path
root=Path(os.environ['OPENCLAW_WORK']); folder=root/'gatekeeper-before'
raw=(folder/'gatekeeper.json').read_text().strip()
old=json.loads(raw) if raw else None
ns=os.environ['OPENCLAW_NS']
def hook(filename, name):
    matches=[w for d in json.loads((folder/filename).read_text())['items']
             for w in d.get('webhooks',[]) if w['name']==name]
    assert len(matches)==1, 'Expected exactly one '+name+'; diagnose the existing operand'
    return matches[0]
if old is None:
    obj={'apiVersion':'operator.gatekeeper.sh/v1alpha1','kind':'Gatekeeper',
         'metadata':{'name':'gatekeeper'},'spec':{
         'validatingWebhook':'Enabled','mutatingWebhook':'Disabled',
         'audit':{'replicas':1},'webhook':{'replicas':3,'failurePolicy':'Fail',
         'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':ns}},
         'rules':[{'apiGroups':['*'],'apiVersions':['*'],'operations':['CREATE','UPDATE'],
                   'resources':['*','pods/ephemeralcontainers'],'scope':'Namespaced'}]}}}
    action='create'
else:
    assert old['metadata']['name']=='gatekeeper'
    main=hook('validating.json','validation.gatekeeper.sh')
    rules=main['rules']
    # A '*' resource rule does not match subresources.
    covered=set()
    for r in rules:
        if ('*' in r['apiGroups'] or '' in r['apiGroups']) and ('*' in r['apiVersions'] or 'v1' in r['apiVersions']) and r.get('scope','*') in ['*','Namespaced']:
            if set(r['resources']) & {'*/*','pods/*','*/ephemeralcontainers','pods/ephemeralcontainers'}:
                covered.update(['CREATE','UPDATE'] if '*' in r['operations'] else r['operations'])
    if not {'CREATE','UPDATE'} <= covered:
        rules=rules+[{'apiGroups':[''],'apiVersions':['v1'],'operations':['CREATE','UPDATE'],
                     'resources':['pods/ephemeralcontainers'],'scope':'Namespaced'}]
    spec={'validatingWebhook':'Enabled','webhook':{'failurePolicy':'Fail'}}
    if rules!=main['rules']: spec['webhook']['rules']=rules
    if old.get('spec',{}).get('mutatingWebhook','Enabled')!='Disabled':
        mutation=hook('mutating.json','mutation.gatekeeper.sh')
        spec['mutatingWebhookConfig']={k:mutation[k] for k in
            ['failurePolicy','namespaceSelector','rules','timeoutSeconds'] if k in mutation}
    obj={'metadata':{'resourceVersion':old['metadata']['resourceVersion']},'spec':spec}
    action='patch'
(root/'gatekeeper-operator-change.json').write_text(json.dumps(obj,indent=2)+'\n')
(root/'gatekeeper-operator-action').write_text(action)
print('Prepared',action,'through the Gatekeeper CR; review scope before applying')
