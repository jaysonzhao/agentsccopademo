"""Clone the current OpenClaw into a separate Deployment using the restricted SCC.

The script reuses the current ServiceAccount, API-key configuration, image, probes,
resources, and Gateway settings. It creates a separate PVC and Gateway token, and
does not patch or restart the existing OpenClaw Deployment. Credential-like config
fields are removed from the copied ConfigMap; the provider key is set to the existing
environment-variable reference and comes from a cloned Kubernetes Secret.
"""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import yaml

NAMESPACE = os.environ.get('OPENCLAW_NS', 'openclaw-baseline')
NAME = os.environ.get('OPENCLAW_SECOND_NAME', 'openclaw-restricted')
SCC = os.environ.get('OPENCLAW_SECOND_SCC', 'openclaw-baseline-restricted')
OUT = Path(os.environ.get('OPENCLAW_OUT', Path(__file__).parent / 'rendered'))


def oc_json(kind, name):
    raw = subprocess.check_output(
        ['oc', '-n', NAMESPACE, 'get', kind, name, '-o', 'json'], text=True)
    return json.loads(raw)


def clean(obj):
    obj = copy.deepcopy(obj)
    metadata = obj.get('metadata', {})
    for key in ('uid', 'resourceVersion', 'generation', 'creationTimestamp',
                'deletionTimestamp', 'deletionGracePeriodSeconds', 'managedFields',
                'selfLink', 'finalizers'):
        metadata.pop(key, None)
    obj.pop('status', None)
    return obj


def app_labels(labels):
    labels = labels or {}
    if labels.get('app') == 'openclaw':
        labels['app'] = NAME
    return labels


def set_secret_refs(deployment, secret_name):
    pod = deployment['spec']['template']['spec']
    for container in pod.get('initContainers', []) + pod.get('containers', []):
        for env_from in container.get('envFrom', []):
            ref = env_from.get('secretRef')
            if ref and ref.get('name') == 'openclaw-secrets':
                ref['name'] = secret_name
        for env in container.get('env', []):
            ref = env.get('valueFrom', {}).get('secretKeyRef')
            if ref and ref.get('name') == 'openclaw-secrets':
                ref['name'] = secret_name
    for volume in pod.get('volumes', []):
        ref = volume.get('secret')
        if ref and ref.get('secretName') == 'openclaw-secrets':
            ref['secretName'] = secret_name


def active_safe_config():
    script = r'''const fs=require("node:fs");
const c=JSON.parse(fs.readFileSync("/home/node/.openclaw/openclaw.json","utf8"));
function scrub(x,k="") {
  if (/(api.?key|password|secret|credential)/i.test(k) || /(^|_)(access|refresh|auth|gateway)?_?token($|_)/i.test(k)) return undefined;
  if (Array.isArray(x)) return x.map(v=>scrub(v)).filter(v=>v!==undefined);
  if (x&&typeof x==="object") { const o={}; for (const [a,b] of Object.entries(x)) { const v=scrub(b,a); if(v!==undefined)o[a]=v; } return o; }
  return x;
}
const out={gateway:c.gateway,channels:c.channels,agents:c.agents,tools:c.tools,
  models:{mode:c.models?.mode||"merge",providers:{minimax:scrub(c.models?.providers?.minimax||{})}},
  plugins:{entries:{minimax:c.plugins?.entries?.minimax||{enabled:true}}}};
out.models.providers.minimax.apiKey="${OPENCLAW_MODEL_API_KEY}";
console.log(JSON.stringify(out));'''
    raw = subprocess.check_output(
        ['oc', '-n', NAMESPACE, 'exec', 'deployment/openclaw', '-c', 'gateway', '--', 'node', '-e', script],
        text=True)
    config = json.loads(raw)
    if config.get('agents', {}).get('defaults', {}).get('model', {}).get('primary') != 'minimax/MiniMax-M2.7-highspeed':
        raise RuntimeError('The active model does not match the expected MiniMax configuration; refusing to clone.')
    return config


def build_documents():
    secret_name = NAME + '-secrets'
    config_name = NAME + '-config'
    claim_name = NAME + '-state'
    service_name = NAME
    route_name = NAME
    policy_name = NAME + '-open-network'
    rolebinding_name = NAME + '-use-scc'

    targets = [
        ('deployment', NAME), ('service', service_name), ('route', route_name),
        ('pvc', claim_name), ('configmap', config_name), ('secret', secret_name),
        ('networkpolicy', policy_name), ('rolebinding', rolebinding_name),
    ]
    def check_target(target):
        kind, name = target
        existing = subprocess.run(
            ['oc', '-n', NAMESPACE, 'get', kind, name, '-o', 'name',
             '--ignore-not-found=true'], capture_output=True, text=True)
        if existing.returncode:
            raise RuntimeError(f'Could not check target {kind}/{name}; refusing to continue.')
        if existing.stdout.strip():
            raise RuntimeError(f'{kind}/{name} already exists; refusing to overwrite it.')
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(check_target, targets))

    source_keys = [('deployment', 'openclaw'), ('configmap', 'openclaw-config'),
                   ('route', 'openclaw'), ('pvc', 'openclaw-state'),
                   ('service', 'openclaw'), ('networkpolicy', 'openclaw-open-network'),
                   ('secret', 'openclaw-secrets'), ('role', 'use-openclaw-scc')]
    with ThreadPoolExecutor(max_workers=8) as pool:
        source_values = list(pool.map(lambda key: oc_json(*key), source_keys))
    source = dict(zip((kind for kind, _ in source_keys), source_values))

    deployment = clean(source['deployment'])
    deployment['metadata']['name'] = NAME
    deployment['metadata']['labels'] = app_labels(deployment['metadata'].get('labels'))
    deployment['spec']['selector']['matchLabels']['app'] = NAME
    podmeta = deployment['spec']['template']['metadata']
    podmeta['labels'] = app_labels(podmeta.get('labels'))
    podmeta.setdefault('annotations', {})['openshift.io/required-scc'] = SCC
    podspec = deployment['spec']['template']['spec']
    for volume in podspec.get('volumes', []):
        if volume.get('name') == 'config':
            volume['configMap']['name'] = config_name
        if volume.get('name') == 'data':
            volume['persistentVolumeClaim']['claimName'] = claim_name
    set_secret_refs(deployment, secret_name)

    source_configmap = clean(source['configmap'])
    config = {
        'apiVersion': 'v1', 'kind': 'ConfigMap',
        'metadata': {'name': config_name, 'namespace': NAMESPACE,
                     'labels': app_labels(source_configmap['metadata'].get('labels'))},
        'data': {'openclaw.json': json.dumps(active_safe_config(), indent=2) + '\n'},
    }
    openclaw_config = json.loads(config['data']['openclaw.json'])
    host = source['route']['spec']['host']
    prefix, suffix = host.split('.', 1)
    if prefix.startswith('openclaw-'):
        new_prefix = 'openclaw-restricted-' + prefix[len('openclaw-'):]
    else:
        new_prefix = 'openclaw-restricted-' + prefix
    new_host = new_prefix + '.' + suffix
    new_origin = 'https://' + new_host
    origins = openclaw_config.setdefault('gateway', {}).setdefault('controlUi', {}).setdefault('allowedOrigins', [])
    if new_origin not in origins:
        origins.append(new_origin)
    config['data']['openclaw.json'] = json.dumps(openclaw_config, indent=2) + '\n'

    pvc = clean(source['pvc'])
    pvc['metadata']['name'] = claim_name
    pvc['metadata']['labels'] = app_labels(pvc['metadata'].get('labels'))
    annotations = pvc['metadata'].get('annotations', {})
    for key in list(annotations):
        if key.startswith(('pv.kubernetes.io/', 'volume.kubernetes.io/', 'volume.beta.kubernetes.io/')) or key == 'kubectl.kubernetes.io/last-applied-configuration':
            annotations.pop(key, None)
    if not annotations:
        pvc['metadata'].pop('annotations', None)
    pvc['spec'].pop('volumeName', None)

    service = clean(source['service'])
    service['metadata']['name'] = service_name
    service['metadata']['labels'] = app_labels(service['metadata'].get('labels'))
    service['spec']['selector']['app'] = NAME
    for key in ('clusterIP', 'clusterIPs', 'ipFamilies', 'ipFamilyPolicy', 'internalTrafficPolicy'):
        service['spec'].pop(key, None)

    route = clean(source['route'])
    route['metadata']['name'] = route_name
    route['metadata']['labels'] = app_labels(route['metadata'].get('labels'))
    route['spec']['host'] = new_host
    route['spec']['to']['name'] = service_name

    network = clean(source['networkpolicy'])
    network['metadata']['name'] = policy_name
    network['metadata']['labels'] = app_labels(network['metadata'].get('labels'))
    network['spec']['podSelector'].setdefault('matchLabels', {})['app'] = NAME

    secret = clean(source['secret'])
    secret['metadata']['name'] = secret_name
    secret['metadata']['labels'] = app_labels(secret['metadata'].get('labels'))
    secret.setdefault('data', {})['OPENCLAW_GATEWAY_TOKEN'] = base64.b64encode(
        secrets.token_urlsafe(48).encode()).decode()
    if 'OPENCLAW_MODEL_API_KEY' not in secret.get('data', {}):
        raise RuntimeError('Existing OpenClaw Secret lacks the model API key; refusing to create a partial clone.')

    rolebinding = {
        'apiVersion': 'rbac.authorization.k8s.io/v1',
        'kind': 'RoleBinding',
        'metadata': {'name': rolebinding_name, 'namespace': NAMESPACE},
        'subjects': [{'kind': 'ServiceAccount', 'name': 'openclaw-agent', 'namespace': NAMESPACE}],
        'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'use-openclaw-scc'},
    }

    role = source['role']
    permitted = any(
        rule.get('apiGroups') == ['security.openshift.io']
        and rule.get('resources') == ['securitycontextconstraints']
        and SCC in rule.get('resourceNames', [])
        and 'use' in rule.get('verbs', [])
        for rule in role.get('rules', []))
    if not permitted:
        raise RuntimeError(f'Role use-openclaw-scc does not authorize use of {SCC}.')

    return [secret, config, pvc, rolebinding, service, network, route, deployment], new_host


def main():
    apply = '--apply' in sys.argv[1:]
    docs, host = build_documents()
    payload = yaml.safe_dump_all(docs, sort_keys=False)
    command = ['oc', '-n', NAMESPACE, 'apply']
    if not apply:
        command.append('--dry-run=server')
    command += ['-f', '-']
    result = subprocess.run(command, input=payload, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'OpenShift rejected the second-instance bundle.')
    print(result.stdout.strip())
    print(('Created' if apply else 'Server-validated') + f' second OpenClaw: {NAME}; Route host: {host}')
    print('A separate Gateway token was generated; the existing provider key was copied without printing it.')
    if not apply:
        print('Pass --apply to create the resources after reviewing the generated plan.')


if __name__ == '__main__':
    main()
