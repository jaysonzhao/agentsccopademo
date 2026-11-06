import base64
import json
import subprocess
import time
from pathlib import Path

NAMESPACE = 'openclaw-baseline'
TOKEN_KEY = 'OPENCLAW_POLICY_TEST_TOKEN'
URL_KEY = 'OPENCLAW_POLICY_TEST_API_URL'
SCRIPT_KEY = 'policy-test.mjs'
CA_KEY = 'policy-test-ca.crt'
WORK = Path(__file__).parent


def oc(args, input_text=None):
    result = subprocess.run(
        ['oc', *args], input=input_text, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'oc command failed')
    return result.stdout


def replace(kind, name, obj):
    return oc(['-n', NAMESPACE, 'replace', '-f', '-'], json.dumps(obj))


def main():
    secret = json.loads(oc(['-n', NAMESPACE, 'get', 'secret', 'openclaw-secrets', '-o', 'json']))
    config = json.loads(oc(['-n', NAMESPACE, 'get', 'configmap', 'openclaw-config', '-o', 'json']))
    deployment = json.loads(oc(['-n', NAMESPACE, 'get', 'deployment', 'openclaw', '-o', 'json']))

    if TOKEN_KEY in secret.get('data', {}) or URL_KEY in secret.get('data', {}):
        raise RuntimeError('A policy-test credential key already exists; refusing to overwrite it.')
    if SCRIPT_KEY in config.get('data', {}) or CA_KEY in config.get('data', {}):
        raise RuntimeError('A policy-test ConfigMap key already exists; refusing to overwrite it.')
    gateway = next(c for c in deployment['spec']['template']['spec']['containers'] if c['name'] == 'gateway')
    if any(m.get('name') == 'config' for m in gateway.get('volumeMounts', [])):
        raise RuntimeError('Gateway already has the config mount; refusing to overwrite its state.')
    if not any(v.get('name') == 'config' and v.get('configMap', {}).get('name') == 'openclaw-config'
               for v in deployment['spec']['template']['spec']['volumes']):
        raise RuntimeError('Expected bootstrap ConfigMap volume is missing.')

    view = json.loads(oc(['config', 'view', '--minify', '-o', 'json']))
    cluster = view['clusters'][0]['cluster']
    api_url = cluster['server']
    ca_data = cluster.get('certificate-authority-data')
    if ca_data:
        ca = base64.b64decode(ca_data)
    elif cluster.get('certificate-authority'):
        ca = Path(cluster['certificate-authority']).read_bytes()
    else:
        raise RuntimeError('Kubeconfig does not provide a CA; refusing to disable TLS verification.')
    if not ca.startswith(b'-----BEGIN CERTIFICATE-----'):
        raise RuntimeError('Cluster CA is not PEM encoded.')

    token = oc(['create', 'token', 'openclaw-policy-probe', '-n', NAMESPACE, '--duration=10m']).strip()
    if token.count('.') != 2:
        raise RuntimeError('TokenRequest did not return a JWT.')
    payload = token.split('.')[1]
    payload += '=' * (-len(payload) % 4)
    expiration = json.loads(base64.urlsafe_b64decode(payload.encode()))['exp']
    ttl = max(0, expiration - int(time.time()))
    if ttl < 120:
        raise RuntimeError(f'TokenRequest lifetime is too short ({ttl}s); refusing to continue.')

    secret.setdefault('data', {})[TOKEN_KEY] = base64.b64encode(token.encode()).decode()
    secret['data'][URL_KEY] = base64.b64encode(api_url.encode()).decode()
    replace('secret', 'openclaw-secrets', secret)
    print('Temporary short-lived token added to the existing OpenClaw Secret; value withheld.')

    config.setdefault('data', {})[SCRIPT_KEY] = (WORK / 'policy-test.mjs').read_text()
    config['data'][CA_KEY] = ca.decode('ascii')
    replace('configmap', 'openclaw-config', config)
    print('Read-only policy-test script and trusted cluster CA added to the existing ConfigMap.')

    gateway.setdefault('volumeMounts', []).append({
        'name': 'config', 'mountPath': '/config', 'readOnly': True,
    })
    replace('deployment', 'openclaw', deployment)
    print(f'Gateway updated with the read-only /config mount; token lifetime is {ttl}s.')


if __name__ == '__main__':
    main()
