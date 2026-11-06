import json
import subprocess
import sys

NS = 'openclaw-baseline'
TOKEN_KEY = 'OPENCLAW_POLICY_TEST_TOKEN'
URL_KEY = 'OPENCLAW_POLICY_TEST_API_URL'


def oc(args, input_text=None, check=True):
    r = subprocess.run(['oc', *args], input=input_text, capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(r.stderr.strip() or 'oc command failed')
    return r


def get(kind, name):
    return json.loads(oc(['-n', NS, 'get', kind, name, '-o', 'json']).stdout)


def replace(obj):
    oc(['-n', NS, 'replace', '-f', '-'], json.dumps(obj))


def main():
    approvals = {
        'version': 1,
        'defaults': {
            'security': 'allowlist', 'ask': 'on-miss',
            'askFallback': 'deny', 'autoAllowSkills': False,
        },
        'agents': {
            'main': {
                'security': 'allowlist', 'ask': 'on-miss',
                'askFallback': 'deny', 'autoAllowSkills': False,
                'allowlist': [],
            },
        },
    }
    reset = oc([
        '-n', NS, 'exec', '-i', 'deployment/openclaw', '-c', 'gateway', '--',
        'node', '/app/dist/index.js', 'approvals', 'set', '--stdin',
    ], json.dumps(approvals))
    print('Temporary exec allowlist removed; unmatched commands remain fail-closed.')

    for kind, name in [
        ('rolebinding', 'openclaw-policy-probe'),
        ('role', 'openclaw-policy-probe'),
        ('serviceaccount', 'openclaw-policy-probe'),
    ]:
        oc(['-n', NS, 'delete', kind, name, '--ignore-not-found=true'])
    print('Temporary Kubernetes Role, RoleBinding, and ServiceAccount removed.')

    secret = get('secret', 'openclaw-secrets')
    secret.get('data', {}).pop(TOKEN_KEY, None)
    secret.get('data', {}).pop(URL_KEY, None)
    replace(secret)

    config = get('configmap', 'openclaw-config')
    config.get('data', {}).pop('policy-test.mjs', None)
    config.get('data', {}).pop('policy-test-ca.crt', None)
    replace(config)

    deployment = get('deployment', 'openclaw')
    gateway = next(c for c in deployment['spec']['template']['spec']['containers'] if c['name'] == 'gateway')
    gateway['volumeMounts'] = [m for m in gateway.get('volumeMounts', [])
                               if not (m.get('name') == 'config' and m.get('mountPath') == '/config')]
    replace(deployment)
    print('Temporary Secret keys and mounted policy-test files removed; Gateway rollout started.')

    status = oc(['-n', NS, 'rollout', 'status', 'deployment/openclaw', '--timeout=180s'])
    print(status.stdout.strip())

    state = oc([
        '-n', NS, 'exec', 'deployment/openclaw', '-c', 'gateway', '--', 'node', '-e',
        'const fs=require("node:fs"); console.log(JSON.stringify({tokenPresent:Boolean(process.env.OPENCLAW_POLICY_TEST_TOKEN),apiUrlPresent:Boolean(process.env.OPENCLAW_POLICY_TEST_API_URL),testScriptMounted:fs.existsSync("/config/policy-test.mjs")}))',
    ])
    clean = json.loads(state.stdout)
    if any(clean.values()):
        raise RuntimeError('A temporary token or test script remains in the Gateway pod.')

    validation = oc(['-n', NS, 'exec', 'deployment/openclaw', '-c', 'gateway', '--',
                     'node', '/app/dist/index.js', 'config', 'validate'])
    print(validation.stdout.strip())
    print('Cleanup verified: temporary token and script are absent from the new pod.')


if __name__ == '__main__':
    main()
