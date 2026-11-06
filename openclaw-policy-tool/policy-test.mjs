import fs from 'node:fs';
import https from 'node:https';

const apiBase = process.env.OPENCLAW_POLICY_TEST_API_URL;
const token = process.env.OPENCLAW_POLICY_TEST_TOKEN;
const caPath = '/config/policy-test-ca.crt';
const namespace = 'openclaw-baseline';
const sourceName = 'openclaw';
const requestName = 'prompt-gk-replicas';

if (!apiBase || !token) {
  console.error('Policy-test API configuration is missing.');
  process.exit(2);
}

let api;
let ca;
try {
  api = new URL(apiBase);
  ca = fs.readFileSync(caPath);
} catch {
  console.error('Policy-test API URL or CA file is unavailable.');
  process.exit(2);
}

function request(method, path, payload) {
  return new Promise((resolve, reject) => {
    const body = payload === undefined ? undefined : Buffer.from(JSON.stringify(payload));
    const req = https.request({
      protocol: api.protocol,
      hostname: api.hostname,
      port: api.port || 443,
      path,
      method,
      ca,
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/json',
        ...(body ? {
          'content-type': 'application/json',
          'content-length': String(body.length),
        } : {}),
      },
      timeout: 15000,
    }, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 1024 * 1024) {
          req.destroy(new Error('Kubernetes API response exceeded the size limit.'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve({
        status: response.statusCode || 0,
        statusMessage: response.statusMessage || '',
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('timeout', () => req.destroy(new Error('Kubernetes API request timed out.')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function stripServerMetadata(object) {
  for (const key of [
    'uid', 'resourceVersion', 'generation', 'creationTimestamp',
    'deletionTimestamp', 'deletionGracePeriodSeconds', 'managedFields', 'selfLink',
  ]) delete object.metadata[key];
  delete object.status;
}

try {
  const source = await request(
    'GET',
    `/apis/apps/v1/namespaces/${namespace}/deployments/${sourceName}`,
  );
  if (source.status !== 200) {
    console.log(`Source Deployment read failed: HTTP ${source.status} ${source.statusMessage}\n${source.body}`);
    process.exit(3);
  }

  const deployment = JSON.parse(source.body);
  stripServerMetadata(deployment);
  deployment.metadata.name = requestName;
  deployment.spec.replicas = 2;

  // This is the only CREATE request: dryRun=All guarantees no object is persisted.
  const admission = await request(
    'POST',
    `/apis/apps/v1/namespaces/${namespace}/deployments?dryRun=All`,
    deployment,
  );
  console.log(`Admission response: HTTP ${admission.status} ${admission.statusMessage}`);
  console.log(admission.body);
} catch (error) {
  console.error(`Policy-test request failed: ${error.message}`);
  process.exit(4);
}
