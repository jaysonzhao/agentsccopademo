# OpenClaw SCC/OPA demo

OpenShift demo resources and evidence for OpenClaw security-context and Gatekeeper policy checks.

## Contents

- `openclaw-baseline-work/` — deployment renderer, Gatekeeper Rego, SCC/admission test drivers, and run evidence.
- `openclaw-policy-tool/` — the temporary native OpenClaw exec policy test and its cleanup utilities.
- `test-results.html` and `test-results.json` — generated results summary.

The recorded run used OpenClaw 2026.9.8 with MiniMax-M2.7-highspeed. The test report is a snapshot from 2026-11-05. On 2026-11-06, the live `OpenClawBaseline/openclaw-baseline-baseline` constraint was removed from the demo namespace to allow the requested ServiceAccount token mount; the test results describe the earlier policy-enabled state.

## Credentials

Local Gateway tokens, provider settings, and key files are excluded. Do not commit credentials or generated Secret values.
