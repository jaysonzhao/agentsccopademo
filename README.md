# OpenClaw SCC/OPA demo

OpenShift demo resources and evidence for OpenClaw security-context and Gatekeeper policy checks.

## Contents

- `openclaw-baseline-work/` — deployment renderer, Gatekeeper Rego, SCC/admission test drivers, and run evidence.
- `openclaw-policy-tool/` — the temporary native OpenClaw exec policy test and its cleanup utilities. The current script changes only the Deployment replica count; the saved token-denial response is historical.
- `test-results.html` and `test-results.json` — generated results summary.

The demo uses OpenClaw 2026.9.8 with MiniMax-M2.7-highspeed. The live `OpenClawBaseline/openclaw-baseline-baseline` constraint is enforced in `openclaw-baseline` with `enforcementAction: deny`. It is aligned with the `openclaw-baseline-anyuid` SCC and permits the requested ServiceAccount token mount; the ServiceAccount has namespace-scoped Deployment create permission only. The current results page includes all 22 passing SCC/Gatekeeper dry-run cases and the active policy state. The filesystem/SQLite probe is marked pending because it predates the token mount.

## Credentials

Local Gateway tokens, provider settings, and key files are excluded. Do not commit credentials or generated Secret values.
