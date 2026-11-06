# Live admission-suite evidence

All cases below used Kubernetes server-side dry-run. No test Deployment or Pod was persisted.

<a id="a01-gk-positive"></a>
## A01 — `gk-positive`

- Layer: Gatekeeper
- Expected: Allow
- Result: Allowed

```text
deployment.apps/demo-gk-positive
```

<a id="a02-gk-tag"></a>
## A02 — `gk-tag`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-tag.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] gateway: image must match an approved digest
```

<a id="a03-gk-other-digest"></a>
## A03 — `gk-other-digest`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-other-digest.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] gateway: image must match an approved digest
```

<a id="a04-gk-missing-limit"></a>
## A04 — `gk-missing-limit`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-missing-limit.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] gateway: require nonzero limits.memory
```

<a id="a05-gk-writable-root"></a>
## A05 — `gk-writable-root`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-writable-root.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] gateway: readOnlyRootFilesystem must be true
```

<a id="a06-gk-wrong-sa"></a>
## A06 — `gk-wrong-sa`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-wrong-sa.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] require dedicated workload service account
```

<a id="a07-gk-missing-scc"></a>
## A07 — `gk-missing-scc`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-missing-scc.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] require the dedicated SCC annotation
```

<a id="a08-gk-init-capability"></a>
## A08 — `gk-init-capability`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Warning: would violate PodSecurity "baseline:latest": non-default capabilities (container "init-config" must not include "SYS_ADMIN" in securityContext.capabilities.add)
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-init-capability.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] init-config: added capabilities are forbidden
```

<a id="a09-gk-two-replicas"></a>
## A09 — `gk-two-replicas`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-two-replicas.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] OpenClaw requires exactly one Deployment replica
```

<a id="a10-gk-share-process"></a>
## A10 — `gk-share-process`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-share-process.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] shareProcessNamespace must be false
```

<a id="a11-gk-projected-configmap"></a>
## A11 — `gk-projected-configmap`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-projected-configmap.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] unapproved projected ConfigMap
```

<a id="a12-gk-sidecar"></a>
## A12 — `gk-sidecar`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-sidecar.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] unsafe-sidecar: allowPrivilegeEscalation must be false
[openclaw-baseline-baseline] unsafe-sidecar: drop ALL capabilities
[openclaw-baseline-baseline] unsafe-sidecar: readOnlyRootFilesystem must be true
[openclaw-baseline-baseline] unsafe-sidecar: require nonzero limits.cpu
[openclaw-baseline-baseline] unsafe-sidecar: require nonzero limits.memory
[openclaw-baseline-baseline] unsafe-sidecar: require nonzero requests.cpu
[openclaw-baseline-baseline] unsafe-sidecar: require nonzero requests.memory
```

<a id="a13-gk-other-secret"></a>
## A13 — `gk-other-secret`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-other-secret.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] unapproved envFrom Secret reference
```

<a id="a14-gk-bad-mount"></a>
## A14 — `gk-bad-mount`

- Layer: Gatekeeper
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/gk-bad-mount.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [openclaw-baseline-baseline] gateway: mount data has an unapproved path
```

<a id="a15-scc-positive"></a>
## A15 — `scc-positive`

- Layer: SCC
- Expected: Allow
- Result: Allowed

```text
pod/scc-positive
```

<a id="a16-scc-host-port"></a>
## A16 — `scc-host-port`

- Layer: SCC
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/scc-host-port.yaml": pods "scc-host-port" is forbidden: unable to validate against any security context constraint: [provider openclaw-baseline-anyuid: .initContainers[0].containers[0].hostPort: Invalid value: 8080: Host ports are not allowed to be used, provider openclaw-baseline-anyuid: .containers[0].containers[0].hostPort: Invalid value: 8080: Host ports are not allowed to be used]
```

<a id="a17-scc-privileged"></a>
## A17 — `scc-privileged`

- Layer: SCC
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/scc-privileged.yaml": pods "scc-privileged" is forbidden: unable to validate against any security context constraint: provider openclaw-baseline-anyuid: .containers[0].privileged: Invalid value: true: Privileged containers are not allowed
```

<a id="a18-scc-host-network"></a>
## A18 — `scc-host-network`

- Layer: SCC
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/scc-host-network.yaml": pods "scc-host-network" is forbidden: unable to validate against any security context constraint: [provider openclaw-baseline-anyuid: .spec.securityContext.hostNetwork: Invalid value: true: Host network is not allowed to be used, provider openclaw-baseline-anyuid: .initContainers[0].hostNetwork: Invalid value: true: Host network is not allowed to be used, provider openclaw-baseline-anyuid: .initContainers[0].containers[0].hostPort: Invalid value: 18789: Host ports are not allowed to be used, provider openclaw-baseline-anyuid: .containers[0].hostNetwork: Invalid value: true: Host network is not allowed to be used, provider openclaw-baseline-anyuid: .containers[0].containers[0].hostPort: Invalid value: 18789: Host ports are not allowed to be used]
```

<a id="a19-scc-host-path"></a>
## A19 — `scc-host-path`

- Layer: SCC
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/scc-host-path.yaml": pods "scc-host-path" is forbidden: unable to validate against any security context constraint: spec.volumes[3]: Invalid value: "hostPath": hostPath volumes are not allowed to be used
```

<a id="a20-scc-writable-root"></a>
## A20 — `scc-writable-root`

- Layer: SCC
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/scc-writable-root.yaml": pods "scc-writable-root" is forbidden: unable to validate against any security context constraint: provider openclaw-baseline-anyuid: .containers[0].readOnlyRootFilesystem: Invalid value: false: ReadOnlyRootFilesystem must be set to true
```

<a id="a21-scc-capability"></a>
## A21 — `scc-capability`

- Layer: SCC
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/scc-capability.yaml": pods "scc-capability" is forbidden: unable to validate against any security context constraint: provider openclaw-baseline-anyuid: .containers[0].capabilities.add: Invalid value: "SYS_ADMIN": capability may not be added
```

<a id="a22-scc-init-escalation"></a>
## A22 — `scc-init-escalation`

- Layer: SCC
- Expected: Deny
- Result: Denied

```text
Error from server (Forbidden): error when creating "/Users/haozhao/Documents/ChatGPT/openclawsccopa/openclaw-baseline-work/rendered/demos/scc-init-escalation.yaml": pods "scc-init-escalation" is forbidden: unable to validate against any security context constraint: provider openclaw-baseline-anyuid: .initContainers[0].allowPrivilegeEscalation: Invalid value: true: Allowing privilege escalation for containers is not allowed
```
