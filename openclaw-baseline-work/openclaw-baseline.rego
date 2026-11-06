package openclawbaseline

pod[p] { input.review.kind.kind == "Pod"; p := input.review.object }
pod[p] { {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController"}[input.review.kind.kind]; p := input.review.object.spec.template }
pod[p] { input.review.kind.kind == "CronJob"; p := input.review.object.spec.jobTemplate.spec.template }
pod[p] { input.review.kind.kind == "PodTemplate"; p := input.review.object.template }
container[c] { p := pod[_]; c := object.get(p.spec, "containers", [])[_] }
container[c] { p := pod[_]; c := object.get(p.spec, "initContainers", [])[_] }
allowed_image(image) { image == input.parameters.images[_] }
allowed_scc(name) { name == input.parameters.scc }
allowed_scc(name) { name == input.parameters.sccs[_] }
allowed_state_claim(name) { name == "openclaw-state" }
allowed_state_claim(name) { name == input.parameters.stateClaims[_] }
allowed_config_map(name) { name == "openclaw-config" }
allowed_config_map(name) { name == input.parameters.configMaps[_] }
allowed_secret(name) { name == "openclaw-secrets" }
allowed_secret(name) { name == input.parameters.secrets[_] }
drop_all(c) { object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "drop", [])[_] == "ALL" }
allowed_volume(v) { k := {"configMap", "secret", "emptyDir", "persistentVolumeClaim", "downwardAPI", "projected"}[_]; object.get(v, k, null) != null }
allowed_mount(m) { m.name == "data"; m.mountPath == "/home/node" }
allowed_mount(m) { m.name == "config"; m.mountPath == "/config" }
allowed_mount(m) { m.name == "tmp"; m.mountPath == "/tmp" }
allowed_mount(m) { startswith(m.name, "kube-api-access-"); m.mountPath == "/var/run/secrets/kubernetes.io/serviceaccount" }

violation[{"msg": "require dedicated workload service account"}] { p := pod[_]; object.get(p.spec, "serviceAccountName", "default") != input.parameters.serviceAccount }
violation[{"msg": "require an approved dedicated SCC annotation"}] { p := pod[_]; not allowed_scc(object.get(object.get(p.metadata, "annotations", {}), "openshift.io/required-scc", "")) }
violation[{"msg": msg}] { p := pod[_]; k := ["hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"][_]; object.get(p.spec, k, false) != false; msg := sprintf("%s must be false", [k]) }
violation[{"msg": "ephemeral containers require a separate reviewed support workflow"}] { p := pod[_]; count(object.get(p.spec, "ephemeralContainers", [])) > 0 }
violation[{"msg": "custom sysctls are not allowed"}] { p := pod[_]; count(object.get(object.get(p.spec, "securityContext", {}), "sysctls", [])) > 0 }
violation[{"msg": msg}] { c := container[_]; not allowed_image(c.image); msg := sprintf("%s: image must match an approved digest", [c.name]) }
violation[{"msg": msg}] { c := container[_]; s := object.get(c, "securityContext", {}); object.get(s, "privileged", false) != false; msg := sprintf("%s: privileged is forbidden", [c.name]) }
violation[{"msg": msg}] { c := container[_]; s := object.get(c, "securityContext", {}); object.get(s, "allowPrivilegeEscalation", null) != false; msg := sprintf("%s: allowPrivilegeEscalation must be false", [c.name]) }
violation[{"msg": msg}] { c := container[_]; s := object.get(c, "securityContext", {}); object.get(s, "readOnlyRootFilesystem", null) != true; msg := sprintf("%s: readOnlyRootFilesystem must be true", [c.name]) }
violation[{"msg": msg}] { c := container[_]; not drop_all(c); msg := sprintf("%s: drop ALL capabilities", [c.name]) }
violation[{"msg": msg}] { c := container[_]; count(object.get(object.get(object.get(c, "securityContext", {}), "capabilities", {}), "add", [])) > 0; msg := sprintf("%s: added capabilities are forbidden", [c.name]) }
violation[{"msg": msg}] { p := pod[_]; c := container[_]; ps := object.get(p.spec, "securityContext", {}); s := object.get(c, "securityContext", {}); object.get(s, "runAsNonRoot", object.get(ps, "runAsNonRoot", false)) != true; msg := sprintf("%s: require non-root execution", [c.name]) }
violation[{"msg": msg}] { p := pod[_]; c := container[_]; ps := object.get(p.spec, "securityContext", {}); s := object.get(c, "securityContext", {}); object.get(s, "runAsUser", object.get(ps, "runAsUser", -1)) == 0; msg := sprintf("%s: UID 0 is forbidden", [c.name]) }
violation[{"msg": msg}] { p := pod[_]; c := container[_]; ps := object.get(p.spec, "securityContext", {}); s := object.get(c, "securityContext", {}); sec := object.get(s, "seccompProfile", object.get(ps, "seccompProfile", {})); object.get(sec, "type", "") != "RuntimeDefault"; msg := sprintf("%s: require RuntimeDefault seccomp", [c.name]) }
violation[{"msg": msg}] { c := container[_]; port := object.get(c, "ports", [])[_]; object.get(port, "hostPort", 0) != 0; msg := sprintf("%s: hostPort is forbidden", [c.name]) }
violation[{"msg": msg}] { c := container[_]; k := ["requests", "limits"][_]; r := ["cpu", "memory"][_]; value := object.get(object.get(object.get(c, "resources", {}), k, {}), r, ""); {"", "0", "0m", "0Mi", "0Gi", 0}[value]; msg := sprintf("%s: require nonzero %s.%s", [c.name, k, r]) }
violation[{"msg": msg}] { p := pod[_]; v := object.get(p.spec, "volumes", [])[_]; not allowed_volume(v); msg := sprintf("%s: volume type is forbidden", [v.name]) }
violation[{"msg": "only an approved OpenClaw state PVC is allowed"}] { p := pod[_]; v := object.get(p.spec, "volumes", [])[_]; not allowed_state_claim(v.persistentVolumeClaim.claimName) }
violation[{"msg": "only an approved OpenClaw credential Secret is allowed"}] { p := pod[_]; v := object.get(p.spec, "volumes", [])[_]; secret := object.get(v, "secret", null); secret != null; not allowed_secret(object.get(secret, "secretName", "")) }
violation[{"msg": "only an approved OpenClaw bootstrap ConfigMap is allowed"}] { p := pod[_]; v := object.get(p.spec, "volumes", [])[_]; not allowed_config_map(v.configMap.name) }
violation[{"msg": "unapproved projected Secret"}] { p := pod[_]; v := object.get(p.spec, "volumes", [])[_]; source := v.projected.sources[_]; secret := object.get(source, "secret", null); secret != null; not allowed_secret(object.get(secret, "name", "")) }
allowed_projected_configmap(name) { allowed_config_map(name) }
allowed_projected_configmap(name) { name == "kube-root-ca.crt" }
allowed_projected_configmap(name) { name == "openshift-service-ca.crt" }
violation[{"msg": "unapproved projected ConfigMap"}] { p := pod[_]; v := object.get(p.spec, "volumes", [])[_]; name := v.projected.sources[_].configMap.name; not allowed_projected_configmap(name) }
violation[{"msg": "unapproved environment Secret reference"}] { c := container[_]; env := c.env[_]; secret := object.get(object.get(env, "valueFrom", {}), "secretKeyRef", null); secret != null; not allowed_secret(object.get(secret, "name", "")) }
violation[{"msg": "unapproved envFrom Secret reference"}] { c := container[_]; env := c.envFrom[_]; secret := object.get(env, "secretRef", null); secret != null; not allowed_secret(object.get(secret, "name", "")) }
violation[{"msg": "unapproved environment ConfigMap reference"}] { c := container[_]; c.env[_].valueFrom.configMapKeyRef.name != "openclaw-config" }
violation[{"msg": "unapproved envFrom ConfigMap reference"}] { c := container[_]; c.envFrom[_].configMapRef.name != "openclaw-config" }
violation[{"msg": msg}] { c := container[_]; m := object.get(c, "volumeMounts", [])[_]; not allowed_mount(m); msg := sprintf("%s: mount %s has an unapproved path", [c.name, m.name]) }
violation[{"msg": "bootstrap config mount must be read-only"}] { c := container[_]; m := object.get(c, "volumeMounts", [])[_]; m.name == "config"; object.get(m, "readOnly", false) != true }
violation[{"msg": "raw block devices are forbidden"}] { c := container[_]; count(object.get(c, "volumeDevices", [])) > 0 }
violation[{"msg": "OpenClaw requires exactly one Deployment replica"}] { input.review.kind.kind == "Deployment"; object.get(input.review.object.spec, "replicas", 1) != 1 }
violation[{"msg": "OpenClaw Deployment strategy must be Recreate"}] { input.review.kind.kind == "Deployment"; object.get(object.get(input.review.object.spec, "strategy", {}), "type", "RollingUpdate") != "Recreate" }
violation[{"msg": "Service must be ClusterIP"}] { input.review.kind.kind == "Service"; object.get(input.review.object.spec, "type", "ClusterIP") != "ClusterIP" }
violation[{"msg": "Service externalIPs are forbidden"}] { input.review.kind.kind == "Service"; count(object.get(input.review.object.spec, "externalIPs", [])) > 0 }
violation[{"msg": "Route must use edge TLS and redirect HTTP"}] { input.review.kind.kind == "Route"; object.get(object.get(input.review.object.spec, "tls", {}), "termination", "") != "edge" }
violation[{"msg": "Route must use edge TLS and redirect HTTP"}] { input.review.kind.kind == "Route"; object.get(object.get(input.review.object.spec, "tls", {}), "insecureEdgeTerminationPolicy", "") != "Redirect" }
