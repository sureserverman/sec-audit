# Kubernetes Pod and Cluster Security

## Source

- https://kubernetes.io/docs/concepts/security/pod-security-standards/ — Pod Security Standards (baseline / restricted)
- https://kubernetes.io/docs/concepts/security/rbac-good-practices/ — RBAC good practices
- https://kubernetes.io/docs/concepts/services-networking/network-policies/ — NetworkPolicy
- https://kubernetes.io/docs/concepts/configuration/secret/ — Secrets (env vs volume mount)
- https://kubernetes.io/docs/concepts/containers/images/#imagepullpolicy — ImagePullPolicy
- https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/ — Admission controllers
- https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html — OWASP Kubernetes Security Cheat Sheet
- https://www.cisecurity.org/benchmark/kubernetes — CIS Kubernetes Benchmark

## Scope

Covers Kubernetes 1.23+ Pod specs, RBAC manifests, NetworkPolicy objects, and admission-webhook configuration. Applies to any distribution (EKS, GKE, AKS, k3s, kubeadm). Does not cover node-level OS hardening, etcd encryption at rest configuration, or cloud-provider IAM integration — those are separate concerns.

## Dangerous patterns (regex/AST hints)

### allowPrivilegeEscalation not set to false — CWE-269

- Why: Without `allowPrivilegeEscalation: false` a process may call `setuid`/`setgid` or gain additional Linux capabilities via setuid binaries.
- Grep: `allowPrivilegeEscalation:\s*true` or absence of `allowPrivilegeEscalation: false` inside `securityContext`
- File globs: `*.yaml`, `*.yml`, `**/templates/*.yaml`
- Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/ (Restricted profile)

### runAsNonRoot not enforced — CWE-250

- Why: A container running as UID 0 (root) maps to real root on the host if user namespaces are not configured; any container escape yields host root.
- Grep: `runAsNonRoot:\s*false|runAsUser:\s*0`
- File globs: `*.yaml`, `*.yml`
- Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/ (Baseline profile)

### hostPath volume mount — CWE-284

- Why: `hostPath` volumes expose arbitrary host filesystem paths to the container, enabling read/write access to sensitive host files or escape paths.
- Grep: `hostPath:`
- File globs: `*.yaml`, `*.yml`, `**/templates/*.yaml`
- Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/ (Baseline — hostPath volumes restricted)

### hostNetwork / hostPID / hostIPC enabled — CWE-284

- Why: Sharing host namespaces removes isolation; `hostPID: true` allows a process to see and signal all host processes; `hostNetwork: true` bypasses NetworkPolicy.
- Grep: `hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true`
- File globs: `*.yaml`, `*.yml`
- Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/ (Baseline)

### Overly broad RBAC (cluster-admin, wildcard verbs/resources) — CWE-732

- Why: Binding `cluster-admin` to a ServiceAccount or using `verbs: ["*"]` / `resources: ["*"]` grants full cluster control; a compromised workload becomes a full cluster compromise.
- Grep: `cluster-admin|verbs:\s*\["\*"\]|resources:\s*\["\*"\]`
- File globs: `*.yaml`, `*.yml`
- Source: https://kubernetes.io/docs/concepts/security/rbac-good-practices/

### Secrets exposed as environment variables — CWE-214

- Why: Env vars are visible in `kubectl describe pod`, process listings, crash dumps, and log forwarders; mounted files limit exposure surface.
- Grep: `secretKeyRef:|envFrom:.*secretRef`
- File globs: `*.yaml`, `*.yml`
- Source: https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-environment-variables

## Secure patterns

Container-level restricted security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
```

Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/ (Restricted profile)

Default-deny NetworkPolicy (deny all ingress and egress, then add allow rules):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

Source: https://kubernetes.io/docs/concepts/services-networking/network-policies/

Secret mounted as projected volume (not env var):

```yaml
volumes:
  - name: db-creds
    secret:
      secretName: db-password
      defaultMode: 0400
containers:
  - name: app
    volumeMounts:
      - name: db-creds
        mountPath: /run/secrets/db
        readOnly: true
```

Source: https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod

## Fix recipes

### Recipe: Harden container securityContext to Restricted profile — addresses CWE-250, CWE-269

**Before (dangerous):**

```yaml
containers:
  - name: api
    image: myapi:latest
    # no securityContext
```

**After (safe):**

```yaml
containers:
  - name: api
    image: myapi:1.8.2@sha256:<digest>
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]
      seccompProfile:
        type: RuntimeDefault
```

Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/

### Recipe: Replace wildcard RBAC with least-privilege Role — addresses CWE-732

**Before (dangerous):**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: app
    namespace: production
```

**After (safe):**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-rolebinding
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: app-role
subjects:
  - kind: ServiceAccount
    name: app
    namespace: production
```

Source: https://kubernetes.io/docs/concepts/security/rbac-good-practices/

### Recipe: Move secret from envFrom to projected volume mount — addresses CWE-214

**Before (dangerous):**

```yaml
envFrom:
  - secretRef:
      name: db-credentials
```

**After (safe):**

```yaml
volumes:
  - name: db-credentials
    secret:
      secretName: db-credentials
      defaultMode: 0400
containers:
  - name: app
    volumeMounts:
      - name: db-credentials
        mountPath: /run/secrets/db
        readOnly: true
```

Source: https://kubernetes.io/docs/concepts/configuration/secret/

### Recipe: Replace :latest image tag with digest-pinned reference — addresses CWE-829

**Before (dangerous):**

```yaml
image: myregistry/app:latest
imagePullPolicy: IfNotPresent
```

**After (safe):**

```yaml
image: myregistry/app:1.2.3@sha256:<digest>
imagePullPolicy: Always
```

Source: https://kubernetes.io/docs/concepts/containers/images/#imagepullpolicy

## Version notes

- Pod Security Admission (PSA) replaced PodSecurityPolicy (PSP) in Kubernetes 1.25; PSP was removed entirely. Use the `pod-security.kubernetes.io/enforce` namespace label to apply `restricted` profile.
- `seccompProfile.type: RuntimeDefault` requires Kubernetes 1.19+. On 1.18 and earlier, set via annotation `seccomp.security.alpha.kubernetes.io/pod`.
- The `Restricted` Pod Security Standard requires `seccompProfile` to be set as of Kubernetes 1.25.
- OPA Gatekeeper v3 and Kyverno 1.9+ both support PSA-equivalent policies for clusters that need fine-grained exemptions beyond what PSA labels allow.

## Common false positives

- `hostNetwork: true` in DaemonSet manifests for CNI plugins (Flannel, Calico) — required for network plumbing; flag only in workload Pods, not infrastructure DaemonSets.
- `hostPID: true` in node-level monitoring DaemonSets (Falco, Datadog agent) — legitimate for process-level telemetry; verify image provenance.
- `secretKeyRef` in init containers that bootstrap a Vault agent sidecar — the secret may be a short-lived Vault token rather than a long-lived credential; check rotation policy.
- `cluster-admin` bound to the `kube-system` namespace default ServiceAccount — the default SA does not auto-mount tokens in Kubernetes 1.24+ (`automountServiceAccountToken: false` is now the default for new clusters).
