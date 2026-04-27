# Kubernetes Cluster API Surface (RBAC, NetworkPolicy, Secrets, Ingress, Webhooks, ServiceAccounts)

## Source

- https://kubernetes.io/docs/concepts/security/ — Kubernetes Security Concepts
- https://kubernetes.io/docs/reference/access-authn-authz/rbac/ — Kubernetes RBAC Authorization
- https://kubernetes.io/docs/concepts/services-networking/network-policies/ — Kubernetes Network Policies
- https://kubernetes.io/docs/concepts/configuration/secret/ — Kubernetes Secrets
- https://kubernetes.io/docs/concepts/services-networking/ingress/ — Kubernetes Ingress
- https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/ — Kubernetes Dynamic Admission Control (Webhooks)
- https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html — OWASP Kubernetes Security Cheat Sheet

## Scope

In scope: Kubernetes cluster-level API surface — RBAC Role and ClusterRole definitions, RoleBinding and ClusterRoleBinding subjects, NetworkPolicy presence and coverage per namespace, Secret manifest handling (data fields, env injection vs. volume mounts), Ingress TLS configuration, ValidatingWebhookConfiguration and MutatingWebhookConfiguration failure policy, and ServiceAccount hygiene (default SA usage, automountServiceAccountToken). Out of scope: workload-level security context directives such as `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation`, and `seccompProfile` (covered by `k8s-workloads.md`); Helm chart and Kustomize overlay tooling; cluster-bootstrap tooling (kubeadm, kops, eksctl); service-mesh-specific authorization policy (Istio `AuthorizationPolicy`, Linkerd `Server` resources — separate concern).

## Dangerous patterns (regex/AST hints)

### ClusterRole/Role with wildcard resources and verbs — CWE-250

- Why: Granting `resources: ["*"]` combined with `verbs: ["*"]` in a Role or ClusterRole gives the bound principal unrestricted access to every Kubernetes API resource in the scope of the binding. At the ClusterRole level this is equivalent to `cluster-admin`. Even at the namespace Role level, wildcard verbs over wildcard resources allow the principal to read Secrets, delete workloads, and escalate to other ServiceAccounts within that namespace.
- Grep: `resources:\s*\[["']\*["']\]|verbs:\s*\[["']\*["']\]`
- File globs: `**/*.yaml`, `**/*.yml`
- Source: https://kubernetes.io/docs/reference/access-authn-authz/rbac/

### ClusterRoleBinding to system:authenticated or system:unauthenticated — CWE-732

- Why: A ClusterRoleBinding whose `subjects:` block contains `kind: Group` with `name: system:authenticated` grants the bound ClusterRole to every user who can present a valid certificate or token to the API server — including service accounts from all namespaces. `system:unauthenticated` extends the grant to anonymous callers with no credentials at all. Either form effectively makes the cluster's API surface public to the scope defined by the ClusterRole.
- Grep: `name:\s*system:(un)?authenticated`
- File globs: `**/*.yaml`, `**/*.yml`
- Source: https://kubernetes.io/docs/reference/access-authn-authz/rbac/

### NetworkPolicy absent on namespaced workloads — CWE-284

- Why: Kubernetes imposes no network restrictions between Pods by default. In the absence of any NetworkPolicy selecting a Pod, the Pod receives unrestricted ingress from and egress to every other Pod in the cluster, including across namespace boundaries. An attacker who compromises one workload can reach internal databases, metadata APIs, and other Pods without traversing any network control boundary. Detection is hint-level: enumerate namespaces with running Pods and check whether at least one NetworkPolicy exists whose `podSelector` would match those Pods.
- Grep: `kind:\s*NetworkPolicy` — absence of this kind in a namespace's manifests is the signal; presence alone does not confirm coverage without inspecting `podSelector`.
- File globs: `**/*.yaml`, `**/*.yml`
- Source: https://kubernetes.io/docs/concepts/services-networking/network-policies/

### Secret data embedded in manifest YAML — CWE-312, CWE-798

- Why: A `kind: Secret` manifest with a `data:` block stores credentials as base64, not encrypted. Base64 is trivially reversible. When such manifests are committed to a git repository — even a private one — the credentials are exposed to everyone with repository read access, persist indefinitely in git history, and are typically replicated to CI caches and artifact stores. This does not apply to Sealed Secrets (`kind: SealedSecret`) or External Secrets Operator (`kind: ExternalSecret`), which store ciphertext and a reference, respectively.
- Grep: `kind:\s*Secret` combined with presence of a `data:` block; exclude files containing `kind:\s*SealedSecret` or `kind:\s*ExternalSecret`.
- File globs: `**/*.yaml`, `**/*.yml`
- Source: https://kubernetes.io/docs/concepts/configuration/secret/

### Secret injected via env rather than volumeMounts — CWE-532

- Why: Environment variables injected from a Secret via `env[].valueFrom.secretKeyRef` are visible in `/proc/<pid>/environ` to any process running as the same UID on the node, surfaced verbatim by `kubectl describe pod` (which logs them in cluster audit trails), and frequently captured by crash reporters, debug tooling, and process listing. Mounting the Secret as a volume with `readOnly: true` and `defaultMode: 0400` limits access to the file descriptor and avoids the `/proc` exposure and audit-log capture.
- Grep: `valueFrom:\s*\n\s*secretKeyRef:`
- File globs: `**/*.yaml`, `**/*.yml`
- Source: https://kubernetes.io/docs/concepts/configuration/secret/

### Ingress without TLS — CWE-319

- Why: An Ingress resource that lacks a `spec.tls` section terminates connections over plain HTTP. Any credential, session token, or sensitive payload transmitted through the Ingress controller is transmitted in cleartext on the network, exposable to passive eavesdropping, ARP spoofing, or rogue-node attacks within the cluster's underlay network. TLS termination at the Ingress is the standard control boundary between external traffic and in-cluster workloads.
- Grep: `kind:\s*Ingress` without a subsequent `tls:` block before the next top-level `kind:` or end of file.
- File globs: `**/*.yaml`, `**/*.yml`
- Source: https://kubernetes.io/docs/concepts/services-networking/ingress/

### ValidatingWebhookConfiguration or MutatingWebhookConfiguration with failurePolicy: Ignore — CWE-693

- Why: A webhook configured with `failurePolicy: Ignore` silently allows the admission request to proceed whenever the webhook endpoint is unreachable, returns an error, or times out. For security-critical webhooks — policy engines (OPA/Gatekeeper, Kyverno), image signature verifiers (Sigstore/Cosign), or secrets mutation webhooks — this means a network partition, a crash loop, or a targeted denial-of-service against the webhook service can disable the entire enforcement mechanism without any visible error on the requesting client.
- Grep: `kind:\s*(Validating|Mutating)WebhookConfiguration` combined with `failurePolicy:\s*Ignore`
- File globs: `**/*.yaml`, `**/*.yml`
- Source: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/

### ServiceAccount default SA used by workloads that call the Kubernetes API — CWE-732

- Why: Kubernetes automatically creates a `default` ServiceAccount in every namespace and, unless `automountServiceAccountToken: false` is set, mounts its token into every Pod that does not specify an explicit `serviceAccountName`. The `default` SA is frequently over-permissive because operators grant it permissions without realizing which workloads inherit it. Any workload that calls the Kubernetes API (via an in-cluster client or by reading the mounted token) and does not name a dedicated SA is operating under the shared `default` SA identity, meaning a compromise of any such Pod exposes that SA's API grants to the attacker.
- Grep: workload specs (`kind:\s*(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod)`) that do not contain `serviceAccountName:` within their `spec.template.spec` block.
- File globs: `**/*.yaml`, `**/*.yml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html

## Secure patterns

Scoped Role and RoleBinding with explicit resources, resourceNames, and verbs — no wildcards:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: configmap-reader
  namespace: my-app
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config", "feature-flags"]
    verbs: ["get", "watch", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: configmap-reader-binding
  namespace: my-app
subjects:
  - kind: ServiceAccount
    name: my-app-worker
    namespace: my-app
roleRef:
  kind: Role
  apiGroup: rbac.authorization.k8s.io
  name: configmap-reader
```

`resourceNames` restricts the grant to named ConfigMaps only; the ServiceAccount cannot list or get any other ConfigMap in the namespace. `verbs` lists only the operations the workload needs — `get`, `watch`, `list` — omitting `create`, `update`, `patch`, and `delete`. The binding is a `RoleBinding` (namespace-scoped), not a `ClusterRoleBinding`, so the grant does not extend to other namespaces.

Source: https://kubernetes.io/docs/reference/access-authn-authz/rbac/

Secret mounted as a read-only volume with restrictive defaultMode instead of env injection:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: my-app
spec:
  serviceAccountName: my-app-worker
  automountServiceAccountToken: false
  containers:
    - name: app
      image: registry.example.com/my-app:v1.2.3
      volumeMounts:
        - name: db-credentials
          mountPath: /run/secrets/db
          readOnly: true
  volumes:
    - name: db-credentials
      secret:
        secretName: db-credentials
        defaultMode: 0o0400
```

`readOnly: true` on the `volumeMount` prevents the container from writing back to the projected path. `defaultMode: 0o0400` (octal 256) sets file permissions to owner-read-only on all projected secret files, preventing other UIDs on the node from reading the files if the container escapes its filesystem namespace. The secret value is never present in `/proc/<pid>/environ`, never surfaced by `kubectl describe pod`, and not captured in cluster audit logs at the Pod description level.

Source: https://kubernetes.io/docs/concepts/configuration/secret/; https://kubernetes.io/docs/concepts/security/

## Fix recipes

### Recipe: Replace wildcard verbs and resources with explicit scoped lists — addresses CWE-250

**Before (dangerous):**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: app-operator
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
```

**After (safe):**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-operator
  namespace: my-app
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "update", "patch"]
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["app-config"]
    verbs: ["get", "watch", "list"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
```

Demote from `ClusterRole` to `Role` if the workload operates in a single namespace. Replace each `"*"` with the narrowest set of `apiGroups`, `resources`, and `verbs` that satisfies the workload's actual API calls. Add `resourceNames` wherever the workload only ever touches a named subset of a resource type. Audit existing grants with `kubectl auth can-i --list --as=system:serviceaccount:<namespace>:<sa-name>` to enumerate the effective permissions before and after.

Source: https://kubernetes.io/docs/reference/access-authn-authz/rbac/

### Recipe: Move a hardcoded Secret manifest to External Secrets Operator — addresses CWE-312, CWE-798

**Before (dangerous):**

```yaml
# committed to git — base64 value is trivially decoded
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: my-app
type: Opaque
data:
  username: YWRtaW4=        # admin
  password: c3VwZXJzZWNyZXQ=  # supersecret
```

**After (safe):**

```yaml
# ExternalSecret — references a secret stored in an external vault;
# no credential value is committed to git
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
  namespace: my-app
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: db-credentials
    creationPolicy: Owner
  data:
    - secretKey: username
      remoteRef:
        key: my-app/db-credentials
        property: username
    - secretKey: password
      remoteRef:
        key: my-app/db-credentials
        property: password
```

Delete the plaintext `kind: Secret` manifest from the repository and purge it from git history (`git filter-repo --path <file> --invert-paths` or BFG Repo-Cleaner). Rotate the credentials immediately — treat them as compromised for the full history of the repository. The `ExternalSecret` stores only a reference path and policy; the credential value is fetched at runtime from the configured `SecretStore` (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, or equivalent). An alternative approach for air-gapped environments is Bitnami Sealed Secrets (`kind: SealedSecret`), which stores RSA-encrypted ciphertext that only the in-cluster controller can decrypt.

Source: https://kubernetes.io/docs/concepts/configuration/secret/

### Recipe: Change webhook failurePolicy from Ignore to Fail with timeoutSeconds — addresses CWE-693

**Before (dangerous):**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: policy-engine
webhooks:
  - name: validate.policy.example.com
    failurePolicy: Ignore
    rules:
      - apiGroups: ["*"]
        apiVersions: ["*"]
        operations: ["CREATE", "UPDATE"]
        resources: ["*"]
    clientConfig:
      service:
        name: policy-engine
        namespace: policy-system
        path: /validate
```

**After (safe):**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: policy-engine
webhooks:
  - name: validate.policy.example.com
    failurePolicy: Fail
    timeoutSeconds: 10
    rules:
      - apiGroups: ["*"]
        apiVersions: ["*"]
        operations: ["CREATE", "UPDATE"]
        resources: ["*"]
    clientConfig:
      service:
        name: policy-engine
        namespace: policy-system
        path: /validate
```

Set `failurePolicy: Fail` so that any webhook endpoint error, timeout, or network failure causes the admission request to be rejected with an explicit error returned to the caller. Set `timeoutSeconds` to the lowest value the webhook service can reliably meet under load (the API server default is 10 s; the maximum is 30 s) — a short timeout bounds the blast radius on the API server's admission-control goroutine pool if the webhook service degrades. Ensure the webhook Deployment has a `PodDisruptionBudget` and is scheduled with anti-affinity rules so that node failures do not take the webhook below quorum and block all admission. For webhooks that genuinely cannot be made highly available, use `namespaceSelector` or `objectSelector` to scope the webhook to only the resources it must enforce, reducing the blast radius of a webhook outage.

Source: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/

## Version notes

- `resourceNames` in RBAC rules applies to the named resource itself but does not restrict sub-resources. A rule granting `get` on `pods` with `resourceNames: ["my-pod"]` still allows `get` on `pods/log`, `pods/exec`, and `pods/portforward` for the named pod. To restrict sub-resource access, add a separate rule entry specifying the sub-resource (e.g. `resources: ["pods/exec"]`) with an explicit empty `verbs: []` or no entry at all. This behavior is documented as of Kubernetes 1.20+ and has not changed since.
- `automountServiceAccountToken: false` is available on both the `ServiceAccount` object and on individual Pod specs. The Pod-spec field takes precedence. Set it on the `ServiceAccount` as the default and override per-Pod only for workloads that explicitly need the token. Kubernetes 1.24+ no longer auto-creates long-lived token Secrets for ServiceAccounts; tokens are bound and time-limited by the `TokenRequest` API, reducing the blast radius of token exposure.
- `defaultMode` in a `secret` volume must be specified as a decimal integer in JSON (e.g. `256` for octal `0400`) or as a YAML integer. YAML octal literals (`0o0400`) are recognized by `kubectl` but may be rejected by some validators; prefer the decimal form `256` for portability.
- `ValidatingWebhookConfiguration` and `MutatingWebhookConfiguration` gained the `matchConditions` field in Kubernetes 1.28 (beta), allowing CEL expressions to scope webhook invocation without relying solely on `namespaceSelector` and `objectSelector`. Use `matchConditions` to further narrow webhook scope and reduce load on the webhook service.
- The External Secrets Operator `ExternalSecret` API is at `v1beta1` as of ESO 0.9.x. The `SecretStore` and `ClusterSecretStore` kinds are also `v1beta1`. Check the ESO release notes when upgrading — the `v1alpha1` API was removed in ESO 0.6.0.

## Common false positives

- `verbs: ["*"]` in a Role scoped to a single custom resource group (e.g. `apiGroups: ["myapp.example.com"]`, `resources: ["mywidgets"]`) — wildcard verbs over a namespaced CRD with no cross-cutting API access may be acceptable for an operator's own reconciliation loop; verify the CRD's scope and whether the operator also has access to core resources before escalating.
- `kind: Secret` with a `data:` block in files under `tests/`, `testdata/`, `fixtures/`, or `e2e/` — test fixtures routinely contain non-production example credentials; confirm the values are not reused in production before treating as CWE-798.
- `serviceAccountName` absent from a Pod spec — if `automountServiceAccountToken: false` is set on the namespace's `default` ServiceAccount and no RBAC binds the `default` SA to any Role, the absence of an explicit `serviceAccountName` carries low risk; verify the `default` SA's effective permissions with `kubectl auth can-i --list` before flagging.
- `failurePolicy: Ignore` on a `MutatingWebhookConfiguration` that performs non-security mutations (e.g. injecting sidecar image tags, adding resource labels) — the security impact depends entirely on what the webhook enforces; non-enforcement mutations do not warrant the same severity as security-policy webhooks; confirm the webhook's purpose before assigning CWE-693.
- `name: system:authenticated` in a `RoleBinding` (namespace-scoped) rather than a `ClusterRoleBinding` — granting all authenticated users a read-only Role in a dedicated namespace (e.g. a shared metrics namespace) may be intentional; confirm the Role's permissions and the namespace's data sensitivity before treating as a high-severity CWE-732 finding.
