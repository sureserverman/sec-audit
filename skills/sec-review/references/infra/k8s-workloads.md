# Kubernetes Workload Manifests

## Source

- https://kubernetes.io/docs/concepts/security/ — Kubernetes security overview: threat model, attack surface, and defence-in-depth concepts
- https://kubernetes.io/docs/concepts/security/pod-security-standards/ — Pod Security Standards (PSS): Privileged / Baseline / Restricted policy profiles and field-level enforcement rules
- https://kubernetes.io/docs/tasks/configure-pod-container/security-context/ — Configure a Security Context for a Pod or Container: field reference for `securityContext` at Pod and container scope
- https://kubernetes.io/docs/concepts/workloads/pods/ — Pods: workload primitive reference; pod-level spec fields including `hostNetwork`, `hostPID`, `hostIPC`, `automountServiceAccountToken`
- https://kubernetes.io/docs/concepts/policy/resource-quotas/ — Resource Quotas: `requests` / `limits` semantics, quota enforcement, and interaction with the scheduler
- https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html — OWASP Kubernetes Security Cheat Sheet: runtime controls, image hygiene, RBAC, and network policy guidance
- https://www.cisecurity.org/benchmark/kubernetes — CIS Kubernetes Benchmark: prescriptive hardening controls for workload manifests, API server, and node configuration

## Scope

In-scope: Kubernetes workload manifests for the core workload kinds — `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, and `CronJob` — covering container-level and pod-level `securityContext` fields, privilege-escalation flags, Linux capability grants, resource request/limit constraints, image tag and digest hygiene, and the `automountServiceAccountToken` flag on Pod and ServiceAccount specs. Out of scope: RBAC, `NetworkPolicy`, `Secret` / `ConfigMap` management, and Ingress TLS configuration (covered by `k8s-api.md`); admission-controller and webhook hygiene; Helm chart templating security; Kustomize overlay drift; node-level configuration (kubelet, etcd, API-server flags) covered by CIS Benchmark section 2–4.

## Dangerous patterns (regex/AST hints)

### `securityContext.runAsNonRoot` absent or container runs as UID 0 — CWE-250

- Why: When `runAsNonRoot: true` is absent from a container's `securityContext`, the container process runs as whatever user the image `USER` instruction specifies — often root (UID 0). A process running as root inside a container has the same UID as the host root; combined with any container-escape vector, this yields full host compromise. The Pod Security Standards Restricted profile mandates `runAsNonRoot: true` on every container.
- Grep: `runAsUser:\s*0` — or scan `securityContext:` blocks in which `runAsNonRoot` is absent or `runAsNonRoot:\s*false`
- File globs: `**/*.yaml`, `**/*.yml`, `**/k8s/**/*.yaml`, `**/manifests/**/*.yaml`, `**/helm/templates/**/*.yaml`
- Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/

### `securityContext.privileged: true` — CWE-250

- Why: Setting `privileged: true` gives the container process all Linux capabilities and disables most kernel namespace isolation that normally separates it from the host. The result is effectively equivalent to running a root shell on the node. This is the broadest privilege-escalation surface in a Kubernetes workload and is explicitly forbidden by the PSS Baseline and Restricted profiles.
- Grep: `privileged:\s*true`
- File globs: `**/*.yaml`, `**/*.yml`, `**/k8s/**/*.yaml`, `**/manifests/**/*.yaml`, `**/helm/templates/**/*.yaml`
- Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/

### `securityContext.allowPrivilegeEscalation` not explicitly `false` — CWE-269

- Why: When `allowPrivilegeEscalation` is absent (it defaults to `true` unless `privileged: true` is set and the container runs as root), any setuid or file-capability binary inside the container image can acquire elevated privileges at runtime. An attacker who achieves code execution as an unprivileged process can then exec a setuid helper to obtain a root context inside the container. The PSS Restricted profile requires `allowPrivilegeEscalation: false` on all containers.
- Grep: absence of `allowPrivilegeEscalation:\s*false` within `securityContext:` blocks in container specs; or `allowPrivilegeEscalation:\s*true`
- File globs: `**/*.yaml`, `**/*.yml`, `**/k8s/**/*.yaml`, `**/manifests/**/*.yaml`, `**/helm/templates/**/*.yaml`
- Source: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/

### `securityContext.readOnlyRootFilesystem` absent or `false` — CWE-732

- Why: Without `readOnlyRootFilesystem: true`, a compromised process can write to any path in the container's overlay filesystem — dropping backdoors into `PATH` directories, modifying application binaries, or persisting malware across restarts within the same pod lifetime. A read-only root filesystem forces legitimate writable paths to be explicit (`emptyDir` or `persistentVolumeClaim` mounts), which narrows the blast radius of code execution.
- Grep: absence of `readOnlyRootFilesystem:\s*true` in container-level `securityContext:` blocks; or `readOnlyRootFilesystem:\s*false`
- File globs: `**/*.yaml`, `**/*.yml`, `**/k8s/**/*.yaml`, `**/manifests/**/*.yaml`, `**/helm/templates/**/*.yaml`
- Source: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/

### `hostNetwork: true` / `hostPID: true` / `hostIPC: true` — CWE-653

- Why: These pod-level flags collapse the corresponding kernel namespace boundary between the pod and the host. `hostNetwork: true` exposes the node's full network stack — the pod can bind host ports, sniff traffic on host interfaces, and interact with node-local services (kubelet, etcd, cloud metadata endpoints). `hostPID: true` lets the pod see and signal every process on the node, enabling direct ptrace of host processes. `hostIPC: true` exposes host shared-memory segments, which some infrastructure components use for inter-process communication. All three are forbidden by the PSS Baseline profile.
- Grep: `hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true`
- File globs: `**/*.yaml`, `**/*.yml`, `**/k8s/**/*.yaml`, `**/manifests/**/*.yaml`, `**/helm/templates/**/*.yaml`
- Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/

### Capabilities `add: [SYS_ADMIN | NET_ADMIN | ALL | SYS_PTRACE]` — CWE-250

- Why: Linux capabilities granularise the root privilege set, but several capabilities are individually as dangerous as root. `SYS_ADMIN` allows mounting filesystems, configuring namespaces, and dozens of other privileged operations. `NET_ADMIN` allows reconfiguring network interfaces, routing tables, and iptables rules. `SYS_PTRACE` allows tracing any process in the same PID namespace, enabling memory reads and injection. Granting `ALL` is equivalent to `privileged: true`. The PSS Restricted profile requires that `capabilities.drop` contains `ALL` and that `capabilities.add` is either absent or contains only `NET_BIND_SERVICE`.
- Grep: `add:\s*\[.*(SYS_ADMIN|NET_ADMIN|ALL|SYS_PTRACE|SYS_MODULE|DAC_OVERRIDE)`
- File globs: `**/*.yaml`, `**/*.yml`, `**/k8s/**/*.yaml`, `**/manifests/**/*.yaml`, `**/helm/templates/**/*.yaml`
- Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/

### Resource limits absent — CWE-400

- Why: When a container spec omits `resources.limits.cpu` and `resources.limits.memory`, the container is unconstrained and can exhaust node resources, causing noisy-neighbour starvation or a node `OOMKilled` event that evicts unrelated critical workloads. An attacker who achieves code execution in a limitless container can mount a denial-of-service against the entire node. The CIS Kubernetes Benchmark requires resource limits on all production workloads.
- Grep: scan `kind:\s*(Deployment|StatefulSet|Pod|DaemonSet|Job|CronJob)` manifests for `containers:` blocks that lack a `limits:` sub-key under `resources:`; or `resources:\s*{}` (empty resource block)
- File globs: `**/*.yaml`, `**/*.yml`, `**/k8s/**/*.yaml`, `**/manifests/**/*.yaml`, `**/helm/templates/**/*.yaml`
- Source: https://kubernetes.io/docs/concepts/policy/resource-quotas/

### `automountServiceAccountToken` not explicitly `false` — CWE-522

- Why: Kubernetes automatically mounts a service-account token into every pod at `/var/run/secrets/kubernetes.io/serviceaccount/token` unless `automountServiceAccountToken: false` is set on the Pod spec or the ServiceAccount. Any workload that does not call the Kubernetes API carries this token unnecessarily. If the container is compromised, the token can be used to authenticate to the kube-apiserver and perform actions permitted by the pod's RBAC bindings — often broader than intended. The OWASP Kubernetes Cheat Sheet and CIS Benchmark both require workloads to opt out if they do not need API access.
- Grep: absence of `automountServiceAccountToken:\s*false` in Pod/Deployment/StatefulSet/DaemonSet/Job spec sections and in `kind:\s*ServiceAccount` objects
- File globs: `**/*.yaml`, `**/*.yml`, `**/k8s/**/*.yaml`, `**/manifests/**/*.yaml`, `**/helm/templates/**/*.yaml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html

### `image:` with `:latest` tag or no tag — CWE-494

- Why: The `:latest` tag (and an absent tag, which resolves to `:latest`) is a mutable pointer. The image it references can be replaced by a supply-chain compromise, a registry mishap, or an accidental push without any change to the manifest. Kubernetes cannot detect that the runtime image differs from what was reviewed; `imagePullPolicy: Always` silently pulls the replacement on every pod restart. Reproducible, auditable deployments require an immutable reference — either a specific version tag combined with digest pinning, or a digest-only reference.
- Grep: `image:\s*[^:\s]+:latest|image:\s*[a-zA-Z0-9/_.-]+$` (image name with no colon — no tag at all)
- File globs: `**/*.yaml`, `**/*.yml`, `**/k8s/**/*.yaml`, `**/manifests/**/*.yaml`, `**/helm/templates/**/*.yaml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html

### Image reference without digest pinning — CWE-494

- Why: A tag-only image reference (e.g. `myapp:1.2.3`) remains mutable if the registry allows tag overwriting. Silent upstream drift means a pod rescheduled after a node failure may pull a different image layer than was security-reviewed, without any manifest change. Digest-pinned references (`myapp:1.2.3@sha256:<hash>`) are immutable: the runtime rejects any image whose digest does not match, providing integrity verification at the pull layer. This is a hint-level finding; flag images not using `@sha256:` for follow-up verification.
- Grep: `image:\s*\S+:\S+[^@\s]$` — matches tag references that do not include `@sha256:`; cross-reference with registry policy on tag immutability
- File globs: `**/*.yaml`, `**/*.yml`, `**/k8s/**/*.yaml`, `**/manifests/**/*.yaml`, `**/helm/templates/**/*.yaml`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html

## Secure patterns

### (a) Hardened Pod spec — full PSS Restricted security-context baseline

A single-container Pod applying every field required by the Pod Security Standards Restricted profile, plus a seccomp profile and explicit capability management:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-pod
  namespace: production
spec:
  # Disable automatic service-account token mount; this pod does not
  # call the Kubernetes API.
  automountServiceAccountToken: false

  # No host-namespace sharing.
  hostNetwork: false
  hostPID: false
  hostIPC: false

  # Pod-level seccomp profile (required by PSS Restricted since Kubernetes 1.25).
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault

  containers:
    - name: app
      image: registry.example.com/myapp:1.4.2@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        privileged: false
        capabilities:
          drop:
            - ALL
          # Add NET_BIND_SERVICE only if the container must bind a port < 1024.
          # Omit the add block entirely if not required.
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
        limits:
          cpu: "500m"
          memory: "256Mi"
      # Writable directories must be explicit volume mounts; the root filesystem
      # is read-only.
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache

  volumes:
    - name: tmp
      emptyDir: {}
    - name: cache
      emptyDir: {}
```

Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/

### (b) Hardened Deployment — resource limits, token opt-out, and digest-pinned image

A production Deployment that combines resource constraints, explicit token opt-out at the ServiceAccount level, and a digest-pinned image reference to eliminate silent upstream drift:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp
  namespace: production
# Disable default token mount for every pod that uses this service account.
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      serviceAccountName: myapp
      # Belt-and-suspenders: also opt out at the pod level.
      automountServiceAccountToken: false

      hostNetwork: false
      hostPID: false
      hostIPC: false

      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault

      containers:
        - name: myapp
          # Digest-pinned: tag for human readability, sha256 for integrity.
          image: registry.example.com/myapp:2.3.1@sha256:deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
            limits:
              cpu: "1000m"
              memory: "512Mi"
          volumeMounts:
            - name: tmp
              mountPath: /tmp

      volumes:
        - name: tmp
          emptyDir: {}
```

Source: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/

## Fix recipes

### Recipe: Add baseline securityContext to an unhardened container — addresses CWE-250 / CWE-269 / CWE-732

**Before (dangerous):**

```yaml
spec:
  containers:
    - name: app
      image: registry.example.com/myapp:latest
      ports:
        - containerPort: 8080
      resources: {}
```

**After (safe):**

```yaml
spec:
  automountServiceAccountToken: false   # add at pod spec level
  securityContext:                       # add pod-level securityContext
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault

  containers:
    - name: app
      image: registry.example.com/myapp:2.1.0@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
      ports:
        - containerPort: 8080
      securityContext:                   # add container-level securityContext
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
        limits:
          cpu: "500m"
          memory: "256Mi"
      volumeMounts:
        - name: tmp
          mountPath: /tmp              # provide an explicit writable volume

  volumes:
    - name: tmp
      emptyDir: {}
```

If the application writes to paths other than `/tmp`, mount additional `emptyDir` volumes at those paths rather than disabling `readOnlyRootFilesystem`. Identify required writable paths by running the container with `readOnlyRootFilesystem: true` in a staging environment and observing `Read-only file system` errors.

Source: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/

### Recipe: Replace `:latest` with a digest-pinned image reference — addresses CWE-494

**Before (dangerous):**

```yaml
containers:
  - name: app
    image: registry.example.com/myapp:latest
    # OR — no tag at all:
    image: registry.example.com/myapp
```

**After (safe):**

```yaml
containers:
  - name: app
    # Tag retained for readability; sha256 digest pins the exact layer set.
    # Obtain the digest with:
    #   docker buildx imagetools inspect registry.example.com/myapp:2.1.0
    # or from the CI build artefact manifest.
    image: registry.example.com/myapp:2.1.0@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
    # imagePullPolicy defaults to IfNotPresent when a digest is specified;
    # Always is redundant and increases pull load without improving security.
    imagePullPolicy: IfNotPresent
```

Automate digest resolution in CI: pin the digest in the manifest at build time and open a bot-driven PR to rotate it when the upstream tag is updated. Tools such as Renovate and Dependabot support digest pinning for container images.

Source: https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html

### Recipe: Remove `privileged: true` and replace with targeted capability grant — addresses CWE-250

**Before (dangerous):**

```yaml
containers:
  - name: app
    image: registry.example.com/myapp:2.1.0@sha256:a1b2c3d4...
    securityContext:
      privileged: true   # grants all ~40 capabilities + disables namespace isolation
```

**After (safe):**

```yaml
containers:
  - name: app
    image: registry.example.com/myapp:2.1.0@sha256:a1b2c3d4...
    securityContext:
      privileged: false
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
        # Add back only the specific capability the container legitimately requires.
        # Example: the container needs to bind a port below 1024.
        add:
          - NET_BIND_SERVICE
        # If the container required SYS_ADMIN for a specific sub-operation (e.g.
        # reading /proc/sys kernel parameters), prefer a more targeted approach:
        #   - Mounting the required /proc/sys path as a read-only volume from the
        #     host (requires a security review of the specific path), or
        #   - Switching to a kernel feature (e.g. sysctl in pod securityContext)
        #     rather than a capability grant.
```

To determine the minimum required capabilities, run the container under `amicontained` or use `crictl inspect` to observe the effective capability set during normal operation. Reduce to the observed minimum. Document any non-`NET_BIND_SERVICE` additions with a rationale comment in the manifest.

Source: https://kubernetes.io/docs/concepts/security/pod-security-standards/

## Version notes

- Pod Security Standards (`pod-security.kubernetes.io/enforce` namespace label) replaced the deprecated PodSecurityPolicy (PSP) API. PSP was removed in Kubernetes 1.25. Clusters still on PSP (Kubernetes ≤ 1.24) should migrate to PSA (Pod Security Admission) or a webhook-based policy engine (OPA/Gatekeeper, Kyverno).
- `seccompProfile.type: RuntimeDefault` at the pod or container level requires Kubernetes 1.19+ (GA in 1.25 via PSS). On 1.18 and earlier, seccomp was enabled via an annotation: `seccomp.security.alpha.kubernetes.io/pod: runtime/default`. Do not use the annotation form on clusters ≥ 1.25 — it is ignored.
- The PSS Restricted profile became the recommended baseline for new workloads as of Kubernetes 1.23 (GA enforcement via Pod Security Admission in 1.25). CIS Kubernetes Benchmark v1.8+ aligns with PSS Restricted for container-level controls.
- `readOnlyRootFilesystem: true` with JVM or Node.js workloads: JIT compilers and class loaders may write temporary files to the container filesystem. Mount explicit `emptyDir` volumes at the paths they require (commonly `/tmp`, JVM temp dirs, Node module caches) rather than disabling the read-only root filesystem.
- Digest pinning format `image: name:tag@sha256:<hash>` is supported by containerd (the default CRI since Kubernetes 1.24) and by CRI-O. The hash must be the manifest digest, not the layer digest — obtain it with `docker manifest inspect` or `crane digest`.

## Common false positives

- `privileged: true` in a DaemonSet that is an official node agent (Datadog Agent, Falco, Cilium CNI) — these vendors document the requirement; flag for review but downgrade to informational if the image is from the official vendor registry and the DaemonSet is in the `kube-system` namespace.
- `hostNetwork: true` on a CNI plugin or kube-proxy DaemonSet — host networking is required for CNI operation; this is expected and not a finding in `kube-system`.
- `automountServiceAccountToken` absent on pods managed by operators that inject the token via a projected volume with a bounded `expirationSeconds` — confirm the projected volume exists before flagging; the injected token may have a shorter TTL than the default.
- `capabilities.add: [NET_BIND_SERVICE]` paired with `capabilities.drop: [ALL]` — this is the PSS Restricted-compliant pattern for services binding ports below 1024; it is safe and should not be flagged.
- `readOnlyRootFilesystem` absent on an `initContainer` — init containers perform setup tasks (chown, file generation) that legitimately require filesystem writes; apply the read-only flag to app containers and review init containers individually.
- `resources: {}` in a Helm chart values file (not a rendered manifest) — the empty block may be overridden by values at deploy time; verify the rendered output (`helm template`) before raising a finding.
