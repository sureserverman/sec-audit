# vulnerable-k8s fixture

Minimal K8s manifest tree for the sec-review Kubernetes lane E2E
assertions (v1.1.0 Stage 2).

## Intentional findings

- `manifests/deployment.yaml` — privileged: true (CWE-250), CAP
  SYS_ADMIN + NET_ADMIN (CWE-250), hostNetwork: true + hostPID:
  true (CWE-653), image: nginx:latest (CWE-494), no resources.limits
  (CWE-400), no NetworkPolicy target (CWE-284).
- `manifests/rbac.yaml` — ClusterRole with wildcard resources + verbs
  (CWE-250), ClusterRoleBinding to `system:authenticated` (CWE-732).
- `manifests/secret.yaml` — base64 plaintext credentials in git
  (CWE-312 + CWE-798).
- `manifests/ingress.yaml` — Ingress without `tls:` block (CWE-319).

## `.pipeline/`

- `kube-score-report.json` — synthetic kube-score JSON with 4
  findings.
- `kubesec-report.json` — synthetic kubesec JSON with 5 findings
  (3 critical + 2 advise).
- `k8s.jsonl` — expected k8s-runner output: 9 findings + `__k8s_
  status__: "ok"` trailing line.
