# k8s-tools

<!--
    Tool-lane reference for sec-audit's Kubernetes admission-control
    lane (v1.1.0+). Consumed by the `k8s-runner` sub-agent.
-->

## Source

- https://github.com/zegl/kube-score — kube-score canonical (Go-based manifest scorer)
- https://github.com/controlplaneio/kubesec — kubesec canonical (admission-scoring scanner with JSON output)
- https://kubernetes.io/docs/concepts/security/ — K8s security model
- https://cwe.mitre.org/
- https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html

## Scope

In-scope: the two tools invoked by `k8s-runner` — `kube-score` and
`kubesec`. Both are static-YAML scanners; neither needs a live
cluster. Out of scope: runtime cluster audit (kube-bench / kube-hunter
against a running cluster — live-host territory); Helm chart
templating audit; Kustomize overlay drift; OPA/Gatekeeper policy
testing against manifests (covered in part by sec-expert reasoning
against the k8s-api.md pack).

## Canonical invocations

### kube-score

- Install: `go install github.com/zegl/kube-score/cmd/kube-score@latest` OR `brew install kube-score` OR docker image `zegl/kube-score:latest`.
- Invocation (JSON output):
  ```bash
  kube-score score --output-format json \
      $(find "$target_path" -type f \( -name '*.yaml' -o -name '*.yml' \) \
        -not -path '*/node_modules/*' -not -path '*/.git/*') \
      > "$TMPDIR/k8s-runner-kube-score.json" \
      2> "$TMPDIR/k8s-runner-kube-score.stderr"
  rc_ks=$?
  ```
- Output: JSON array of per-file objects, each with a `checks` array
  where each check has `check.id`, `grade` (0-10), `comments[]` with
  `summary`/`description`/`path`/`severity`.
- Exit code 0 means clean; non-zero means issues found — NOT a crash.
- Primary source: https://github.com/zegl/kube-score

Source: https://github.com/zegl/kube-score

### kubesec

- Install: `brew install kubesec` OR docker `docker pull controlplane/kubesec:latest`.
- Invocation (JSON per-file):
  ```bash
  while IFS= read -r manifest; do
      kubesec scan "$manifest" \
          >> "$TMPDIR/k8s-runner-kubesec.json" \
          2>> "$TMPDIR/k8s-runner-kubesec.stderr"
  done < <(find "$target_path" -type f \( -name '*.yaml' -o -name '*.yml' \) -not -path '*/node_modules/*')
  ```
- Output: JSON array-per-file. Each file-object has `score` (signed
  integer — positive is safer), `scoring.critical[]` (severe
  findings), `scoring.advise[]` (lower-severity hardening
  suggestions). Each entry has `id`, `reason`, `points`.
- Primary source: https://github.com/controlplaneio/kubesec

Source: https://github.com/controlplaneio/kubesec

## Output-field mapping

Every finding carries `origin: "k8s"`, `tool: "kube-score" | "kubesec"`,
`reference: "k8s-tools.md"`.

### kube-score → sec-audit finding

| upstream                                    | sec-audit field             |
|---------------------------------------------|------------------------------|
| `"kube-score:" + check.id`                  | `id`                         |
| `comments[].severity` remap: `"CRITICAL"` → HIGH, `"WARNING"` → MEDIUM, `"IGNORED"` → LOW, other → LOW | `severity` |
| per-check CWE table: `container-security-context-user-group-id` → CWE-250; `container-privilege-escalation` → CWE-269; `container-privileged` → CWE-250; `container-resources` → CWE-400; `container-image-tag` → CWE-494; `pod-networkpolicy` → CWE-284; `container-security-context-readonlyrootfilesystem` → CWE-732. Unmapped check → `null`. | `cwe` |
| `check.comments[].summary`                  | `title`                      |
| file path relative to `target_path`         | `file`                       |
| `comments[].path` line if parseable, else `0` | `line`                     |
| `comments[].description`                    | `evidence`                   |
| `null`                                      | `reference_url`              |
| synthesised from the k8s-workloads.md / k8s-api.md fix recipe matching the check | `fix_recipe` |
| `"high"` (deterministic YAML checks)        | `confidence`                 |

### kubesec → sec-audit finding

| upstream                                    | sec-audit field             |
|---------------------------------------------|------------------------------|
| `"kubesec:" + scoring.critical[].id` (or `advise[].id`) | `id`              |
| critical → HIGH; advise → MEDIUM             | `severity`                   |
| CWE per the same table as kube-score when rule names align; else `null` | `cwe` |
| `reason` verbatim                           | `title`                      |
| manifest file path                          | `file`                       |
| 0                                           | `line`                       |
| `"(" + points + ") " + reason`              | `evidence`                   |
| `null`                                      | `reference_url`              |
| synthesised from the matching recipe         | `fix_recipe`                |
| `"high"`                                    | `confidence`                 |

## Degrade rules

The `k8s-runner` agent follows the three-state sentinel contract.
`__k8s_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}. Only
`tool-missing` applies as a skip reason in this lane — both tools
are cross-platform source-tree scanners with no host-OS gates and no
target-artifact preconditions beyond the presence of `*.yaml` /
`*.yml` files (verified by §2 inventory).

Canonical status-line shapes:

```json
{"__k8s_status__": "ok", "tools": ["kube-score","kubesec"], "runs": 2, "findings": 12}
{"__k8s_status__": "partial", "tools": ["kube-score"], "runs": 1, "findings": 7, "failed": ["kubesec"]}
{"__k8s_status__": "unavailable", "tools": [], "skipped": [{"tool": "kube-score", "reason": "tool-missing"}, {"tool": "kubesec", "reason": "tool-missing"}]}
```

## Version pins

- `kube-score` ≥ 1.17 (stable JSON schema). Pinned 2026-04.
- `kubesec` ≥ 2.14 (stable `scan` JSON output). Pinned 2026-04.
