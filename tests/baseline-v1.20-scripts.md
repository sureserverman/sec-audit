# Deterministic-script conversion — cost baseline (v1.20)

Closes the Stage 7 "measure token/cost delta vs baseline" deliverable of
`docs/plans/2026-05-27-deterministic-scripts-tiers-1-2-plan.md`. Records the
cost delta of moving the deterministic pipeline work out of the LLM runner
agents into the config-driven Python engine (v1.17 → v1.20), and the non-cost
benefits that motivated it.

## Honesty note

No live two-run token capture was performed. A faithful before/after needs the
lane tools installed (semgrep, bandit, hadolint, mcp-scan, trivy, …) plus a run
of the pre-v1.17 all-LLM-runner agents — neither is available in the authoring
environment. Per the plan ("qualitative if a live run isn't available"), this is
a structured estimate from **measurable proxies** plus the **methodology** to
capture a precise live number (below). Numbers labeled *estimate* use a
~4-chars/token heuristic and the haiku rate from `tests/model-costs.json`
(input $1.00/Mtok, output $5.00/Mtok, blended $2.00/Mtok).

## The cost model — what work moved

**Before** (LLM runner agent, haiku) — per dispatch the agent:
1. loaded its full `*-tools.md` reference pack as **input tokens**, and
2. **reasoned** through the field-mapping recipe to emit JSONL findings
   (**output tokens**, scaling with finding count).

**After** (thin wrapper) — the engine (`runner.py`, pure Python) does
probe → run → map → emit at **zero token cost**; the agent body is short and
performs only an optional presentation-only *polish* + relay. The mapping recipe
is encoded once as `lanes/<lane>.json`, read by Python — not the model.

Per converted lane, the conversion **removes**: pack-read input tokens +
mapping-reasoning output tokens + long-procedure prompt tokens. It **retains**: a
short prompt + relay/polish of the engine's output.

## Measurable proxies (v1.20, 16 converted lanes)

| Proxy | Measurement |
|---|---|
| Thin runner-agent prose | 95–170 lines (median ~127). `virt`: 230 → 127 lines (−45%), 8016 → 5160 bytes (−36%) |
| Reference packs no longer loaded by runners at dispatch | ~220 KB across these lanes' `*-tools.md` (≈ 13.7 KB / ~3.4K tokens average per lane; `mobile-tools.md` serves both android + ios) |
| Engine config that replaced the prose mapping | `scripts/secaudit/lanes/*.json` ≈ 35 KB total — read by Python, **0 model tokens** |

## First-order cost estimate (haiku)

Per-lane dispatch, **input side**:
- reference pack no longer read: ~3,440 tok → ~$0.0034
- agent-body shrink (e.g. `virt` −2,856 bytes ≈ −714 tok) → ~$0.0007
- **input saved ≈ ~4,150 tok ≈ $0.004 / lane dispatch**

**Output side**: the field-mapping the model used to *generate* token-by-token is
eliminated — findings are now relayed (or lightly polished) rather than
synthesized. This is lane-dependent and not priced here without a live run, but
it is the larger of the two savings for finding-heavy lanes.

**Aggregate**: a full multi-lane run dispatching all 16 converted lanes avoids on
the order of **~55K input tokens** of reference-pack loading alone ≈ **~$0.05/run**
at the haiku input rate — *before* counting the eliminated output reasoning. Real
runs dispatch only the inventory-matched subset, so realized per-run savings scale
with stack breadth.

## The benefit that isn't a number

- **Determinism** — identical input → identical findings every run; no model
  variance in `id`/`cwe`/`severity`/`file`/`line`.
- **Zero fabrication risk on mapped fields** — the engine cannot invent a finding,
  CWE, or tool name. The error class the agents' "never fabricate" hard-rules
  guarded against is now *structurally impossible* for extraction.
- **One tested mapping per lane** — each recipe lives in a single
  `lanes/<lane>.json` with a `script-runner.sh <lane>` parity test, instead of
  prose that can drift across 16 agents.
- **Speed** — a Python map is instant vs. an LLM round-trip per lane.

## How to capture a precise live number

1. Check out the last pre-v1.17 commit (all-LLM-runner agents).
2. Run a full `/sec-audit` on a multi-stack fixture *with the tools installed*;
   capture `total_tokens` per agent → `tokens-before.json`.
3. Repeat on v1.20 → `tokens-after.json`.
4. `tests/measure-pipeline.sh --json <tokens.json>` prices each against
   `tests/model-costs.json`; diff the two runs.

(Recorded as reproducible methodology; not executed in this environment.)

## Scope

**Converted (16, script-backed):** sast, go, shell, ansible, gh-actions, python,
iac, image, dast, supply-chain, k8s, webext, webapp, rust, android, virt. Plus the
Tier-1 scripts `cve_enricher.py`, `score.py`, `inventory.py`.

**Still LLM by design:** sec-expert / finding-triager / dep-diff-analyst /
report-writer (irreducible judgement); ai-tools (planned), linux (parked),
macos / ios / windows / netcfg (permanent). See COVERAGE.md, "Deterministic
scripts vs LLM agents".
