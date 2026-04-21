# <Technology / Domain Name>

<!--
    REFERENCE PACK TEMPLATE — sec-review plugin.

    Every reference file in this tree MUST follow this structure. The
    sec-expert subagent and the sec-review skill both load these files and
    rely on the section headers being present verbatim.

    Citation rule (hard):
        Every "Fix recipes" entry, every "Secure patterns" snippet, and every
        "Dangerous patterns" category MUST be traceable to a primary source
        listed under "## Source". Primary sources are:
          - Official vendor docs (django/nginx/postgres/docker/etc.)
          - IETF RFCs (datatracker.ietf.org)
          - OWASP Cheat Sheet Series (cheatsheetseries.owasp.org)
          - OWASP ASVS / Top 10 (owasp.org)
          - CIS Benchmarks (cisecurity.org)
          - NIST SP / FIPS (csrc.nist.gov, pages.nist.gov)
          - Mozilla / MDN (developer.mozilla.org, ssl-config.mozilla.org)
          - OpenID Foundation (openid.net)
          - SLSA / Sigstore / CISA (slsa.dev, sigstore.dev, cisa.gov)

    If a pattern or fix cannot cite one of these, it does NOT go in.
    Training-data folk wisdom is explicitly disallowed.
-->

## Source

- <Primary source URL #1 — name of doc>
- <Primary source URL #2 — name of doc>
- <OWASP / RFC / CIS link as applicable>

## Scope

One paragraph: what is in scope (versions, components, deployment modes) and
what is out of scope (e.g. "does not cover <related adjacent tech>"). The
sec-expert uses this to decide whether a project's detected stack maps here.

## Dangerous patterns (regex/AST hints)

Each pattern has: a name, a short rationale, the associated CWE, and a
grep/ripgrep pattern that hints at the sink. Patterns are hints, not proofs
— the sec-expert will triage matches for real context before flagging.

### <Pattern 1 name>  — CWE-XXX

- Why: <one-line rationale>
- Grep: `<regex>`
- File globs: `<glob(s)>`
- Source: <URL from the `## Source` list above>

### <Pattern 2 name>  — CWE-YYY

- Why: ...
- Grep: ...
- File globs: ...
- Source: ...

## Secure patterns

Short, copy-pasteable "this is what right looks like" snippets. Each snippet
must be traceable to a `## Source` URL.

```
<code / config snippet>
```

Source: <URL>

## Fix recipes

Named, self-contained recipes the sec-expert can quote VERBATIM into a
finding's `fix_recipe` field. Each recipe has: a name, the CWE/pattern it
addresses, a minimal diff-style before/after, and a source URL.

### Recipe: <fix name>  — addresses CWE-XXX

**Before (dangerous):**

```
<dangerous example>
```

**After (safe):**

```
<safe example>
```

Source: <URL>

## Version notes

Anything version-specific (e.g. "this fix applies to Django >= 4.2; for 3.2
use <alternative>"). Keep terse — the point is to avoid stale advice.

## Common false positives

Patterns that will match but are usually fine in context. The sec-expert
downgrades confidence on these unless corroborating evidence is present.

- <pattern> — usually safe when <condition>
