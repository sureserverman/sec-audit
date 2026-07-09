# php-tools

<!--
    Tool-lane reference for sec-audit's php lane (v1.27.0+).
    Consumed by the `php-runner` sub-agent. Documents
    phpcs + the WordPress Coding Standards security sniffs.
-->

## Source

- https://github.com/PHPCSStandards/PHP_CodeSniffer — phpcs canonical (PHP_CodeSniffer)
- https://github.com/WordPress/WordPress-Coding-Standards — WordPress Coding Standards (WPCS; the `WordPress` standard + its `WordPress.Security.*` / `WordPress.DB.*` sniffs)
- https://make.wordpress.org/core/handbook/testing/automated-testing/phpcs/ — WordPress PHPCS handbook
- https://developer.wordpress.org/apis/security/ — WordPress security APIs (escaping, nonces, sanitization, `$wpdb->prepare`)
- https://cwe.mitre.org/ — CWE catalogue

## Scope

In-scope: the single tool invoked by `php-runner` — `phpcs` (PHP_CodeSniffer)
run with the WordPress Coding Standards **security** sniff subset. This is a
lexical + token-stream analyzer, not a full taint engine: it flags output that
is not passed through a WordPress escaping function, request input that is not
validated / sanitized / unslashed, form processing without a nonce, and SQL
built without `$wpdb->prepare`. Out of scope: full data-flow taint analysis
(`psalm --taint-analysis` / `progpilot` need a Composer autoload root — deferred,
tracked as a coverage-gap fingerprint), non-WordPress framework deep support
(Laravel/Symfony — the sniffs still fire on universal issues with more FPs), and
`composer.json` dependency CVEs (enriched separately via the `Packagist`
ecosystem feed).

## Canonical invocations

### phpcs (WordPress security sniffs)

- Install: `composer global require squizlabs/php_codesniffer
  wp-coding-standards/wpcs dealerdirect/phpcodesniffer-composer-installer`
  (the installer auto-registers WPCS's `installed_paths`); confirm with
  `phpcs -i` listing `WordPress`. Requires PHP ≥ 7.2 with the `xml` extension.
- Invocation:
  ```bash
  phpcs --standard=WordPress \
      --sniffs=WordPress.Security.EscapeOutput,WordPress.Security.NonceVerification,WordPress.Security.ValidatedSanitizedInput,WordPress.DB.PreparedSQL,WordPress.DB.PreparedSQLPlaceholders \
      --report=json "$target_path"
  ```
  `--sniffs=<security subset>` restricts phpcs to the security-relevant sniffs —
  the full `WordPress` standard adds naming/spacing/style noise the lane does not
  want. `--report=json` emits machine-readable output on stdout.
- Output: JSON. `files` is an OBJECT keyed by file path; each value has
  `errors`, `warnings`, and a `messages[]` array whose entries carry `message`,
  `source` (the sniff code, e.g. `WordPress.Security.EscapeOutput.OutputNotEscaped`),
  `severity` (phpcs's internal 1–5), `type` (`ERROR` / `WARNING`), `line`,
  `column`, `fixable`. The runner iterates the `files` object's VALUES (exposing
  the path key as `_parent._key`) and flattens `messages`.
- Tool behaviour: exits non-zero when any sniff fires; NOT a crash — read the
  JSON regardless. An empty `files` object with exit 0 means no findings.
- Path note: phpcs reports the file path as an ABSOLUTE path (it resolves the
  argument internally), consistent with the other tool-driven lanes whose
  `target_path` is absolute.
- Primary source: https://make.wordpress.org/core/handbook/testing/automated-testing/phpcs/

Source: https://github.com/WordPress/WordPress-Coding-Standards

## Output-field mapping

Every finding carries `origin: "php"`, `tool: "phpcs"`,
`reference: "php-tools.md"`.

### phpcs → sec-audit finding

| upstream                                              | sec-audit field             |
|-------------------------------------------------------|------------------------------|
| `"phpcs:" + .source` (the sniff code)                 | `id`                         |
| `.type` remap: `ERROR` → HIGH, `WARNING` → MEDIUM     | `severity`                   |
| CWE looked up from `.source`: `EscapeOutput.*` → CWE-79, `NonceVerification.*` → CWE-352, `ValidatedSanitizedInput.*` → CWE-20, `PreparedSQL(.Placeholders).*` → CWE-89, else `null` | `cwe` |
| `.message` (truncated to 120 chars)                   | `title`                      |
| the `files` object KEY (`_parent._key`)               | `file`                       |
| `.line`                                               | `line`                       |
| `.message` (truncated to 200 chars)                   | `evidence`                   |
| null (phpcs ships no per-sniff fix URL in JSON)       | `reference_url`              |
| null                                                  | `fix_recipe`                 |
| `"medium"` (token-stream sniffs, not full taint)      | `confidence`                 |

## Degrade rules

`__php_status__` ∈ {`"ok"`, `"partial"`, `"unavailable"`}.

Skip vocabulary:

- `tool-missing` — phpcs is absent from PATH (or the `WordPress` standard is
  not registered — `phpcs -i` does not list it).
- `no-php-source` — phpcs is on PATH but the target tree contains no `*.php`
  file. Target-shape clean-skip.

No host-OS gate — phpcs is cross-platform with no `requires-<host>-host`
precondition.

## Version pins

- `phpcs` (`squizlabs/php_codesniffer`) ≥ 3.9 (stable `--report=json` schema:
  `files` keyed by path, `messages[]` with `source`/`type`/`line`). Pinned
  2026-07.
- `wp-coding-standards/wpcs` ≥ 3.0 (the `WordPress.Security.*` /
  `WordPress.DB.PreparedSQL*` sniff codes are stable in 3.x; 3.0 moved several
  sniffs to `PHPCSExtra`, pulled in transitively by the installer). Pinned
  2026-07.
