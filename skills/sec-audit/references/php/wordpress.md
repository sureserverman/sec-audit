# WordPress Theme / Plugin Security

## Source

- https://developer.wordpress.org/apis/security/ — WordPress Security APIs (the canonical escaping / sanitizing / nonce / capability reference)
- https://developer.wordpress.org/apis/security/escaping/ — Escaping output (`esc_html`, `esc_attr`, `esc_url`, `wp_kses`)
- https://developer.wordpress.org/apis/security/nonces/ — Nonces (CSRF protection)
- https://developer.wordpress.org/reference/classes/wpdb/prepare/ — `$wpdb->prepare()` (parameterised SQL)
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html — OWASP XSS Prevention
- https://cwe.mitre.org/ — CWE index

## Scope

The WordPress-specific security surface the `php` lane's phpcs + WPCS security
sniffs operationalise: output escaping (XSS), request-input validation /
sanitization, CSRF nonces, capability checks, and parameterised SQL via
`$wpdb->prepare`. This pack is the pattern reference the sec-expert reads to
reason about a phpcs finding (is this echo reachable with attacker input? is the
missing nonce on a state-changing action?) and the source of the quoted WordPress
fix recipes. Out of scope: non-WordPress PHP (see `php/php-web.md`), plugin
dependency CVEs (the `Packagist` ecosystem feed), and full taint analysis (a
coverage-gap fingerprint).

## Dangerous patterns (regex/AST hints)

### Unescaped output — CWE-79 (XSS)

- Why: echoing a variable — especially request input or stored data — without an
  escaping function lets an attacker inject `<script>`. WordPress requires output
  to be escaped at the point of output with the context-appropriate function:
  `esc_html` (text), `esc_attr` (HTML attribute), `esc_url` (URLs), `esc_js`
  (inline JS), `wp_kses`/`wp_kses_post` (allowed-HTML). Escape late, escape every
  time.
- Grep: `echo\s+\$` / `print\s+\$` / `<\?=\s*\$` where the value is not wrapped in an `esc_*` / `wp_kses*` call
- phpcs sniff: `WordPress.Security.EscapeOutput.OutputNotEscaped` (the lane maps this → CWE-79)
- Source: https://developer.wordpress.org/apis/security/escaping/

### Form / action processed without a nonce — CWE-352 (CSRF)

- Why: a state-changing handler (saving an option, deleting a post, updating
  user data) that does not verify a nonce can be triggered cross-site. Every
  form and admin/AJAX action must call `wp_verify_nonce()` /
  `check_admin_referer()` / `check_ajax_referer()` before acting on `$_POST` /
  `$_GET`.
- Grep: an `if ( isset( $_POST[...] ) )` / `$_POST[...]` write path with no
  `wp_verify_nonce` / `check_admin_referer` / `check_ajax_referer` in scope
- phpcs sniff: `WordPress.Security.NonceVerification.Missing` / `.Recommended` (→ CWE-352)
- Source: https://developer.wordpress.org/apis/security/nonces/

### Unvalidated / unsanitized / unslashed input — CWE-20

- Why: reading `$_GET` / `$_POST` / `$_REQUEST` / `$_SERVER` and using it without
  `wp_unslash()` then a `sanitize_*` function (`sanitize_text_field`,
  `absint`, `sanitize_email`, …) feeds untrusted, magic-quotes-slashed data into
  the app. WordPress requires unslash-then-sanitize on every superglobal read.
- Grep: `\$_(GET|POST|REQUEST|SERVER|COOKIE)\[` not wrapped in `wp_unslash(` + a `sanitize_*(` / `absint(` call
- phpcs sniff: `WordPress.Security.ValidatedSanitizedInput.*` (→ CWE-20)
- Source: https://developer.wordpress.org/apis/security/sanitizing/

### SQL built without `$wpdb->prepare` — CWE-89 (SQLi)

- Why: `$wpdb->query( "SELECT ... WHERE id = " . $id )` concatenates input
  straight into SQL. Use `$wpdb->prepare( "... WHERE id = %d", $id )` with
  `%d`/`%s`/`%f` placeholders for every dynamic value.
- Grep: `\$wpdb->(query|get_results|get_var|get_row)\s*\(\s*["'][^"']*\.\s*\$` (concatenation into the SQL string)
- phpcs sniff: `WordPress.DB.PreparedSQL.NotPrepared` / `WordPress.DB.PreparedSQLPlaceholders.*` (→ CWE-89)
- Source: https://developer.wordpress.org/reference/classes/wpdb/prepare/

### Missing capability check on a privileged action — CWE-862

- Why: an admin action that does not call `current_user_can( '<cap>' )` lets any
  authenticated (or unauthenticated, via a public AJAX action) user perform it —
  broken access control. Pair the nonce (intent) with a capability check
  (authorization).
- Grep: an `add_action( 'admin_post_...' )` / `wp_ajax_...` handler with no `current_user_can(` in scope
- phpcs sniff: not directly (capability logic is semantic) — sec-expert reasoning
- Source: https://developer.wordpress.org/apis/security/

## Secure patterns

A handler that verifies nonce + capability, unslashes+sanitizes input, prepares
SQL, and escapes output:

```php
function my_save_handler() {
    if ( ! isset( $_POST['my_nonce'] )
        || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['my_nonce'] ) ), 'my_action' ) ) {
        wp_die( 'Bad nonce' );
    }
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'Forbidden' );
    }
    $name = sanitize_text_field( wp_unslash( $_POST['name'] ?? '' ) );
    update_option( 'display_name', $name );

    global $wpdb;
    $id  = absint( $_GET['id'] ?? 0 );
    $row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}users WHERE id = %d", $id ) );

    echo esc_html( $name );   // escape at output
}
```

Source: https://developer.wordpress.org/apis/security/

## Fix recipes

### Recipe: Escape output — addresses CWE-79

**Before (dangerous):**

```php
echo $_GET['q'];
```

**After (safe):**

```php
echo esc_html( sanitize_text_field( wp_unslash( $_GET['q'] ?? '' ) ) );
```

Source: https://developer.wordpress.org/apis/security/escaping/

### Recipe: Prepare SQL — addresses CWE-89

**Before (dangerous):**

```php
$wpdb->query( "SELECT * FROM users WHERE id = " . $id );
```

**After (safe):**

```php
$wpdb->query( $wpdb->prepare( "SELECT * FROM users WHERE id = %d", $id ) );
```

Source: https://developer.wordpress.org/reference/classes/wpdb/prepare/

## Version notes

- WPCS 3.0 (2023) reorganised sniffs (several moved to PHPCSExtra, pulled in
  transitively). The `WordPress.Security.*` / `WordPress.DB.PreparedSQL*` codes
  the lane maps are stable across 3.x.
- `esc_html__()` / `esc_html_e()` combine translation + escaping for i18n'd
  strings — the correct pattern for translatable output.

## Common false positives

- `echo esc_html( $x )` flagged by a shallow grep — the escaping IS present;
  phpcs's `EscapeOutput` sniff correctly does not fire here.
- Output of a value that was escaped on a prior line and stored in a variable —
  phpcs may still flag it (it escapes at output, not by data-flow); confirm the
  stored value is escaped before down-ranking.
- `$wpdb->query()` on a fully static SQL literal (no concatenation) — not
  injectable; `PreparedSQL` should not fire, but verify no hidden interpolation.
