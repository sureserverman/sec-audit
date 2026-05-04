# Command Injection in Web Handlers

## Source

- https://cwe.mitre.org/data/definitions/78.html — CWE-78: Improper Neutralization of Special Elements used in an OS Command
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html — OWASP OS Command Injection Defense Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A03:2021 Injection)
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html — OWASP Input Validation Cheat Sheet

## Scope

Covers OS command injection arising from HTTP request data (path parameters, query strings, POST bodies, headers) being passed to shell execution APIs in web handler code. Applies to Python (subprocess, os.system), Node.js (child_process), Java (Runtime.exec, ProcessBuilder), Ruby (backticks, system, %x), and PHP (exec, shell_exec, passthru). Does not cover blind SSRF, SQL injection, or template injection — see separate packs.

## Dangerous patterns (regex/AST hints)

### Python: subprocess.run / Popen with shell=True and request data — CWE-78

- Why: `shell=True` passes the command to `/bin/sh -c`, meaning any shell metacharacters in the user-supplied string (`;`, `|`, `$(...)`) execute arbitrary commands.
- Grep: `subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### Python: os.system / os.popen with request parameter — CWE-78

- Why: `os.system` always uses a shell; any string interpolation from user input is exploitable.
- Grep: `os\.(system|popen)\s*\(`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### Node.js: child_process.exec with template string — CWE-78

- Why: `exec` passes the command string to `/bin/sh`; template literal interpolation of `req.query`, `req.params`, or `req.body` directly enables injection.
- Grep: `child_process\.exec\s*\(`  (look for template literal or string concatenation with `req\.`)
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### Node.js: child_process.execSync with interpolated string — CWE-78

- Why: `execSync` is the synchronous variant of `exec`; same shell-invocation risk, frequently used in scripts called from web handlers.
- Grep: `execSync\s*\(\s*\`|execSync\s*\(\s*['"].*\+`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### Java: Runtime.exec with string concatenation of request parameter — CWE-78

- Why: `Runtime.exec(String)` splits the string on spaces but does not invoke a shell; however, `Runtime.exec(new String[]{"/bin/sh", "-c", userInput})` does, and many developers write it that way explicitly.
- Grep: `Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\([^)]*getParameter`
- File globs: `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### Ruby: backticks or %x{} with request param interpolation — CWE-78

- Why: Backtick execution and `%x{}` pass the string to a shell; interpolating `params` values enables full command injection.
- Grep: "`[^`]*#\{.*params|%x\{[^}]*#\{.*params|\bsystem\s*\([^)]*params|\bexec\s*\([^)]*params`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### PHP: exec / shell_exec / passthru / system without escapeshellarg — CWE-78

- Why: PHP's `exec()` family passes strings to the shell. Without `escapeshellarg()` or `escapeshellcmd()`, user data injects arbitrary commands.
- Grep: `\b(exec|shell_exec|passthru|system|proc_open|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`
- File globs: `**/*.php`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### Python: f-string / string formatting into subprocess command list — CWE-78

- Why: Even with `shell=False`, passing a pre-built f-string as a single string element (rather than a proper argument list) can result in a single token that contains spaces and breaks argument boundary assumptions.
- Grep: `subprocess\.(run|Popen)\s*\(\s*f['"]|subprocess\.(run|Popen)\s*\(\s*['"].*%\s*\(`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

## Secure patterns

Python — pass arguments as a list with shell=False (never interpolate user input into a shell string):

```python
import subprocess

# Safe: no shell; each argument is a separate list element
result = subprocess.run(
    ['convert', '-resize', user_size, input_path, output_path],
    shell=False,         # explicit; this is also the default
    capture_output=True,
    timeout=30,
    check=True,
)
# user_size, input_path, output_path are never interpreted as shell syntax
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

Node.js — use execFile or spawn (not exec) with argument arrays:

```js
const { execFile } = require('child_process');

// Safe: execFile does not invoke a shell; arguments are passed directly
execFile('/usr/bin/ffmpeg', ['-i', req.body.inputFile, outputPath], (err, stdout) => {
  if (err) return res.status(500).json({ error: 'Processing failed' });
  res.json({ output: outputPath });
});
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

Java — use ProcessBuilder with a list (never single-string shell invocation):

```java
ProcessBuilder pb = new ProcessBuilder(
    "convert",
    "-resize", userSize,
    inputPath, outputPath
);
pb.redirectErrorStream(true);
Process p = pb.start();
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

## Fix recipes

### Recipe: Python — remove shell=True and use argument list — addresses CWE-78

**Before (dangerous):**

```python
filename = request.args.get('file')
output = subprocess.check_output(f'cat /reports/{filename}', shell=True)
```

**After (safe):**

```python
import os, pathlib
filename = request.args.get('file', '')
# Validate: only allow safe characters, no path traversal
safe_name = pathlib.Path(filename).name
report_dir = pathlib.Path('/reports')
target = (report_dir / safe_name).resolve()
if not str(target).startswith(str(report_dir)):
    abort(400)
output = subprocess.check_output(['cat', str(target)], shell=False, timeout=10)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### Recipe: Node.js — replace exec with execFile — addresses CWE-78

**Before (dangerous):**

```js
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => res.send(stdout));
});
```

**After (safe):**

```js
const { execFile } = require('child_process');
const HOSTNAME_RE = /^[a-zA-Z0-9.-]{1,253}$/;

app.get('/ping', (req, res) => {
  const host = req.query.host || '';
  if (!HOSTNAME_RE.test(host)) return res.status(400).send('Invalid host');
  execFile('/bin/ping', ['-c', '1', host], { timeout: 5000 }, (err, stdout) => {
    if (err) return res.status(500).send('Error');
    res.send(stdout);
  });
});
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### Recipe: PHP — wrap user input with escapeshellarg — addresses CWE-78

**Before (dangerous):**

```php
$file = $_GET['file'];
$output = shell_exec("convert $file output.png");
```

**After (safe):**

```php
$file = escapeshellarg($_GET['file']);
$output = shell_exec("convert $file output.png");
// Better still: use a PHP image library (Imagick) to avoid the shell entirely
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

### Recipe: Ruby — use array form of system instead of backticks — addresses CWE-78

**Before (dangerous):**

```ruby
output = `identify #{params[:image_path]}`
```

**After (safe):**

```ruby
# Array form: no shell interpolation; each element is a literal argument
output = IO.popen(['identify', params[:image_path]], &:read)
# Or: use a dedicated library (MiniMagick, ruby-vips) instead of shelling out
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

## Version notes

- Python 3.12 added a `shell=False` lint warning in subprocess docs; nothing prevents `shell=True` at runtime — a linter or Bandit rule (`B602`) is required to catch it automatically.
- Node.js `child_process.exec` has been unchanged since Node 0.x; no version made it safe with user input. Use `execFile` or `spawn` with separate argument arrays in all Node versions.
- Java's `Runtime.exec(String)` does NOT invoke a shell and splits on spaces; it is safer than `Runtime.exec(new String[]{"/bin/sh","-c",cmd})`. Distinguish these two signatures when triaging — the array form with `/bin/sh -c` is the dangerous variant.
- PHP 8.x did not change `escapeshellarg` behavior; it remains the correct mitigation for string-based shell calls, but avoiding the shell entirely (via native PHP extensions) is preferred.

## Common false positives

- `subprocess.run([...], shell=False)` where all arguments are compile-time constants or come from a validated allowlist — not exploitable; lower to informational.
- `os.system` called in a CLI management script or cron job that is not reachable via HTTP — out of scope for web handler analysis; flag separately for non-web contexts.
- `child_process.exec` called with a fully static string (no variable interpolation) — no injection surface; still note for hygiene but not a finding.
- Ruby `system('command', arg1, arg2)` multi-argument form — Ruby's `system` with more than one argument does not invoke a shell; safe if no single-string form is used.
