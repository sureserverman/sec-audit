# Path Traversal

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — OWASP File Upload Cheat Sheet (traversal via filename)
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A01:2021 Broken Access Control)
- https://cwe.mitre.org/data/definitions/22.html — CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- https://cwe.mitre.org/data/definitions/23.html — CWE-23: Relative Path Traversal
- https://cwe.mitre.org/data/definitions/24.html — CWE-24: Path Traversal — '../filedir'
- https://snyk.io/research/zip-slip-vulnerability — Snyk Zip Slip research (ZIP slip subclass)

## Scope

Covers path traversal in server-side file access: open/read/write operations where the path is derived from user input. Includes ZIP slip (extracting archives with `../` entries to escape the target directory). Applies to Python, Node.js, Java, Ruby, and Go. Does not cover file-type confusion (see file-upload pack) or symlink attacks.

## Dangerous patterns (regex/AST hints)

### Python open() with user-controlled path — CWE-22

- Why: Concatenating user input to a base path without normalization and prefix checking allows `../../etc/passwd`-style traversal.
- Grep: `open\s*\(\s*(?:os\.path\.join|base_dir\s*\+|path\s*\+)[^,)]*`
- File globs: `**/*.py`
- Source: https://cwe.mitre.org/data/definitions/22.html

### Python os.path.join with absolute-path injection — CWE-22

- Why: `os.path.join('/safe/base', '/etc/passwd')` returns `/etc/passwd`; a leading slash in user input discards the base entirely.
- Grep: `os\.path\.join\s*\([^)]*request\.|os\.path\.join\s*\([^)]*params`
- File globs: `**/*.py`
- Source: https://cwe.mitre.org/data/definitions/22.html

### Node.js fs.readFile/createReadStream with user path — CWE-22

- Why: Passing a user-supplied filename to any `fs` method without sanitization reads arbitrary server files.
- Grep: `fs\.(readFile|createReadStream|writeFile|unlink)\s*\(\s*[^"'][^,)]*`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cwe.mitre.org/data/definitions/22.html

### Java FileInputStream / new File() with user input — CWE-22

- Why: `new File(baseDir, userPath)` followed by `getCanonicalPath()` check is the correct pattern; skipping the canonical-path check allows traversal.
- Grep: `new\s+File\s*\([^)]*request\.|new\s+FileInputStream\s*\([^)]*param`
- File globs: `**/*.java`
- Source: https://cwe.mitre.org/data/definitions/22.html

### Ruby File.read/open/expand_path with params — CWE-22

- Why: Rails `params` passed directly to `File.read` or `send_file` enables traversal; `Pathname#cleanpath` is a start but not sufficient without a prefix check.
- Grep: `File\.(read|open|expand_path)\s*\([^)]*params\[|send_file\s*params`
- File globs: `**/*.rb`
- Source: https://cwe.mitre.org/data/definitions/22.html

### Go filepath.Join without Clean + prefix assertion — CWE-22

- Why: `filepath.Join` does not resolve symlinks or assert containment; a `../` segment in user input escapes the base directory.
- Grep: `filepath\.Join\s*\([^)]*r\.(URL|Form|PostForm|PathValue)`
- File globs: `**/*.go`
- Source: https://cwe.mitre.org/data/definitions/22.html

### ZIP / TAR extraction without path validation (ZIP Slip) — CWE-22

- Why: Archived entries with `../` filenames extract to arbitrary locations on disk when the destination path is not sanitized.
- Grep: `ZipFile\.(extract|extractall)|tarfile\.(extract|extractall)|ZipEntry\.getName\(\)|entry\.getName\(\)`
- File globs: `**/*.py`, `**/*.java`, `**/*.js`, `**/*.ts`, `**/*.go`, `**/*.rb`
- Source: https://snyk.io/research/zip-slip-vulnerability

### Path traversal sequences in URL routing — CWE-23

- Why: Some frameworks URL-decode `%2e%2e%2f` after routing; explicitly decoding before normalization can expose static file servers.
- Grep: `decodeURIComponent|urllib\.parse\.unquote` (check if decoded value is used in file path)
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`
- Source: https://cwe.mitre.org/data/definitions/23.html

## Secure patterns

Python — normalize and assert containment after joining:

```python
import os

BASE_DIR = "/var/app/uploads"

def safe_path(filename: str) -> str:
    # Resolve to absolute, then verify it is inside BASE_DIR
    candidate = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not candidate.startswith(BASE_DIR + os.sep):
        raise ValueError("Path traversal detected")
    return candidate
```

Source: https://cwe.mitre.org/data/definitions/22.html

Go — Clean and prefix-assert:

```go
func safePath(base, userInput string) (string, error) {
    clean := filepath.Join(base, filepath.Clean("/"+userInput))
    if !strings.HasPrefix(clean, filepath.Clean(base)+string(os.PathSeparator)) {
        return "", fmt.Errorf("path traversal detected")
    }
    return clean, nil
}
```

Source: https://cwe.mitre.org/data/definitions/22.html

Python — safe ZIP extraction (ZIP Slip mitigation):

```python
import zipfile, os

def safe_extract(zf: zipfile.ZipFile, dest: str) -> None:
    dest = os.path.realpath(dest)
    for member in zf.namelist():
        target = os.path.realpath(os.path.join(dest, member))
        if not target.startswith(dest + os.sep):
            raise ValueError(f"Zip Slip: {member}")
        zf.extract(member, dest)
```

Source: https://snyk.io/research/zip-slip-vulnerability

## Fix recipes

### Recipe: Add containment check to os.path.join — addresses CWE-22

**Before (dangerous):**

```python
file_path = os.path.join(UPLOAD_DIR, request.args.get('file'))
with open(file_path) as f:
    return f.read()
```

**After (safe):**

```python
candidate = os.path.realpath(os.path.join(UPLOAD_DIR, request.args.get('file', '')))
if not candidate.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
    abort(400)
with open(candidate) as f:
    return f.read()
```

Source: https://cwe.mitre.org/data/definitions/22.html

### Recipe: Java canonical-path containment check — addresses CWE-22

**Before (dangerous):**

```java
File file = new File(baseDir, request.getParameter("filename"));
return Files.readAllBytes(file.toPath());
```

**After (safe):**

```java
File base = new File(baseDir).getCanonicalFile();
File file = new File(base, request.getParameter("filename")).getCanonicalFile();
if (!file.getPath().startsWith(base.getPath() + File.separator)) {
    throw new SecurityException("Path traversal detected");
}
return Files.readAllBytes(file.toPath());
```

Source: https://cwe.mitre.org/data/definitions/22.html

### Recipe: Validate ZIP entry names before extraction — addresses CWE-22

**Before (dangerous):**

```java
ZipInputStream zis = new ZipInputStream(upload.getInputStream());
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    Files.copy(zis, Paths.get(destDir, entry.getName()));
}
```

**After (safe):**

```java
Path destPath = Paths.get(destDir).toRealPath();
ZipInputStream zis = new ZipInputStream(upload.getInputStream());
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    Path target = destPath.resolve(entry.getName()).normalize();
    if (!target.startsWith(destPath)) {
        throw new SecurityException("Zip Slip: " + entry.getName());
    }
    Files.copy(zis, target);
}
```

Source: https://snyk.io/research/zip-slip-vulnerability

## Version notes

- Python's `zipfile.ZipFile.extractall()` does not protect against ZIP Slip in any current CPython release; manual entry validation is always required.
- Java's `ZipEntry.getName()` returns the raw stored name including any `../` segments; `Path.normalize()` resolves these but does not guarantee containment — always follow with a `startsWith(destPath)` check.
- Node.js `path.resolve()` resolves `..` segments but returns an absolute path that may be outside the base; follow with `startsWith(baseDir)`.
- Go `filepath.Clean` removes `..` segments but can still produce a path outside the base if the user input starts with `/` after cleaning; always prepend `/` to the input before joining (as shown in the secure pattern above).

## Common false positives

- `os.path.join(BASE_DIR, filename)` immediately followed by a `startswith` containment check — the dangerous join grep matches, but the assertion makes it safe; triage the two lines together.
- `send_file(params[:file])` in a Rails test helper or fixture — not a production endpoint; confirm it is not reachable in production routes.
- ZIP extraction in a build tool or CI script operating on developer-supplied archives — risk is significantly lower than production user-upload flows; note in the finding.
- `decodeURIComponent` used for display purposes only, where the decoded value is not subsequently passed to a file system API.
