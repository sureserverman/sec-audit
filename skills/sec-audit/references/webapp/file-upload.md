# Unrestricted File Upload

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html — OWASP File Upload Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A04:2021 Insecure Design)
- https://cwe.mitre.org/data/definitions/434.html — CWE-434: Unrestricted Upload of File with Dangerous Type
- https://docs.djangoproject.com/en/stable/ref/models/fields/#filefield — Django FileField documentation
- https://expressjs.com/en/resources/middleware/multer.html — Express multer documentation

## Scope

Covers unrestricted file upload vulnerabilities including: dangerous-type upload leading to server-side code execution, MIME-type confusion (Content-Type vs actual content), polyglot files, and filename-based path traversal. Applies to Express/multer, Django FileField/ImageField, and Rails Active Storage. Does not cover path traversal resulting from the extracted filename (see path-traversal pack) or stored-XSS via SVG upload (see XSS pack).

## Dangerous patterns (regex/AST hints)

### Express multer with no fileFilter or limits — CWE-434

- Why: `multer()` with no `fileFilter`, no `limits.fileSize`, and disk storage allows uploading arbitrary files including `.php`, `.js`, and executable binaries.
- Grep: `multer\s*\(\s*\{?\s*storage\s*:|multer\s*\(\s*\)`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://expressjs.com/en/resources/middleware/multer.html

### Django FileField without validator — CWE-434

- Why: `FileField` and `ImageField` without a `validate_file_extension` or content-type validator accept any uploaded file type.
- Grep: `models\.FileField\s*\(|forms\.FileField\s*\(`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### MIME type check on Content-Type header only — CWE-434

- Why: The browser-supplied `Content-Type` is fully attacker-controlled; a server that trusts it without reading magic bytes can be tricked into accepting dangerous files.
- Grep: `content.type|content_type|mimetype.*==.*request|request\.content_type`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### Storing uploaded files inside the web root — CWE-434

- Why: Files stored under a publicly accessible directory are directly executable by the web server if the server is configured to run scripts.
- Grep: `MEDIA_ROOT.*static|upload.*public|uploads.*wwwroot|upload_to\s*=\s*['"]static`
- File globs: `**/*.py`, `**/*.js`, `**/*.ts`, `**/*.rb`, `**/*.conf`, `**/*.env`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### Filename taken directly from user input — CWE-434

- Why: Using `file.originalname` or `request.files[].name` as the stored filename enables path traversal and extension spoofing.
- Grep: `file\.originalname|req\.files\[.*\]\.name|uploaded_file\.name\b`
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### No file-size limit on upload handler — CWE-434

- Why: Missing size limits enable denial-of-service by filling disk or exhausting memory in upload buffering.
- Grep: `multer\s*\({(?!.*fileSize)|InMemoryUploadedFile|request\.files` (no adjacent size check)
- File globs: `**/*.js`, `**/*.ts`, `**/*.py`, `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### Rails Active Storage with no content-type restriction — CWE-434

- Why: `has_one_attached` and `has_many_attached` accept any content type unless `content_type` validation is added.
- Grep: `has_one_attached\s*:|has_many_attached\s*:`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

## Secure patterns

Express multer with allowlist fileFilter and size limit:

```js
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');

const ALLOWED_EXTS = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp']);
const ALLOWED_MIMES = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp']);

const storage = multer.diskStorage({
  destination: '/var/uploads/pending',  // outside web root
  filename: (_req, _file, cb) => cb(null, crypto.randomUUID()),  // discard original name
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },  // 5 MB
  fileFilter(_req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTS.has(ext) || !ALLOWED_MIMES.has(file.mimetype)) {
      return cb(new Error('File type not permitted'));
    }
    cb(null, true);
  },
});
```

Source: https://expressjs.com/en/resources/middleware/multer.html

Python — validate magic bytes with `python-magic` after upload:

```python
import magic, os

ALLOWED_MIMES = {"image/jpeg", "image/png", "image/gif", "image/webp"}

def validate_upload(file_path: str) -> None:
    mime = magic.from_file(file_path, mime=True)
    if mime not in ALLOWED_MIMES:
        os.remove(file_path)
        raise ValueError(f"Rejected file type: {mime}")
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

Django — validate extension and MIME in a custom validator:

```python
from django.core.exceptions import ValidationError
import magic

ALLOWED_MIMES = {"image/jpeg", "image/png"}

def validate_image(file):
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    if mime not in ALLOWED_MIMES:
        raise ValidationError("Unsupported file type.")

class Profile(models.Model):
    avatar = models.FileField(upload_to='avatars/', validators=[validate_image])
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

## Fix recipes

### Recipe: Replace original filename with random UUID in multer — addresses CWE-434

**Before (dangerous):**

```js
const storage = multer.diskStorage({
  destination: 'public/uploads',
  filename: (_req, file, cb) => cb(null, file.originalname),
});
```

**After (safe):**

```js
const crypto = require('crypto');
const storage = multer.diskStorage({
  destination: '/var/uploads',  // outside public root
  filename: (_req, _file, cb) => cb(null, crypto.randomUUID()),
});
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### Recipe: Add magic-byte check instead of Content-Type trust — addresses CWE-434

**Before (dangerous):**

```python
if request.files['upload'].content_type not in ('image/jpeg', 'image/png'):
    abort(400)
```

**After (safe):**

```python
import magic
data = request.files['upload'].read(2048)
request.files['upload'].seek(0)
mime = magic.from_buffer(data, mime=True)
if mime not in ('image/jpeg', 'image/png'):
    abort(400, "Invalid file type")
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### Recipe: Add content-type restriction to Rails Active Storage — addresses CWE-434

**Before (dangerous):**

```ruby
class Document < ApplicationRecord
  has_one_attached :file
end
```

**After (safe):**

```ruby
class Document < ApplicationRecord
  has_one_attached :file

  validate :acceptable_file

  def acceptable_file
    return unless file.attached?
    unless file.content_type.in?(%w[application/pdf image/jpeg image/png])
      errors.add(:file, "must be a PDF or image")
    end
    if file.byte_size > 10.megabytes
      errors.add(:file, "is too large (max 10 MB)")
    end
  end
end
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

## Version notes

- Express multer does not perform any content-type validation by default; `fileFilter` is entirely the application's responsibility regardless of multer version.
- Django's `ImageField` calls Pillow's `verify()` to confirm the image is parseable, but does not reject non-image files if the extension matches; always add an explicit MIME validator.
- Rails Active Storage switched from `content_type_whitelist` to a `content_type` validation API in Rails 6.1; older code using `whitelist` callbacks should be migrated.
- `python-magic` requires the system `libmagic` library; `python-magic-bin` bundles it on Windows. Confirm the dependency exists before using it.

## Common false positives

- `multer()` with `memoryStorage()` and an immediate type check in the route handler — the dangerous pattern fires on the multer instantiation, but if a `fileFilter` is applied or the mimetype is validated immediately after, the risk is mitigated; triage together.
- `models.FileField` used for developer-uploaded static assets (e.g. site logos in an admin panel with restricted access) — the attack surface is limited when the upload endpoint requires admin authentication; note in the finding.
- `has_many_attached :screenshots` in a model where a content-type validator is defined on the same model in a concern or superclass — search for the validator in parent classes before flagging.
- `file.content_type` check that is then followed immediately by a magic-byte check — the Content-Type check alone is insufficient, but if both are present the combined control is acceptable.
