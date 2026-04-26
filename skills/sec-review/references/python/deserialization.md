# Python — Deserialization and Dynamic Code Execution

## Source

- https://docs.python.org/3/library/pickle.html — `pickle` (canonical, with documented "never unpickle untrusted data" warning)
- https://docs.python.org/3/library/marshal.html — `marshal`
- https://docs.python.org/3/library/shelve.html — `shelve` (built atop `pickle`)
- https://pyyaml.org/wiki/PyYAMLDocumentation — PyYAML
- https://docs.python.org/3/library/xml.html — `xml.*` security warnings
- https://github.com/tiran/defusedxml — `defusedxml` (the canonical safe XML wrapper)
- https://docs.python.org/3/library/functions.html#eval — `eval` reference
- https://docs.python.org/3/library/functions.html#exec — `exec` reference
- https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data — OWASP
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html — OWASP cheatsheet
- https://cwe.mitre.org/data/definitions/502.html — CWE-502

## Scope

Covers Python deserialization and dynamic code-execution surfaces: `pickle.loads` / `pickle.load` / `cPickle.loads`, `marshal.loads`, `shelve.open`, `yaml.load` without `SafeLoader`, `xml.etree.ElementTree` / `lxml.etree` / `xml.dom.minidom` without `defusedxml`, `eval`/`exec`/`compile` on untrusted strings, `__import__` and `importlib.import_module` with attacker-influenced names, `pandas.read_pickle`, `joblib.load`, `numpy.load(allow_pickle=True)`, `torch.load` (PyTorch model deserialization), `tensorflow.keras.models.load_model` for h5/pickle paths. Out of scope: framework-specific deserialization (Django session signing, Flask `session` cookies — covered in `python/framework-deepening.md`); subprocess and OS-level injection (covered in `python/subprocess-and-async.md`); dependency-level CVEs (handled by cve-enricher's PyPI ecosystem pass).

## Dangerous patterns (regex/AST hints)

### `pickle.loads` / `pickle.load` on untrusted bytes — CWE-502

- Why: Python's pickle format is a stack-based serialization that includes opcodes for arbitrary class instantiation and method invocation. `pickle.loads(attacker_bytes)` executes `__reduce__` callbacks of any class the bytes reference, which is full RCE — not a parser bug, but the documented format. The `pickle` module itself carries a security warning at the top of the docs: "Never unpickle data received from an untrusted or unauthenticated source." Mitigations: switch to JSON / msgpack / protobuf for inter-process serialization; if pickle is unavoidable for performance reasons (numpy, pandas), authenticate the source with HMAC-signed payloads where the signing key is not known to the attacker.
- Grep: `\bpickle\.(loads?|Unpickler)\s*\(` OR `\bcPickle\.(loads?)\s*\(` in code paths receiving HTTP requests, file uploads, or socket data.
- File globs: `**/*.py`
- Source: https://docs.python.org/3/library/pickle.html

### `yaml.load` without `Loader=yaml.SafeLoader` — CWE-502

- Why: PyYAML's `yaml.load(data)` defaults (pre-5.1) to `FullLoader` which can construct arbitrary Python objects via the `!!python/object/apply:` tag. `yaml.load(attacker_yaml)` becomes RCE through the same class-instantiation pathway as pickle. PyYAML 5.1+ requires explicit `Loader=` and `yaml.load_all` / `yaml.safe_load` are the same pattern. The hardened pattern is `yaml.safe_load(data)` (no `!!python/...` tags allowed) for any untrusted YAML; reserve `FullLoader`/`UnsafeLoader` for parsing trusted in-house config files only.
- Grep: `\byaml\.(load|load_all)\s*\(` not followed by `Loader\s*=\s*yaml\.SafeLoader` or `yaml\.CSafeLoader`.
- File globs: `**/*.py`
- Source: https://pyyaml.org/wiki/PyYAMLDocumentation

### `xml.etree.ElementTree.parse` / `fromstring` / `lxml.etree.parse` on untrusted XML — CWE-611 (XXE)

- Why: Python's stdlib `xml.etree.ElementTree` and `lxml.etree` resolve external entity references by default in some configurations, leading to XXE: file disclosure (`<!ENTITY x SYSTEM "file:///etc/passwd">`), SSRF (`SYSTEM "http://internal-host/"`), and billion-laughs DoS. The fix is `defusedxml` — `from defusedxml.ElementTree import parse` is a drop-in replacement that disables external-entity resolution. `defusedxml` is canonical because it covers ALL Python XML libraries (etree, minidom, sax, expat) with one consistent hardening surface.
- Grep: `from\s+xml\.(etree|dom|sax)|import\s+xml\.(etree|dom|sax)` AND no corresponding `import\s+defusedxml` in the same module, OR `lxml\.etree\.parse|fromstring` without `XMLParser(resolve_entities=False)`.
- File globs: `**/*.py`
- Source: https://github.com/tiran/defusedxml

### `eval` / `exec` on attacker-influenced strings — CWE-95

- Why: `eval(user_input)` parses and executes arbitrary Python expressions; `exec(user_input)` parses and executes arbitrary Python statements. Both are direct RCE in any context where the input is influenced by an attacker (form fields, URL params, file contents, environment variables on a multi-tenant host). Even `eval(input, {"__builtins__": {}}, {})` (the "sandbox" pattern) is bypassable via `().__class__.__bases__[0].__subclasses__()` traversals — there is no safe sandboxed eval in Python. The fix is to express the user's intent through a constrained DSL (e.g. `ast.literal_eval` for literal-only values like dicts of numbers/strings, or a purpose-built expression parser).
- Grep: `\b(eval|exec|compile)\s*\(\s*(?!ast\.literal_eval)` followed by an identifier-formed string (variable, request data, file contents).
- File globs: `**/*.py`
- Source: https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data

### `__import__` / `importlib.import_module` with attacker-controlled name — CWE-94

- Why: `importlib.import_module(name_from_user)` loads a Python module by name. Combined with the search-path semantics, an attacker who controls the name can load modules from a path they wrote — including `os` (which has `system` etc.), or a malicious package they uploaded to PyPI under a typosquatted name. The hardened pattern is to validate the name against an allow-list of expected modules before importing, OR to use a registry-based dispatch (`HANDLERS = {"json": JsonHandler, "csv": CsvHandler}`) instead of dynamic imports.
- Grep: `(__import__|importlib\.import_module)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,\)]` where the argument is a variable.
- File globs: `**/*.py`
- Source: https://cwe.mitre.org/data/definitions/94.html

### `numpy.load(file, allow_pickle=True)` — CWE-502

- Why: NumPy's `.npy`/`.npz` format optionally embeds pickle objects for non-numeric arrays (e.g. `dtype=object` arrays). With `allow_pickle=True` (the default before NumPy 1.16, requires explicit opt-in since), loading attacker-supplied `.npy` data executes the pickle. The hardened pattern is `np.load(file, allow_pickle=False)` (the post-1.16 default) — this is sufficient for numeric arrays, which are the overwhelmingly common case. Any pipeline that handles user-uploaded `.npy` files with `allow_pickle=True` is structurally vulnerable.
- Grep: `np\.load\s*\([^)]*allow_pickle\s*=\s*True` OR `numpy\.load\s*\([^)]*allow_pickle\s*=\s*True`.
- File globs: `**/*.py`, `**/*.ipynb`
- Source: https://numpy.org/doc/stable/reference/generated/numpy.load.html

### `torch.load(file)` / `torch.load(file, weights_only=False)` — CWE-502

- Why: PyTorch's `torch.load` deserializes via `pickle` by default — loading an attacker-supplied `.pt` / `.pth` file is RCE. PyTorch 2.6+ defaults `weights_only=True` (which uses a constrained unpickler that only allows tensors, primitives, and known PyTorch types), but explicit `weights_only=False` re-enables the full pickle path. Models distributed on Hugging Face / model zoos / arbitrary URLs are an active supply-chain attack surface. Use `weights_only=True` for any model from outside your trust boundary, or switch to `safetensors` (the format-design alternative that has no code-execution surface).
- Grep: `torch\.load\s*\([^)]*weights_only\s*=\s*False` OR `torch\.load\s*\(` without `weights_only` kwarg in PyTorch 2.5 or earlier code paths.
- File globs: `**/*.py`, `**/*.ipynb`
- Source: https://pytorch.org/docs/stable/generated/torch.load.html

### `pandas.read_pickle` / `joblib.load` on untrusted file paths — CWE-502

- Why: `pandas.read_pickle` is `pickle.load` with a thin wrapper for path handling — same RCE surface. `joblib.load` is the scikit-learn canonical model-persistence call and uses pickle under the hood. Any pipeline that reads model files from a user-controlled path (uploaded models, fetched-from-URL models, models stored in S3 buckets where the bucket policy is not strict-read-only-by-data-team) is vulnerable. Switch to `safetensors` for tensor data; for arbitrary Python objects, design the system so models are only loaded from a trusted in-house bucket with mTLS and strict authn.
- Grep: `(pandas|pd)\.read_pickle\s*\(` OR `joblib\.load\s*\(`.
- File globs: `**/*.py`, `**/*.ipynb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html

## Secure patterns

Safe YAML parsing:

```python
import yaml

with open("config.yaml") as f:
    config = yaml.safe_load(f)   # never yaml.load — even with FullLoader
```

Source: https://pyyaml.org/wiki/PyYAMLDocumentation

Hardened XML parsing via defusedxml:

```python
from defusedxml.ElementTree import parse, fromstring

tree = parse(uploaded_path)             # external entities disabled
elem = fromstring(payload_bytes)        # billion-laughs DoS protected
```

Source: https://github.com/tiran/defusedxml

Constrained eval via `ast.literal_eval`:

```python
import ast

# Accepts: dict, list, set, tuple, int, float, str, bool, None.
# Rejects: any function call, attribute access, name lookup.
data = ast.literal_eval(user_input)
```

Source: https://docs.python.org/3/library/ast.html#ast.literal_eval

PyTorch with weights-only loading:

```python
import torch

# weights_only=True is the default on PyTorch 2.6+; explicit on older.
state = torch.load("model.pt", weights_only=True, map_location="cpu")
```

Source: https://pytorch.org/docs/stable/generated/torch.load.html

## Fix recipes

### Recipe: replace `pickle.loads` with JSON / msgpack — addresses CWE-502

**Before (dangerous):**

```python
import pickle

@app.post("/state")
def restore_state(req):
    state = pickle.loads(req.body)   # RCE on any malicious request body
    return apply(state)
```

**After (safe):**

```python
import json

@app.post("/state")
def restore_state(req):
    state = json.loads(req.body.decode("utf-8"))
    if not is_valid_state_shape(state):       # explicit schema validation
        raise BadRequest("invalid state shape")
    return apply(state)
```

Source: https://docs.python.org/3/library/pickle.html

### Recipe: replace `yaml.load` with `yaml.safe_load` — addresses CWE-502

**Before (dangerous):**

```python
config = yaml.load(uploaded_yaml)
```

**After (safe):**

```python
config = yaml.safe_load(uploaded_yaml)
```

Source: https://pyyaml.org/wiki/PyYAMLDocumentation

### Recipe: defusedxml drop-in for stdlib XML — addresses CWE-611

**Before (dangerous):**

```python
import xml.etree.ElementTree as ET
tree = ET.parse(uploaded_path)
```

**After (safe):**

```python
from defusedxml.ElementTree import parse
tree = parse(uploaded_path)
```

Source: https://github.com/tiran/defusedxml

### Recipe: replace `eval` with `ast.literal_eval` — addresses CWE-95

**Before (dangerous):**

```python
result = eval(user_input)
```

**After (safe):**

```python
import ast
try:
    result = ast.literal_eval(user_input)
except (ValueError, SyntaxError):
    raise BadRequest("expected literal expression")
```

Source: https://docs.python.org/3/library/ast.html#ast.literal_eval

## Version notes

- PyYAML 6.0+ has removed the bare `yaml.load(data)` deprecation warning; the call still works but is unsafe. Audit by grep, not by `python -W default`.
- `defusedxml` is a third-party package on PyPI but is so universally recommended that "no defusedxml in `requirements.txt` AND `xml.*` imports present" is a high-confidence finding.
- NumPy 1.16+ defaults `allow_pickle=False`. Older code paths (pinned to 1.15 or earlier) silently allow pickle deserialization on `.npy` load. Combine the version pin with the call to flag.
- PyTorch 2.6 (Jan 2025) made `weights_only=True` the default. Pre-2.6 code is structurally vulnerable to malicious model files; PyTorch 2.4 and earlier do not even support `weights_only=True`.
- `safetensors` (the Hugging Face format) is the format-design alternative — no Python code is deserialized; only tensor data. Migration path: re-save existing `.pt`/`.pth` checkpoints as `.safetensors` via `safetensors.torch.save_model`.

## Common false positives

- `pickle` use within a single trust boundary (e.g. inter-process communication on a single host where both ends are owned by the same operator) — annotate; downgrade to MEDIUM unless the data crosses a network boundary.
- `eval` in REPL-like tools (Jupyter cell-execution helpers, IDE plugins) where the input is the user's own typed code — not an attack surface.
- `xml.etree.ElementTree` parsing well-known-vendor files (e.g. plist files generated by the script itself) — annotate; flag only when the XML originates from an untrusted source.
- `torch.load` in a training pipeline that loads a checkpoint the same script just wrote — same trust boundary; downgrade unless model files cross a network boundary.
- Test-fixture pickle files under `tests/fixtures/` — annotate; flag only when the pattern reaches production code paths.
