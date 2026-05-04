# XML External Entity Injection (XXE)

## Source

- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html — OWASP XXE Prevention Cheat Sheet
- https://owasp.org/www-project-top-ten/ — OWASP Top 10 (A05:2021 Security Misconfiguration)
- https://cwe.mitre.org/data/definitions/611.html — CWE-611: Improper Restriction of XML External Entity Reference
- https://docs.python.org/3/library/xml.html#xml-vulnerabilities — Python xml module security notes

## Scope

Covers XXE injection in server-side XML parsing across Python (`lxml`, `xml.etree.ElementTree`, `xml.sax`), Java (`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`), Node.js (`libxmljs`, `sax`, `fast-xml-parser`), and Ruby (`Nokogiri`). Includes file-read XXE, SSRF-via-XXE, and denial-of-service via billion-laughs. Does not cover XPath injection or XQuery injection.

## Dangerous patterns (regex/AST hints)

### Python lxml.etree with external entity support — CWE-611

- Why: `lxml.etree.parse()` and `fromstring()` resolve external entities by default unless an `XMLParser(resolve_entities=False)` is passed.
- Grep: `lxml\.etree\.(parse|fromstring|XML)\s*\(`
- File globs: `**/*.py`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

### Python xml.etree.ElementTree (unsafe expat default) — CWE-611

- Why: `ElementTree` in CPython < 3.8 does not disable external DTDs; even in later versions `xml.etree` is vulnerable to billion-laughs unless input is pre-validated.
- Grep: `ElementTree\.(parse|fromstring|XML)\s*\(|ET\.(parse|fromstring)\s*\(`
- File globs: `**/*.py`
- Source: https://docs.python.org/3/library/xml.html#xml-vulnerabilities

### Java DocumentBuilderFactory without feature hardening — CWE-611

- Why: Default `DocumentBuilderFactory` resolves external entities and DTDs; each feature must be explicitly disabled.
- Grep: `DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)|XMLInputFactory\.newInstance\(\)`
- File globs: `**/*.java`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

### Node.js libxmljs parseXml/parseXmlString — CWE-611

- Why: `libxmljs` exposes `noent` option; if set to `true` (or left at default in older versions) external entities are resolved.
- Grep: `libxmljs\.(parseXml|parseXmlString)\s*\(`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

### Node.js fast-xml-parser without entity expansion disabled — CWE-611

- Why: `fast-xml-parser` < 4.2.4 resolves `<!ENTITY>` declarations; versions >= 4.2.4 require `allowBooleanAttributes` and entity configuration to be reviewed.
- Grep: `require\s*\(\s*['"]fast-xml-parser['"]\)|new\s+XMLParser\s*\(`
- File globs: `**/*.js`, `**/*.ts`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

### Ruby Nokogiri parse without NOENT/NONET — CWE-611

- Why: `Nokogiri::XML.parse` defaults allow external entity substitution unless `Nokogiri::XML::ParseOptions::NOENT` and `NONET` are cleared.
- Grep: `Nokogiri::XML\.(parse|Document\.parse)\s*\(`
- File globs: `**/*.rb`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

### DOCTYPE declaration in user-supplied XML — CWE-611

- Why: An attacker-crafted `<!DOCTYPE>` can define external entities or billion-laughs regardless of the parser; if user input contains DOCTYPE, parsing should be rejected.
- Grep: `<!DOCTYPE|SYSTEM\s+['"]\w+://`
- File globs: `**/*.xml`, `**/*.xsd`, `**/*.xsl`
- Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

## Secure patterns

Python — use defusedxml for all user-supplied XML:

```python
import defusedxml.ElementTree as ET

# defusedxml raises DefusedXmlException on DOCTYPE / entity expansion
tree = ET.fromstring(user_xml_bytes)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

Java — harden DocumentBuilderFactory before any parse:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder builder = dbf.newDocumentBuilder();
Document doc = builder.parse(inputStream);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

Ruby Nokogiri — disable substitution and network access:

```ruby
options = Nokogiri::XML::ParseOptions::DEFAULT_XML |
          Nokogiri::XML::ParseOptions::NONET
# Do NOT set NOENT — that would substitute entities; omit it to leave them unexpanded
doc = Nokogiri::XML.parse(user_xml, nil, nil, options)
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

## Fix recipes

### Recipe: Replace lxml with defusedxml for user input — addresses CWE-611

**Before (dangerous):**

```python
from lxml import etree
tree = etree.parse(request.files['upload'])
```

**After (safe):**

```python
import defusedxml.ElementTree as ET
tree = ET.parse(request.files['upload'])
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

### Recipe: Harden Java SAXParser — addresses CWE-611

**Before (dangerous):**

```java
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser parser = spf.newSAXParser();
parser.parse(inputStream, handler);
```

**After (safe):**

```java
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
SAXParser parser = spf.newSAXParser();
parser.parse(inputStream, handler);
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

### Recipe: Disable entity resolution in libxmljs — addresses CWE-611

**Before (dangerous):**

```js
const libxmljs = require('libxmljs');
const doc = libxmljs.parseXmlString(userXml);
```

**After (safe):**

```js
const libxmljs = require('libxmljs');
// noent: false disables entity substitution; nonet: true blocks network access
const doc = libxmljs.parseXmlString(userXml, { noent: false, nonet: true });
```

Source: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

## Version notes

- Python's `xml.etree.ElementTree` was patched to raise `ParseError` on billion-laughs payloads in Python 3.8 via the expat 2.4.0 update; external entity file-read still requires `defusedxml` or explicit DTD rejection.
- `defusedxml` 0.7.1+ is the recommended drop-in for all Python stdlib XML modules; it is not a substitute for Nokogiri configuration in Ruby or DocumentBuilderFactory hardening in Java.
- Java's built-in JDK parser (JAXP) defaults differ between JDK versions — JDK 17+ sets `jdk.xml.enableExtensionFunctions` to false but does not disable external DTDs. Always set features explicitly rather than relying on defaults.
- `fast-xml-parser` >= 4.2.4 introduced `processEntities: false` as a configuration option; earlier versions have no mitigation.

## Common false positives

- `ET.parse("config.xml")` — parsing a static, developer-controlled file path with no user input is safe; confirm the argument is a literal string.
- `Nokogiri::XML.parse(File.read("schema.xsd"))` — parsing internal files under the application's own directory is not a user-input XXE sink; verify the file path is not derived from request parameters.
- `DocumentBuilderFactory.newInstance()` followed immediately by `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` — the dangerous instantiation grep matches, but the subsequent hardening call makes it safe; triage together.
- DOCTYPE declarations in XSD or WSDL files committed to the repository — these are developer-authored schema files, not attacker-supplied data, unless the application copies them from a user upload.
