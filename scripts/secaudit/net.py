"""Minimal stdlib HTTP with an offline fixture-replay seam.

No third-party deps (urllib only) so the shipped plugin needs no pip install.
When SECAUDIT_FEED_REPLAY_DIR is set, GET/POST return recorded fixtures keyed
by a sanitized URL (deterministic, offline tests). In replay mode a URL with no
fixture returns status 599 — letting tests exercise the unreachable/offline
degrade path without touching the network.
"""

import os
import re
import urllib.error
import urllib.parse
import urllib.request


def _blocked(url):
    """True if url is not http/https — keep the feed seam from reaching
    file://, ftp://, data:, etc. when an endpoint base is env-overridden
    (references/cve-feeds.md). Egress pinning."""
    return urllib.parse.urlparse(url).scheme not in ("http", "https")


def _replay_path(url):
    d = os.environ.get("SECAUDIT_FEED_REPLAY_DIR")
    if not d:
        return None
    key = re.sub(r"[^A-Za-z0-9]+", "_", url).strip("_")[:180]
    return os.path.join(d, key + ".json")


def _replay(url):
    p = _replay_path(url)
    if p and os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return f.read()
    return None


def _replay_mode():
    return bool(os.environ.get("SECAUDIT_FEED_REPLAY_DIR"))


def get(url, headers=None, timeout=15):
    """Return (status_code, body_text). Never raises on network failure."""
    if _blocked(url):
        return 0, ""
    rp = _replay(url)
    if rp is not None:
        return 200, rp
    if _replay_mode():
        return 599, ""  # replay mode, no fixture -> simulate unreachable
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return getattr(r, "status", 200), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception:
        return 0, ""


def post(url, body, headers=None, timeout=15):
    """Return (status_code, body_text). `body` is a str (JSON)."""
    if _blocked(url):
        return 0, ""
    rp = _replay(url)
    if rp is not None:
        return 200, rp
    if _replay_mode():
        return 599, ""
    data = body.encode("utf-8") if isinstance(body, str) else body
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return getattr(r, "status", 200), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception:
        return 0, ""
