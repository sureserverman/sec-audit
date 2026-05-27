"""Self-test for the http replay seam: replay returns the fixture, no network."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secaudit import net as http  # noqa: E402


def main():
    d = tempfile.mkdtemp()
    os.environ["SECAUDIT_FEED_REPLAY_DIR"] = d
    url = "https://api.osv.dev/v1/querybatch"
    with open(http._replay_path(url), "w", encoding="utf-8") as f:
        f.write('{"ok": true}')
    status, body = http.post(url, '{"queries":[]}')
    assert status == 200 and '"ok": true' in body, (status, body)
    # a URL with no fixture -> 599 (offline) in replay mode
    s2, _ = http.get("https://services.nvd.nist.gov/none")
    assert s2 == 599, s2
    print("http-selftest: OK")


if __name__ == "__main__":
    main()
