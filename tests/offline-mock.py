#!/usr/bin/env python3
# offline-mock.py — a minimal always-503 HTTP server for the offline drill.
#
# Used by tests/offline-drill.sh to simulate all CVE feeds being unreachable.
# Returns 503 Service Unavailable for every request path and method. Logs one
# line per request to stderr so the drill transcript shows what the pipeline
# actually tried to fetch.
#
# Usage:
#   ./offline-mock.py [--port 9999]
#
# The server runs until killed (Ctrl-C or SIGTERM).

import argparse
import http.server
import sys


class AlwaysFailHandler(http.server.BaseHTTPRequestHandler):
    def _fail(self):
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"offline-mock: service unavailable"}')

    def do_GET(self):
        self._fail()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 0:
                self.rfile.read(length)
        except Exception:
            pass
        self._fail()

    def log_message(self, format, *args):
        sys.stderr.write(
            "offline-mock %s - %s\n" % (self.address_string(), format % args)
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    server = http.server.HTTPServer((args.host, args.port), AlwaysFailHandler)
    sys.stderr.write(f"offline-mock: listening on {args.host}:{args.port}\n")
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
