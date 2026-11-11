#!/usr/bin/env python3
"""Echo backend for integration tests.

Returns JSON: {"headers": {...}, "body": "...", "path": "..."}.
Single-threaded is fine — tests are sequential.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def _reply(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n).decode(errors="replace") if n else ""
        payload = json.dumps({
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body,
            "path": self.path,
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("x-backend-tag", "backend")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _reply

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
