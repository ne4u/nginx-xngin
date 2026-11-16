#!/usr/bin/env python3
"""Echo backend for integration tests.

Returns JSON: {"headers": {...}, "body": "...", "path": "..."}.
Single-threaded is fine — tests are sequential.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    def _reply(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n).decode(errors="replace") if n else ""
        if self.path == "/big":
            # fixed-size plain response for byte-exact assertions
            payload = b"B" * (512 * 1024)
        elif self.path == "/gzip-big":
            # plaintext far above res_body_max but tiny on the wire:
            # inflate should hit the cap and bypass, not fail the request
            import gzip
            payload = gzip.compress(b"P" * (200 * 1024))
            self.send_response(200)
            self.send_header("content-type", "application/octet-stream")
            self.send_header("content-encoding", "gzip")
            self.send_header("x-backend-tag", "backend")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        elif self.path in ("/gzip", "/br"):
            # compressed wire body: the agent should see plaintext
            import gzip
            import brotli
            plain = json.dumps({
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body,
                "path": self.path,
            }).encode()
            payload = (gzip.compress(plain) if self.path == "/gzip"
                       else brotli.compress(plain))
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-encoding",
                             "gzip" if self.path == "/gzip" else "br")
            self.send_header("x-backend-tag", "backend")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        else:
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
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
