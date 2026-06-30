"""Vercel serverless function: POST /api/verify (routed to /v1/verify)."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler

from _lib import do_verify

_MAX_BODY = 1_000_000  # pseudonymous package parts; generous but bounded


def _cors(handler: BaseHTTPRequestHandler) -> None:
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")


class handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # silence request logging (privacy)
        return

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        _cors(self)
        self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > _MAX_BODY:
            self._json(413, {"error": "request too large"})
            return
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"error": "invalid JSON"})
            return
        code, body = do_verify(payload)
        self._json(code, body)

    def _json(self, code: int, body: dict) -> None:
        self.send_response(code)
        _cors(self)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode("utf-8"))
