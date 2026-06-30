"""IRP Evidence API — single Flask entrypoint (Vercel Python).

Routes /v1/timestamp and /v1/verify to the shared core logic in _lib.
Stateless, no persistence, no body logging.
"""
from __future__ import annotations

from flask import Flask, jsonify, request

try:  # works whether imported as `api.index` (Vercel) or `index` (local)
    from api._lib import do_timestamp, do_verify
except ImportError:  # pragma: no cover
    from _lib import do_timestamp, do_verify

app = Flask(__name__)


@app.after_request
def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "IRP Evidence API",
        "version": "0",
        "endpoints": ["POST /v1/timestamp", "POST /v1/verify"],
        "docs": "https://github.com/S0tman/irp-evidence",
    })


@app.route("/v1/timestamp", methods=["POST", "OPTIONS"])
def timestamp():
    if request.method == "OPTIONS":
        return ("", 204)
    code, body = do_timestamp(request.get_json(silent=True) or {})
    return jsonify(body), code


@app.route("/v1/verify", methods=["POST", "OPTIONS"])
def verify():
    if request.method == "OPTIONS":
        return ("", 204)
    code, body = do_verify(request.get_json(silent=True) or {})
    return jsonify(body), code
