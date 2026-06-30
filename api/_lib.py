"""IRP Evidence API core logic (the black box).

Reuses the proven IRP RFC 3161 verifier (irp.integrity.rfc3161 from irp-capture,
installed via the [integrity] extra). EXACT-BYTE model: digests are SHA-256 over
the exact bytes supplied, never canonicalised. We use only the RFC 3161 part of
the IRP verifier, never JCS.

Stateless. No persistence. No body logging.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from typing import Any, Optional

from irp.integrity.rfc3161 import read_tst_info, request_timestamp, verify_token

DEFAULT_TSA = os.environ.get("TSA_URL", "https://freetsa.org/tsr")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def do_timestamp(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """POST /v1/timestamp — receives only a digest, returns a timestamp token."""
    digest_hex = str(payload.get("digest_hex", "")).strip().lower()
    hash_alg = str(payload.get("hash_alg", "sha256")).strip().lower()

    if hash_alg != "sha256":
        return 400, {"error": "only sha256 is supported"}
    if not _HEX64.match(digest_hex):
        return 400, {"error": "digest_hex must be a 64-character lowercase sha256 hex digest"}

    try:
        token_der = request_timestamp(bytes.fromhex(digest_hex), DEFAULT_TSA, timeout=20)
    except Exception as exc:  # noqa: BLE001 — surface a clean error, never the stack
        return 502, {"error": f"timestamp authority unavailable: {exc}"}

    info = read_tst_info(token_der)
    if info["hashed_message"] != bytes.fromhex(digest_hex):
        return 502, {"error": "TSA returned a token for a different digest"}

    gen = info["gen_time"]
    return 200, {
        "tsr_b64": base64.b64encode(token_der).decode("ascii"),
        "gen_time": gen.isoformat() if hasattr(gen, "isoformat") else str(gen),
        "accuracy_seconds": info["accuracy"],
        "policy": info["policy"],
        "serial": str(info["serial_number"]),
        "tsa": DEFAULT_TSA,
        "disclaimer": "Existence-by-time only. Not identity, delivery, or truth. "
                      "TSA trust-root validation is the verifier's policy.",
    }


def do_verify(payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """POST /v1/verify — checks the exact-byte chain: event -> manifest -> token."""
    try:
        manifest_bytes = _b64decode(payload["manifest_b64"])
        token_der = _b64decode(payload["token_b64"])
    except (KeyError, ValueError, base64.binascii.Error):
        return 400, {"error": "manifest_b64 and token_b64 (base64) are required"}

    event_bytes: Optional[bytes] = None
    if payload.get("event_b64"):
        try:
            event_bytes = _b64decode(payload["event_b64"])
        except (ValueError, base64.binascii.Error):
            return 400, {"error": "event_b64 is not valid base64"}

    report: dict[str, Any] = {}

    # Parse the manifest (for the event-link check). Hashing uses the exact bytes.
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return 422, {"error": f"manifest is not valid JSON/UTF-8: {exc}"}

    # 1. Event digest matches the manifest (only if the event file was supplied).
    if event_bytes is not None:
        event_sha = hashlib.sha256(event_bytes).hexdigest()
        claimed = ((manifest.get("event") or {}).get("sha256") or "").lower()
        report["event_digest_matches_manifest"] = (event_sha == claimed)
    else:
        report["event_digest_matches_manifest"] = "NOT CHECKED (event file not supplied)"

    # 2. The token binds the exact manifest bytes' digest, and the signature is valid.
    manifest_digest = hashlib.sha256(manifest_bytes).digest()
    try:
        v = verify_token(token_der, manifest_digest)
    except Exception as exc:  # noqa: BLE001
        return 422, {"error": f"could not parse timestamp token: {exc}"}

    report["manifest_imprint_ok"] = v["imprint_ok"]
    report["timestamp_message_digest_ok"] = v["message_digest_ok"]
    report["timestamp_signature_ok"] = v["signature_ok"]
    report["tsa_trust"] = "UNTRUSTED — signature checked, no trust roots configured (verifier policy)"
    gen = v["gen_time"]
    report["externally_witnessed_at"] = gen.isoformat() if hasattr(gen, "isoformat") else str(gen)
    report["accuracy_seconds"] = v["accuracy"]
    report["witnessed_by"] = v["signer_subject"]

    # The honesty layer — never a bare trusted:true.
    report["citizen_identity"] = "NOT VERIFIED"
    report["request_delivery"] = "NOT VERIFIED"
    report["underlying_truth"] = "NOT ASSESSED"

    crypto_ok = bool(v["cryptographically_valid"])
    event_ok = report["event_digest_matches_manifest"] is True or event_bytes is None
    report["externally_witnessed"] = bool(crypto_ok and event_ok)
    report["result"] = (
        "WITNESSED — this exact snapshot existed no later than the stated time, subject to "
        "trusting the TSA. Not proof of identity, delivery, or truth."
        if report["externally_witnessed"]
        else "NOT ESTABLISHED — the timestamp does not validly bind this exact package."
    )
    return 200, report
