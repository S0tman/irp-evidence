#!/usr/bin/env python3
"""Offline verifier for an IRP Evidence package (the open trust anchor).

Verification never requires the hosted API. Given the downloaded files, this
recomputes the exact-byte digests, checks the event->manifest->token chain, and
prints a granular, honest report.

Usage:
    python3 verify_package.py <event.json> <manifest.json> <token.tsr>
    python3 verify_package.py path/to/evidence-package.zip

Needs the RFC 3161 verifier from irp-capture:
    pip install "irp-capture[integrity]"
"""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

try:
    from irp.integrity.rfc3161 import verify_token
except ImportError:
    sys.exit("Install the verifier first:  pip install 'irp-capture[integrity]'")


def _load(args):
    if len(args) == 1 and args[0].lower().endswith(".zip"):
        with zipfile.ZipFile(args[0]) as z:
            return (
                z.read("privacy-event.json"),
                z.read("snapshot-manifest.json"),
                z.read("timestamp-response.tsr"),
            )
    if len(args) == 3:
        return tuple(Path(a).read_bytes() for a in args)
    sys.exit(__doc__)


def main() -> int:
    event_bytes, manifest_bytes, token_der = _load(sys.argv[1:])

    rows = []

    # 1. Parse.
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        rows.append(("manifest parse", True, ""))
    except (ValueError, UnicodeDecodeError) as exc:
        rows.append(("manifest parse", False, str(exc)))
        manifest = {}

    # 2. Event digest matches the manifest (exact bytes).
    event_sha = hashlib.sha256(event_bytes).hexdigest()
    claimed = ((manifest.get("event") or {}).get("sha256") or "").lower()
    rows.append(("event digest matches manifest", event_sha == claimed, ""))

    # 3. The token binds the exact manifest bytes, and the signature is valid.
    manifest_digest = hashlib.sha256(manifest_bytes).digest()
    v = verify_token(token_der, manifest_digest)
    rows.append(("timestamp message imprint", v["imprint_ok"], ""))
    rows.append(("timestamp content consistent", v["message_digest_ok"], ""))
    rows.append(("timestamp signature", v["signature_ok"], ""))

    witnessed = all(r[1] for r in rows)

    print("IRP Evidence — package verification\n")
    for name, ok, detail in rows:
        suffix = f"  ({detail})" if detail else ""
        print(f"  {name:<32} {'PASS' if ok else 'FAIL'}{suffix}")
    print()
    print(f"  {'TSA certificate chain':<32} UNTRUSTED (signature checked; no trust roots configured)")
    print(f"  {'externally witnessed at':<32} {v['gen_time']}"
          + (f"  (accuracy +/- {v['accuracy']}s)" if v["accuracy"] else "  (accuracy unspecified)"))
    print(f"  {'witnessed by':<32} {v['signer_subject'] or '(unknown)'}")
    print(f"  {'citizen identity':<32} NOT VERIFIED")
    print(f"  {'request delivery':<32} NOT VERIFIED")
    print(f"  {'underlying event truth':<32} NOT ASSESSED")
    print()
    print("RESULT: " + (
        "WITNESSED — these exact files existed no later than the stated time, subject to "
        "trusting the TSA. Not proof of identity, delivery, or truth."
        if witnessed else
        "NOT ESTABLISHED — the package does not validly verify."
    ))
    return 0 if witnessed else 10


if __name__ == "__main__":
    raise SystemExit(main())
