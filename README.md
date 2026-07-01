# IRP Evidence API + SDK

A small, honest service that lets anyone prove that an exact evidence snapshot existed no later than a given time, without revealing any personal data. It is the externally-witnessed layer for [IRP](https://github.com/S0tman/irp-capture), packaged so a client integration is a few lines.

First user: the Forget Me Sweden privacy-evidence PoC. The same service is the seed of IRP's commercial hosted-attestation layer.

**What it proves:** this exact snapshot existed no later than time T (an external RFC 3161 timestamp authority witnessed its digest).
**What it does not prove:** identity, delivery, or the truth of the underlying statement. The verifier always says so.

## Privacy and firewall

- The timestamp endpoint receives **only a SHA-256 digest**. No event, no manifest, no identity. The operator cannot see citizen data because it never arrives.
- Stateless: no database, no body logging, no retention.
- The verifier is **open and runs offline**, so no one is forced to trust the hosted service.
- Served from a neutral domain (`evidence.intentrecord.xyz`), not a compliance brand.

## Integrity model

Exact-byte. The digest is SHA-256 over the exact UTF-8 bytes of the exported files. Any reformat invalidates verification. This is deliberately simpler than IRP Core's RFC 8785 canonicalisation; the goal here is to prove an exact package, not equivalence across reformatted JSON.

## API

`POST /v1/timestamp`
```json
// in  (only a digest leaves the browser)
{ "digest_hex": "<64 lowercase hex>", "hash_alg": "sha256" }
// out
{ "tsr_b64": "...", "gen_time": "2026-06-30T18:22:28+00:00",
  "accuracy_seconds": null, "policy": "1.2.3.4.1", "serial": "...", "tsa": "https://freetsa.org/tsr" }
```

`POST /v1/verify`
```json
// in  (pseudonymous package parts, base64)
{ "manifest_b64": "...", "token_b64": "...", "event_b64": "<optional>" }
// out  (granular, never a bare trusted:true)
{ "event_digest_matches_manifest": true, "manifest_imprint_ok": true,
  "timestamp_signature_ok": true, "tsa_trust": "UNTRUSTED — ...",
  "externally_witnessed_at": "...", "externally_witnessed": true,
  "citizen_identity": "NOT VERIFIED", "request_delivery": "NOT VERIFIED",
  "underlying_truth": "NOT ASSESSED", "result": "WITNESSED — ..." }
```

## Client integration (the easy way)

```html
<!-- SDK served from the public repo via jsDelivr; API calls go to evidence.intentrecord.xyz -->
<script src="https://cdn.jsdelivr.net/gh/S0tman/irp-evidence@main/sdk/irp-evidence.js"></script>
<irp-evidence-receipt service-id="service-A"></irp-evidence-receipt>
```

Or call the API directly:
```js
const r = await irpEvidence.createReceipt({ serviceId: "service-A", eventType: "removal_requested" });
irpEvidence.download(r.zip, "evidence.zip"); // event + manifest + .tsr + README
```

The SDK builds the pseudonymous event, hashes it (Web Crypto), builds the manifest with a 256-bit salt, sends only the manifest digest to `/v1/timestamp`, and packages the result. It refuses to record anything matching personnummer / email / phone patterns.

## Offline verification (the trust anchor)

```bash
pip install "irp-capture[integrity]"
python3 verifier/verify_package.py evidence-package.zip
```
Recomputes the exact-byte digests, checks the event→manifest→token chain, verifies the RFC 3161 signature (RSA or ECDSA), and prints a granular report. Verification never depends on the hosted API.

## Known follow-on (not in this PoC)

Certificate-chain and validity-period validation (`TRUSTED`/`UNTRUSTED`, expired-cert). The verifier checks the signature with the embedded TSA cert but does not validate the chain to a configured trust root; it reports `UNTRUSTED` honestly. Required for IMY-grade evidence, lands with the qualified-TSA layer.

## License

MIT. Reuses the IRP RFC 3161 verifier without modifying IRP Core.
