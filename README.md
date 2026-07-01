# IRP Evidence API + SDK

A small, honest service that proves a file existed, unchanged, no later than a given moment, without revealing anything inside it. It is the outside-witness layer for [IRP](https://github.com/S0tman/irp-capture), packaged so adding it to an app takes a few lines.

First user: the Forget Me Sweden privacy-evidence PoC. The same service is the seed of IRP's commercial hosted-attestation layer.

**What it proves:** this exact file existed, unchanged, no later than time T. An independent timestamping service witnessed a fingerprint of it.
**What it does not prove:** who you are, that anything was delivered, or that the file's contents are true. The checker always says so.

## In plain words

IRP keeps a record of decisions in a file on your own computer (a local JSON file). A fair question follows: if the file sits on your machine, you could edit it and recompute its checks, so why should an outsider (a regulator, a court, a counterparty) trust it, and what stops you backdating an entry?

This service is the answer. Before you rely on a record, you send a *fingerprint* of the file (not the file itself) to an independent timestamping service. It signs that fingerprint together with the current date and time. From then on, anyone can check two things: that the file still matches the fingerprint, and that the timestamp is genuine. Change one character later and the fingerprint stops matching, so the edit is obvious. You cannot backdate, because the date came from someone other than you.

The service never sees your data. Only the fingerprint leaves your computer, and a fingerprint cannot be turned back into the file it came from.

## Privacy and firewall

- The timestamp endpoint receives **only a fingerprint (a SHA-256 hash)**. No event, no manifest, no identity. The operator cannot see citizen data because it never arrives.
- Stateless: no database, no body logging, no retention.
- The verifier is **open and runs offline**, so no one is forced to trust the hosted service.
- Served from a neutral domain (`evidence.intentrecord.xyz`), not a compliance brand.

## How the fingerprint works

The fingerprint is a SHA-256 hash of the exact bytes of the file. Change anything, even reformatting the JSON, and the fingerprint changes, so the check fails. This is deliberately stricter and simpler than IRP Core's RFC 8785 canonicalisation: here we prove one exact file, not that two differently-formatted files carry the same meaning.

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
