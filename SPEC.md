# IRP Evidence API + SDK — Locked Spec (v0)

Status: locked 2026-06-30. First user: Forget Me Sweden (Allen Smith) PoC, which doubles as the first reference for the commercial hosted-attestation layer.

## Purpose

Prove one property, end to end, with the smallest honest surface:

> An external RFC 3161 timestamp authority can prove that an exact evidence snapshot existed no later than time T, without receiving any personal data.

This is the cryptographic answer to Allen's challenge (a local file and local hashes cannot prove their own history). It reuses the proven IRP PR2b verifier; it does **not** modify IRP Core.

## What this is and is not

- **Is:** a hosted black-box API (two endpoints) plus an open browser SDK plus an open offline verifier. The hard crypto lives in the API; the client does only trivial work.
- **Is not:** an IRP product inside FMS, a compliance assessment, a citizen account system, or central evidence storage.

## Firewall and domain

Served at **`evidence.intentrecord.xyz`** (neutral, not `irp-compliance.xyz`), so anchoring citizen evidence never looks like a compliance sales funnel. The strongest firewall is technical: the timestamp endpoint receives only a digest, so the operator never sees citizen data. The verifier is open and offline-capable, so no one is forced to trust the hosted service.

## Integrity model: EXACT-BYTE (not JCS)

Deliberate divergence from IRP Core. IRP `irp integrity` canonicalises with RFC 8785; this PoC does **not**. We hash the exact UTF-8 bytes of the exported files. Consequence: any reformat invalidates verification, which is acceptable because the goal is to prove the integrity and external timestamp of an exact evidence package, not equivalence across differently formatted JSON. We reuse only the RFC 3161 part of the IRP verifier (`irp.integrity.rfc3161.verify_token`), never `irp integrity verify` (which would apply JCS).

## Two-store boundary (Allen's app, stated so the SDK can't drift)

FMS keeps the citizen's audit inputs (name, birth year) in its own erasable store. The SDK **never** receives them. Only a pseudonymous event reaches the SDK. The append-only evidence package contains no directly identifying data.

## Timeline-ready from day one

The PoC demos one event, but the schema carries `previous_event_id` and `case_id` so Allen can grow into the four-event reappearance timeline (exposure_found, removal_requested, removal_confirmed, data_reappeared) without a format change. The reappearance moment is the demonstration payoff, not a single timestamp.

## The three times

- `occurred_at` (optional, citizen-stated) — when the citizen says it happened.
- `recorded_at` (browser) — when the record was created.
- `anchored_at` — the TSA `genTime`, in the receipt, not the event. Independently witnessed.

## API (the black box, Python serverless, wraps PR2b)

`POST /v1/timestamp` — citizen-facing.
- In: `{ "digest_hex": "<64 hex>", "hash_alg": "sha256" }`. Rejects anything not a 32-byte sha256 digest.
- Out: `{ "tsr_b64", "gen_time", "accuracy_seconds", "policy", "serial", "tsa" }`.
- Stateless, zero retention, no body logging, configurable `TSA_URL`.

`POST /v1/verify` — verifier-facing (IMY/auditor or the citizen's own check).
- In: `{ "manifest_b64", "token_b64", "event_b64"? }` (pseudonymous only).
- Out: granular report, never a bare `trusted:true`:
  - `event_digest_matches_manifest`, `manifest_imprint_ok`, `timestamp_signature_ok`,
    `tsa_trust` ("UNTRUSTED — no roots configured" for the PoC),
    `externally_witnessed_at`, `accuracy_seconds`, plus explicit `citizen_identity: NOT VERIFIED`,
    `request_delivery: NOT VERIFIED`, `underlying_truth: NOT ASSESSED`.
- Stateless, zero retention.

## SDK (the open client, KISS)

`<irp-evidence-receipt service-id="..." api="...">` web component + `irpEvidence` JS API. In the user's browser it: builds `privacy-event.json` (pseudonymous, with a PII guard), exact-byte SHA-256 (Web Crypto), builds `snapshot-manifest.json` (256-bit `snapshot_salt` from `crypto.getRandomValues`, references event by digest + size), exact-byte SHA-256 of the manifest, calls `/v1/timestamp` with the manifest digest, assembles and downloads `evidence-package.zip` (event + manifest + `.tsr` + README). Only the digest ever leaves the browser.

## Offline verifier (the open trust anchor)

A Python CLI (`verify_package.py`) that recomputes the exact-byte digests of the downloaded files, checks the event-digest-in-manifest link, recomputes the manifest digest, calls `verify_token`, and prints the same granular report. So verification never requires the hosted API.

## Known follow-on (not in PoC)

Certificate-chain and validity-period validation (`TRUSTED/UNTRUSTED`, expired-cert detection). The verifier checks the signature with the embedded TSA cert but does not validate the chain to a configured trust root. Honest for the PoC (reported as UNTRUSTED); required for IMY-grade evidence. Lands with the BSL/qualified-TSA layer.

## Non-goals (unchanged from the converged brief)

No IRP Core changes, no IRP Compliance integration, no C2PA, no PDF signing, no eIDAS-qualified claims, no hash chains, no Merkle, no blockchain, no Sigstore/Rekor, no accounts, no central storage, no identity verification, no AI.
