/*!
 * IRP Evidence SDK v0 — open client for evidence.intentrecord.xyz
 * MIT. Zero dependencies. Runs entirely in the user's browser.
 *
 * Privacy invariant: the only thing that ever leaves the browser is a SHA-256
 * digest sent to /v1/timestamp. The event and manifest never leave the device.
 * Inspect this file: confirm no event/manifest bytes are sent anywhere.
 */
(function (global) {
  "use strict";

  var DEFAULT_API = "https://evidence.intentrecord.xyz";
  var enc = new TextEncoder();

  // ── helpers ────────────────────────────────────────────────────────────────
  function utf8(obj) { return enc.encode(JSON.stringify(obj)); } // exact bytes we hash AND package

  async function sha256Hex(bytes) {
    var d = await crypto.subtle.digest("SHA-256", bytes);
    return [].map.call(new Uint8Array(d), function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }
  function b64(bytes) { return btoa(String.fromCharCode.apply(null, bytes)); }
  function b64url(bytes) { return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function fromB64(s) { var bin = atob(s); var a = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; }

  // PII guard: refuse to build a record that contains directly identifying data.
  var PII = [
    /\b\d{6,8}[-+]?\d{4}\b/,                 // Swedish personnummer
    /[^\s@]+@[^\s@]+\.[^\s@]+/,              // email
    /\b(?:\+?46|0)\s?7[02369]\s?\d{3}\s?\d{2}\s?\d{2}\b/ // Swedish mobile
  ];
  function assertNoPII(obj) {
    JSON.stringify(obj, function (k, v) {
      if (typeof v === "string") {
        for (var i = 0; i < PII.length; i++) {
          if (PII[i].test(v)) throw new Error("Refusing to record value that looks like personal data in field '" + k + "'. The evidence record must stay pseudonymous.");
        }
      }
      return v;
    });
  }

  // ── event + manifest ────────────────────────────────────────────────────────
  function createEvent(opts) {
    var event = {
      schema: "se.forgetmesweden.rights-event/0.1",
      event_id: crypto.randomUUID(),
      case_id: opts.caseId || crypto.randomUUID(),
      service_id: String(opts.serviceId || ""),
      event_type: opts.eventType || "removal_requested",
      evidence_level: "self_attested",
      occurred_at: opts.occurredAt || null,
      recorded_at: new Date().toISOString(),
      confirmed_by: "data_subject",
      source: "forget-me-sweden",
      previous_event_id: opts.previousEventId || null
    };
    assertNoPII(event);
    return event;
  }

  function createManifest(eventBytes, eventSha) {
    var salt = new Uint8Array(32); crypto.getRandomValues(salt);
    return {
      schema: "se.forgetmesweden.evidence-snapshot/0.1",
      snapshot_id: crypto.randomUUID(),
      created_at: new Date().toISOString(),
      snapshot_salt: b64url(salt),
      event: { filename: "privacy-event.json", sha256: eventSha, size_bytes: eventBytes.length },
      generator: { name: "IRP Evidence SDK", version: "0" }
    };
  }

  async function timestamp(manifestDigestHex, apiBase) {
    var res = await fetch((apiBase || DEFAULT_API) + "/v1/timestamp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ digest_hex: manifestDigestHex, hash_alg: "sha256" })
    });
    if (!res.ok) throw new Error("timestamp failed: " + res.status);
    return res.json();
  }

  // ── minimal STORED zip (no deps) ──────────────────────────────────────────────
  var CRC = (function () { var t = []; for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  function crc32(b) { var c = 0xFFFFFFFF; for (var i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
  function u16(n) { return new Uint8Array([n & 255, (n >>> 8) & 255]); }
  function u32(n) { return new Uint8Array([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]); }
  function concat(arrs) { var len = arrs.reduce(function (a, x) { return a + x.length; }, 0); var out = new Uint8Array(len), o = 0; arrs.forEach(function (x) { out.set(x, o); o += x.length; }); return out; }
  function makeZip(files) {
    var locals = [], central = [], offset = 0;
    files.forEach(function (f) {
      var name = enc.encode(f.name), crc = crc32(f.bytes);
      var lh = concat([u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0), u32(crc), u32(f.bytes.length), u32(f.bytes.length), u16(name.length), u16(0), name, f.bytes]);
      locals.push(lh);
      central.push(concat([u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0), u32(crc), u32(f.bytes.length), u32(f.bytes.length), u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(offset), name]));
      offset += lh.length;
    });
    var cd = concat(central);
    var end = concat([u32(0x06054b50), u16(0), u16(0), u16(files.length), u16(files.length), u32(cd.length), u32(offset), u16(0)]);
    return new Blob([concat(locals), cd, end], { type: "application/zip" });
  }

  function readmeText(meta) {
    return [
      "Forget Me Sweden — Private Evidence Package",
      "",
      "Files:",
      "  privacy-event.json      Your pseudonymous record of what you did.",
      "  snapshot-manifest.json  References the event by its exact-byte SHA-256.",
      "  timestamp-response.tsr  An RFC 3161 timestamp token (binary).",
      "",
      "What the timestamp PROVES:",
      "  This exact snapshot existed no later than " + (meta.gen_time || "(see token") + ".",
      "What it does NOT prove:",
      "  Your identity, that the removal request was delivered, or that anything is true.",
      "",
      "Verify with any RFC 3161 tool, or the open offline verifier at:",
      "  https://github.com/<your-org>/irp-evidence (verifier/verify_package.py)",
      "",
      "These files are pseudonymous evidence. Changing ANY byte of the event or",
      "manifest will invalidate verification (exact-byte integrity)."
    ].join("\n");
  }

  // ── top-level orchestration ──────────────────────────────────────────────────
  async function createReceipt(opts, apiBase) {
    var event = createEvent(opts);
    var eventBytes = utf8(event);
    var eventSha = await sha256Hex(eventBytes);

    var manifest = createManifest(eventBytes, eventSha);
    var manifestBytes = utf8(manifest);
    var manifestDigestHex = await sha256Hex(manifestBytes);

    var ts = await timestamp(manifestDigestHex, apiBase);
    var tsr = fromB64(ts.tsr_b64);

    var zip = makeZip([
      { name: "privacy-event.json", bytes: eventBytes },
      { name: "snapshot-manifest.json", bytes: manifestBytes },
      { name: "timestamp-response.tsr", bytes: tsr },
      { name: "README.txt", bytes: enc.encode(readmeText(ts)) }
    ]);
    return { zip: zip, genTime: ts.gen_time, caseId: event.case_id, eventId: event.event_id };
  }

  function download(blob, name) {
    var url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href = url; a.download = name || "evidence-package.zip"; a.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // ── web component ─────────────────────────────────────────────────────────────
  if (typeof HTMLElement !== "undefined" && typeof customElements !== "undefined") {
    customElements.define("irp-evidence-receipt", class extends HTMLElement {
      connectedCallback() {
        var api = this.getAttribute("api") || DEFAULT_API;
        var serviceId = this.getAttribute("service-id") || "service";
        var self = this;
        this.innerHTML = '<button>I submitted the removal request</button>';
        this.querySelector("button").onclick = async function () {
          self.innerHTML = "Creating your private evidence record…";
          try {
            var r = await createReceipt({ serviceId: serviceId, eventType: "removal_requested" }, api);
            self.innerHTML =
              '<p>Externally timestamped.</p>' +
              '<p>This exact evidence snapshot existed no later than <b>' + r.genTime + '</b>.</p>' +
              '<p style="font-size:.9em;color:#666">This shows that you stated you submitted the request. It does not prove the service received it.</p>' +
              '<button>Download evidence package</button>';
            self.querySelector("button").onclick = function () { download(r.zip, "evidence-" + r.caseId + ".zip"); };
          } catch (e) {
            self.innerHTML = '<p>Timestamping failed: ' + e.message + '. Your local record is unaffected.</p>';
          }
        };
      }
    });
  }

  global.irpEvidence = { createEvent: createEvent, createManifest: createManifest, timestamp: timestamp, createReceipt: createReceipt, makeZip: makeZip, download: download, sha256Hex: sha256Hex };
})(typeof window !== "undefined" ? window : this);
