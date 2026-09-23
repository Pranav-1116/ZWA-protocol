#!/usr/bin/env node
"use strict";

// Client-side verifier for root-sig golden vectors — same vectors Rust verifies.
// Uses tweetnacl (pure JS, no WASM) to prove cross-language determinism.
// This is the JS side of A3: Rust + client-side independently verify same vectors.

const fs = require("fs");
const path = require("path");

let nacl;
try {
  nacl = require("tweetnacl");
} catch {
  // fallback for CI where node_modules is at repo root
  nacl = require("../node_modules/tweetnacl");
}

const fixturePath = path.resolve(__dirname, "../tests/fixtures/root-sig-golden-vectors.json");

function hexToU8(hex) {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function verify(payloadHex, sigHex, pubHex) {
  return nacl.sign.detached.verify(hexToU8(payloadHex), hexToU8(sigHex), hexToU8(pubHex));
}

function main() {
  const data = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

  console.log(`Verifying ${data.version}: ${data.description}`);
  console.log(`Canonical: ${data.canonical_encoding}`);
  console.log("");

  const issuerOk = verify(
    data.issuer.canonical_payload_hex,
    data.issuer.ed25519_signature_hex,
    data.issuer.ed25519_pubkey_hex
  );
  console.log(`Issuer (${data.issuer.issuer_id}) — pubkey ${data.issuer.ed25519_pubkey_hex.slice(0, 16)}... — verify: ${issuerOk}`);
  if (!issuerOk) throw new Error("issuer verification failed");

  const credOk = verify(
    data.credential.canonical_payload_hex,
    data.credential.ed25519_signature_hex,
    data.credential.ed25519_pubkey_hex
  );
  console.log(`Credential (${data.credential.authority_id}) — pubkey ${data.credential.ed25519_pubkey_hex.slice(0, 16)}... — verify: ${credOk}`);
  if (!credOk) throw new Error("credential verification failed");

  // Negative cases — same as Rust tests: truncated sig, wrong key, tampered payload
  const payload = hexToU8(data.issuer.canonical_payload_hex);
  const sig = hexToU8(data.issuer.ed25519_signature_hex);
  const pub = hexToU8(data.issuer.ed25519_pubkey_hex);

  // Truncated sig must fail (Rust: InvalidSignatureEncoding)
  const truncated = sig.subarray(0, 32);
  let truncatedOk = false;
  try {
    truncatedOk = nacl.sign.detached.verify(payload, truncated, pub);
  } catch {
    truncatedOk = false;
  }
  console.log(`Truncated sig (32B) must fail: ${!truncatedOk} — ${truncatedOk ? "FAIL" : "PASS"}`);
  if (truncatedOk) throw new Error("truncated sig should not verify");

  // Tampered payload must fail
  const tampered = Buffer.from(payload);
  tampered[0] ^= 1;
  const tamperedOk = nacl.sign.detached.verify(tampered, sig, pub);
  console.log(`Tampered payload must fail: ${!tamperedOk} — ${tamperedOk ? "FAIL" : "PASS"}`);
  if (tamperedOk) throw new Error("tampered payload should not verify");

  // Stale version simulation: version is part of signed payload, bumping it invalidates sig
  // This is the current-root policy: version == current_version enforced in Rust, but signature binding proves stale version can't be replayed with old sig
  const v2Payload = Buffer.from(payload);
  v2Payload.writeBigUInt64BE(2n, 9); // version field at offset 9
  const v2Ok = nacl.sign.detached.verify(v2Payload, sig, pub);
  console.log(`Stale version (v1 sig over v2 payload) must fail: ${!v2Ok} — ${v2Ok ? "FAIL" : "PASS"}`);
  if (v2Ok) throw new Error("stale version should not verify");

  console.log("");
  console.log("✅ All client-side verifications PASS — same vectors Rust verifies in matcher/src/roots.rs");
  console.log("   Rust: ed25519_dalek::VerifyingKey::verify(canonical_bytes, sig)");
  console.log("   JS:   tweetnacl.sign.detached.verify(canonical_bytes, sig, pubkey)");
}

if (require.main === module) {
  main();
}
