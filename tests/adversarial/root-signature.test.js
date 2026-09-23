"use strict";

// A2 + A3: Ed25519 root signatures over frozen ZWA1ROOT canonical payload.
// Verifies the same golden vectors that Rust `matcher/src/roots.rs` verifies,
// using pure JS tweetnacl — no Rust, no WASM. Proves cross-language determinism.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

// Try to load tweetnacl from local install, fallback to /tmp install used during generation
let nacl;
try {
  nacl = require("tweetnacl");
} catch {
  nacl = require("/tmp/node_modules/tweetnacl");
}

const fixturePath = path.resolve(__dirname, "../fixtures/root-sig-golden-vectors.json");

function hexToU8(hex) {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function verifyDetached(payloadHex, sigHex, pubHex) {
  return nacl.sign.detached.verify(hexToU8(payloadHex), hexToU8(sigHex), hexToU8(pubHex));
}

test("golden vectors file exists and has expected structure", () => {
  const raw = fs.readFileSync(fixturePath, "utf8");
  const data = JSON.parse(raw);
  assert.equal(data.version, "root-sig-golden-v1");
  assert.ok(data.issuer);
  assert.ok(data.credential);
  assert.equal(data.issuer.kind, 1);
  assert.equal(data.credential.kind, 2);
  assert.ok(
    data.canonical_encoding.includes("ZWA1ROOT 8B | kind 1B"),
    "canonical_encoding must describe frozen layout"
  );
  assert.ok(data.canonical_encoding.includes("root 32B BE"));
});

test("issuer root golden vector verifies in JS (tweetnacl) independently from Rust", () => {
  const data = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const { canonical_payload_hex, ed25519_signature_hex, ed25519_pubkey_hex } = data.issuer;

  // Valid signature must verify
  assert.equal(
    verifyDetached(canonical_payload_hex, ed25519_signature_hex, ed25519_pubkey_hex),
    true,
    "issuer signature must verify in JS"
  );

  // Canonical layout checks — proves we sign exactly frozen bytes, no reserialization
  const payload = Buffer.from(canonical_payload_hex, "hex");
  assert.equal(payload.subarray(0, 8).toString(), "ZWA1ROOT");
  assert.equal(payload[8], 1, "kind 1 = issuer");
  // version 1 BE
  assert.equal(payload.readBigUInt64BE(9), 1n);
  assert.equal(payload.readBigUInt64BE(17), 1900000000n, "valid_from");
  assert.equal(payload.readBigUInt64BE(25), 2100000000n, "expires_at");
  const idLen = payload[33];
  assert.equal(idLen, 12);
  assert.equal(payload.subarray(34, 34 + idLen).toString(), "issuer-atlas");
  // root 32B at end
  assert.equal(payload.length, 8 + 1 + 8 * 3 + 1 + 12 + 32);
  assert.equal(payload.subarray(payload.length - 32).toString("hex"), data.issuer.authorized_issuance_root_be_hex);
});

test("credential root golden vector verifies in JS (tweetnacl) independently from Rust", () => {
  const data = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const { canonical_payload_hex, ed25519_signature_hex, ed25519_pubkey_hex } = data.credential;

  assert.equal(
    verifyDetached(canonical_payload_hex, ed25519_signature_hex, ed25519_pubkey_hex),
    true,
    "credential signature must verify in JS"
  );

  const payload = Buffer.from(canonical_payload_hex, "hex");
  assert.equal(payload.subarray(0, 8).toString(), "ZWA1ROOT");
  assert.equal(payload[8], 2, "kind 2 = credential");
  assert.equal(payload.readBigUInt64BE(9), 1n);
  const idLen = payload[33];
  assert.equal(idLen, 11);
  assert.equal(payload.subarray(34, 34 + idLen).toString(), "cred-auth-1");
  assert.equal(payload.length, 8 + 1 + 8 * 3 + 1 + 11 + 32);
});

test("tampering any signed field breaks JS verification — same as Rust rejects", () => {
  const data = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

  // Flip first byte of canonical payload (magic) → must fail
  const tamperedMagic = Buffer.from(data.issuer.canonical_payload_hex, "hex");
  tamperedMagic[0] ^= 1;
  assert.equal(
    nacl.sign.detached.verify(tamperedMagic, hexToU8(data.issuer.ed25519_signature_hex), hexToU8(data.issuer.ed25519_pubkey_hex)),
    false,
    "tampered magic must fail"
  );

  // Flip version
  const tamperedVersion = Buffer.from(data.issuer.canonical_payload_hex, "hex");
  tamperedVersion[16] ^= 1; // last byte of version BE
  assert.equal(
    nacl.sign.detached.verify(tamperedVersion, hexToU8(data.issuer.ed25519_signature_hex), hexToU8(data.issuer.ed25519_pubkey_hex)),
    false,
    "tampered version must fail"
  );

  // Flip root
  const tamperedRoot = Buffer.from(data.issuer.canonical_payload_hex, "hex");
  tamperedRoot[tamperedRoot.length - 1] ^= 1;
  assert.equal(
    nacl.sign.detached.verify(tamperedRoot, hexToU8(data.issuer.ed25519_signature_hex), hexToU8(data.issuer.ed25519_pubkey_hex)),
    false,
    "tampered root must fail"
  );
});

test("truncated or wrong-length signature is rejected (InvalidSignatureEncoding equivalent)", () => {
  const data = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const payload = hexToU8(data.issuer.canonical_payload_hex);
  const pubkey = hexToU8(data.issuer.ed25519_pubkey_hex);

  // tweetnacl expects 64B sig — 32B truncated must fail (Rust returns InvalidSignatureEncoding)
  const truncatedSig = hexToU8(data.issuer.ed25519_signature_hex).subarray(0, 32);
  // tweetnacl throws or returns false for wrong length — we assert falsey
  let ok = false;
  try {
    ok = nacl.sign.detached.verify(payload, truncatedSig, pubkey);
  } catch {
    ok = false;
  }
  assert.equal(ok, false, "truncated sig must not verify");

  // Wrong key must fail
  const wrongKey = hexToU8(data.credential.ed25519_pubkey_hex);
  assert.equal(
    nacl.sign.detached.verify(payload, hexToU8(data.issuer.ed25519_signature_hex), wrongKey),
    false,
    "wrong pubkey must fail"
  );
});

test("issuer and credential use distinct keys — BTreeMap<IssuerKeyId, VerifyingKey> separation", () => {
  const data = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  assert.notEqual(data.issuer.ed25519_pubkey_hex, data.credential.ed25519_pubkey_hex, "issuer and credential must have distinct pubkeys");
  // Cross-verification must fail — proves key registry separation (IssuerKeyId vs AuthorityKeyId)
  assert.equal(
    verifyDetached(data.issuer.canonical_payload_hex, data.issuer.ed25519_signature_hex, data.credential.ed25519_pubkey_hex),
    false
  );
  assert.equal(
    verifyDetached(data.credential.canonical_payload_hex, data.credential.ed25519_signature_hex, data.issuer.ed25519_pubkey_hex),
    false
  );
});

test("current-root policy: stale version would change canonical bytes and thus signature", () => {
  // This mirrors Rust's VersionNotCurrent check: version is part of signed payload.
  // If we bump version from 1 to 2, canonical bytes change and old sig fails.
  // Freshness and version checks are enforced separately in Rust, but JS can show
  // that stale-but-signed would be caught by signature mismatch if version were mutated.
  const data = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const payloadV1 = Buffer.from(data.issuer.canonical_payload_hex, "hex");
  const payloadV2 = Buffer.from(payloadV1);
  payloadV2.writeBigUInt64BE(2n, 9); // version 2
  assert.notDeepEqual(payloadV1, payloadV2);
  assert.equal(
    nacl.sign.detached.verify(payloadV2, hexToU8(data.issuer.ed25519_signature_hex), hexToU8(data.issuer.ed25519_pubkey_hex)),
    false,
    "version bump invalidates signature — stale version rejected"
  );
});
