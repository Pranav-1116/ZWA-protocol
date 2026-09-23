# ADR 0005: Root signature scheme — Ed25519

- **Status:** Accepted for Phase 2
- **Decision:** Use Ed25519 (ed25519-dalek / tweetnacl) over frozen `ZWA1ROOT` canonical payload for issuer and credential root authentication.
- **Alternatives considered:** BLS12-381, secp256k1 ECDSA

## Context

Phase 1B defines `IssuerRootPayload` and `CredentialRootPayload` with deterministic canonical bytes:

```
"ZWA1ROOT" 8B | kind 1B | version 8B BE | valid_from 8B BE | expires_at 8B BE | id_len 1B | id | root 32B BE
kind: 1 = issuer, 2 = credential
```

`zwa-credentials` does not select a signature algorithm — `OpaqueSignature` is an opaque validated byte container. The matcher must choose a concrete scheme per handbook Sec 13. Requirements:

- Deterministic signatures (no RNG failure leaking key)
- Non-malleable, canonical 64-byte encoding
- Mature Rust + JS implementations, auditable, constant-time
- Verifies exactly `canonical_bytes()`, no reserialization
- Production-safe for venue key management

## Options

### 1. Ed25519 (chosen)

**Determinism:** RFC8032 — nonce `r = H(h_b .. h_{2b-1}, M)` derived from private key + message. No per-signature RNG, no k-reuse catastrophic failure. Same message + same key → same signature, which makes golden vectors reproducible across Rust and JS.

**Malleability:** Non-malleable by design. Signatures are canonical `(R,S)` with `S < L`, small-order checks in `ed25519-dalek` and `tweetnacl`. No low-S/high-S equivalence like ECDSA. No signature malleability to bypass replay checks.

**Library maturity:**
- Rust: `ed25519-dalek 2.1.1` — pure Rust, `no_std`, formally verified field arithmetic, widely used (Solana, Zcash zcashd, dalek ecosystem), audited, constant-time.
- JS: `tweetnacl 1.0.3` — 1000 LOC, audited, works in browser and Node, same RFC8032 vectors. Alternative `noble-ed25519` also compatible.
- Both produce identical signatures for same seed + message, enabling cross-language golden vectors (`tests/fixtures/root-sig-golden-vectors.json`).

**JS compat:** TweetNaCl `sign.detached.verify(msg, sig, pubkey)` is one call, no WASM, no pairing. Verification fast (~0.5ms). Key 32B, sig 64B fixed.

**Security:** Ed25519 cofactor 8 handling in dalek prevents small-subgroup attacks; `VerifyingKey::verify` checks canonical S and canonical R. No need for hash-to-curve or pairing.

**Trade-offs:** Not aggregatable, not pairing-friendly. For ZWA root signing we need single-authority signatures, not threshold aggregation, so aggregation is unnecessary complexity.

### 2. BLS12-381

**Determinism:** BLS signatures are deterministic given hash-to-curve, but require careful domain separation (`hash_to_curve` DST) and pairing library.

**Malleability:** Unique signatures, non-malleable, aggregatable — useful if we later need threshold or multi-authority aggregation. Currently not required; aggregation adds rogue-key attack surface.

**Library maturity:**
- Rust: `blst`, `ark-bls12-381` — mature but heavier, requires `pairing` crate, larger binary, WASM build ~500KB.
- JS: Requires WASM build of blst or `@noble/curves/bls12-381` — larger, slower startup, not as ubiquitous as tweetnacl. No built-in browser support.

**JS compat:** Poor for MVP — WASM loading, async init, larger bundle. Verification requires pairing, slower in pure JS.

**Decision against:** Overkill for single-signer root authentication, increases audit surface, JS compat weaker, no benefit for current threat model. Could be reconsidered if we need aggregated authority signatures later (ADR would supersede).

### 3. secp256k1 ECDSA

**Determinism:** ECDSA requires random `k`. RFC6979 makes it deterministic, but historically many implementations failed (Sony PS3, blockchain k-reuse). Even with RFC6979, implementation must enforce it.

**Malleability:** ECDSA is malleable — `(r,s)` and `(r, n-s)` both valid unless low-S normalization enforced. Bitcoin required BIP-62/BIP-66 to fix. This is a footgun for replay logic: two different byte encodings could represent same logical signature.

**Library maturity:**
- Rust: `k256`, `libsecp256k1` — mature, audited, widely used in Bitcoin/Ethereum.
- JS: `secp256k1`, `@noble/curves/secp256k1` — mature.

**JS compat:** Good, but DER vs compact encoding variability (64 vs 70-72B) complicates `OpaqueSignature` fixed-size expectation. Requires low-S check in matcher.

**Decision against:** Malleability and RNG dependence are unnecessary risks when Ed25519 gives deterministic, non-malleable 64B signatures with simpler verification. secp256k1 makes sense for EVM compatibility, but ZWA matcher is off-chain Rust service + JS frontend, not EVM.

## Decision

**Ed25519** for Phase 2 root authentication:

- Signs exactly `payload.canonical_bytes()` — no re-encoding, no field reordering. Test `canonical_payload_is_not_changed_by_authenticator` asserts layout.
- Verification: `ed25519_dalek::VerifyingKey::from_bytes(pubkey).verify(canonical_bytes, Signature::from_bytes(sig))`
- JS verification: `tweetnacl.sign.detached.verify(canonical_bytes, sig, pubkey)`
- Golden vectors: `tests/fixtures/root-sig-golden-vectors.json` contains one issuer root and one credential root with frozen pubkeys and signatures generated from deterministic seeds `[1;32]` and `[2;32]`. Both Rust and JS can independently verify using only hex fields in that file — no Rust-specific serialization.

## Consequences

- `OpaqueSignature` for roots must be exactly 64B for Ed25519. Other schemes would be rejected by `InvalidSignatureEncoding`.
- Venue key management: store 32B seed, derive pubkey, publish pubkey in approved keyset `BTreeMap<IssuerKeyId, VerifyingKey>`.
- Supersession and freshness enforced separately (`version == current_version`, `window.contains(now)`, `trade_expiry <= root_expiry`). Signature only proves authenticity, not currency.
- If aggregation needed later, we can add BLS as additional scheme behind versioned envelope, keeping Ed25519 for v1.
- Security: Ed25519 does not hide payload — canonical bytes are public. No confidentiality needed for roots.
- Test coverage: `matcher/src/roots.rs` includes `canonical_payload_is_not_changed_by_authenticator`, stale version rejection, tampered bytes rejection, and golden vector verification from JSON file.

## References

- RFC8032 Ed25519
- `ed25519-dalek` docs: https://docs.rs/ed25519-dalek
- `tweetnacl` audit: https://tweetnacl.cr.yp.to/
- BLS12-381: https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/
- secp256k1 malleability: BIP-62, https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
- ZWA canonical payload: `crates/credentials/src/envelope.rs`
- Golden vectors: `tests/fixtures/root-sig-golden-vectors.json`
