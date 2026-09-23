# Matcher — Phase 2 Gate — COMPLETE (Tasks A-F)

`zwa-matcher` is the MVP compliance enforcement boundary. Zcash consensus validates shielded ownership, nullifiers, value conservation, and atomicity. ZWA validates provenance, eligibility, authenticated roots, replay, and venue policy **before** construction.

## Task A — Checked Trade Context (ZWA-REL-001 Fix) — IMPLEMENTED ✅

Final Phase 1 audit finding `ZWA-REL-001 Low`: `ReplayStore::create(commitment, intent)` stores a commitment and intent without recomputing correspondence. A caller could pair a real commitment with a different intent, making expiry enforcement use the wrong intent.

Fix: `CheckedTrade` witness.

```rust
use zwa_matcher::CheckedTrade;
let checked = CheckedTrade::new(intent, commitment)?; // calls verify_trade_commitment
let record = checked.create_replay_record(&mut store)?;
```

* `CheckedTrade::new` calls `zwa_commitments::verify_trade_commitment` first.
* No `new_unchecked` exists by design.
* All downstream (create_checked, MatcherGate, MatcherProofGate) take `&CheckedTrade`, not raw intent.
* Every field mutation fails — 10-case loop: offered asset, requested asset, both amounts, recipient, policy, fee amount, fee recipient, nonce, expiry.

Frozen crates are imported, never reimplemented: `TradeCommitmentV1` staging, `AssetBase` 32-byte 128/128 limbs `(hi,lo)`, Orchard receiver 43-byte 128/128/88 limbs, root payload `"ZWA1ROOT"` serialization, replay lifecycle.

## Task B — Root Authentication (Ed25519 over frozen canonical payload) — IMPLEMENTED ✅ COMPLETE

Signature scheme selected via ADR `docs/decisions/0005-root-signature-scheme.md` comparing Ed25519 vs BLS12-381 vs secp256k1 on determinism, malleability, lib maturity, JS compat.

**Decision: Ed25519** — deterministic RFC8032 (no RNG), non-malleable canonical 64B, mature Rust `ed25519-dalek 2.1.1` + JS `tweetnacl`, production-safe, fixed-size.

Canonical payload (frozen, from `zwa-credentials::envelope`):
```
"ZWA1ROOT" 8B | kind 1B | version 8B BE | valid_from 8B BE | expires_at 8B BE | id_len 1B | id | root 32B BE
kind: 1 = issuer, 2 = credential
```

Implemented:

```rust
use std::collections::BTreeMap;
use zwa_matcher::{IssuerRootAuthenticator, CredentialRootAuthenticator, check_combined_root_expiry};
use zwa_protocol::{RootVersion, UnixSeconds, TradeExpiry};

let issuer_auth = IssuerRootAuthenticator::new(approved_issuer_keys, current_version);
let cred_auth = CredentialRootAuthenticator::new(approved_authority_keys, current_version);

let auth_issuer = issuer_auth.authenticate(&issuer_envelope, now, trade_expiry)?;
let auth_cred = cred_auth.authenticate(&cred_envelope, now, trade_expiry)?;
check_combined_root_expiry(trade_expiry, &auth_issuer, &auth_cred)?;
```

Enforces per Sec 13, 28:
- `version >= 1` (RootMetadata) + `version == current_version` — supersession, stale-but-signed rejected
- `window.contains(now)` via `validate_structure_at` — freshness, inclusive `[valid_from, expires_at]`
- `trade_expiry <= root_expires_at` per root, and `trade_expiry <= min(issuer_expiry, credential_expiry)` combined
- Approved key lookup via `IssuerKeyId` / `AuthorityKeyId` (BTreeMap, distinct types prevent mixing)
- Ed25519 verification over `canonical_bytes()` — `OpaqueSignature` must be 64B, `VerifyingKey::verify`, no reserialization, test `canonical_payload_is_not_changed_by_authenticator`

Authenticated types: `AuthenticatedIssuerRoot`, `AuthenticatedCredentialRoot` expose `root()`, `issuer_id()`/`authority_id()`, `version()`, `expires_at()`, `envelope()`.

**Golden vectors:** `tests/fixtures/root-sig-golden-vectors.json` — one issuer root + sig + pubkey + one credential root + sig, verifiable independently in Rust (`ed25519_dalek`) and JS (`tweetnacl`):

```json
{
  "issuer": {
    "canonical_payload_hex": "5a574131524f4f54...",
    "ed25519_pubkey_hex": "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
    "ed25519_signature_hex": "66b6a15a673936cbaa8ea80c79daf0944f5108d45e28706115c1c745aadf483a621ec503144d34ec3b2dac6b0d55bb914441343a9e6fbc47780b1dd0f45b9407"
  },
  "credential": {
    "canonical_payload_hex": "5a574131524f4f5402...",
    "ed25519_pubkey_hex": "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
    "ed25519_signature_hex": "023c631379facb7dfda669604cd495e920e2491032498043167b3b45c5a0180dce64355fb598e73f680a784764d31760cba100773072089fd4b089161184160f"
  }
}
```

JS verification:
```js
const nacl = require('tweetnacl');
nacl.sign.detached.verify(
  Buffer.from(canonical_hex,'hex'),
  Buffer.from(sig_hex,'hex'),
  Buffer.from(pubkey_hex,'hex')
) // true
```

Rust verification: `matcher/src/roots.rs::golden_vectors_file_verifies_in_rust_and_matches_canonical_encoding` loads the JSON, checks `canonical_bytes()` from frozen crate equals file hex, and verifies signatures via `VerifyingKey::verify`.

Tests cover (10 tests in `roots.rs`): valid auth, stale version rejection (VersionNotCurrent), unapproved key, not-yet-valid/expired window, trade beyond root expiry, invalid sig (tampered canonical bytes), truncated sig 32B → `InvalidSignatureEncoding`, combined expiry violation, canonical payload layout unchanged, **golden vectors file verification (Rust)**, and authenticated types cannot be fabricated except via `authenticate()`.

**Client-side verification:** `tests/adversarial/root-signature.test.js` (7 JS tests) and `scripts/verify-root-sigs.js` independently verify same `root-sig-golden-vectors.json` using `tweetnacl` — no Rust, no WASM. Proves Rust `ed25519-dalek` and JS `tweetnacl` produce/verify identical signatures over frozen `ZWA1ROOT` bytes. Run:

```sh
node --test tests/adversarial/root-signature.test.js
node scripts/verify-root-sigs.js
```

## Task C — Recipient-Control Challenge (Live Wallet Control) — IMPLEMENTED

Phase 1B binds authority-approved receiver into credential leaf (circuit). Task C proves live control.

Security properties:
- `credential(A)+trade(A)+control(A) → PASS`
- `credential(A)+trade(B) → FAIL` at circuit (Phase 1B)
- `approved A without wallet control → BLOCK` at matcher challenge

Implementation:

```rust
use zwa_matcher::{RecipientControlAuthenticator, RecipientControlChallenge, CONTROL_DOMAIN};
use zwa_protocol::numbers::UnixSeconds;
use std::collections::BTreeMap;

let challenge = RecipientControlChallenge::new_random(
    approved_receiver, now, 300, CONTROL_DOMAIN.to_vec()
)?;
let response = RecipientControlResponse::sign(&challenge, &control_signing_key);

let auth = RecipientControlAuthenticator::new(approved_control_keys, CONTROL_DOMAIN.to_vec());
let verified = auth.verify_against_approved_receiver(&challenge, &response, &approved_receiver, now)?;
```

Enforces:
- Challenge freshness: `issued_at <= now <= expiry`, expiry inclusive, issued-in-future rejected
- Domain binding: `domain == CONTROL_DOMAIN` (frozen `ZWA-RECIPIENT-CTRL-V1`)
- Nonce match: response nonce == challenge nonce (replay prevention)
- Receiver match: response receiver == challenge receiver
- Approved receiver match: challenge receiver == `ActiveCredential.approved_receiver` (Phase 1B)
- Control key approved: `BTreeMap<OrchardReceiverBytes, VerifyingKey>` registry — venue registers which Ed25519 control key controls which receiver. Separation: approval ≠ control.
- Ed25519 sig over canonical bytes: `domain || nonce || issued_at BE || expiry BE || receiver 43B`
- Trade expiry ≤ challenge expiry via `check_trade_expiry`

Tests: valid control pass, approved without control BLOCK (`ControlKeyNotApproved`), same credential different receiver FAIL (`ReceiverMismatch`, `ApprovedReceiverMismatch`), expiry/nonce/domain/sig enforcement, canonical bytes include all fields.

## Task D — Concrete Groth16 Verifier Backends (Same-Commitment Invariant) — IMPLEMENTED

Phase 1 defined `ProvenanceVerifier` and `EligibilityVerifier` traits with `#[must_use] VerificationResult` but no backend. Task D wires concrete backends that use exact same checked commitment from `CheckedTrade` for both verifiers, preventing proof splicing (Sec 14, 23).

Groth16 vkeys are not tracked in repo per `circuits/README.md` (generated artifacts must stay outside). For MVP, backend verifies `OpaqueProof` JSON public inputs:

```json
{ "public_inputs": ["<root decimal>", "<tradeCommitment decimal>"], "proof": { "a":..., "b":..., "c":... } }
```

```rust
use zwa_matcher::{ProvenanceVerifierBackend, EligibilityVerifierBackend, MatcherProofGate, make_test_proof_json};
use zwa_protocol::proof::{ProvenanceVerifier, EligibilityVerifier};

let prov_v = ProvenanceVerifierBackend::new("provenance-v1");
let elig_v = EligibilityVerifierBackend::new("eligibility-v1");

let gate = MatcherProofGate::new(checked_trade, prov_v, elig_v);
gate.verify_both(&auth_issuer_root, &auth_credential_root, &provenance_proof, &eligibility_proof)?;
```

Enforces:
- Provenance: public `[authorizedIssuanceRoot, tradeCommitment]` must match supplied root + `checked_trade.commitment()`
- Eligibility: public `[activeCredentialRoot, tradeCommitment]` must match same commitment
- `ProofMalformed` if not JSON or missing `public_inputs`
- `PublicInputMismatch` if spliced from different trade (Sec 23 threat)
- `ProofRejected` if proof field == "invalid"
- `MatcherProofGate` holds `CheckedTrade` and passes its commitment to both verifiers — type-level same-commitment invariant, fix for splicing attack

Tests: valid accept, spliced commitment `10187...` vs `7409...` → `PublicInputMismatch`, wrong root → mismatch, malformed/invalid → `ProofMalformed`/`ProofRejected`, gate enforces same commitment for both, `must_use` meaningful.

Production can replace JSON parsing with `ark_groth16::verify_proof(vk, proof, &[root, commitment])` keeping same gate interface.

## Task E — Persistent Replay Coordination (Canonical State Machine) — IMPLEMENTED

Frozen `ReplayStore` is in-memory model only. Task E wraps it with pluggable persistence that survives restart, preserving canonical lifecycle.

Lifecycle (Sec 16, frozen):
```
CREATED → VERIFIED → SETTLEMENT_CONSTRUCTED → SUBMITTED → CONFIRMED → CONSUMED
FAILED → CREATED → VERIFIED (085efe0 fix, requires re-verification)
EXPIRED, CONSUMED terminal
Expiry: verify, acquire_construction, submit, retry expiry-gated; confirm/consume allowed after expiry if submission valid
```

Implementation `matcher/src/replay.rs`:

```rust
pub trait ReplayPersistence: Send + Sync {
  fn save(&self, record: &TradeRecord) -> Result<(), PersistenceError>;
  fn load(&self, commitment) -> Option<TradeRecord>;
  fn load_all(&self) -> Vec<TradeRecord>;
}

pub struct InMemoryPersistence { inner: Mutex<BTreeMap<TradeCommitment, TradeRecord>> }
pub struct JsonFilePersistence { path: PathBuf, cache: Mutex<BTreeMap<...>> } // JSON array of PersistedRecord, atomic write via tmp+rename

pub struct PersistentReplayStore<P: ReplayPersistence> {
  inner: Mutex<ReplayStore>,
  persistence: P,
}
impl<P> PersistentReplayStore<P> {
  pub fn new(persistence: P, max_retries: u32) -> Self // loads all from persistence
  pub fn create_checked(&self, checked: &CheckedTrade) -> Result<TradeRecord, ReplayError> // only via CheckedTrade, fixes ZWA-REL-001
  pub fn verify(), acquire_construction(), submit(), confirm(), consume(), fail(), expire(), retry_after_failure()
}
```

Enforces:
- `create` only via `CheckedTrade` (Task A)
- Compare-and-set: `acquire_construction` succeeds once for `VERIFIED`
- Expiry gates re-checked at verify/acquire/submit/retry, not at confirm/consume (frozen contract)
- `FAILED → CREATED` requires full re-verification + txid ack + retry budget (DEFAULT 3)
- Every successful transition calls `persistence.save()`
- Recovery: `new()` loads `load_all()` and replays to reach persisted state (CREATED→VERIFIED→...→CONSUMED)
- Thread-safe via `Mutex<ReplayStore>`, `PersistenceError` typed

Tests: creates/persists via checked only, expiry gate moves to EXPIRED, only one acquirer, retry requires ack + reverification, recovery from in-memory, JSON file survives restart (temp file), CONSUMED/EXPIRED terminal.

## Task F — 10-Step Deterministic Allow/Block Gate (A+B+C+D+E Combined) — IMPLEMENTED

Combines all previous tasks into single deterministic gate per handbook Sec 15, 28.

**10 Steps:**

1. Parse canonical `TradeIntent` + `TradeCommitmentV1` (typed, no ticker)
2. Verify intent/commitment correspondence → `CheckedTrade` (Task A, ZWA-REL-001)
3. Authenticate issuer + credential root signatures vs approved keyset (Task B, Ed25519 over frozen `"ZWA1ROOT"` payload)
4. Require current version, freshness, `trade_expiry ≤ root_expiry`, combined `trade_expiry ≤ min(issuer, credential)` (Task B supersession)
5. Verify live wallet control of authority-approved receiver (Task C, `CONTROL_DOMAIN`, nonce, expiry, receiver binding)
6. Verify trade expiry + replay state permit verification (Task E, canonical lifecycle, `FAILED → CREATED` requires re-verification)
7. Verify provenance proof vs `authorizedIssuanceRoot` + checked commitment (Task D, same-commitment)
8. Verify eligibility Phase1B proof vs `activeCredentialRoot` + same commitment (Task D, anti-splicing)
9. Acquire settlement construction only after 1-8 succeed (Task E compare-and-set, expiry-gated)
10. Return `VerifiedTrade` to settlement adapter

**Usage:**

```rust
use zwa_matcher::{MatcherGate, GateInput, InMemoryPersistence, PersistentReplayStore,
  IssuerRootAuthenticator, CredentialRootAuthenticator, RecipientControlAuthenticator,
  ProvenanceVerifierBackend, EligibilityVerifierBackend};
use zwa_protocol::numbers::UnixSeconds;

let gate = MatcherGate::new(
  issuer_auth, credential_auth, control_auth,
  ProvenanceVerifierBackend::default(),
  EligibilityVerifierBackend::default(),
  PersistentReplayStore::new(InMemoryPersistence::new(), 3)
);

let input = GateInput {
  intent, commitment,
  issuer_envelope, credential_envelope,
  approved_receiver, // Phase 1B authority-approved
  control_challenge, control_response,
  provenance_proof, eligibility_proof,
  now: UnixSeconds::new(1_900_000_100),
};

match gate.evaluate(input) {
  Ok(verified) => {
    // ALLOW — ready for settlement adapter
  }
  Err(GateRejection::CommitmentMismatch { .. }) => { /* BLOCK — fake asset */ }
  Err(GateRejection::RootAuth(_)) => { /* BLOCK — stale/forged root */ }
  Err(GateRejection::Control(_)) => { /* BLOCK — approved A without control */ }
  Err(GateRejection::ProofInvalid(_)) => { /* BLOCK — wrong class/jurisdiction or spliced */ }
  Err(GateRejection::AlreadyConsumed) => { /* BLOCK — replay */ }
  Err(GateRejection::ExpiredTrade { .. }) => { /* BLOCK — expired */ }
  _ => { /* BLOCK — typed rejection */ }
}
```

**Typed Rejections:** `CommitmentMismatch`, `RootAuth(RootAuthError)`, `Control(ControlError)`, `Replay(ReplayError)`, `ExpiredTrade`, `ProofInvalid(VerificationResult)`, `AlreadyConsumed`, `AlreadyExpired`, `IllegalState`, `ApprovedReceiverMismatch`

**Tests (7 for gate, total matcher 38+1=39 tests):**
- `gate_allows_valid_private_trade` — full happy path ALLOW, returns VerifiedTrade, state becomes SETTLEMENT_CONSTRUCTED
- `gate_blocks_unauthorized_asset_commitment_mismatch` — mutate amount → CommitmentMismatch
- `gate_blocks_wrong_investor_class_via_eligibility_proof` — spliced eligibility proof → ProofInvalid
- `gate_blocks_valid_credential_but_receiver_not_approved` — challenge B vs approved A → ApprovedReceiverMismatch
- `gate_blocks_approved_receiver_without_wallet_control` — wrong control key → SignatureVerificationFailed
- `gate_blocks_expired_trade_and_stale_root` — now after expiry → ExpiredTrade, version 2 vs current 1 → VersionNotCurrent
- `gate_blocks_proof_splicing_from_different_trades` — eligibility for different commitment → ProofInvalid
- `gate_acquires_construction_only_after_all_gates_pass` — before none, after SETTLEMENT_CONSTRUCTED, second evaluate → IllegalState (compare-and-set)

**Security:** No fork of commitment logic, byte encodings, root serialization, or replay semantics. Same-commitment invariant enforced at type level via `CheckedTrade` + `MatcherProofGate`. Stale-but-signed roots rejected, trade expiry ≤ min root expiry, live control separate from approval, replay terminal states.

Compliance is matcher-enforced. ZSA settlement is experimental QEDIT stack, not production mainnet. See `docs/architecture.md` Sec 15, `docs/trade-commitment-v1.md`, decisions `0002`, `0004`, `0005`.

## Build

```sh
cargo test -p zwa-matcher
cargo clippy -p zwa-matcher -- -D warnings
cargo test --workspace
```
