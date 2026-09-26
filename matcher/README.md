# Matcher — Phase 2 Gate — COMPLETE (Tasks A-F + A1-A8)

`zwa-matcher` is the MVP compliance enforcement boundary. Zcash consensus validates shielded ownership, nullifiers, value conservation, and atomicity. ZWA validates provenance, eligibility, authenticated roots, replay, and venue policy **before** construction.

This crate completes A1-A8: CheckedTrade boundary, root signature scheme ADR + golden vectors, root authentication & current-root policy, Groth16 verifier backends (real), recipient-control verifier boundary, persistent replay coordinator, deterministic orchestration (opaque MatcherApproval), integration & release audit.

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
    approved_receiver, trade_commitment, now, 300, CONTROL_DOMAIN.to_vec()
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
- Trade commitment binding: `domain||nonce||issued_at||expiry||receiver||trade_commitment` (A5) — prevents challenge replay across trades
- Approved receiver match: challenge receiver == `ActiveCredential.approved_receiver` (Phase 1B)
- Control key approved: `BTreeMap<OrchardReceiverBytes, VerifyingKey>` registry — venue registers which Ed25519 control key controls which receiver. Separation: approval ≠ control.
- Ed25519 sig over canonical bytes: `domain || nonce || issued_at BE || expiry BE || receiver 43B || trade_commitment 32B`
- Trade expiry ≤ challenge expiry via `check_trade_expiry`
- Trade commitment equality via `check_trade_commitment`
- Fail-closed: `UnconfiguredControlVerifier` returns `Unconfigured` error, trait `RecipientControlVerifier` is opaque boundary for Vikram V4, test-only `FakeControlVerifier` behind `#[cfg(test)]`

Tests: valid control pass, approved without control BLOCK (`ControlKeyNotApproved`), same credential different receiver FAIL (`ReceiverMismatch`, `ApprovedReceiverMismatch`), expiry/nonce/domain/sig enforcement, canonical bytes include all fields.

## Task D — Groth16 Verifier Backends (Same-Commitment Invariant) — REMEDIATED (F-01)

`ProvenanceVerifierBackend` / `EligibilityVerifierBackend` verify real Groth16 (BN254, `ark-groth16`) against pinned verification keys (SHA-256 identity check in `from_fixture()`), with public inputs `[root, tradeCommitment]` taken from the authenticated root and `CheckedTrade::commitment()`.

```rust
use zwa_matcher::{ProvenanceVerifierBackend, EligibilityVerifierBackend, MatcherProofGate};

let prov_v = ProvenanceVerifierBackend::from_fixture()?;   // VK hash pinned
let elig_v = EligibilityVerifierBackend::from_fixture()?;
let gate = MatcherProofGate::new(checked_trade, prov_v, elig_v);
gate.verify_both(&auth_issuer_root, &auth_credential_root, &provenance_proof, &eligibility_proof)?;
```

Enforces:
- Malformed or non-Groth16 input **always** rejects (`ProofMalformed`). There is no JSON/"public_inputs" fallback in any build or feature combination; `--all-features` enables no bypass. The `test-helpers` feature is inert (kept only so dependants' manifests resolve) and a source-scan test asserts no bypass symbol or `cfg(feature = "test-helpers")` exists.
- `PublicInputMismatch` if the proof's public signals are for another root or commitment (splicing).
- `ProofRejected` if the pairing check fails. Unconfigured backends fail closed.
- Test doubles are `#[cfg(test)]` only and injected through the `ProvenanceVerifier`/`EligibilityVerifier` traits (`gate::tests::FakeVerifier`).

Regression tests (F-01): old fake JSON `{"public_inputs":[root,commitment]}` rejected by both backends, malformed bytes, wrong commitment, wrong root, real fixture proofs verify.

## Task E — Persistent Replay Coordination — REMEDIATED (F-05 / F-06)

Frozen `ReplayStore` is an in-memory model whose `TradeRecord` has private fields and no restore API. The matcher therefore never reconstructs `TradeRecord`s (the old code replayed transitions with hardcoded timestamps, a fake txid, a forced failure reason and a reset retry count). Instead:

- `ReplayRecord` (M2-owned) holds every frozen field — commitment, intent, state, failure reason, prior txid, retry count — plus a CAS `version`, and is persisted **as is**.
- `replay::apply` is a pure transition function that mirrors frozen `ReplayStore` exactly (incl. "move to `EXPIRED`, then reject"). A differential test drives both through every operation sequence to depth 7 and requires identical results.
- `PersistentReplayStore<P>` keeps **no** lifecycle state in memory. Each transition is: fallible `load` → `apply` → `compare_and_swap(expected state + version)`. A failed or lost write leaves the durable record unchanged and returns an error; there is nothing in memory that could run ahead.

```rust
pub trait ReplayPersistence: Send + Sync {
  fn load(&self, c: TradeCommitment) -> Result<Option<ReplayRecord>, PersistenceError>;
  fn load_all(&self) -> Result<Vec<ReplayRecord>, PersistenceError>;
  // expected None: insert if absent; Some(e): replace only if stored state+version == e's
  fn compare_and_swap(&self, expected: Option<&ReplayRecord>, new: &ReplayRecord)
      -> Result<(), PersistenceError>; // PersistenceError::Conflict on a lost race
}
```

Backends:
- `InMemoryPersistence` — mutex-guarded map, CAS under the lock (share via `Arc` across stores).
- `JsonFilePersistence` — schema v2, strict decoding (`deny_unknown_fields`, explicit state/failure tags, canonical txid hex, commitment must recompute from intent), re-read on every operation, write via fsync'd tmp + rename. Single-writer: two processes on one file are not supported (use SQLite).
- `SqlitePersistence` (`sqlite` feature) — table `replay_records_v2`, `BEGIN IMMEDIATE`, conditional `UPDATE … WHERE state = ? AND version = ?` / `INSERT OR IGNORE`, `synchronous=FULL`. Safe for several store instances/processes on one DB file.
- `RocksDbPersistence` — placeholder; every call fails closed (`NotConfigured`).

Corrupt, tampered, legacy (v1 / bare array / old SQLite table), empty or unknown-version data is rejected at open/load — never silently skipped, migrated or rewritten.

API: `PersistentReplayStore::new(p, max_retries) -> Result<Self, ReplayError>` (validates all stored records); `state()`/`get()` return `Result<Option<_>>`. `create_checked`, `verify`, `acquire_construction` are `pub(crate)`: only `MatcherGate::evaluate` can create, verify and lock a trade. `submit`, `confirm`, `consume`, `fail`, `expire`, `retry_after_failure(ack_txid, now)` remain public for the settlement side.

Tests: exact restart round-trip (JSON; SQLite) of retry count, txids, failure reason, expiry; injected persistence failure does not advance state; concurrent CAS has exactly one winner (shared in-memory, two SQLite connections to one DB); stale CAS rejected on every backend; corrupt/legacy/tampered data fails closed.

## Task F / A7 — Deterministic Allow/Block Gate (A+B+C+D+E Combined)

Combines all previous tasks into single deterministic **fail-closed** gate per handbook Sec 15, 28. Cheap checks before expensive proofs.

**10 Steps — why each exists (Sec 23 threat model):**

1. Parse canonical `TradeIntent` + `TradeCommitmentV1` (typed, no ticker) — prevents ticker/symbol confusion, only 32B AssetBase + 43B receiver. Prevents fake RWA with convincing name.
2. Verify intent/commitment correspondence → `CheckedTrade` (Task A / A1, ZWA-REL-001) — `ReplayStore::create` stores without recomputing. Prevents intent substitution (10 fields: offered asset, requested asset, both amounts, recipient, policy, fee amount, fee recipient, nonce, expiry) + expiry bypass. Output opaque witness, only via `verify_trade_commitment`.
3. Authenticate issuer + credential root signatures vs approved keyset (Task B / A3, Ed25519 over frozen `"ZWA1ROOT"` payload) — roots are public inputs to circuits, authenticity not in circuits. Prevents forged/stale issuer/credential root, wrong authority, malleability.
4. Require current version, freshness, `trade_expiry ≤ root_expiry`, combined `trade_expiry ≤ min(issuer, credential)` (Task B) — version 0 invalid, only current version accepted (supersession, stale-but-signed rejected), `window.contains(now)` inclusive, trade must not outlive roots. Prevents stale/superseded replay, not-yet-valid, trade beyond root, revocation latency. Output `AuthenticatedIssuerRoot`, `AuthenticatedCredentialRoot` private envelope, cannot be fabricated.
5. Bind the approved receiver to the trade (F-02), then verify live wallet control (Task C / A5). The raw `approved_receiver` is caller-supplied, so the gate recomputes `H(RCPBIND1, recipient_subject_commitment, H(RECEIVR1, approved_receiver))` (frozen `zwa-commitments`) and requires it to equal `intent.recipient_commitment` (`RecipientBindingMismatch` otherwise). Phase1B eligibility binds the same recipient commitment to the credential leaf's receiver; control is verified for exactly `approved_receiver`. Result: trade, credential and controlled wallet name one receiver — proof for A + control of B rejects.
6. Verify provenance proof vs `authorizedIssuanceRoot` + checked commitment (Task D / A4).
7. Verify eligibility Phase1B proof vs `activeCredentialRoot` + same commitment (Task D / A4).
8. Only now write replay state (F-07): create if absent → `VERIFIED` → `SETTLEMENT_CONSTRUCTED`, each a CAS. Before any root/proof work a read-only precheck admits only none/`CREATED`/`VERIFIED`: `FAILED` → `RetryRequired` (explicit `retry_after_failure` with exact txid ack, then full re-verification), `CONSUMED`/`EXPIRED` terminal, active settlement states are replays. Trade expiry (`now > expiry`; `now == expiry` valid) is checked right after the precheck; an existing `CREATED`/`VERIFIED` record becomes `EXPIRED`, none is created. Any failed check leaves replay state untouched.
9. (merged into 8) The construction lock is the final CAS; exactly one concurrent caller wins.
10. Return `VerifiedTrade` / `MatcherApproval` to settlement adapter — opaque, non-serializable, only via `evaluate()`. Proves all 9 gates passed. Does NOT prove non-custodial settlement (Phase 3), wallet spending-key beyond control challenge, global compliance enforcement, production ZSA mainnet, recursive lineage.

**Output A7: MatcherApproval opaque non-serializable**

```rust
#[derive(Debug)] // !Clone, !Serialize, private _private: ()
pub struct VerifiedTrade {
  checked_trade: private,
  authenticated_issuer_root: private,
  authenticated_credential_root: private,
  verified_control: private,
  _private: (),
}
pub type MatcherApproval = VerifiedTrade;

impl VerifiedTrade {
  pub fn commitment(&self) -> TradeCommitment
  pub fn intent(&self) -> TradeIntent
  pub fn checked_trade(&self) -> &CheckedTrade
  // no Clone, no Serialize, no public constructor, cannot use struct literal outside gate module
}
```

**Usage:**

```rust
use zwa_matcher::{MatcherGate, GateInput, InMemoryPersistence, PersistentReplayStore,
  IssuerRootAuthenticator, CredentialRootAuthenticator, RecipientControlAuthenticator,
  ProvenanceVerifierBackend, EligibilityVerifierBackend};
use zwa_protocol::numbers::UnixSeconds;

let gate = MatcherGate::new(
  issuer_auth, credential_auth, control_auth,
  ProvenanceVerifierBackend::from_fixture()?, // real Groth16 with VK hash check
  EligibilityVerifierBackend::from_fixture()?,
  PersistentReplayStore::new(JsonFilePersistence::new(path)?, 3)?,
);

let input = GateInput { intent, commitment, issuer_envelope, credential_envelope, approved_receiver,
  recipient_subject_commitment, control_challenge, control_response, provenance_proof, eligibility_proof, now };

match gate.evaluate(input) {
  Ok(approval) => { /* approval.commitment(), approval.intent() → Phase 3 */ },
  Err(GateRejection::CommitmentMismatch { .. }) => { /* BLOCK Step 2 fake asset */ },
  Err(GateRejection::RootAuth(_)) => { /* BLOCK Step 3/4 stale/forged root */ },
  Err(GateRejection::Control(_)) => { /* BLOCK Step 5 approved A without control */ },
  Err(GateRejection::ProofInvalid(_)) => { /* BLOCK Step 7/8 wrong class or spliced */ },
  Err(GateRejection::AlreadyConsumed) => { /* BLOCK Step 6 replay */ },
  Err(GateRejection::ExpiredTrade { .. }) => { /* BLOCK Step 6 expired */ },
  _ => { /* BLOCK typed */ }
}
```

**Typed Rejections:** `CommitmentMismatch`, `RootAuth(RootAuthError)`, `Control(ControlError)`, `Replay(ReplayError)`, `ExpiredTrade`, `ProofInvalid(VerificationResult)`, `AlreadyConsumed`, `AlreadyExpired`, `RetryRequired`, `IllegalState`, `RecipientBindingMismatch`

**Tests A7 (13 for gate, total matcher 38+5=43 tests):**
- `gate_allows_valid_private_trade` — happy ALLOW → `MatcherApproval`, state `SETTLEMENT_CONSTRUCTED`
- `verified_trade_is_opaque_non_clone` — proves no Clone, private `_private`, only via `evaluate()`, Debug contains `VerifiedTrade`, no Display
- `identical_request_twice_does_not_create_two_approvals` — first ALLOW, second identical → `IllegalState`, still one record `SETTLEMENT_CONSTRUCTED` — spec A7 identical request twice
- `no_later_verifier_runs_after_early_failure` — commitment mismatch at Step 2 → replay None (no create/verify/proof/construction), root auth fail at Step 3 → replay None (no control/proof), control fail at Step 5 → replay None (no proof) — proves cheap before expensive, no later verifier runs
- `gate_blocks_unauthorized_asset_commitment_mismatch` — amount mutate → CommitmentMismatch at Step 2
- `gate_blocks_wrong_investor_class_via_eligibility_proof` — spliced eligibility → ProofInvalid at Step 8
- `gate_blocks_valid_credential_but_receiver_not_approved` — challenge B vs approved A → ApprovedReceiverMismatch at Step 5
- `gate_blocks_approved_receiver_without_wallet_control` — wrong key → SignatureVerificationFailed at Step 5
- `gate_blocks_expired_trade_and_stale_root` — now after expiry → ExpiredTrade, version 2 vs current 1 → VersionNotCurrent at Step 3
- `gate_blocks_proof_splicing_from_different_trades` — eligibility different commitment → ProofInvalid at Step 8 (same-commitment invariant)
- `gate_acquires_construction_only_after_all_gates_pass` — before None, after `SETTLEMENT_CONSTRUCTED`, second → IllegalState (compare-and-set)
- `a8_integration_real_signatures_real_control_persistent_replay_injected_fake_proofs` — real Ed25519 issuer+credential+control, `JsonFilePersistence` file survives close/reopen, versioned `schema_version`, state `SETTLEMENT_CONSTRUCTED` recovered
- `a8_integration_real_groth16_proofs_individually_verify` — real Groth16 `provenance-proof.json` + `eligibility-proof.json` verify with VK hash `4831d3...` and `879d42...`
- F-02 (`f02_*`): proof/credential for receiver A + control of B rejects; A/A passes; wrong raw receiver and wrong recipient commitment reject; trade bound to B with a real proof for A rejects.
- F-07 (`f07_*`): persisted state and verifier call counts after invalid provenance, invalid eligibility, failed control, every root failure (wrong signer, expired, not-yet-valid, superseded, expiring before trade), expired trade with/without record, `now == expiry`, FAILED → explicit retry → CREATED → full re-verification, VERIFIED re-verified before lock, replay attempt, concurrent identical requests (one approval).

**Security:** No fork of commitment logic, byte encodings, root serialization, or replay semantics. Same-commitment invariant via `CheckedTrade` + `MatcherProofGate`. Stale-but-signed rejected, trade expiry ≤ min root expiry, live control separate from approval, replay terminal states, opaque non-cloneable approval.

Compliance is matcher-enforced. ZSA settlement is experimental QEDIT stack, not production mainnet. See `docs/architecture.md` Sec 15, `docs/trade-commitment-v1.md`, decisions `0002`, `0004`, `0005`, handoff `docs/matcher-handoff.md`.

## Task A8 — Integration & Release Audit — NOT ACCEPTED (pending independent re-audit)

> **M2 remediation status.** Findings F-01, F-02, F-05/F-06 and F-07 were fixed on
> this branch (see sections above). Acceptance of A8 is for the independent
> re-auditor, not the implementer. Open items: (1) there is no end-to-end ALLOW
> with *real* Groth16 proofs, because the fixture proofs are for two different
> trades (provenance `7409…`, eligibility `10187…`) and regenerating proofs is
> out of M2 scope; (2) frozen circuits were modified in `ef7fc73` (`dummyProd`
> constraint + regenerated VKs) and could not be reverted without an M1 frozen
> VK to return to; (3) the replay/gate API change breaks `crates/settlement`
> (M4) until its owner adapts it. Statements below that predate the
> remediation are historical.

**One complete valid flow: real signatures, real proofs, real recipient control, persistent replay → MatcherApproval**

- Real Ed25519 signatures: issuer seed `[1;32]` pubkey `8a88e3dd...` sig `66b6a1...`, credential seed `[2;32]` pubkey `8139770e...` sig `023c63...` over frozen `ZWA1ROOT` canonical bytes — same file `tests/fixtures/root-sig-golden-vectors.json` verified in Rust `ed25519_dalek` + JS `tweetnacl` (`node scripts/verify-root-sigs.js`, `node --test tests/adversarial/root-signature.test.js`)
- Real recipient control: Ed25519 control key seed `[3;32]` registered for receiver `781671f8...be233`, challenge `domain||nonce||issued_at BE||expiry BE||receiver 43B||trade_commitment 32B` signed, verified via `RecipientControlAuthenticator`
- Persistent replay: `JsonFilePersistence` versioned `{"schema_version":2,"records":[...]}` (complete records + CAS version) fsync'd tmp+rename, `SqlitePersistence` behind `sqlite` feature with `rusqlite bundled`, `RocksDbPersistence` placeholder fail-closed. Test `a8_integration_real_signatures_real_control_persistent_replay_injected_fake_proofs` creates file, evaluates → `SETTLEMENT_CONSTRUCTED`, file exists with `schema_version`, drop + reopen recovers same state.
- Real Groth16 proofs: `tests/fixtures/groth16/provenance-vkey.json` hash `4831d3eef9575ef7daf318eb8767e1a39ef1e26da20339ddda137b1e246f1350`, `eligibility-vkey.json` hash `879d427a16f334edc163e78614c94dfe00c3ae3cb657c3ef4d7d82c39e4f5e75`, `provenance-proof.json` public `[8857867840332676380575934803462643968319857770249975039236308904195120230546, 7409670081847436957289371955571360481923983184454289247710022466448715682310]` (Phase0F), `eligibility-proof.json` public `[7721491042898277899686830032817687831050368809629386580479309633507500868506, 10187400613857124614980227259922066295752635539032972479692659299555113110306]` (Phase1B) — both verify via `ark-groth16` in `verifiers::tests::real_provenance_proof_verifies_with_real_vkey` and `real_eligibility_proof_verifies_with_real_vkey` in debug and release (VK hash prevents substitution).
- Same-commitment invariant: fixtures have different commitments (7409... vs 10187...), so combined gate with both real proofs for same commitment would correctly fail `PublicInputMismatch` (splicing prevention). Gate happy-path tests inject `#[cfg(test)]` trait fakes (`FakeVerifier`) for the same commitment; the real Groth16 path is exercised in verifiers tests and in a gate test with the real eligibility verifier. No production code path accepts fake proofs. Documented in `docs/matcher-handoff.md`.
- Every attack scenario blocks at intended gate: 13 gate tests + 10 roots + 10 control + 6 verifiers + 13 replay = 43 matcher tests cover CommitmentMismatch at Step 2, VersionNotCurrent/TradeExpiryBeyondRootExpiry at Step 3/4, ApprovedReceiverMismatch/SignatureVerificationFailed at Step 5, ExpiredTrade/AlreadyConsumed/IllegalState at Step 6/9, ProofInvalid/PublicInputMismatch at Step 7/8.
- Debug ↔ release parity: `cargo test --workspace` and `cargo test --workspace --release` must pass 82 frozen + 43 matcher = 125 tests. `paste 1.0.15` unmaintained warning via arkworks/light-poseidon is not vulnerability. Sandbox has no cargo, CI will run.
- Handoff docs for Vikram: `docs/matcher-handoff.md` — exact public API (what can he call, what errors), what `MatcherApproval` proves and does NOT prove (not non-custodial, not wallet spending-key, not global compliance, not production ZSA mainnet, not recursive lineage), root configuration (Ed25519 ADR, golden vectors, approved keys, current version, freshness, combined expiry), verifier VK identity (SHA256 hash check), persistence setup (JSON versioned, SQLite feature, RocksDB placeholder).
- Audit gates (historical, pre-remediation; superseded by findings F-01…F-07): `cargo fmt --check`, `clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` — ZWA-REL-001 fixed via `CheckedTrade`, no unsafe, no unwrap in non-test, typed errors, distinct newtypes, redacted secrets, opaque `MatcherApproval`.

**Deliverables for Vikram:**

- `matcher/src/lib.rs`, `checked.rs`, `roots.rs`, `control.rs`, `verifiers.rs`, `replay.rs`, `gate.rs` + 43 tests, zero edits to frozen crates (`crates/`, `circuits/`)
- `docs/decisions/0005-root-signature-scheme.md` (ADR Ed25519 vs BLS vs secp256k1)
- `tests/fixtures/root-sig-golden-vectors.json` (frozen Ed25519 golden vectors)
- `tests/fixtures/groth16/provenance-vkey.json`, `eligibility-vkey.json`, `provenance-proof.json`, `eligibility-proof.json`, `*-public.json` (real Groth16 fixtures with VK hash)
- `tests/adversarial/root-signature.test.js` (JS verification) + `scripts/verify-root-sigs.js` (client-side)
- `docs/matcher-handoff.md` (public API, proves/does NOT prove, root config, VK identity, persistence)
- `docs/decisions/0005-root-signature-scheme.md` already documents why Ed25519

Ready for independent re-audit once `cargo fmt --check`, `cargo clippy -p zwa-matcher --all-targets --all-features -- -D warnings` and `cargo test -p zwa-matcher --all-features` pass locally. Not accepted.

## Build

```sh
cargo test -p zwa-matcher --all-features     # includes SQLite persistence tests
cargo test -p zwa-matcher --lib verifiers::tests::real_provenance_proof_verifies_with_real_vkey -- --nocapture
cargo test -p zwa-matcher --lib verifiers::tests::real_eligibility_proof_verifies_with_real_vkey -- --nocapture
cargo clippy -p zwa-matcher --all-targets --all-features -- -D warnings
cargo fmt --check
cargo test --workspace                       # 82 frozen + 43 matcher = 125
cargo test --workspace --release             # debug ↔ release parity
node --test tests/adversarial/root-signature.test.js  # JS golden vectors
node scripts/verify-root-sigs.js                      # client-side
```
