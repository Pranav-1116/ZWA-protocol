# Matcher Handoff — Phase 2 → Phase 3 (Vikram)

This document is the handoff for Vikram (Phase 3 settlement adapter + integration). It defines exact public API, what `MatcherApproval` proves and does NOT prove, root configuration, verifier VK identity, and persistence setup.

## Public API (frozen for Vikram)

All types are in `zwa-matcher` crate, which imports frozen `zwa-protocol`, `zwa-commitments`, `zwa-credentials` — single source of truth, no reimplementation.

### Core types

```rust
// Task A — checked trade witness, fix ZWA-REL-001
pub struct CheckedTrade { intent, commitment, parts } // private fields, only via new()
impl CheckedTrade {
  pub fn new(intent: TradeIntent, commitment: TradeCommitment) -> Result<Self, ProtocolError>
  pub fn intent(&self) -> TradeIntent
  pub fn commitment(&self) -> TradeCommitment
  pub fn parts(&self) -> TradeCommitmentParts
  pub fn create_replay_record(&self, store: &mut ReplayStore) -> Result<TradeRecord>
}

// Task B — root authentication (Ed25519 over frozen canonical payload)
pub struct IssuerRootAuthenticator { approved_keys: BTreeMap<IssuerKeyId, VerifyingKey>, current_version }
impl IssuerRootAuthenticator {
  pub fn new(approved: BTreeMap<IssuerKeyId, VerifyingKey>, current_version: RootVersion) -> Self
  pub fn authenticate(&self, envelope: &IssuerRootEnvelope, now: UnixSeconds, trade_expiry: TradeExpiry) -> Result<AuthenticatedIssuerRoot, RootAuthError>
}
pub struct CredentialRootAuthenticator { approved_keys: BTreeMap<AuthorityKeyId, VerifyingKey>, current_version }
pub struct AuthenticatedIssuerRoot { envelope: private } // cannot be fabricated
pub struct AuthenticatedCredentialRoot { envelope: private }
pub fn check_combined_root_expiry(trade_expiry, issuer_root, credential_root) -> Result<(), RootAuthError>
pub enum RootAuthError { Structural, IssuerKeyNotApproved, AuthorityKeyNotApproved, VersionNotCurrent, TradeExpiryBeyondRootExpiry, CombinedExpiryViolation, InvalidSignatureEncoding, SignatureVerificationFailed }

// Task C + A5 — recipient control
pub const CONTROL_DOMAIN: &[u8] = b"ZWA-RECIPIENT-CTRL-V1";
pub const DEFAULT_CONTROL_TTL_SECONDS: u64 = 300;
pub struct RecipientControlChallenge { nonce[32], domain, issued_at, expiry, receiver, trade_commitment } // private
impl RecipientControlChallenge {
  pub fn new(receiver, nonce, domain, issued_at, expiry, trade_commitment) -> Result<Self, ControlError>
  pub fn new_random(receiver, trade_commitment, issued_at, ttl, domain) -> Result<Self, ControlError>
  pub fn canonical_bytes(&self) -> Vec<u8> // domain||nonce||issued_at BE||expiry BE||receiver 43B||trade_commitment 32B
}
pub struct RecipientControlResponse { nonce, receiver, trade_commitment, signature[64] }
impl RecipientControlResponse {
  pub fn sign(challenge: &RecipientControlChallenge, signing_key: &SigningKey) -> Self
}
pub trait RecipientControlVerifier {
  fn verify(&self, challenge: &RecipientControlChallenge, response: &RecipientControlResponse, now: UnixSeconds) -> Result<VerifiedRecipientControl, ControlError>
}
pub struct RecipientControlAuthenticator { approved_control_keys: BTreeMap<OrchardReceiverBytes, VerifyingKey>, expected_domain }
impl RecipientControlAuthenticator {
  pub fn new(approved_keys, expected_domain) -> Self
  pub fn verify_against_approved_receiver(&self, challenge, response, approved_receiver, now) -> Result<VerifiedRecipientControl, ControlError>
  pub fn check_trade_expiry(trade_expiry, challenge) -> Result<(), ControlError>
  pub fn check_trade_commitment(expected, challenge) -> Result<(), ControlError>
}
pub struct UnconfiguredControlVerifier; // fail-closed default, returns Unconfigured
#[cfg(test)] pub struct FakeControlVerifier; // test-only, behind cfg(test)
pub enum ControlError { ChallengeExpired, ChallengeIssuedInFuture, DomainMismatch, NonceMismatch, ReceiverMismatch, TradeCommitmentMismatch, ApprovedReceiverMismatch, ControlKeyNotApproved, SignatureVerificationFailed, TradeExpiryBeyondChallengeExpiry, Unconfigured, ... }

// Task D + A4 — Groth16 verifiers (real)
pub struct ProvenanceVerifierBackend { verifier: Groth16Verifier } // real ark-groth16
impl ProvenanceVerifierBackend {
  pub fn from_fixture() -> Result<Self, Groth16VerificationError> // loads tests/fixtures/groth16/provenance-vkey.json with hash check
  pub fn from_vkey_json(vkey_json, expected_hash) -> Result<Self, _>
  pub fn vk_hash(&self) -> &str
}
impl ProvenanceVerifier for ProvenanceVerifierBackend {
  fn verify(&self, authorized_issuance_root, trade_commitment, proof) -> VerificationResult
}
pub struct EligibilityVerifierBackend { /* same */ }
pub struct MatcherProofGate { checked_trade, prov_verifier, elig_verifier }
impl MatcherProofGate {
  pub fn new(checked_trade, prov_verifier, elig_verifier) -> Self
  pub fn verify_both(&self, issuer_root: &AuthenticatedIssuerRoot, credential_root: &AuthenticatedCredentialRoot, prov_proof, elig_proof) -> Result<(), VerificationResult>
}

// Task E + A6 — persistent replay (remediated F-05/F-06: complete records, fallible load, CAS)
pub struct ReplayRecord { /* commitment, intent, state, failure_reason, prior_txid, retry_count, version — read-only accessors */ }
pub trait ReplayPersistence: Send + Sync {
  fn load(&self, commitment) -> Result<Option<ReplayRecord>, PersistenceError>;
  fn load_all(&self) -> Result<Vec<ReplayRecord>, PersistenceError>;
  fn compare_and_swap(&self, expected: Option<&ReplayRecord>, new: &ReplayRecord) -> Result<(), PersistenceError>; // Conflict on lost race
}
pub struct InMemoryPersistence;                    // CAS under a mutex; share via Arc
pub struct JsonFilePersistence;                    // schema v2, strict, re-read per op, fsync tmp+rename, single writer
#[cfg(feature="sqlite")] pub struct SqlitePersistence; // replay_records_v2, BEGIN IMMEDIATE + conditional UPDATE; multi-instance safe
pub struct RocksDbPersistence;                     // placeholder, every call fails closed
pub struct PersistentReplayStore<P: ReplayPersistence> { /* persistence only — no in-memory lifecycle state */ }
impl<P> PersistentReplayStore<P> {
  pub fn new(persistence, max_retries) -> Result<Self, ReplayError> // validates every stored record
  pub(crate) fn create_checked / verify / acquire_construction      // gate-only
  pub fn submit(&self, commitment, txid, now) -> Result<ReplayRecord, ReplayError>
  pub fn confirm(&self, commitment) -> Result<ReplayRecord, ReplayError>
  pub fn consume(&self, commitment) -> Result<ReplayRecord, ReplayError>
  pub fn fail(&self, commitment, reason) -> Result<ReplayRecord, ReplayError>
  pub fn expire(&self, commitment, now) -> Result<ReplayRecord, ReplayError>
  pub fn retry_after_failure(&self, commitment, ack_txid, now) -> Result<ReplayRecord, ReplayError>
  pub fn state(&self, commitment) -> Result<Option<TradeLifecycleState>, ReplayError>
  pub fn get(&self, commitment) -> Result<Option<ReplayRecord>, ReplayError>
}

// Task F + A7 — 10-step gate
pub struct GateInput { intent, commitment, issuer_envelope, credential_envelope, approved_receiver, recipient_subject_commitment /* F-02 */, control_challenge, control_response, provenance_proof, eligibility_proof, now }
pub enum GateRejection { CommitmentMismatch, RootAuth(RootAuthError), Control(ControlError), Replay(ReplayError), ExpiredTrade, ProofInvalid(VerificationResult), AlreadyConsumed, AlreadyExpired, RetryRequired, IllegalState, RecipientBindingMismatch }
#[derive(Debug)] // opaque, !Clone, !Serialize, private _private: ()
pub struct VerifiedTrade { checked_trade: private, authenticated_issuer_root: private, authenticated_credential_root: private, verified_control: private, _private: () }
impl VerifiedTrade {
  pub fn checked_trade(&self) -> &CheckedTrade
  pub fn authenticated_issuer_root(&self) -> &AuthenticatedIssuerRoot
  pub fn authenticated_credential_root(&self) -> &AuthenticatedCredentialRoot
  pub fn verified_control(&self) -> &VerifiedRecipientControl
  pub fn commitment(&self) -> TradeCommitment
  pub fn intent(&self) -> TradeIntent
}
pub type MatcherApproval = VerifiedTrade; // A7 opaque approval
pub struct MatcherGate<P: ReplayPersistence> { issuer_auth, credential_auth, control_auth, prov_verifier, elig_verifier, replay_store }
impl<P> MatcherGate<P> {
  pub fn new(issuer_auth, credential_auth, control_auth, prov_verifier, elig_verifier, replay_store) -> Self
  pub fn evaluate(&self, input: GateInput) -> Result<MatcherApproval, GateRejection> // 10-step deterministic allow/block
  pub fn replay_store(&self) -> &PersistentReplayStore<P>
}
```

Vikram should only call `MatcherGate::evaluate()` and handle `GateRejection`. Do not call `ReplayStore::create` directly, do not reimplement commitment, encodings, or root serialization.

## What MatcherApproval proves and does NOT prove

### Proves (after 10 gates PASS)

1. Intent/commitment correspondence — `verify_trade_commitment(intent, commitment)` succeeded, recomputed `H(TRADE_V1, ...)` equals presented commitment. Prevents expiry bypass via intent substitution.
2. Issuer root authentic — Ed25519 signature over frozen canonical bytes `ZWA1ROOT | kind=1 | version BE | valid_from BE | expires_at BE | id_len | id | root 32B` valid under approved `IssuerKeyId`, version == current_version (supersession), `valid_from ≤ now ≤ expires_at`, `trade_expiry ≤ root_expires_at`.
3. Credential root authentic — same for `kind=2`, `AuthorityKeyId`, `trade_expiry ≤ root_expiry`, combined `trade_expiry ≤ min(issuer_expiry, credential_expiry)`.
4. Live wallet control — challenge `domain||nonce||issued_at BE||expiry BE||receiver 43B||trade_commitment 32B` signed by control key registered for that receiver, nonce match, domain `ZWA-RECIPIENT-CTRL-V1`, freshness, trade_commitment binding, approved receiver match (Phase1B `credential(A)+trade(A) PASS, credential(A)+trade(B) FAIL` + live control).
5. Replay allowed — trade not expired (`now > expiry` predicate, `now == expiry` valid), state `CREATED → VERIFIED` or `FAILED → CREATED → VERIFIED`, not `CONSUMED`/`EXPIRED` terminal, retry budget 3, txid ack.
6. Provenance proof valid — Groth16 `rwa_trade_provenance_v1` (8837 constraints, 2 public inputs) verifies for `authorizedIssuanceRoot` + exact `tradeCommitment` from `CheckedTrade`.
7. Eligibility proof valid — Groth16 `rwa_investor_eligibility_v1` (13502 constraints, 2 public inputs) verifies for `activeCredentialRoot` + same `tradeCommitment`, investor class 8b, jurisdiction 16b, expiry 64b, nonce 64b, single receiverHasher reused twice.
8. Settlement construction acquired — compare-and-set, only one worker wins, expiry-gated.

### Does NOT prove

- Not non-custodial settlement — seller/buyer independent authorization of own ZSA actions is Phase 3 (Vikram). Do not claim venue non-custodial until Phase 3 demonstrates independent signing without handing spending authority to matcher.
- Not wallet spending-key control beyond Ed25519 control challenge — real Orchard ivk/nullifier proof is research track, Ed25519 registry is MVP.
- Not global compliance enforcement — matcher is MVP compliance boundary per `docs/decisions/0002-matcher-enforced-compliance.md`. Zcash consensus does not enforce investor policy. Direct ZSA transfers outside venue are not blocked.
- Not production ZSA mainnet — ZSA settlement is experimental QEDIT branches (`zcash_tx_tool 6bcf2c5`, `zsa-swap 217b979`, Zebra `0aef55c`, librustzcash `5a55da9`, orchard `d91aaf1`). Demo must label experimental.
- Not recursive lineage — optional research track `docs/decisions/0001-zk-origin-reuse.md`, not settlement prerequisite.
- Not instant global revocation — revocation latency is root refresh interval.
- Not production trusted setup — Phase 0 used local dev setup, not ceremony.

## Root configuration

- Scheme: Ed25519 (RFC8032, deterministic `r = H(h_b..h_{2b-1}, M)`, non-malleable 64B `(R,S)` with `S < L`, small-order checks in `ed25519-dalek 2.1.1`).
- Alternatives considered in ADR `docs/decisions/0005-root-signature-scheme.md`: BLS12-381 (aggregatable but heavier, WASM, rogue-key surface), secp256k1 ECDSA (RNG-dependent, malleable low-S/high-S).
- Canonical payload: frozen, `IssuerRootPayload::canonical_bytes()` and `CredentialRootPayload::canonical_bytes()` from `zwa-credentials::envelope`. No re-encoding.
- Golden vectors: `tests/fixtures/root-sig-golden-vectors.json` — deterministic seeds `[1;32]` issuer, `[2;32]` credential, pubkeys `8a88e3dd...`, `8139770e...`, signatures `66b6a1...`, `023c63...`. Rust `ed25519_dalek::VerifyingKey::verify` and JS `tweetnacl.sign.detached.verify` both verify same file.
- Approved keys: `BTreeMap<IssuerKeyId, VerifyingKey>` and `BTreeMap<AuthorityKeyId, VerifyingKey>` — distinct types prevent mixing. `IssuerKeyId::new(b"issuer-atlas")`, `AuthorityKeyId::new(b"cred-auth-1")`.
- Current version policy: only `version == current_version` accepted. Stale-but-still-signed rejected. `RootVersion::MIN = 1`.
- Freshness: `valid_from ≤ now ≤ expires_at` inclusive, `ValidityWindow::contains(now)`.
- Expiry: `trade_expiry ≤ root_expires_at` per root, combined `trade_expiry ≤ min(issuer_exp, credential_exp)`.

## Verifier VK identity

- Real Groth16 via `ark-groth16 0.5.0` + `ark-bn254 0.5.0` (BN128/BN254 same).
- VKeys generated outside repo via `circom 2.2.2` + `snarkjs 0.7.5`, stored as frozen fixtures `tests/fixtures/groth16/provenance-vkey.json`, `eligibility-vkey.json` — not generated artifacts in `circuits/`.
- **Circuit/key provenance (M2 remediation):** the `.circom` sources are restored to the frozen M1 versions (`b017962`); the tautological `dummyProd` constraints added in `ef7fc73` are removed. The key/proof fixtures are deliberately left byte-for-byte unchanged, but they were generated from the `dummyProd` variant, so they do not correspond to the frozen source. Constraint counts quoted here (8837/13502) are from that variant. The M1 owner must re-issue or approve keys for the frozen circuits; M2 does not regenerate them.
- VK hash checked: `VkHash::from_json_str(vkey_json)` SHA256 hex, `ProvenanceVerifierBackend::from_fixture()` expects `4831d3eef9575ef7daf318eb8767e1a39ef1e26da20339ddda137b1e246f1350`, `Eligibility` expects `879d427a16f334edc163e78614c94dfe00c3ae3cb657c3ef4d7d82c39e4f5e75`. Prevents substitution (threat model).
- Public inputs order frozen: provenance `[authorizedIssuanceRoot, tradeCommitment]`, eligibility `[activeCredentialRoot, tradeCommitment]` — 2 public inputs, 21/ private inputs, constraints 8837/13502.
- Proofs: `tests/fixtures/groth16/provenance-proof.json` + `provenance-public.json` = `[8857867840332676380575934803462643968319857770249975039236308904195120230546, 7409670081847436957289371955571360481923983184454289247710022466448715682310]` (Phase0F), `eligibility-proof.json` + `eligibility-public.json` = `[7721491042898277899686830032817687831050368809629386580479309633507500868506, 10187400613857124614980227259922066295752635539032972479692659299555113110306]` (Phase1B). Real proofs verify in `cargo test -p zwa-matcher --lib verifiers::tests::real_provenance_proof_verifies_with_real_vkey` and `real_eligibility_proof_verifies_with_real_vkey` in both debug and release.
- No fallback (F-01): malformed or non-Groth16 input always rejects with `ProofMalformed`, in every build and feature combination (the `test-helpers` feature is deleted). Tests inject `#[cfg(test)]` trait fakes instead. Production must use `from_fixture()` with hash check.

## Persistence setup

- See the API block above. Every transition is `load → apply (mirrors frozen ReplayStore) → compare_and_swap(expected state + version)`; nothing is cached in memory, so a failed write cannot advance state and a lost race returns `Conflict`.
- Stored data is validated on open and on every load (commitment must recompute from intent, canonical encodings, no unknown fields, version >= 1). Corrupt, legacy (schema 1, bare array, old `replay` SQLite table), empty or unknown-version data fails closed and is never migrated or rewritten.
- Use `SqlitePersistence` when more than one process or store instance shares state; `JsonFilePersistence` is single-writer.
- Expiry contract frozen: `verify`, `acquire_construction`, `submit`, `retry_after_failure` expiry-gated (`now > expiry` → Expired), `confirm`/`consume` allowed after expiry if submission was valid. `FAILED → CREATED` requires full re-verification, retry budget 3, txid ack exact.

## Integration & release audit (A8)

**Status: NOT ACCEPTED — pending independent re-audit after M2 remediation (F-01, F-02, F-05/F-06, F-07).**

- Gate happy-path tests use real Ed25519 roots and control with `#[cfg(test)]` injected proof fakes for the same commitment; the real Groth16 path is tested in `verifiers::tests` and with the real eligibility verifier in `gate::tests::f02_*`. No end-to-end ALLOW with two real proofs exists: the fixture proofs are for different trades (`7409…` vs `10187…`).
- Gate order: CheckedTrade → read-only replay precheck → trade expiry → roots → recipient binding + control → provenance → eligibility → create/VERIFIED/SETTLEMENT_CONSTRUCTED (CAS). No replay write happens before all checks pass.
- `FAILED` is never retried by the gate (`RetryRequired`); the settlement side must call `retry_after_failure` with the exact prior txid, after which the trade must pass the full gate again.
- Matcher API changes that affect the settlement side: `PersistentReplayStore::new` returns `Result` (startup scan) and `PersistentReplayStore::lazy` skips the scan (every operation still loads and fails closed); `state/get` return `Result<Option<_>>` and `ReplayRecord` instead of `TradeRecord`; the commitment-keyed `create_checked/verify/acquire_construction` are crate-private, and other crates use the approval-gated `create_from_approval` / `verify_approved` / `acquire_construction_approved` (they take a `&MatcherApproval`); the `ReplayPersistence` trait is now CAS-based (`load` / `load_all` / `compare_and_swap`); `GateInput.recipient_subject_commitment` was added; `RocksDbPersistence` fails closed; the `test-helpers` feature and `make_test_proof_json` were removed.
- Compile-only adaptation of `crates/settlement` and `crates/zcash-adapter` (M4, **pending review by the M4 owner**; no settlement logic changed):
  - `SettlementReplayCoordinator` uses `PersistentReplayStore::lazy` (so `new` stays infallible). `verify_commitment` / `acquire_settlement_construction` now take `&MatcherApproval` instead of a commitment. `state` / `get` return `Result<Option<_>, SettlementReplayError>`. Records are `ReplayRecord`.
  - `SettlementExecutor::state` / `get` return `Result<Option<_>, ExecutionError>`. The executor's record-returning methods return `ReplayRecord`.
  - `EndToEndSettlementCoordinator<P, PV = ProvenanceVerifierBackend, EV = EligibilityVerifierBackend>` is generic over the proof verifiers, with the real Groth16 backends as defaults. It gains `with_ed25519_registry_and_verifiers`. `process_rfq_and_settle` (inherent and `IntegrationTrait`) takes a new `recipient_subject_commitment: SubjectCommitment` argument after `approved_receiver` (F-02).
  - Tests: every settlement/adapter test built approvals from `make_test_proof_json` JSON proofs, which F-01 makes invalid in every build. They now inject a `#[cfg(test)]` fake verifier through the frozen traits: `crates/settlement/src/test_support.rs`, plus a local copy in the adapter tests. The fake accepts only proof bytes for the exact root and commitment. The tests also pass the golden subject commitment, and the dev-dependencies no longer name `test-helpers`.

## For Vikram — what to call

```rust
let gate = MatcherGate::new(
  IssuerRootAuthenticator::new(approved_issuer_keys, current_issuer_version),
  CredentialRootAuthenticator::new(approved_credential_keys, current_credential_version),
  RecipientControlAuthenticator::new(approved_control_keys, CONTROL_DOMAIN.to_vec()),
  ProvenanceVerifierBackend::from_fixture()?,
  EligibilityVerifierBackend::from_fixture()?,
  PersistentReplayStore::new(JsonFilePersistence::new(path)?, 3)?,
);

let input = GateInput { intent, commitment, issuer_envelope, credential_envelope, approved_receiver, recipient_subject_commitment, control_challenge, control_response, provenance_proof, eligibility_proof, now };

match gate.evaluate(input) {
  Ok(approval) => { /* approval.commitment(), approval.intent() → hand to Phase 3 settlement adapter */ },
  Err(GateRejection::CommitmentMismatch { expected, actual }) => { /* BLOCK at Step 2 */ },
  Err(GateRejection::RootAuth(e)) => { /* BLOCK at Step 3/4 */ },
  Err(GateRejection::Control(e)) => { /* BLOCK at Step 5 */ },
  Err(GateRejection::Replay(e)) => { /* BLOCK at Step 6/9 */ },
  Err(GateRejection::ProofInvalid(result)) => { /* BLOCK at Step 7/8 */ },
  Err(e) => { /* AlreadyConsumed, AlreadyExpired, IllegalState */ },
}
```

`approval` is opaque `MatcherApproval` — do not serialize, do not clone, do not fabricate. Only `gate.evaluate()` can produce it.
