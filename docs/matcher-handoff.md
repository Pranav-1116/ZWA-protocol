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

// Task E + A6 — persistent replay
pub trait ReplayPersistence: Send + Sync { fn save(&self, record: &TradeRecord) -> Result<(), PersistenceError>; fn load(&self, commitment) -> Option<TradeRecord>; fn load_all(&self) -> Vec<TradeRecord>; }
pub struct InMemoryPersistence { inner: Mutex<BTreeMap> }
pub struct JsonFilePersistence { path, cache } // versioned {"schema_version":1,"records":[...]}, atomic tmp+rename
#[cfg(feature="sqlite")] pub struct SqlitePersistence { path, conn } // rusqlite bundled, production-ready
pub struct RocksDbPersistence; // placeholder fail-closed
pub struct PersistentReplayStore<P: ReplayPersistence> { inner: Mutex<ReplayStore>, persistence: P }
impl<P> PersistentReplayStore<P> {
  pub fn new(persistence, max_retries) -> Self // loads load_all() and replays to reach state
  pub fn create_checked(&self, checked: &CheckedTrade) -> Result<TradeRecord, ReplayError> // only via CheckedTrade
  pub fn verify(&self, commitment, now) -> Result<TradeRecord, ReplayError>
  pub fn acquire_construction(&self, commitment, now) -> Result<TradeRecord, ReplayError> // compare-and-set, only one winner
  pub fn submit(&self, commitment, txid, now) -> Result<TradeRecord, ReplayError>
  pub fn confirm(&self, commitment) -> Result<TradeRecord, ReplayError>
  pub fn consume(&self, commitment) -> Result<TradeRecord, ReplayError>
  pub fn state(&self, commitment) -> Option<TradeLifecycleState>
  pub fn get(&self, commitment) -> Option<TradeRecord>
}

// Task F + A7 — 10-step gate
pub struct GateInput { intent, commitment, issuer_envelope, credential_envelope, approved_receiver, control_challenge, control_response, provenance_proof, eligibility_proof, now }
pub enum GateRejection { CommitmentMismatch, RootAuth(RootAuthError), Control(ControlError), Replay(ReplayError), ExpiredTrade, ProofInvalid(VerificationResult), AlreadyConsumed, AlreadyExpired, IllegalState, ApprovedReceiverMismatch }
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
- VK hash checked: `VkHash::from_json_str(vkey_json)` SHA256 hex, `ProvenanceVerifierBackend::from_fixture()` expects `4831d3eef9575ef7daf318eb8767e1a39ef1e26da20339ddda137b1e246f1350`, `Eligibility` expects `879d427a16f334edc163e78614c94dfe00c3ae3cb657c3ef4d7d82c39e4f5e75`. Prevents substitution (threat model).
- Public inputs order frozen: provenance `[authorizedIssuanceRoot, tradeCommitment]`, eligibility `[activeCredentialRoot, tradeCommitment]` — 2 public inputs, 21/ private inputs, constraints 8837/13502.
- Proofs: `tests/fixtures/groth16/provenance-proof.json` + `provenance-public.json` = `[8857867840332676380575934803462643968319857770249975039236308904195120230546, 7409670081847436957289371955571360481923983184454289247710022466448715682310]` (Phase0F), `eligibility-proof.json` + `eligibility-public.json` = `[7721491042898277899686830032817687831050368809629386580479309633507500868506, 10187400613857124614980227259922066295752635539032972479692659299555113110306]` (Phase1B). Real proofs verify in `cargo test -p zwa-matcher --lib verifiers::tests::real_provenance_proof_verifies_with_real_vkey` and `real_eligibility_proof_verifies_with_real_vkey` in both debug and release.
- Mock fallback: In `#[cfg(test)]` only, `make_test_proof_json(root, commitment)` creates `{"public_inputs":[root, commitment]}` that passes `ProvenanceVerifierBackend::default()` / `EligibilityVerifierBackend::default()` via mock path — never reachable in non-test build. Production must use `from_fixture()` with hash check.

## Persistence setup

- Trait `ReplayPersistence: Send + Sync { save, load, load_all, delete }`.
- `InMemoryPersistence` — `Mutex<BTreeMap<TradeCommitment, TradeRecord>>`, for tests.
- `JsonFilePersistence` — versioned `{"schema_version":1,"records":[{commitment_decimal,intent,state,...}]}`, atomic write via `path.tmp` + rename, survives restart, `new(path)` loads and replays transitions to reach state. Corrupted JSON returns `Deserialization` without destructive migration, unknown version returns `UnknownSchemaVersion {got, expected}` without overwriting file.
- `SqlitePersistence` behind `sqlite` feature — `rusqlite 0.31 bundled`, `CREATE TABLE replay(commitment TEXT PRIMARY KEY, data TEXT, schema_version INTEGER)`, checks distinct versions on `new()` and rejects unknown, production-ready alternative to JSON MVP.
- `RocksDbPersistence` placeholder — fails closed with Io error mentioning RocksDB not configured, satisfies spec listing SQLite/RocksDB while JSON remains MVP.
- `PersistentReplayStore<P>` — wraps `ReplayStore` in `Mutex<ReplayStore>` + persistence, every successful transition `save()`, `new()` loads `load_all()` into inner via transitions (CREATED→VERIFIED→...), thread-safe compare-and-set for `acquire_construction`.
- Expiry contract frozen: `verify`, `acquire_construction`, `submit`, `retry_after_failure` expiry-gated (`now > expiry` → Expired), `confirm`/`consume` allowed after expiry if submission was valid. `FAILED → CREATED` requires full re-verification, retry budget 3, txid ack exact.

## Integration & release audit (A8)

- One complete valid flow test `gate::tests::gate_allows_valid_private_trade` — real Ed25519 signatures for issuer (seed 1) + credential (seed 2) + control (seed 3), `RecipientControlChallenge` with trade_commitment binding, `JsonFilePersistence` or `InMemoryPersistence`, `make_test_proof_json` mock proofs for same commitment (real Groth16 path tested separately in `verifiers::tests`).
- Every attack scenario blocks at intended gate — 7 gate tests cover unauthorized asset (CommitmentMismatch at Step 2), wrong investor class (ProofInvalid at Step 8), receiver not approved (ApprovedReceiverMismatch at Step 5), approved without control (SignatureVerificationFailed at Step 5), expired trade (ExpiredTrade at Step 6), stale root (VersionNotCurrent at Step 3), proof splicing (ProofInvalid at Step 7/8), double construction (IllegalState at Step 9), identical request twice (IllegalState).
- Debug ↔ release parity — `cargo test --workspace` and `cargo test --workspace --release` must both pass 82 frozen + 38 matcher = 120 tests. Paste 1.0.15 unmaintained warning via arkworks/light-poseidon is not vulnerability.
- Final audit goal SAFE (0 Critical, 0 High, 0 Medium) — ZWA-REL-001 fixed via CheckedTrade, no unsafe, no unwrap in non-test (clippy deny), typed errors, distinct newtypes, redacted secrets.

## For Vikram — what to call

```rust
let gate = MatcherGate::new(
  IssuerRootAuthenticator::new(approved_issuer_keys, current_issuer_version),
  CredentialRootAuthenticator::new(approved_credential_keys, current_credential_version),
  RecipientControlAuthenticator::new(approved_control_keys, CONTROL_DOMAIN.to_vec()),
  ProvenanceVerifierBackend::from_fixture()?,
  EligibilityVerifierBackend::from_fixture()?,
  PersistentReplayStore::new(JsonFilePersistence::new(path)?, 3),
);

let input = GateInput { intent, commitment, issuer_envelope, credential_envelope, approved_receiver, control_challenge, control_response, provenance_proof, eligibility_proof, now };

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
