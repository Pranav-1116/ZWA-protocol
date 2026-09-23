# V0: Repository Inventory — RFQ Boundary → Frozen Types + Akshay Matcher API

This is V0 for Vikram (Phase 3 settlement). It maps RFQ boundary to frozen protocol types and Akshay's matcher API, and identifies what stays private vs public. Frozen types are never recomputed — only referenced.

## FROZEN TYPE MAPPING

### From Phase 1 (zwa-protocol crate) — FROZEN, never recompute

#### TradeIntent
- **Fields:**
  - `offered_asset: AssetBaseBytes` — 32B compressed Pallas, 128/128 LE limbs, canonical only, no ticker
  - `offered_amount: TradeAmount` — u64 ZatoshiAmount wrapper
  - `requested_asset: AssetBaseBytes` — 32B Pallas, same encoding
  - `requested_amount: TradeAmount`
  - `recipient_commitment: RecipientCommitment` — `H(RECEIVR1, limb0, limb1, limb2)` canonical, 43B receiver → commitment, public
  - `policy_root: PolicyRoot` — Merkle root of policy set, decimal string, public
  - `matcher_fee: MatcherFee { amount: ZatoshiAmount, recipient_commitment: RecipientCommitment }` — fee amount + fee recipient commitment, both bound
  - `nonce: TradeNonce` — u64, prevents replay, public
  - `expiry: TradeExpiry` — u64 UnixSeconds, inclusive `now == expiry` valid, public
- **Location:** `crates/protocol/src/intent.rs` + `crates/protocol/src/values.rs` + `crates/commitments/src/trade.rs` for commitment construction
- **Status:** FROZEN — `TradeCommitmentV1` is `H(TRADE_V1, offered_asset_hi, offered_asset_lo, requested_asset_hi, requested_asset_lo, offered_amount, requested_amount, recipient_commitment, policy_root, fee_amount, fee_recipient_commitment, nonce, expiry)` with exact domain separators from `crates/commitments/src/domain.rs` (`TRADE_V1 = "ZWA-TRADE-V1"`, `RECEIVR1`, etc.). Your RFQ must reference `TradeIntent` and `TradeCommitmentV1`, never recompute Poseidon staging or limb encoding.
- **Private vs Public:**
  - **Public:** All fields are public inputs to circuits and to matcher gate — `offered_asset`, `requested_asset`, amounts, `recipient_commitment` (hash, not raw receiver), `policy_root`, fee, nonce, expiry. These go into `TradeCommitmentV1` which is public.
  - **Private:** Raw Orchard receiver `OrchardReceiverBytes` (43B diversifier + transmission key) is private — only its commitment is public in `TradeIntent`. Raw receiver is revealed only in control challenge `RecipientControlChallenge` to prove live control, but must not be logged in settlement. Subject secret (credential preimage) is private, never in `TradeIntent`.

#### TradeCommitmentV1
- **Construction:** `zwa_commitments::trade::compute_trade_commitment(intent) -> TradeCommitment` → Poseidon hash with exact staging: 2 limbs per AssetBase (hi,lo), amounts, recipient_commitment, policy_root, fee, nonce, expiry, domain `TRADE_V1`. Frozen per `docs/trade-commitment-v1.md`.
- **Fields bound:** All `TradeIntent` fields + `fee_recipient_commitment` — 10-field mutation fails: offered_asset, requested_asset, both amounts, recipient, policy, fee_amount, fee_recipient, nonce, expiry (see `checked::tests::checked_trade_every_field_mutation_fails`).
- **Reference values:**
  - Phase 0F (provenance fixture): `7409670081847436957289371955571360481923983184454289247710022466448715682310` — intent with recipient `9164735690016291275717655492237784651611678784535903954999391667413316204280`, offered `4889ad11564115f3655f7e434bffb23074d42aafd58cfecae32a5b5eafaf5301`, requested `a7ac13ded8b51e7a59c400097b70fe6d5d855b30ad19b1897de1fd74721a9339`
  - Phase 0G (eligibility fixture): `10187400613857124614980227259922066295752635539032972479692659299555113110306` — intent with recipient `13135279047718387126053226034283670929172341955108098732820235388025453726181`, same assets as above, policy `1514393595722546217125953798550283818470332284949639873172624869558831825935`
- **Location:** `crates/commitments/src/trade.rs`, `crates/protocol/src/values.rs` (`TradeCommitment` newtype)
- **Status:** FROZEN — your RFQ and settlement must reference, never compute. `CheckedTrade::new(intent, commitment)` calls `verify_trade_commitment` first — fix for ZWA-REL-001. All downstream takes `&CheckedTrade`, not raw intent.

#### TradeSubmission / GateInput (your V3 converts RFQ into this)
- **Fields:**
  - `intent: TradeIntent` — canonical, typed
  - `commitment: TradeCommitment` — presented, must correspond via `CheckedTrade`
  - `issuer_envelope: IssuerRootEnvelope` — signed `AuthorizedIssuanceRoot`, `IssuerKeyId`, version, window, `OpaqueSignature` 64B Ed25519
  - `credential_envelope: CredentialRootEnvelope` — signed `ActiveCredentialRoot`, `AuthorityKeyId`, same
  - `approved_receiver: OrchardReceiverBytes` — 43B, authority-approved from credential leaf (Phase 1B)
  - `control_challenge: RecipientControlChallenge` — `{ domain=ZWA-RECIPIENT-CTRL-V1, nonce[32], issued_at, expiry, receiver 43B, trade_commitment 32B }`
  - `control_response: RecipientControlResponse` — `{ nonce, receiver, trade_commitment, signature[64] }`
  - `provenance_proof: OpaqueProof` — JSON `{"public_inputs":[root, commitment], proof:{a,b,c}}` or real Groth16 `pi_a, pi_b, pi_c`
  - `eligibility_proof: OpaqueProof` — same
  - `now: UnixSeconds` — current time for freshness/expiry
- **Location:** `matcher/src/gate.rs` (`GateInput`), `crates/credentials/src/envelope.rs` (payloads), `matcher/src/control.rs` (challenge/response)
- **Status:** FROZEN — your RFQ boundary must produce canonical `TradeIntent` + `TradeCommitmentV1` that will be wrapped into `GateInput` for `MatcherGate::evaluate()`. Do not reimplement commitment, AssetBase 32B encoding, receiver 43B encoding, root canonical payload `ZWA1ROOT`.

### From Akshay's Matcher (Milestone 1 — Tasks A-F + A1-A8) — READ-ONLY, you receive, never construct

#### MatcherApproval / VerifiedTrade
- **What it is:** Opaque type, non-serializable, `!Clone`, `!Serialize`, private `_private: ()` marker, `Debug` only, no public constructor outside `gate` module. Only `MatcherGate::evaluate()` can produce it.
- **Location:** `matcher/src/gate.rs:115-180` (`VerifiedTrade`, `pub type MatcherApproval = VerifiedTrade`)
- **Status:** You receive this, never construct it. Invariant: Only Akshay's matcher can produce it. Proves all 10 gates passed. Contains getters: `commitment() -> TradeCommitment`, `intent() -> TradeIntent`, `checked_trade() -> &CheckedTrade`, `authenticated_issuer_root()`, `authenticated_credential_root()`, `verified_control()`.
- **Private vs Public:**
  - **Public:** `commitment()`, `intent()` (which contains public fields) — safe to pass to settlement adapter
  - **Private:** Internal `authenticated_issuer_root`, `authenticated_credential_root`, `verified_control` contain verified witnesses but not secrets. No spending keys. `VerifiedTrade` itself must not be serialized or logged with debug in production (debug contains `VerifiedTrade` string but not secrets).

#### Root Authentication Types
- **Types:**
  - `IssuerRootEnvelope` / `CredentialRootEnvelope` — signed envelopes: payload + `OpaqueSignature` 64B Ed25519, `IssuerKeyId` / `AuthorityKeyId` distinct newtypes
  - `IssuerRootPayload` / `CredentialRootPayload` — canonical bytes `ZWA1ROOT 8B || kind 1B (1=issuer,2=credential) || version 8B BE || valid_from 8B BE || expires_at 8B BE || id_len 1B || id || root 32B BE`, frozen per `zwa-credentials/src/envelope.rs`
  - `IssuerRootAuthenticator` / `CredentialRootAuthenticator` — `BTreeMap<IssuerKeyId, VerifyingKey>` / `BTreeMap<AuthorityKeyId, VerifyingKey>`, `current_version: RootVersion`, `authenticate(envelope, now, trade_expiry) -> Result<AuthenticatedIssuerRoot>`
  - `AuthenticatedIssuerRoot` / `AuthenticatedCredentialRoot` — private envelope, cannot be fabricated except via `authenticate()`, getters `root()`, `issuer_id()`, `version()`, `expires_at()`, `envelope()`
  - `RootAuthError` — typed: `Structural`, `IssuerKeyNotApproved`, `AuthorityKeyNotApproved`, `VersionNotCurrent`, `TradeExpiryBeyondRootExpiry`, `CombinedExpiryViolation`, `InvalidSignatureEncoding`, `SignatureVerificationFailed`
  - `check_combined_root_expiry(trade_expiry, issuer_root, credential_root)` — enforces `trade_expiry <= min(issuer_expiry, credential_expiry)`
- **Location:** `matcher/src/roots.rs`, `crates/credentials/src/envelope.rs`, `crates/credentials/src/ids.rs`
- **Status:** Read-only; you pass these through to settlement as part of `VerifiedTrade` (already verified). Do not re-verify, do not re-encode canonical payload. Golden vectors: `tests/fixtures/root-sig-golden-vectors.json` — issuer seed `[1;32]` pubkey `8a88e3dd...` sig `66b6a1...`, credential seed `[2;32]` pubkey `8139770e...` sig `023c63...`, verifiable in Rust `ed25519_dalek` + JS `tweetnacl`.
- **Private vs Public:**
  - **Public:** Roots (decimal strings), key IDs (`b"issuer-atlas"`, `b"cred-auth-1"`), version, window, signatures (64B) — all public, go into gate
  - **Private:** Signing keys `[1;32]`, `[2;32]` — never in matcher, only in test fixtures for golden vectors. Verifying keys are public.

#### Recipient-Control (Task C + A5 — Vikram V4 boundary)
- **Types:**
  - `CONTROL_DOMAIN = b"ZWA-RECIPIENT-CTRL-V1"` frozen, `DEFAULT_CONTROL_TTL_SECONDS = 300`
  - `RecipientControlChallenge` — private fields: `nonce[32]`, `domain: Vec<u8>`, `issued_at: UnixSeconds`, `expiry: UnixSeconds`, `receiver: OrchardReceiverBytes 43B`, `trade_commitment: TradeCommitment 32B`
  - `RecipientControlResponse` — `nonce[32]`, `receiver 43B`, `trade_commitment`, `signature[64]`
  - `RecipientControlChallenge::canonical_bytes()` — `domain || nonce || issued_at 8B BE || expiry 8B BE || receiver 43B || trade_commitment 32B` — all fields bound
  - `RecipientControlAuthenticator` — `BTreeMap<OrchardReceiverBytes, VerifyingKey>` approved_control_keys + `expected_domain`, `verify_against_approved_receiver(challenge, response, approved_receiver, now) -> VerifiedRecipientControl`, `check_trade_expiry`, `check_trade_commitment`
  - `RecipientControlVerifier` trait — opaque boundary for Vikram V4: `fn verify(&self, challenge, response, now) -> Result<VerifiedRecipientControl, ControlError>`
  - `UnconfiguredControlVerifier` — fail-closed default, returns `Unconfigured`
  - `FakeControlVerifier` — `#[cfg(test)]` only, test-only fake always passes, never reachable in prod
  - `ControlError` — typed: `ChallengeExpired`, `ChallengeIssuedInFuture`, `DomainMismatch`, `NonceMismatch`, `ReceiverMismatch`, `TradeCommitmentMismatch`, `ApprovedReceiverMismatch`, `ControlKeyNotApproved`, `SignatureVerificationFailed`, `TradeExpiryBeyondChallengeExpiry`, `Unconfigured`
  - `VerifiedRecipientControl` — `receiver 43B`, `receiver_commitment: ReceiverCommitment = H(RECEIVR1, limbs)` canonical, `trade_commitment`
- **Location:** `matcher/src/control.rs`
- **Status:** Read-only; `VerifiedTrade` already contains `verified_control`. Your V4 task will design real Orchard ivk proof vs Ed25519 registry MVP. For V1 settlement, you receive `verified_control` via approval.
- **Private vs Public:**
  - **Public:** Challenge fields `domain`, `nonce`, `issued_at`, `expiry`, `receiver` (43B revealed to matcher for control), `trade_commitment`, `receiver_commitment` — public to matcher, but raw receiver should not be logged in settlement beyond control verification
  - **Private:** Control signing keys `[3;32]` etc. — seller's wallet control key, private. Signatures 64B public.

#### Replay (Task E + A6)
- **Types:**
  - `ReplayPersistence: Send + Sync { save, load, load_all, delete }`
  - `InMemoryPersistence` — `Mutex<BTreeMap<TradeCommitment, TradeRecord>>`, for tests
  - `JsonFilePersistence` — versioned `{"schema_version":1,"records":[...]}`, atomic `path.tmp` + rename, survives restart, `new(path)` loads and replays to state, corrupted → `Deserialization` without migration, unknown version → `UnknownSchemaVersion {got, expected}` without overwrite
  - `SqlitePersistence` behind `sqlite` feature — `rusqlite 0.31 bundled`, `CREATE TABLE replay(commitment TEXT PRIMARY KEY, data TEXT, schema_version INTEGER)`, production-ready
  - `RocksDbPersistence` placeholder fail-closed with Io error mentioning RocksDB
  - `PersistentReplayStore<P>` — `Mutex<ReplayStore>` + persistence, `new(persistence, max_retries=3)` loads `load_all()` and replays transitions, `create_checked(&CheckedTrade)` only via `CheckedTrade` (fixes ZWA-REL-001), `verify`, `acquire_construction` compare-and-set only one winner, `submit(txid)`, `confirm()`, `consume()` terminal, `fail()`, `expire()`, `retry_after_failure(ack_txid, now)` requires full re-verification, retry budget 3, txid ack exact
  - `TradeLifecycleState` — `Created → Verified → SettlementConstructed → Submitted → Confirmed → Consumed`, `Failed → Created → Verified` (085efe0), `Expired`, `Consumed` terminal, expiry contract frozen: `verify`, `acquire_construction`, `submit`, `retry` expiry-gated (`now > expiry` → Expired, `now == expiry` valid), `confirm`/`consume` allowed after expiry if submission valid
- **Location:** `matcher/src/replay.rs`, `crates/protocol/src/replay.rs` (canonical in-memory model), `crates/protocol/src/lifecycle.rs`
- **Status:** Read-only for settlement construction check, but you must call `submit`, `confirm`, `consume` after settlement. Do not call `ReplayStore::create` directly.
- **Private vs Public:**
  - **Public:** `TradeCommitment`, `TradeIntent`, state strings, txid hex — public, persisted in JSON file
  - **Private:** None — replay is public coordination, but file contains no secrets

#### Verifiers (Task D + A4)
- **Types:**
  - `ProvenanceVerifierBackend` / `EligibilityVerifierBackend` — real Groth16 via `ark-groth16 0.5.0` + `ark-bn254`, `from_fixture()` loads `tests/fixtures/groth16/provenance-vkey.json` hash `4831d3eef9575ef7daf318eb8767e1a39ef1e26da20339ddda137b1e246f1350`, `eligibility-vkey.json` hash `879d427a16f334edc163e78614c94dfe00c3ae3cb657c3ef4d7d82c39e4f5e75`, `vk_hash()` prevents substitution (threat model)
  - `ProvenanceVerifier` / `EligibilityVerifier` traits — `fn verify(root, commitment, proof) -> VerificationResult`, public inputs order frozen `[root, commitment]`
  - `MatcherProofGate` — holds `CheckedTrade` + both verifiers, `verify_both(issuer_root, credential_root, prov_proof, elig_proof) -> Result<(), VerificationResult>` — enforces same `TradeCommitmentV1` for both, prevents splicing
  - `VerificationResult` — `Valid`, `Invalid { reason: VerificationProblem }`, `#[must_use]`
  - `Groth16VerificationError` — `VKeyMalformed`, `ProofMalformed`, `FieldParse`, `G1Parse`, `G2Parse`, `VkHashMismatch`, `PublicInputsLength`, `ArkVerification`
  - `make_test_proof_json(root, commitment) -> Vec<u8>` — `#[cfg(test)]` only, mock `{"public_inputs":[root, commitment]}` that passes via mock path, never in prod
- **Location:** `matcher/src/verifiers.rs`, `crates/protocol/src/proof.rs`
- **Status:** Read-only; `VerifiedTrade` already proves both proofs verified against same commitment from `CheckedTrade`. Your settlement must not re-verify proofs.
- **Private vs Public:**
  - **Public:** Roots, commitment, VK JSON, proof JSON, public inputs `[root, commitment]` — all public
  - **Private:** None — proofs are public, but credential private inputs (investor class 8b, jurisdiction 16b, expiry 64b, nonce 64b, subject secret) remain private inside proof, never revealed. Investor class/jurisdiction stay private while permitted tuple is proved.

### From Phase 1B (Frozen Circuits) — FROZEN

#### CredentialLeafV2
- **What it is:** Poseidon hash that binds authority-approved receiver into credential leaf: `credential(receiver A) + trade(receiver A) → valid`, `credential(A) + trade(B) → invalid`. Prevents credential lending at circuit level.
- **Location:** `crates/credentials/src/credential.rs` (`Credential::leaf()`), `circuits/shared/eligibility-v1.js` + `circuits/eligibility/rwa_investor_eligibility_v1.circom` (13502 constraints)
- **Status:** FROZEN — Phase 1B already proved receiver A vs receiver B distinction. Your V4 task will design how you verify live control of that approved receiver (Ed25519 registry MVP vs real Orchard ivk).
- **Private vs Public:**
  - **Public:** `approved_receiver` commitment? Actually leaf contains `receiver_commitment`? No, leaf contains approved receiver raw? Let's check: leaf is `H(subject_secret, investor_class, jurisdiction, expiry, nonce, receiver_commitment, policy_root)`? The exact leaf is deterministic and includes `receiver_commitment` canonical. `receiver_commitment` is public? No, credential leaf preimage is private, only `activeCredentialRoot` (Merkle root) and `tradeCommitment` are public. Raw receiver is private inside leaf, but its commitment is bound.
  - **Private:** Subject secret, investor class 8b, jurisdiction 16b, expiry 64b, nonce 64b, raw receiver 43B, policy — all private inputs to eligibility circuit. Only root + commitment public.

#### Groth16 Proof Public Inputs
- **Provenance:** `[authorizedIssuanceRoot, TradeCommitmentV1]` — 2 public inputs, 21 private (asset base, path), constraints 8837, circuit `rwa_trade_provenance_v1.circom` (Merkle depth 3)
- **Eligibility:** `[activeCredentialRoot, TradeCommitmentV1]` — same commitment invariant, 2 public inputs, private: credential leaf, policy, range checks, single receiverHasher reused twice
- **Location:** `tests/fixtures/groth16/*-vkey.json`, `*-proof.json`, `*-public.json`, `circuits/provenance/rwa_trade_provenance_v1.circom`, `circuits/eligibility/rwa_investor_eligibility_v1.circom`, `crates/protocol/src/proof.rs` (public input structs)
- **Status:** FROZEN — both proofs reference exact same commitment per `MatcherProofGate`. Your settlement must preserve same-commitment invariant.
- **Private vs Public:**
  - **Public:** Roots, commitment — public
  - **Private:** All other inputs private, including investor class/jurisdiction which remain private while permitted tuple is proved (security-claims.md).

## RFQ BOUNDARY → FROZEN MAPPING — What Vikram's RFQ Must Do

Your RFQ (Request For Quote) is private order intent that will become canonical `TradeIntent` + `TradeCommitmentV1`.

- **RFQ Private Fields (stay private in RFQ, not in TradeIntent):**
  - Trader's Orchard spending keys, nullifiers, exact notes being spent
  - Raw Orchard receiver of counterparty? Actually `TradeIntent` contains `recipient_commitment` which is hash, not raw receiver — raw receiver is private until control challenge
  - Investor credential subject secret, investor class, jurisdiction — private, only proved via eligibility proof
  - Policy preimage — private, only `policy_root` public

- **RFQ Public Conversion (V3 task):**
  - RFQ must be converted to canonical `TradeIntent` with exact 32B AssetBase encoding (Pallas compressed, 128/128 LE limbs), 43B receiver → commitment via `receiver_commitment()`, amounts, fee, nonce, expiry
  - Then `TradeCommitmentV1 = H(TRADE_V1, ...)` via `zwa_commitments::trade::compute_trade_commitment` — you must NOT recompute Poseidon staging, only call frozen function via `CheckedTrade::new(intent, commitment)`
  - Then build `GateInput` with envelopes (signed roots), control challenge/response, proofs (real Groth16 from fixtures or generated via circom/snarkjs), `now`

- **What you receive from Akshay (never construct):**
  - `MatcherApproval` opaque — proves all gates passed, contains `commitment()`, `intent()`, `checked_trade()`
  - You pass `&MatcherApproval` to `SettlementAdapter::construct()` — type-level enforcement that settlement only after compliance

## SUMMARY TABLE

| Frozen Type | Location | Status | Private vs Public | Your Action |
|-------------|----------|--------|-------------------|-------------|
| TradeIntent | crates/protocol/src/intent.rs, crates/commitments/src/trade.rs | FROZEN, never recompute | Public: all fields (asset 32B, amounts, recipient_commitment hash, policy_root, fee, nonce, expiry). Private: raw receiver 43B, subject secret | Reference via CheckedTrade, never re-encode |
| TradeCommitmentV1 | crates/commitments/src/trade.rs | FROZEN, Poseidon H(TRADE_V1,...) | Public: commitment decimal, bound to all intent fields. Private: none, but preimage intent private until gate | Reference, never compute staging |
| AssetBaseBytes | crates/commitments/src/asset_base.rs | FROZEN, 32B Pallas compressed, 128/128 LE | Public: hex encoding, limbs. Private: none | Use from_hex, never ticker |
| OrchardReceiverBytes | crates/protocol/src/bytes.rs, crates/commitments/src/receiver.rs | FROZEN, 43B diversifier+pk_d, 128/128/88 | Public: commitment hash. Private: raw 43B until control challenge | Use receiver_commitment(), control challenge reveals raw to matcher only |
| RecipientCommitment | crates/protocol/src/values.rs, crates/commitments/src/receiver.rs | FROZEN, H(RECEIVR1, limbs) | Public: decimal string. Private: raw receiver | Reference |
| IssuerRootEnvelope, CredentialRootEnvelope | crates/credentials/src/envelope.rs, matcher/src/roots.rs | FROZEN canonical payload ZWA1ROOT, Ed25519 64B | Public: root, key IDs, version, window, sig. Private: signing keys [1;32],[2;32] | Pass through, never re-encode |
| AuthenticatedIssuerRoot, AuthenticatedCredentialRoot | matcher/src/roots.rs | Opaque, only via authenticate(), cannot be fabricated | Public: root(), version(), expires_at(). Private: envelope private | Receive via VerifiedTrade, never construct |
| RecipientControlChallenge/Response | matcher/src/control.rs | Frozen domain ZWA-RECIPIENT-CTRL-V1, canonical bytes domain||nonce||issued_at||expiry||receiver||commitment | Public: domain, nonce, timestamps, receiver 43B, commitment, sig 64B. Private: control signing keys [3;32] | Receive via VerifiedTrade, V4 real ivk proof research |
| ProvenanceVerifierBackend, EligibilityVerifierBackend | matcher/src/verifiers.rs | Real Groth16 ark-groth16, VK hash 4831d3..., 879d42..., public inputs [root, commitment] frozen | Public: roots, commitment, VK JSON, proof JSON. Private: investor class 8b, jurisdiction 16b, expiry 64b, nonce 64b, subject secret, asset path | Receive via VerifiedTrade, never re-verify |
| PersistentReplayStore | matcher/src/replay.rs, crates/protocol/src/replay.rs | Canonical lifecycle CREATED→...→CONSUMED, expiry frozen | Public: commitment, intent, state, txid. Private: none | Call submit/confirm/consume after settlement |
| MatcherApproval / VerifiedTrade | matcher/src/gate.rs | Opaque !Clone !Serialize _private: (), only via MatcherGate::evaluate() | Public: commitment(), intent() getters. Private: internal auth roots, verified_control | Receive, never construct, pass to SettlementAdapter::construct() |
| SettlementDraft | crates/settlement/src/lib.rs (V1) | Opaque !Clone !Serialize _private: (), only via SettlementAdapter::construct(&MatcherApproval) | Public: commitment, intent, canonical bytes ZWA-SETTLE-V1, txid. Private: seller/buyer signing keys | Construct only from approval, sign seller+buyer independently |
| SellerAuthorization, BuyerAuthorization | crates/settlement/src/lib.rs | Distinct opaque types, Ed25519 sign over draft canonical | Public: signature 64B, verifying key. Private: signing keys | Distinct, same-key rejected, non-custodial |

## COMPLETION CHECK

- [x] Mapped all frozen Phase 1 types with location and status
- [x] Mapped Akshay's matcher API (MatcherApproval, AuthenticatedRoot, Control, Replay, Verifiers) with location and read-only status
- [x] Mapped Phase 1B CredentialLeafV2 and Groth16 public inputs with frozen status
- [x] Identified private vs public for each type (subject secret, investor class/jurisdiction, raw receiver, spending keys private; commitment, roots, asset 32B, amounts, recipient_commitment hash, policy_root, nonce, expiry, signatures public)
- [x] Defined RFQ boundary: private fields stay private, public conversion via frozen `compute_trade_commitment` and `CheckedTrade::new`, never recompute
- [x] Enforced that Vikram receives `MatcherApproval` only, never constructs it, and passes `&MatcherApproval` to settlement
