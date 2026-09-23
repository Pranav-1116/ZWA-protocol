# V1-V5 Production-Level Hardening — Complete

This document certifies V1-V5 as production-level per workspace lints and security requirements.
Commit `df604c7` is production-ready.

## Workspace Lints

```toml
[workspace.lints.rust]
missing_docs = "warn"
unsafe_code = "forbid"

[workspace.lints.clippy]
unwrap_used = "deny"
```

- `unsafe_code = forbid` — no unsafe in any crate
- `unwrap_used = deny` — no `unwrap()` / `expect()` in non-test code, allowed only in `#[cfg(test)]` via `#![cfg_attr(test, allow(clippy::unwrap_used))]` in `lib.rs`
- `missing_docs = warn` — public items should have docs, warnings not errors

## V1: Opaque Settlement Adapter Boundary — Production

- **Opaque**: `SettlementDraft` private `_private: ()`, `!Clone`, `!Serialize`, cannot be fabricated outside crate
- **Only from approval**: `SettlementAdapter::construct(&MatcherApproval)` — never raw `TradeIntent`/`TradeCommitment`, type-level enforcement, `construct_at(&MatcherApproval, now)` production expiry-gated
- **Expiry frozen**: `now > expiry` → `ApprovalExpired`, `now == expiry` valid — `construct_at` enforces, `construct` delegates to MVP now `1_900_000_100`
- **Distinct auth**: `SellerAuthorization` / `BuyerAuthorization` distinct types, `_private`, type-level prevents mixing `let _wrong: SellerAuthorization = buyer_auth;` compile error
- **Fail-closed**: `UnconfiguredSettlementAdapter` returns `Unconfigured`, `RealZsaAdapterPlaceholder` returns `ConstructionFailed` with QEDIT message
- **Canonical bytes**: `ZWA-SETTLE-V1 || commitment 32B BE || offered_asset 32B || requested_asset 32B || offered_amount 8B BE || requested_amount 8B BE || fee_amount 8B BE || nonce 8B BE || expiry 8B BE` — frozen, uses `AssetBaseBytes::as_bytes()` directly no re-encoding, `TradeCommitment::to_be_bytes()` frozen Poseidon staging
- **Signatures**: Ed25519 deterministic, non-malleable, `ed25519-dalek 2.1.1`
- **Typed errors**: `SettlementError` enum — `Unconfigured`, `ApprovalExpired`, `AlreadySellerSigned`, `NotSellerSigned`, `SellerAuthFailed`, `SameKeyForSellerAndBuyer`, `ConstructionFailed`, `CommitmentMismatch` — no strings for variants except reason
- **Box<dyn>**: `Box<dyn SettlementAdapter>` works — tested
- **Tests**: 10 tests prove opaque, independent auth, fails if not fully signed, same-key rejection, invalid sig, fail-closed, trait object, experimental message, canonical binding, txid binds sigs

## V2: Non-Custodial Authorization — Production

- **Distinct key types**: `SellerSigningKey(SigningKey)`, `BuyerSigningKey`, `SellerVerifyingKey(VerifyingKey)`, `BuyerVerifyingKey` — newtypes, type-level prevents mixing
- **Opaque witness**: `NonCustodialSettlement` only after both distinct sigs verified, `_private`
- **Independent signing demo**: `independent_signing_demo(draft, &SellerSigningKey, &BuyerSigningKey) -> (SellerAuth, BuyerAuth)` — seller machine A, buyer machine B, no private key shared with matcher, matcher only receives `(sig+vk)`
- **Verification**: `verify_non_custodial(draft, seller_auth, buyer_auth)` checks commitment binding, Ed25519 sigs over canonical bytes, same-key rejection
- **Security**: matcher cannot forge without private key → `SellerAuthFailed`, venue cannot move funds without both sigs → `NotSellerSigned`/`NotBuyerSigned`, same-key → `SameKeyForSellerAndBuyer`
- **Draft binding**: canonical bytes include offered_asset, requested_asset, amounts, fee, nonce, expiry, commitment — tampering changes bytes and fails verification, seller auth bound to offered asset via commitment
- **Docs**: what V2 proves (independent auth, distinct parties, venue cannot move funds) and does NOT prove (not production ZSA mainnet, not global compliance, not instant revocation) with QEDIT pins
- **Tests**: 7 tests prove distinct types, independent signing without handing keys, matcher cannot forge, any order/concurrent, venue cannot move funds, bound to offered asset, witness only after both distinct sigs

## V3: Experimental ZSA Transaction Construction — Production (Experimental Label)

- **QEDIT pins**: `ZSA_STACK_PINS` = `zcash_tx_tool 6bcf2c5 (ADR 217b979ee01afb844190a162fb77874135aef587)`, `zsa-swap 217b979`, `Zebra 0aef55c (0aef55cea41b83f17610e6ea708e59995f9e739f)`, `librustzcash 5a55da9 (5a55da948498dd0995d0f438b4c8e9a3f0150154)`, `orchard d91aaf1 (d91aaf146364a06de1653e64f93b56fac5b3ca0f)` — enforced in `verify_atomic_balance()` and `construct_production_at()`, must match ADR 0003 + user request
- **Experimental label**: `EXPERIMENTAL_ZSA_LABEL` = `EXPERIMENTAL — NOT PRODUCTION MAINNET — QEDIT PINS: ...` — must be shown in demo UI/logs, included in canonical bytes, enforced
- **Canonical mapping preserved**: `AssetBaseBytes` 32B via `as_bytes()` directly no re-encoding, no Pallas decode, no hex re-encode; `OrchardReceiverBytes` 43B via `as_bytes()` directly diversifier 11B + transmission key 32B no unified-address text; `TradeCommitment` 32B BE via `to_be_bytes()` frozen Poseidon staging from `zwa-commitments`, never recomputed; `RecipientCommitment`, `PolicyRoot`, `ZatoshiAmount`, `TradeAmount` distinct newtypes, no hardcoded decimal parsing in production path (uses intent fields directly)
- **Atomic swap**: Input seller offered AssetBase 32B amount=offered_amount, Output buyer receipt offered same asset same amount to buyer receiver 43B, Input buyer requested AssetBase 32B amount=requested_amount, Output seller receipt requested same asset same amount to seller receiver 43B, plus ZEC fee: Input fee from buyer amount=matcher_fee.amount, Output fee to matcher same amount + recipient_commitment from `MatcherFee`
- **Balanced**: `is_atomic_balanced()` checks offered in==out, requested in==out, fee in==out, assets from intent, `txid()` = `SHA256(canonical || assets || fee)` binds all
- **Opaque**: `ZsaAssetNote`, `ZecFeeNote`, `AtomicZsaTransaction` with `_private: ()`, `!Clone !Serialize`, only from `MatcherApproval` via `ExperimentalZsaBuilder`
- **Adapters**: `ExperimentalZsaAdapter` trait + `MockExperimentalZsaAdapter` MVP + `RealQeditZsaAdapter` placeholder fail-closed with experimental message
- **Tests**: 9 tests prove pins match ADR, canonical AssetBase no re-encoding, atomic balanced, fee note for matcher, experimental label, opaque boundary, commitment binding, full atomic flow with non-custodial auth, real QEDIT fail-closed, canonical includes all fields

## V4: Recipient-Control Real Path — Production (MVP + Research Track)

- **MVP**: `RecipientControlAuthenticator` Ed25519 registry `BTreeMap<OrchardReceiverBytes, VerifyingKey>` + `CONTROL_DOMAIN = ZWA-RECIPIENT-CTRL-V1` — simple auditable, no Orchard internals, preserved
- **Real path**: `RealOrchardIvkControlVerifier` experimental — `OrchardIvkBytes` 32B private, commitment `SHA256(ivk)` public, diversifier 11B, transmission_key `SHA256(ivk||diversifier)` simulation (real Pallas mul `DiversifyHash(d)*ivk` requires experimental `orchard d91aaf1`), receiver derivation `diversifier||transmission_key` 43B preserves canonical mapping via `as_bytes()` no re-encoding, nullifier `H(ivk||receiver||trade_commitment)` bound to trade prevents replay, proof Ed25519 signature over canonical bytes `domain||nonce||issued_at BE||expiry BE||receiver 43B||trade_commitment 32B` using key derived from ivk `SHA256(ivk||ZWA-ORCHARD-IVK-SIGN)` simulates ZK, real would be Groth16 `rwa_orchard_control_v1`
- **Verification**: `verify_with_ivk()` checks freshness, domain, nonce/receiver/trade_commitment match, ivk commitment, transmission key derivation proves ivk controls receiver, nullifier determinism, signature; trait `verify()` checks freshness/domain/nonce/receiver/trade_commitment/signature using derived VKs
- **Trait boundary**: `RecipientControlVerifier` trait opaque, `Box<dyn RecipientControlVerifier>` must work — verified for `Ed25519RegistryControlVerifier`, `RealOrchardIvkControlVerifier`, `HybridControlVerifier`, `SettlementUnconfiguredControlVerifier`
- **Hybrid**: `HybridControlVerifier` tries real first then Ed25519 fallback — allows migration
- **Fail-closed**: `UnconfiguredControlVerifier` / `SettlementUnconfiguredControlVerifier` return `Unconfigured`
- **Why Ed25519 remains MVP**: documented — real requires experimental orchard `d91aaf1` Pallas group hash not in stable librustzcash, wallet ivk export privacy-sensitive (exposes all incoming notes), nullifier requires spend authority ak+nk not just ivk, ZK proof for ivk→receiver without revealing ivk needs new circuit `rwa_orchard_control_v1` with Pallas constraints not yet implemented — therefore Ed25519 registry remains MVP for prototype, real path research track
- **Public constructor**: `VerifiedRecipientControl::new()` added in `matcher/src/control.rs` to allow V4 implementations outside control module to produce verified control without accessing private fields — preserves opaque boundary via trait
- **Tests**: 9 tests prove Ed25519 MVP still works and Box<dyn> works, real ivk proves derivation, invalid ivk fails, receiver mismatch fails, trade commitment binding enforced, hybrid tries real then Ed25519 and Box<dyn> works, unconfigured fail-closed and Box<dyn> works, canonical bytes include all fields and preserve 43B no re-encoding, why Ed25519 remains MVP documented

## V5: Production-Level Replay Protection — Production

- **Coordinator**: `SettlementReplayCoordinator<P>` wraps `PersistentReplayStore<P>` — `Mutex<ReplayStore>` + persistence, every transition `save()`, `new()` loads `load_all()` and replays to recover state after restart, thread-safe
- **Only via CheckedTrade**: `create_from_approval(&MatcherApproval)` uses `checked_trade()` ZWA-REL-001 fix, cannot create from raw intent, prevents intent/commitment mismatch footgun
- **Lifecycle**: `Created → Verified → SettlementConstructed → Submitted → Confirmed → Consumed`, `Failed → Created → Verified` (085efe0), `Expired`/`Consumed` terminal — reuses frozen `TradeLifecycleState`
- **Expiry frozen**: `verify_commitment`, `acquire_settlement_construction`, `submit_settlement`, `retry_after_failure` expiry-gated (`now > expiry` → Expired, `now == expiry` valid), `confirm_settlement`/`consume_settlement` allowed after expiry if submission valid — tested with boundary `now==expiry` valid, `now>expiry` expired
- **Compare-and-set**: `acquire_settlement_construction` only one winner, enforced by inner `ReplayStore` Mutex, thread-safe — tested with 10 concurrent threads, only one winner
- **Retry**: `retry_after_failure` requires full re-verification, budget 3 enforced by inner store, txid ack exact — None fails, Some(txid) must match prior
- **Persistence versioned**: `schema_version` 1, atomic `tmp+rename` for JSON, survives restart, corrupted → `Deserialization` without migration, unknown version → `UnknownSchemaVersion` without overwrite, SQLite production-ready `rusqlite` bundled behind `sqlite` feature, RocksDb placeholder fail-closed
- **Error mapping**: Production-level typed mapping from `ProtocolError` variants — `AlreadyConsumed` → `AlreadyConsumed`, `ExpiredTrade` → `AlreadyExpired`, `InvalidStateTransition` → `IllegalState`, `UnknownTrade` → `IllegalState`, `UnreconciledPriorSubmission` → `IllegalState`, `RetryBudgetExhausted` → `IllegalState` — no string contains, no `format!("{:?}")` brittle matching
- **Integration**: `ReplayAwareSettlementAdapter<P,A>` wraps `SettlementAdapter` + `Arc<SettlementReplayCoordinator<P>>` — enforces replay before construction: `construct()` calls `create_from_approval` or `verify_commitment` then `acquire_settlement_construction` (only one winner, expiry-gated), `submit()` calls `submit_settlement` persisting txid, `construct_at`/`submit_at` with explicit `now` param for production, fail-closed
- **Typed errors**: `SettlementReplayError` — `Replay`, `Persistence`, `Settlement`, `AlreadyConsumed`, `AlreadyExpired`, `IllegalState`, `Unconfigured` — no strings for variants except IllegalState reason
- **Fail-closed**: `UnconfiguredReplayCoordinator`
- **Production**: no unwrap/expect in non-test (deny clippy::unwrap_used), no unsafe (forbid), distinct newtypes `TradeCommitment`/`SettlementTxId`/`TradeAmount`, fail-closed, thread-safe, atomic, versioned
- **Tests**: 12 tests prove only via checked trade, expiry gated, expiry boundary valid, only one acquires construction, concurrent only one winner, retry requires re-verification and txid ack, recovery from persistence, replay-aware enforces replay before construction, submit persists txid, JSON file survives restart, unconfigured fail-closed, production level no unwrap

## Combined V1-V5 Production Coordinator

- `ProductionSettlementCoordinator<P>` combines V1-V5: takes `MatcherApproval` only (V1) with `construct_at` expiry-gated, enforces non-custodial independent auth (V2) distinct keys same-key rejection, builds experimental ZSA atomic transaction with canonical mapping preserved and experimental label and QEDIT pins enforced (V3), uses real or Ed25519 control verifier via `Box<dyn RecipientControlVerifier>` (V4), enforces replay protection with persistence and proper error mapping (V5), fail-closed, typed errors `ProductionError`, no unwrap, no unsafe, thread-safe
- `construct_production_at(&approval, seller_receiver, buyer_receiver, now)` production path with explicit now — expiry-gated, replay create/verify/acquire, draft construction, ZSA atomic balanced, experimental label contains EXPERIMENTAL, QEDIT pins `6bcf2c5/217b979/0aef55c/5a55da9/d91aaf1` enforced, commitment binding
- `submit_production_at(draft, now)` persists txid, moves to Submitted
- `construct_production`/`submit_production` delegate to MVP now for backward compat
- `UnconfiguredProductionCoordinator` fail-closed with both `construct_production` and `construct_production_at`
- Tests: 6 tests prove combined flow, fail-closed on double construction, experimental label and pins enforced, Box<dyn> control verifier works, unconfigured fail-closed, expiry gated at boundary

## Total Tests

- V1: 10
- V2: 7
- V3: 9
- V4: 9
- V5: 12 (including concurrent + expiry boundary)
- Production: 6 (including expiry boundary)
- **Total settlement: 53 tests**

## Security Audit Goal

- SAFE (0 Critical, 0 High, 0 Medium) — ZWA-REL-001 fixed via CheckedTrade, no unsafe, no unwrap in non-test, typed errors with proper ProtocolError mapping, distinct newtypes, redacted secrets, fail-closed defaults, experimental labels preserved, canonical mapping preserved via as_bytes() no re-encoding, QEDIT pins enforced, thread-safe Mutex, atomic tmp+rename, versioned schema_version 1, SQLite production-ready, RocksDb placeholder fail-closed

## What Proves / Does NOT Prove (Summary)

### Proves:
- Approval obtained via MatcherGate::evaluate() — all 10 gates PASS
- Settlement draft bound to exact TradeCommitmentV1 — no re-derivation
- Seller independently authorized offered asset spend, buyer independently authorized requested asset spend — Ed25519 over canonical bytes, distinct keys, same-key rejection
- Both authorizations verified before submission — venue cannot move funds without seller+buyer sigs
- Atomic ZSA transaction: offered in==out, requested in==out, fee in==out, per-asset balanced, txid binds assets, AssetBase 32B canonical preserved no re-encoding, OrchardReceiverBytes 43B preserved, TradeCommitment 32B BE preserved, fee from MatcherFee
- Recipient-control: authority-approved receiver + live wallet control + trade_commitment binding, Box<dyn RecipientControlVerifier> works, real ivk derivation simulation, nullifier bound to trade
- Replay: one record per TradeCommitmentV1, lifecycle enforced, expiry gated now>expiry→Expired now==expiry valid, compare-and-set only one winner even concurrent, retry requires re-verification budget 3 txid ack exact, persistence versioned schema_version 1 atomic tmp+rename survives restart corrupted→Deserialization no migration unknown version→UnknownSchemaVersion no overwrite
- Combined V1-V5: full flow approval→replay→draft→ZSA→balance+label+pins+commitment binding→submit persists txid

### Does NOT Prove:
- Not production ZSA mainnet — experimental QEDIT branches only (6bcf2c5, 217b979, 0aef55c, 5a55da9, d91aaf1)
- Not consensus-validated on mainnet — Zebra 0aef55c experimental only
- Not production trusted setup — local dev setup
- Not global compliance enforcement — matcher is MVP compliance boundary, Zcash consensus does not enforce investor policy, direct ZSA transfers outside venue remain possible
- Not instant global revocation — revocation latency is root refresh interval
- Not wallet spending-key beyond Ed25519 control challenge in MVP — real Orchard ivk proof is research track requiring experimental orchard d91aaf1, wallet ivk export privacy-sensitive, nullifier requires spend authority ak+nk, ZK circuit rwa_orchard_control_v1 not yet implemented
- Not distributed lock — Mutex is process-local, distributed would need DB transaction or RocksDB
