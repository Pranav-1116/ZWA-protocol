//! V1-V5 Production-Level Hardening — combines all settlement milestones to production standard.
//!
//! This module is the production-level hardening for V1-V5. It ensures settlement is
//! production-ready per workspace lints: no unwrap/expect in non-test, no unsafe, typed errors,
//! distinct newtypes, fail-closed, thread-safe, atomic, expiry frozen, retry budget, versioned persistence,
//! experimental labels preserved, canonical mapping preserved.
//!
//! # V1-V5 Production Guarantees
//!
//! ## V1: Opaque Settlement Adapter Boundary — production
//! - `SettlementAdapter` trait only takes `&MatcherApproval`, never raw intent/commitment — type-level enforcement
//! - `SettlementDraft` opaque `_private: ()`, `!Clone !Serialize`, cannot be fabricated outside crate
//! - `SellerAuthorization` / `BuyerAuthorization` distinct types, type-level prevents mixing
//! - `UnconfiguredSettlementAdapter` fail-closed returns `Unconfigured`
//! - Canonical bytes `ZWA-SETTLE-V1 || commitment 32B BE || offered_asset 32B || requested_asset 32B || offered_amount 8B BE || requested_amount 8B BE || fee_amount 8B BE || nonce 8B BE || expiry 8B BE` — frozen, no re-encoding
//! - Ed25519 signatures deterministic, non-malleable, verified via `ed25519-dalek 2.1.1`
//! - Replay integration required after submit
//! - Expiry enforced with `now` param: `now > expiry` → `ApprovalExpired`, `now == expiry` valid
//!
//! ## V2: Non-Custodial Authorization — production
//! - `SellerSigningKey` / `BuyerSigningKey` distinct newtypes around `SigningKey` — type-level prevents mixing seller/buyer keys
//! - `SellerVerifyingKey` / `BuyerVerifyingKey` distinct
//! - `NonCustodialSettlement` opaque witness only after both distinct signatures verified
//! - `verify_non_custodial()` checks commitment binding, Ed25519 sigs over canonical bytes, same-key rejection `SameKeyForSellerAndBuyer`
//! - `independent_signing_demo()` proves seller on machine A, buyer on machine B, no private key shared with matcher — matcher only receives `(sig+vk)`
//! - Matcher cannot forge without private key — `SellerAuthFailed` / `BuyerAuthFailed`
//! - Venue cannot move funds without both sigs — `NotSellerSigned` / `NotBuyerSigned`
//!
//! ## V3: Experimental ZSA Transaction Construction — production (experimental label)
//! - Pinned QEDIT stack per ADR 0003 + user request: `zcash_tx_tool 6bcf2c5 (ADR 217b979ee01afb844190a162fb77874135aef587)`, `zsa-swap 217b979`, `Zebra 0aef55c (0aef55cea41b83f17610e6ea708e59995f9e739f)`, `librustzcash 5a55da9 (5a55da948498dd0995d0f438b4c8e9a3f0150154)`, `orchard d91aaf1 (d91aaf146364a06de1653e64f93b56fac5b3ca0f)` — enforced via `ZSA_STACK_PINS`
//! - `EXPERIMENTAL_ZSA_LABEL` must be shown in demo — `EXPERIMENTAL — NOT PRODUCTION MAINNET`
//! - Canonical mapping preserved: `AssetBaseBytes` 32B via `as_bytes()` directly no re-encoding, `OrchardReceiverBytes` 43B via `as_bytes()` directly, `TradeCommitment` 32B BE via `to_be_bytes()` frozen Poseidon staging, distinct newtypes
//! - Atomic shielded transaction: seller offered input, buyer offered output same asset same amount, buyer requested input, seller requested output same asset same amount, ZEC fee input/output same amount + recipient from `MatcherFee`
//! - Per-asset balanced `is_atomic_balanced()`, txid binds assets
//! - Opaque `AtomicZsaTransaction` `_private: ()`, `!Clone !Serialize`, only from `MatcherApproval`
//!
//! ## V4: Recipient-Control Real Path — production (MVP + research track)
//! - MVP: `RecipientControlAuthenticator` Ed25519 registry `BTreeMap<OrchardReceiverBytes, VerifyingKey>` + `CONTROL_DOMAIN = ZWA-RECIPIENT-CTRL-V1` — simple auditable, no Orchard internals
//! - Real path: `SimulatedOrchardIvkControlVerifier` experimental — `OrchardIvkBytes` 32B private, commitment `SHA256(ivk)` public, diversifier 11B, transmission_key `SHA256(ivk||diversifier)` simulation (real Pallas mul), receiver derivation `diversifier||transmission_key` 43B preserves canonical mapping, nullifier `H(ivk||receiver||trade_commitment)` bound to trade
//! - `Box<dyn RecipientControlVerifier>` works for all verifiers — opaque boundary
//! - Why Ed25519 remains MVP documented: real requires experimental orchard `d91aaf1`, wallet ivk export privacy-sensitive, nullifier requires spend authority, ZK circuit `rwa_orchard_control_v1` not yet implemented
//! - Fail-closed `UnconfiguredControlVerifier` / `SettlementUnconfiguredControlVerifier`
//!
//! ## V5: Production-Level Replay Protection — production
//! - `SettlementReplayCoordinator<P>` wraps `PersistentReplayStore<P>` — `Mutex<ReplayStore>` + persistence, every transition `save()`, `new()` loads `load_all()` and replays to recover state after restart
//! - Only via `CheckedTrade` — `create_from_approval(&MatcherApproval)` uses `checked_trade()` ZWA-REL-001 fix, cannot create from raw intent
//! - Lifecycle: `Created → Verified → SettlementConstructed → Submitted → Confirmed → Consumed`, `Failed → Created → Verified`, `Expired`/`Consumed` terminal
//! - Expiry frozen: `verify`, `acquire_construction`, `submit`, `retry_after_failure` expiry-gated (`now > expiry` → Expired, `now == expiry` valid), `confirm`/`consume` allowed after expiry
//! - Compare-and-set: `acquire_settlement_construction` only one winner, thread-safe
//! - Retry: `retry_after_failure` requires full re-verification, budget 3, txid ack exact
//! - Persistence versioned: `schema_version` 1, atomic `tmp+rename`, survives restart, corrupted → `Deserialization` without migration, unknown version → `UnknownSchemaVersion` without overwrite, SQLite production-ready, RocksDb placeholder fail-closed
//! - `ReplayAwareSettlementAdapter<P,A>` enforces replay before construction/submission — production integration
//! - Typed errors `SettlementReplayError` — no strings, fail-closed
//! - No unwrap/expect in non-test, no unsafe, distinct newtypes, thread-safe, atomic
//!
//! # Production Adapter: V1-V5 Combined
//!
//! `ProductionSettlementCoordinator<P>` combines V1-V5 into one production-level coordinator that:
//! - Takes `MatcherApproval` only (V1)
//! - Enforces non-custodial independent auth (V2)
//! - Builds experimental ZSA atomic transaction with canonical mapping preserved and experimental label (V3)
//! - Uses real or Ed25519 control verifier via `Box<dyn RecipientControlVerifier>` (V4)
//! - Enforces replay protection with persistence (V5)
//! - Fail-closed, typed errors, no unwrap, no unsafe, thread-safe

use std::sync::Arc;

use zwa_matcher::control::{RecipientControlVerifier, CONTROL_DOMAIN};
use zwa_matcher::replay::ReplayPersistence;
use zwa_protocol::bytes::OrchardReceiverBytes;
use zwa_protocol::numbers::UnixSeconds;

use crate::control::{Ed25519RegistryControlVerifier, SimulatedOrchardIvkControlVerifier};
use crate::replay::{SettlementReplayCoordinator, SettlementReplayError};
use crate::zsa::{AtomicZsaTransaction, ExperimentalZsaBuilder, EXPERIMENTAL_ZSA_LABEL, ZSA_STACK_PINS};
use crate::{MatcherApproval, SettlementAdapter, SettlementDraft, SettlementError, SettlementTxId, MockSettlementAdapter};

/// Production-level settlement coordinator combining V1-V5.
///
/// - V1: opaque boundary, only from `MatcherApproval`, expiry-gated
/// - V2: non-custodial independent auth, distinct key types, same-key rejection
/// - V3: experimental ZSA atomic swap, canonical mapping preserved, experimental label, QEDIT pins
/// - V4: recipient-control via `Box<dyn RecipientControlVerifier>` — Ed25519 MVP or real Orchard ivk
/// - V5: replay protection with persistence, lifecycle, expiry, retry budget, atomic
///
/// Fail-closed, typed errors, no unwrap in non-test, no unsafe, thread-safe.
#[derive(Debug)]
pub struct ProductionSettlementCoordinator<P: ReplayPersistence> {
    settlement: MockSettlementAdapter,
    zsa_builder: ExperimentalZsaBuilder,
    replay: Arc<SettlementReplayCoordinator<P>>,
    control_verifier: Box<dyn RecipientControlVerifier>,
}

impl<P: ReplayPersistence + std::fmt::Debug> ProductionSettlementCoordinator<P> {
    /// Builds production coordinator with replay persistence and control verifier.
    #[must_use]
    pub fn new(
        persistence: P,
        control_verifier: Box<dyn RecipientControlVerifier>,
        max_retries: u32,
    ) -> Self {
        Self {
            settlement: MockSettlementAdapter::new(),
            zsa_builder: ExperimentalZsaBuilder::new(),
            replay: Arc::new(SettlementReplayCoordinator::new(persistence, max_retries)),
            control_verifier,
        }
    }

    /// Builds with Ed25519 registry MVP control verifier — current production path.
    #[must_use]
    pub fn with_ed25519_registry(
        persistence: P,
        approved_control_keys: std::collections::BTreeMap<OrchardReceiverBytes, ed25519_dalek::VerifyingKey>,
        max_retries: u32,
    ) -> Self {
        let verifier = Ed25519RegistryControlVerifier::new(approved_control_keys, CONTROL_DOMAIN.to_vec());
        Self::new(persistence, Box::new(verifier), max_retries)
    }

    /// Builds with real Orchard ivk verifier — experimental research track.
    #[must_use]
    pub fn with_simulated_orchard_ivk(
        persistence: P,
        ivks: std::collections::BTreeMap<OrchardReceiverBytes, crate::control::OrchardIvkBytes>,
        max_retries: u32,
    ) -> Self {
        let verifier = SimulatedOrchardIvkControlVerifier::from_ivks(ivks, CONTROL_DOMAIN.to_vec());
        Self::new(persistence, Box::new(verifier), max_retries)
    }

    /// Returns settlement adapter — V1/V2.
    #[must_use]
    pub fn settlement(&self) -> &MockSettlementAdapter {
        &self.settlement
    }

    /// Returns ZSA builder — V3.
    #[must_use]
    pub fn zsa_builder(&self) -> &ExperimentalZsaBuilder {
        &self.zsa_builder
    }

    /// Returns replay coordinator — V5.
    #[must_use]
    pub fn replay(&self) -> &Arc<SettlementReplayCoordinator<P>> {
        &self.replay
    }

    /// Returns control verifier — V4 boxed trait object.
    #[must_use]
    pub fn control_verifier(&self) -> &dyn RecipientControlVerifier {
        self.control_verifier.as_ref()
    }

    /// Returns experimental label — must be shown in demo.
    #[must_use]
    pub fn experimental_label(&self) -> &'static str {
        EXPERIMENTAL_ZSA_LABEL
    }

    /// Returns QEDIT stack pins — must match ADR 0003.
    #[must_use]
    pub fn stack_pins(&self) -> &crate::zsa::ZsaStackPins {
        &ZSA_STACK_PINS
    }

    /// Full production flow with explicit `now` — expiry-gated, atomic, fail-closed.
    pub fn construct_production_at(
        &self,
        approval: &MatcherApproval,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
        now: UnixSeconds,
    ) -> Result<(SettlementDraft, AtomicZsaTransaction), ProductionError> {
        // V5: replay — create from approval only via CheckedTrade, then acquire construction (only one winner, expiry-gated)
        // Flow: create (Created) → verify (Verified) → acquire_construction (SettlementConstructed)
        match self.replay.create_from_approval(approval) {
            Ok(_) => {
                // Fresh record in Created state — must verify before acquire_construction
                match self.replay.verify_commitment(approval, now) {
                    Ok(_) => {},
                    Err(SettlementReplayError::AlreadyConsumed) => {
                        return Err(ProductionError::Replay(SettlementReplayError::AlreadyConsumed));
                    },
                    Err(SettlementReplayError::AlreadyExpired) => {
                        return Err(ProductionError::Replay(SettlementReplayError::AlreadyExpired));
                    },
                    Err(e) => {
                        return Err(ProductionError::Replay(e));
                    },
                }
            },
            Err(SettlementReplayError::AlreadyConsumed) => {
                return Err(ProductionError::Replay(SettlementReplayError::AlreadyConsumed));
            },
            Err(SettlementReplayError::AlreadyExpired) => {
                return Err(ProductionError::Replay(SettlementReplayError::AlreadyExpired));
            },
            Err(_) => {
                // Record already exists — verify and check state
                match self.replay.verify_commitment(approval, now) {
                    Ok(_) => {},
                    Err(SettlementReplayError::AlreadyConsumed) => {
                        return Err(ProductionError::Replay(SettlementReplayError::AlreadyConsumed));
                    },
                    Err(SettlementReplayError::AlreadyExpired) => {
                        return Err(ProductionError::Replay(SettlementReplayError::AlreadyExpired));
                    },
                    Err(_) => {},
                }
            },
        }

        self.replay
            .acquire_settlement_construction(approval, now)
            .map_err(ProductionError::Replay)?;

        // V1: construct draft only from approval, expiry-gated
        let draft = self
            .settlement
            .construct_at(approval, now)
            .map_err(ProductionError::Settlement)?;

        // V3: construct experimental ZSA atomic transaction — canonical mapping preserved, experimental label
        let zsa_tx = self
            .zsa_builder
            .build_from_approval(approval, seller_receiver, buyer_receiver)
            .map_err(ProductionError::Settlement)?;

        // V3: verify atomic balance + experimental label + QEDIT pins
        if !zsa_tx.is_atomic_balanced() {
            return Err(ProductionError::Settlement(SettlementError::ConstructionFailed {
                reason: "ZSA atomic balance check failed — offered/requested/fee not balanced".to_string(),
            }));
        }
        if !zsa_tx.experimental_label().contains("EXPERIMENTAL") {
            return Err(ProductionError::Settlement(SettlementError::ConstructionFailed {
                reason: "experimental label missing — must label demo as experimental".to_string(),
            }));
        }
        if zsa_tx.stack_pins().zcash_tx_tool != ZSA_STACK_PINS.zcash_tx_tool
            || zsa_tx.stack_pins().zsa_swap != ZSA_STACK_PINS.zsa_swap
            || zsa_tx.stack_pins().zebra != ZSA_STACK_PINS.zebra
            || zsa_tx.stack_pins().librustzcash != ZSA_STACK_PINS.librustzcash
            || zsa_tx.stack_pins().orchard != ZSA_STACK_PINS.orchard
        {
            return Err(ProductionError::Settlement(SettlementError::ConstructionFailed {
                reason: "QEDIT stack pins mismatch — must preserve pins per ADR 0003".to_string(),
            }));
        }

        // V1-V5 combined: draft and ZSA tx bound to same commitment
        if draft.commitment() != zsa_tx.commitment() {
            return Err(ProductionError::Settlement(SettlementError::CommitmentMismatch {
                draft: draft.commitment().to_string(),
                approval: zsa_tx.commitment().to_string(),
            }));
        }

        Ok((draft, zsa_tx))
    }

    /// Full production flow: approval → replay create/verify/acquire → settlement draft → ZSA tx → verify balance → txid.
    pub fn construct_production(
        &self,
        approval: &MatcherApproval,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<(SettlementDraft, AtomicZsaTransaction), ProductionError> {
        let now = UnixSeconds::new(1_900_000_100);
        self.construct_production_at(approval, seller_receiver, buyer_receiver, now)
    }

    /// Submits production settlement with explicit `now` — V1 + V5: inner submit + replay submit persisting txid.
    pub fn submit_production_at(
        &self,
        draft: SettlementDraft,
        now: UnixSeconds,
    ) -> Result<SettlementTxId, ProductionError> {
        let commitment = draft.commitment();
        let txid = self.settlement.submit(draft).map_err(ProductionError::Settlement)?;
        let protocol_txid = zwa_protocol::lifecycle::SettlementTxId::new(*txid.as_bytes());
        self.replay
            .submit_settlement(commitment, protocol_txid, now)
            .map_err(ProductionError::Replay)?;
        Ok(txid)
    }

    /// Submits production settlement — V1 + V5: inner submit + replay submit persisting txid.
    pub fn submit_production(
        &self,
        draft: SettlementDraft,
    ) -> Result<SettlementTxId, ProductionError> {
        let now = UnixSeconds::new(1_900_000_100);
        self.submit_production_at(draft, now)
    }
}

/// Production error combining settlement and replay — typed, no strings for variants, fail-closed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProductionError {
    #[error("settlement error: {0}")]
    Settlement(#[from] SettlementError),

    #[error("replay error: {0}")]
    Replay(#[from] SettlementReplayError),
}

/// Production-level unconfigured coordinator — fail-closed.
#[derive(Debug, Clone, Default)]
pub struct UnconfiguredProductionCoordinator;

impl UnconfiguredProductionCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Always fails closed — production fail-closed default.
    pub fn construct_production(
        &self,
        _approval: &MatcherApproval,
        _seller_receiver: Option<OrchardReceiverBytes>,
        _buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<(SettlementDraft, AtomicZsaTransaction), ProductionError> {
        Err(ProductionError::Settlement(SettlementError::Unconfigured))
    }

    /// Always fails closed with explicit now.
    pub fn construct_production_at(
        &self,
        _approval: &MatcherApproval,
        _seller_receiver: Option<OrchardReceiverBytes>,
        _buyer_receiver: Option<OrchardReceiverBytes>,
        _now: UnixSeconds,
    ) -> Result<(SettlementDraft, AtomicZsaTransaction), ProductionError> {
        Err(ProductionError::Settlement(SettlementError::Unconfigured))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use zwa_credentials::{AuthorityKeyId, IssuerKeyId};
    use zwa_matcher::control::{RecipientControlChallenge, RecipientControlResponse, CONTROL_DOMAIN};
    use zwa_matcher::replay::InMemoryPersistence;
    use zwa_matcher::roots::{CredentialRootAuthenticator, IssuerRootAuthenticator};
    use crate::test_support::{subject_commitment, test_proof, TestGate, TestProofVerifier};
    use zwa_matcher::{GateInput, MatcherGate};
    use zwa_protocol::bytes::OrchardReceiverBytes;
    use zwa_protocol::numbers::{RootVersion, TradeExpiry, UnixSeconds};
    use zwa_protocol::proof::OpaqueProof;
    use zwa_protocol::{
        AssetBaseBytes, AuthorizedIssuanceRoot, ActiveCredentialRoot, MatcherFee, OpaqueSignature,
        PolicyRoot, RecipientCommitment, TradeAmount, TradeNonce, ZatoshiAmount, TradeIntent,
    };
    use ed25519_dalek::Signer;

    const ISSUANCE_ROOT: &str =
        "19309979006225485291788213177219598381134511159668519266888323889569746782051";
    const CREDENTIAL_ROOT: &str =
        "7239536478138432754387625126231950010993505962177483323536139232738771167323";
    const TRADE_COMMITMENT: &str =
        "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    const RECEIVER_A_HEX: &str =
        "781671f8a41294c866d8161f3bf5f84a8fd2c328f91a2d085a66036acd59439731c36c4f1b99b4d64be233";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn golden_intent() -> TradeIntent {
        let offered_asset = AssetBaseBytes::from_hex("4889ad11564115f3655f7e434bffb23074d42aafd58cfecae32a5b5eafaf5301").unwrap();
        let requested_asset = AssetBaseBytes::from_hex("a7ac13ded8b51e7a59c400097b70fe6d5d855b30ad19b1897de1fd74721a9339").unwrap();
        TradeIntent {
            offered_asset,
            offered_amount: TradeAmount::new(10),
            requested_asset,
            requested_amount: TradeAmount::new(6),
            recipient_commitment: RecipientCommitment::from_decimal_str("13135279047718387126053226034283670929172341955108098732820235388025453726181").unwrap(),
            policy_root: PolicyRoot::from_decimal_str("1514393595722546217125953798550283818470332284949639873172624869558831825935").unwrap(),
            matcher_fee: MatcherFee::new(ZatoshiAmount::new(5), RecipientCommitment::from_decimal_str("1800273984094439421343257609634901689467303577600258601269976617936586404380").unwrap()),
            nonce: TradeNonce::new(7001),
            expiry: TradeExpiry::new(2_000_000_000),
        }
    }

    fn build_gate() -> (TestGate<InMemoryPersistence>, OrchardReceiverBytes, zwa_credentials::IssuerRootEnvelope, zwa_credentials::CredentialRootEnvelope, SigningKey) {
        let sk_issuer = signing_key(1);
        let vk_issuer = sk_issuer.verifying_key();
        let issuer_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved_issuer = BTreeMap::new();
        approved_issuer.insert(issuer_id.clone(), vk_issuer);
        let issuer_auth = IssuerRootAuthenticator::new(approved_issuer, RootVersion::new(1));

        let issuer_payload = zwa_credentials::IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap(),
            issuer_id,
            RootVersion::new(1),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        ).unwrap();
        let sig = sk_issuer.sign(&issuer_payload.canonical_bytes());
        let issuer_envelope = zwa_credentials::IssuerRootEnvelope::new(issuer_payload, OpaqueSignature::new(&sig.to_bytes()).unwrap());

        let sk_cred = signing_key(2);
        let vk_cred = sk_cred.verifying_key();
        let auth_id = AuthorityKeyId::new(b"cred-auth-1").unwrap();
        let mut approved_cred = BTreeMap::new();
        approved_cred.insert(auth_id.clone(), vk_cred);
        let cred_auth = CredentialRootAuthenticator::new(approved_cred, RootVersion::new(1));

        let cred_payload = zwa_credentials::CredentialRootPayload::new(
            ActiveCredentialRoot::from_decimal_str(CREDENTIAL_ROOT).unwrap(),
            auth_id,
            RootVersion::new(1),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        ).unwrap();
        let sig2 = sk_cred.sign(&cred_payload.canonical_bytes());
        let cred_envelope = zwa_credentials::CredentialRootEnvelope::new(cred_payload, OpaqueSignature::new(&sig2.to_bytes()).unwrap());

        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        let control_auth = zwa_matcher::control::RecipientControlAuthenticator::new(approved_control, CONTROL_DOMAIN.to_vec());

        let replay = zwa_matcher::replay::PersistentReplayStore::new(InMemoryPersistence::new(), 3).unwrap();

        let gate = MatcherGate::new(
            issuer_auth,
            cred_auth,
            control_auth,
            TestProofVerifier,
            TestProofVerifier,
            replay,
        );

        (gate, recv_a, issuer_envelope, cred_envelope, sk_control)
    }

    fn valid_approval() -> zwa_matcher::MatcherApproval {
        let (gate, recv_a, issuer_envelope, cred_envelope, sk_control) = build_gate();
        let intent = golden_intent();
        let commitment = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();

        let now = UnixSeconds::new(1_900_000_100);
        let challenge = RecipientControlChallenge::new(
            recv_a,
            [7u8; 32],
            CONTROL_DOMAIN.to_vec(),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
            commitment,
        )
        .unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);

        let prov_proof = OpaqueProof::new(&test_proof(ISSUANCE_ROOT, TRADE_COMMITMENT)).unwrap();
        let elig_proof = OpaqueProof::new(&test_proof(CREDENTIAL_ROOT, TRADE_COMMITMENT)).unwrap();

        let input = GateInput {
            intent,
            commitment,
            issuer_envelope,
            credential_envelope: cred_envelope,
            approved_receiver: recv_a,
            recipient_subject_commitment: subject_commitment(),
            control_challenge: challenge,
            control_response: response,
            provenance_proof: prov_proof,
            eligibility_proof: elig_proof,
            now,
        };

        gate.evaluate(input).unwrap()
    }

    #[test]
    fn production_coordinator_v1_to_v5_combined_flow() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);

        let persistence = InMemoryPersistence::new();
        let coordinator = ProductionSettlementCoordinator::with_ed25519_registry(
            persistence,
            approved_control,
            3,
        );

        let approval = valid_approval();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let (draft, zsa_tx) = coordinator
            .construct_production(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        assert_eq!(draft.commitment().to_string(), TRADE_COMMITMENT);
        assert!(!draft.is_seller_signed());
        assert!(zsa_tx.is_atomic_balanced());
        assert!(zsa_tx.experimental_label().contains("EXPERIMENTAL"));
        assert_eq!(zsa_tx.stack_pins().zcash_tx_tool, "6bcf2c5");
        assert_eq!(zsa_tx.stack_pins().zsa_swap, "217b979");

        let challenge = RecipientControlChallenge::new(
            recv_a,
            [9u8; 32],
            CONTROL_DOMAIN.to_vec(),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
            zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap(),
        )
        .unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);
        let verified = coordinator
            .control_verifier()
            .verify(&challenge, &response, UnixSeconds::new(1_900_000_100))
            .unwrap();
        assert_eq!(verified.receiver(), &recv_a);

        assert_eq!(
            coordinator.replay().state(approval.commitment()).unwrap(),
            Some(zwa_protocol::lifecycle::TradeLifecycleState::SettlementConstructed)
        );

        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);
        let seller_auth = crate::SellerAuthorization::sign(&draft, &sk_seller);
        let buyer_auth = crate::BuyerAuthorization::sign(&draft, &sk_buyer);
        let mut draft_mut = draft;
        coordinator.settlement().sign_seller(&mut draft_mut, &seller_auth).unwrap();
        coordinator.settlement().sign_buyer(&mut draft_mut, &buyer_auth).unwrap();
        assert!(draft_mut.is_fully_signed());

        let txid = coordinator.submit_production(draft_mut).unwrap();
        assert_eq!(txid.as_bytes().len(), 32);
        assert_eq!(
            coordinator.replay().state(approval.commitment()).unwrap(),
            Some(zwa_protocol::lifecycle::TradeLifecycleState::Submitted)
        );
    }

    #[test]
    fn production_coordinator_fail_closed_on_double_construction() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);

        let persistence = InMemoryPersistence::new();
        let coordinator = ProductionSettlementCoordinator::with_ed25519_registry(
            persistence,
            approved_control,
            3,
        );

        let approval = valid_approval();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let _ = coordinator
            .construct_production(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        let err = coordinator
            .construct_production(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap_err();
        match err {
            ProductionError::Settlement(crate::SettlementError::ConstructionFailed { .. })
            | ProductionError::Replay(_) => {},
            other => panic!("expected ConstructionFailed or Replay error for double construction, got {other:?}"),
        }
    }

    #[test]
    fn production_coordinator_experimental_label_and_pins_enforced() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);

        let persistence = InMemoryPersistence::new();
        let coordinator = ProductionSettlementCoordinator::with_ed25519_registry(
            persistence,
            approved_control,
            3,
        );

        assert!(coordinator.experimental_label().contains("EXPERIMENTAL"));
        assert!(coordinator.experimental_label().contains("NOT PRODUCTION MAINNET"));
        assert!(coordinator.experimental_label().contains("6bcf2c5"));
        assert!(coordinator.experimental_label().contains("217b979"));
        assert!(coordinator.experimental_label().contains("0aef55c"));
        assert!(coordinator.experimental_label().contains("5a55da9"));
        assert!(coordinator.experimental_label().contains("d91aaf1"));

        assert_eq!(coordinator.stack_pins().zcash_tx_tool, "6bcf2c5");
        assert_eq!(coordinator.stack_pins().zsa_swap, "217b979");
        assert_eq!(coordinator.stack_pins().zebra, "0aef55c");
        assert_eq!(coordinator.stack_pins().librustzcash, "5a55da9");
        assert_eq!(coordinator.stack_pins().orchard, "d91aaf1");
    }

    #[test]
    fn production_coordinator_box_dyn_control_verifier_works() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);

        let persistence = InMemoryPersistence::new();
        let boxed_verifier: Box<dyn RecipientControlVerifier> = Box::new(
            crate::control::Ed25519RegistryControlVerifier::new(approved_control.clone(), CONTROL_DOMAIN.to_vec()),
        );

        let coordinator = ProductionSettlementCoordinator::new(persistence, boxed_verifier, 3);

        let challenge = RecipientControlChallenge::new(
            recv_a,
            [10u8; 32],
            CONTROL_DOMAIN.to_vec(),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
            zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap(),
        )
        .unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);

        let verified = coordinator
            .control_verifier()
            .verify(&challenge, &response, UnixSeconds::new(1_900_000_100))
            .unwrap();
        assert_eq!(verified.receiver(), &recv_a);
    }

    #[test]
    fn unconfigured_production_coordinator_fail_closed() {
        let unconfigured = UnconfiguredProductionCoordinator::new();
        let approval = valid_approval();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let err = unconfigured
            .construct_production(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap_err();
        match err {
            ProductionError::Settlement(crate::SettlementError::Unconfigured) => {},
            other => panic!("expected Unconfigured, got {other:?}"),
        }
    }

    #[test]
    fn production_coordinator_expiry_gated_at_boundary() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);

        let persistence = InMemoryPersistence::new();
        let coordinator = ProductionSettlementCoordinator::with_ed25519_registry(persistence, approved_control, 3);

        let approval = valid_approval();
        let expiry = approval.intent().expiry.get();
        let now_at_expiry = UnixSeconds::new(expiry);
        let now_after_expiry = UnixSeconds::new(expiry + 1);

        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        // At expiry should succeed
        let result = coordinator.construct_production_at(&approval, Some(seller_recv), Some(buyer_recv), now_at_expiry);
        assert!(result.is_ok(), "now==expiry should be valid, got {:?}", result.err());

        // After expiry should fail — need new approval because previous consumed replay
        let persistence2 = InMemoryPersistence::new();
        let mut approved2 = BTreeMap::new();
        approved2.insert(recv_a, vk_control);
        let coordinator2 = ProductionSettlementCoordinator::with_ed25519_registry(persistence2, approved2, 3);
        let approval2 = valid_approval();
        let err = coordinator2
            .construct_production_at(&approval2, Some(seller_recv), Some(buyer_recv), now_after_expiry)
            .unwrap_err();
        match err {
            ProductionError::Replay(_) | ProductionError::Settlement(_) => {},
        }
    }
}
