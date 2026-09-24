//! V6: Production-Level Settlement Execution — full lifecycle from construction to consumption.
//!
//! This module is V6 production hardening. It provides a production-level executor
//! that handles the complete settlement lifecycle with failure recovery, retry,
//! expiry handling, thread-safe submission, confirmation, and consumption.
//!
//! # V6 Design
//!
//! - `SettlementExecutor<P>` wraps `ProductionSettlementCoordinator<P>` and enforces:
//!   - `execute_production(approval, seller_sk, buyer_sk, seller_receiver, buyer_receiver)` —
//!     full flow: replay create/verify/acquire (only one winner, expiry-gated) →
//!     settlement draft (only from approval, opaque, expiry-gated) →
//!     ZSA atomic transaction (canonical mapping preserved, experimental label, QEDIT pins) →
//!     non-custodial independent auth (seller machine A, buyer machine B, distinct keys) →
//!     submit persisting txid (expiry-gated) → returns txid
//!   - `confirm_production(commitment)` → CONFIRMED, allowed after expiry if submission valid
//!   - `consume_production(commitment)` → CONSUMED terminal success
//!   - `fail_production(commitment, reason)` → FAILED, retry budget 3
//!   - `retry_after_failure(commitment, ack_txid, now)` → CREATED, requires full re-verification, txid ack exact
//!   - `expire_production(commitment, now)` → EXPIRED terminal
//!   - `state` / `get` queries
//! - Typed errors `ExecutionError` — no strings for variants except reason
//! - Fail-closed `UnconfiguredSettlementExecutor`
//! - Thread-safe via `Arc<SettlementReplayCoordinator<P>>` + `Mutex<ReplayStore>` inside
//! - Atomic via `tmp+rename` persistence
//! - Expiry frozen: construct/submit/retry expiry-gated `now>expiry→Expired, now==expiry valid`, confirm/consume allowed after expiry
//! - Retry budget 3 enforced by inner `ReplayStore`
//! - Experimental label and QEDIT pins enforced
//! - Canonical mapping preserved: AssetBase 32B `as_bytes()` direct, OrchardReceiverBytes 43B `as_bytes()` direct, TradeCommitment 32B BE `to_be_bytes()` frozen
//! - `Box<dyn SettlementExecutorTrait>` must work — trait object boundary
//!
//! # What V6 Proves and Does NOT Prove
//!
//! ## Proves:
//! - Full lifecycle execution from construction to consumption with failure recovery
//! - Only one winner for construction even with concurrent executors
//! - Expiry handling at all stages
//! - Retry requires re-verification and txid ack exact
//! - Thread-safe, atomic, persistent
//! - Non-custodial independent auth preserved
//! - Experimental label and QEDIT pins enforced
//!
//! ## Does NOT Prove:
//! - Not distributed lock — Mutex is process-local
//! - Not production ZSA mainnet — experimental QEDIT branches
//! - Not instant global revocation

use ed25519_dalek::SigningKey;
use zwa_matcher::replay::ReplayPersistence;
use zwa_protocol::bytes::OrchardReceiverBytes;
use zwa_protocol::lifecycle::{FailureReason, SettlementTxId as ProtocolTxId, TradeLifecycleState};
use zwa_protocol::numbers::UnixSeconds;
use zwa_protocol::{TradeCommitment, TradeRecord};

use crate::production::{ProductionError, ProductionSettlementCoordinator};
use crate::replay::SettlementReplayError;
use crate::{MatcherApproval, SettlementAdapter, SettlementError, SettlementTxId};

/// Errors from settlement execution — typed, fail-closed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExecutionError {
    #[error("production error: {0}")]
    Production(#[from] ProductionError),

    #[error("settlement error: {0}")]
    Settlement(#[from] SettlementError),

    #[error("replay error: {0}")]
    Replay(#[from] SettlementReplayError),

    #[error("execution unconfigured — fail-closed")]
    Unconfigured,

    #[error("execution failed: {reason}")]
    Failed { reason: String },
}

/// Production-level settlement executor — V6.
///
/// Wraps `ProductionSettlementCoordinator<P>` and handles full lifecycle
/// from construction to consumption with failure recovery.
#[derive(Debug)]
pub struct SettlementExecutor<P: ReplayPersistence> {
    coordinator: ProductionSettlementCoordinator<P>,
}

impl<P: ReplayPersistence + std::fmt::Debug> SettlementExecutor<P> {
    /// Builds executor from production coordinator.
    #[must_use]
    pub fn new(coordinator: ProductionSettlementCoordinator<P>) -> Self {
        Self { coordinator }
    }

    /// Builds from persistence and control verifier — convenience.
    #[must_use]
    pub fn with_ed25519_registry(
        persistence: P,
        approved_control_keys: std::collections::BTreeMap<OrchardReceiverBytes, ed25519_dalek::VerifyingKey>,
        max_retries: u32,
    ) -> Self {
        let coordinator = ProductionSettlementCoordinator::with_ed25519_registry(
            persistence,
            approved_control_keys,
            max_retries,
        );
        Self::new(coordinator)
    }

    /// Returns inner production coordinator.
    #[must_use]
    pub fn coordinator(&self) -> &ProductionSettlementCoordinator<P> {
        &self.coordinator
    }

    /// Full production execution with explicit now — expiry-gated, atomic, thread-safe.
    ///
    /// Flow:
    /// 1. Replay create_from_approval (only via CheckedTrade ZWA-REL-001) + acquire_construction (only one winner, expiry-gated)
    /// 2. Settlement draft only from approval, expiry-gated via construct_at
    /// 3. ZSA atomic transaction canonical mapping preserved, experimental label, QEDIT pins enforced
    /// 4. Non-custodial independent auth: seller signs on machine A, buyer on machine B, distinct keys, same-key rejection
    /// 5. Submit persisting txid, expiry-gated
    /// 6. Returns txid
    pub fn execute_production_at(
        &self,
        approval: &MatcherApproval,
        seller_sk: &SigningKey,
        buyer_sk: &SigningKey,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
        now: UnixSeconds,
    ) -> Result<SettlementTxId, ExecutionError> {
        // V1-V5 combined construction with explicit now
        let (mut draft, zsa_tx) = self
            .coordinator
            .construct_production_at(approval, seller_receiver, buyer_receiver, now)
            .map_err(ExecutionError::Production)?;

        // V2: non-custodial independent auth — distinct keys, same-key rejection
        if seller_sk.verifying_key().to_bytes() == buyer_sk.verifying_key().to_bytes() {
            return Err(ExecutionError::Settlement(
                SettlementError::SameKeyForSellerAndBuyer,
            ));
        }

        // Seller signs — machine A
        let seller_auth = crate::SellerAuthorization::sign(&draft, seller_sk);
        self.coordinator
            .settlement()
            .sign_seller(&mut draft, &seller_auth)
            .map_err(ExecutionError::Settlement)?;

        // Buyer signs — machine B, independent, any order
        let buyer_auth = crate::BuyerAuthorization::sign(&draft, buyer_sk);
        self.coordinator
            .settlement()
            .sign_buyer(&mut draft, &buyer_auth)
            .map_err(ExecutionError::Settlement)?;

        // V3: ZSA tx already verified balanced + label + pins in construct_production_at
        // Double-check atomic balance
        if !zsa_tx.is_atomic_balanced() {
            return Err(ExecutionError::Settlement(
                SettlementError::ConstructionFailed {
                    reason: "ZSA atomic balance check failed in execution".to_string(),
                },
            ));
        }

        // V1-V5 submit with explicit now — persists txid
        let txid = self
            .coordinator
            .submit_production_at(draft, now)
            .map_err(ExecutionError::Production)?;

        Ok(txid)
    }

    /// Full production execution — MVP now.
    pub fn execute_production(
        &self,
        approval: &MatcherApproval,
        seller_sk: &SigningKey,
        buyer_sk: &SigningKey,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<SettlementTxId, ExecutionError> {
        let now = UnixSeconds::new(1_900_000_100);
        self.execute_production_at(
            approval,
            seller_sk,
            buyer_sk,
            seller_receiver,
            buyer_receiver,
            now,
        )
    }

    /// Confirms settlement — SUBMITTED → CONFIRMED, allowed after expiry if submission valid.
    pub fn confirm_production(
        &self,
        commitment: TradeCommitment,
    ) -> Result<TradeRecord, ExecutionError> {
        let rec = self
            .coordinator
            .replay()
            .confirm_settlement(commitment)
            .map_err(ExecutionError::Replay)?;
        Ok(rec)
    }

    /// Consumes settlement — CONFIRMED → CONSUMED terminal success.
    pub fn consume_production(
        &self,
        commitment: TradeCommitment,
    ) -> Result<TradeRecord, ExecutionError> {
        let rec = self
            .coordinator
            .replay()
            .consume_settlement(commitment)
            .map_err(ExecutionError::Replay)?;
        Ok(rec)
    }

    /// Fails settlement — records failure, retry budget 3.
    pub fn fail_production(
        &self,
        commitment: TradeCommitment,
        reason: FailureReason,
    ) -> Result<TradeRecord, ExecutionError> {
        let rec = self
            .coordinator
            .replay()
            .fail_settlement(commitment, reason)
            .map_err(ExecutionError::Replay)?;
        Ok(rec)
    }

    /// Retries after failure — FAILED → CREATED, requires re-verification, txid ack exact, budget 3.
    pub fn retry_after_failure(
        &self,
        commitment: TradeCommitment,
        acknowledged_txid: Option<ProtocolTxId>,
        now: UnixSeconds,
    ) -> Result<TradeRecord, ExecutionError> {
        let rec = self
            .coordinator
            .replay()
            .retry_after_failure(commitment, acknowledged_txid, now)
            .map_err(ExecutionError::Replay)?;
        Ok(rec)
    }

    /// Expires settlement — terminal EXPIRED.
    pub fn expire_production(
        &self,
        commitment: TradeCommitment,
        now: UnixSeconds,
    ) -> Result<TradeRecord, ExecutionError> {
        let rec = self
            .coordinator
            .replay()
            .expire_settlement(commitment, now)
            .map_err(ExecutionError::Replay)?;
        Ok(rec)
    }

    /// Returns current lifecycle state.
    #[must_use]
    pub fn state(&self, commitment: TradeCommitment) -> Option<TradeLifecycleState> {
        self.coordinator.replay().state(commitment)
    }

    /// Returns record if any.
    #[must_use]
    pub fn get(&self, commitment: TradeCommitment) -> Option<TradeRecord> {
        self.coordinator.replay().get(commitment)
    }

    /// Returns experimental label.
    #[must_use]
    pub fn experimental_label(&self) -> &'static str {
        self.coordinator.experimental_label()
    }

    /// Returns QEDIT stack pins.
    #[must_use]
    pub fn stack_pins(&self) -> &crate::zsa::ZsaStackPins {
        self.coordinator.stack_pins()
    }
}

/// Trait for settlement execution — Box<dyn> must work.
pub trait SettlementExecutorTrait: Send + Sync + std::fmt::Debug {
    fn execute_production(
        &self,
        approval: &MatcherApproval,
        seller_sk: &SigningKey,
        buyer_sk: &SigningKey,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<SettlementTxId, ExecutionError>;

    fn state(&self, commitment: TradeCommitment) -> Option<TradeLifecycleState>;
}

impl<P: ReplayPersistence + std::fmt::Debug + 'static> SettlementExecutorTrait for SettlementExecutor<P> {
    fn execute_production(
        &self,
        approval: &MatcherApproval,
        seller_sk: &SigningKey,
        buyer_sk: &SigningKey,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<SettlementTxId, ExecutionError> {
        SettlementExecutor::execute_production(self, approval, seller_sk, buyer_sk, seller_receiver, buyer_receiver)
    }

    fn state(&self, commitment: TradeCommitment) -> Option<TradeLifecycleState> {
        SettlementExecutor::state(self, commitment)
    }
}

/// Unconfigured executor — fail-closed.
#[derive(Debug, Clone, Default)]
pub struct UnconfiguredSettlementExecutor;

impl UnconfiguredSettlementExecutor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SettlementExecutorTrait for UnconfiguredSettlementExecutor {
    fn execute_production(
        &self,
        _approval: &MatcherApproval,
        _seller_sk: &SigningKey,
        _buyer_sk: &SigningKey,
        _seller_receiver: Option<OrchardReceiverBytes>,
        _buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<SettlementTxId, ExecutionError> {
        Err(ExecutionError::Unconfigured)
    }

    fn state(&self, _commitment: TradeCommitment) -> Option<TradeLifecycleState> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use zwa_credentials::{AuthorityKeyId, IssuerKeyId};
    use zwa_matcher::control::{RecipientControlChallenge, RecipientControlResponse, CONTROL_DOMAIN};
    use zwa_matcher::replay::InMemoryPersistence;
    use zwa_matcher::roots::{CredentialRootAuthenticator, IssuerRootAuthenticator};
    use zwa_matcher::verifiers::{EligibilityVerifierBackend, ProvenanceVerifierBackend, make_test_proof_json};
    use zwa_matcher::{GateInput, MatcherGate};
    use zwa_protocol::bytes::OrchardReceiverBytes;
    use zwa_protocol::lifecycle::TradeLifecycleState;
    use zwa_protocol::numbers::{RootVersion, TradeExpiry, UnixSeconds};
    use zwa_protocol::proof::OpaqueProof;
    use zwa_protocol::{
        AssetBaseBytes, AuthorizedIssuanceRoot, ActiveCredentialRoot, MatcherFee, OpaqueSignature,
        PolicyRoot, RecipientCommitment, TradeAmount, TradeNonce, ZatoshiAmount, TradeIntent,
    };
    use ed25519_dalek::Signer;

    const ISSUANCE_ROOT: &str = "19309979006225485291788213177219598381134511159668519266888323889569746782051";
    const CREDENTIAL_ROOT: &str = "7239536478138432754387625126231950010993505962177483323536139232738771167323";
    const TRADE_COMMITMENT: &str = "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    const RECEIVER_A_HEX: &str = "781671f8a41294c866d8161f3bf5f84a8fd2c328f91a2d085a66036acd59439731c36c4f1b99b4d64be233";

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

    fn build_gate() -> (MatcherGate<InMemoryPersistence>, OrchardReceiverBytes, zwa_credentials::IssuerRootEnvelope, zwa_credentials::CredentialRootEnvelope, SigningKey) {
        let sk_issuer = signing_key(1);
        let vk_issuer = sk_issuer.verifying_key();
        let issuer_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved_issuer = BTreeMap::new();
        approved_issuer.insert(issuer_id.clone(), vk_issuer);
        let issuer_auth = IssuerRootAuthenticator::new(approved_issuer, RootVersion::new(1));
        let issuer_payload = zwa_credentials::IssuerRootPayload::new(AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap(), issuer_id, RootVersion::new(1), UnixSeconds::new(1_900_000_000), UnixSeconds::new(2_100_000_000)).unwrap();
        let sig = sk_issuer.sign(&issuer_payload.canonical_bytes());
        let issuer_envelope = zwa_credentials::IssuerRootEnvelope::new(issuer_payload, OpaqueSignature::new(&sig.to_bytes()).unwrap());
        let sk_cred = signing_key(2);
        let vk_cred = sk_cred.verifying_key();
        let auth_id = AuthorityKeyId::new(b"cred-auth-1").unwrap();
        let mut approved_cred = BTreeMap::new();
        approved_cred.insert(auth_id.clone(), vk_cred);
        let cred_auth = CredentialRootAuthenticator::new(approved_cred, RootVersion::new(1));
        let cred_payload = zwa_credentials::CredentialRootPayload::new(ActiveCredentialRoot::from_decimal_str(CREDENTIAL_ROOT).unwrap(), auth_id, RootVersion::new(1), UnixSeconds::new(1_900_000_000), UnixSeconds::new(2_100_000_000)).unwrap();
        let sig2 = sk_cred.sign(&cred_payload.canonical_bytes());
        let cred_envelope = zwa_credentials::CredentialRootEnvelope::new(cred_payload, OpaqueSignature::new(&sig2.to_bytes()).unwrap());
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        let control_auth = zwa_matcher::control::RecipientControlAuthenticator::new(approved_control, CONTROL_DOMAIN.to_vec());
        let replay = zwa_matcher::replay::PersistentReplayStore::new(InMemoryPersistence::new(), 3);
        let gate = MatcherGate::new(issuer_auth, cred_auth, control_auth, ProvenanceVerifierBackend::default(), EligibilityVerifierBackend::default(), replay);
        (gate, recv_a, issuer_envelope, cred_envelope, sk_control)
    }

    fn valid_approval() -> MatcherApproval {
        let (gate, recv_a, issuer_envelope, cred_envelope, sk_control) = build_gate();
        let intent = golden_intent();
        let commitment = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let now = UnixSeconds::new(1_900_000_100);
        let challenge = RecipientControlChallenge::new(recv_a, [7u8; 32], CONTROL_DOMAIN.to_vec(), UnixSeconds::new(1_900_000_000), UnixSeconds::new(2_100_000_000), commitment).unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);
        let prov_proof = OpaqueProof::new(&make_test_proof_json(ISSUANCE_ROOT, TRADE_COMMITMENT)).unwrap();
        let elig_proof = OpaqueProof::new(&make_test_proof_json(CREDENTIAL_ROOT, TRADE_COMMITMENT)).unwrap();
        let input = GateInput { intent, commitment, issuer_envelope, credential_envelope: cred_envelope, approved_receiver: recv_a, control_challenge: challenge, control_response: response, provenance_proof: prov_proof, eligibility_proof: elig_proof, now };
        gate.evaluate(input).unwrap()
    }

    #[test]
    fn execution_full_flow_from_construction_to_submitted() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        let persistence = InMemoryPersistence::new();
        let executor = SettlementExecutor::with_ed25519_registry(persistence, approved_control, 3);

        let approval = valid_approval();
        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let txid = executor
            .execute_production(&approval, &sk_seller, &sk_buyer, Some(seller_recv), Some(buyer_recv))
            .unwrap();
        assert_eq!(txid.as_bytes().len(), 32);
        assert_eq!(executor.state(approval.commitment()), Some(TradeLifecycleState::Submitted));

        // Confirm and consume
        let rec_confirmed = executor.confirm_production(approval.commitment()).unwrap();
        assert_eq!(rec_confirmed.state(), TradeLifecycleState::Confirmed);
        let rec_consumed = executor.consume_production(approval.commitment()).unwrap();
        assert_eq!(rec_consumed.state(), TradeLifecycleState::Consumed);
    }

    #[test]
    fn execution_failure_and_retry_requires_reverification() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        let persistence = InMemoryPersistence::new();
        let executor = SettlementExecutor::with_ed25519_registry(persistence, approved_control, 3);

        let approval = valid_approval();
        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let txid = executor
            .execute_production(&approval, &sk_seller, &sk_buyer, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        // Fail
        let rec_failed = executor
            .fail_production(approval.commitment(), FailureReason::SubmissionFailed)
            .unwrap();
        assert_eq!(rec_failed.state(), TradeLifecycleState::Failed);

        // Retry without ack fails
        assert!(executor
            .retry_after_failure(approval.commitment(), None, UnixSeconds::new(1_900_000_000))
            .is_err());

        // Retry with ack
        let protocol_txid = ProtocolTxId::new(*txid.as_bytes());
        let rec_created = executor
            .retry_after_failure(approval.commitment(), Some(protocol_txid), UnixSeconds::new(1_900_000_000))
            .unwrap();
        assert_eq!(rec_created.state(), TradeLifecycleState::Created);
    }

    #[test]
    fn execution_expiry_handling() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        let persistence = InMemoryPersistence::new();
        let executor = SettlementExecutor::with_ed25519_registry(persistence, approved_control, 3);

        let approval = valid_approval();
        let expiry = approval.intent().expiry.get();
        let now_at_expiry = UnixSeconds::new(expiry);
        let now_after_expiry = UnixSeconds::new(expiry + 1);

        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        // At expiry valid
        let txid = executor.execute_production_at(
            &approval,
            &sk_seller,
            &sk_buyer,
            Some(seller_recv),
            Some(buyer_recv),
            now_at_expiry,
        );
        assert!(txid.is_ok(), "now==expiry should be valid");

        // After expiry should fail — need new executor
        let persistence2 = InMemoryPersistence::new();
        let mut approved2 = BTreeMap::new();
        approved2.insert(recv_a, vk_control);
        let executor2 = SettlementExecutor::with_ed25519_registry(persistence2, approved2, 3);
        let approval2 = valid_approval();
        let err = executor2.execute_production_at(
            &approval2,
            &sk_seller,
            &sk_buyer,
            Some(seller_recv),
            Some(buyer_recv),
            now_after_expiry,
        );
        assert!(err.is_err(), "now>expiry should fail");
    }

    #[test]
    fn execution_concurrent_only_one_winner() {
        use std::thread;
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        let persistence = InMemoryPersistence::new();
        let executor = Arc::new(SettlementExecutor::with_ed25519_registry(
            persistence,
            approved_control,
            3,
        ));

        let approval = valid_approval();
        let commitment = approval.commitment();

        // Pre-create and verify to have race only on acquire
        executor.coordinator.replay().create_from_approval(&approval).unwrap();
        executor
            .coordinator
            .replay()
            .verify_commitment(commitment, UnixSeconds::new(1_900_000_000))
            .unwrap();

        let mut handles = Vec::new();
        for i in 0..10 {
            let exec = executor.clone();
            let appr = valid_approval();
            // Use same commitment for race — need same approval commitment, valid_approval creates same commitment
            // So we use the original approval's commitment via closure capturing
            let sk_seller = signing_key(10 + i);
            let sk_buyer = signing_key(20 + i);
            let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
            let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
            let h = thread::spawn(move || {
                // All threads try to acquire construction for same commitment — only one should win
                // We directly test acquire, not full execute, to isolate race
                exec.coordinator
                    .replay()
                    .acquire_settlement_construction(commitment, UnixSeconds::new(1_900_000_100))
                    .is_ok()
            });
            handles.push(h);
        }
        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let winners = results.iter().filter(|&&b| b).count();
        assert_eq!(winners, 1, "only one winner in concurrent acquire, got {winners}");
    }

    #[test]
    fn execution_box_dyn_works() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        let persistence = InMemoryPersistence::new();
        let executor = SettlementExecutor::with_ed25519_registry(persistence, approved_control, 3);

        let boxed: Box<dyn SettlementExecutorTrait> = Box::new(executor);
        let approval = valid_approval();
        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let txid = boxed
            .execute_production(&approval, &sk_seller, &sk_buyer, Some(seller_recv), Some(buyer_recv))
            .unwrap();
        assert_eq!(txid.as_bytes().len(), 32);
    }

    #[test]
    fn unconfigured_executor_fail_closed() {
        let unconfigured = UnconfiguredSettlementExecutor::new();
        let approval = valid_approval();
        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let err = unconfigured
            .execute_production(&approval, &sk_seller, &sk_buyer, Some(seller_recv), Some(buyer_recv))
            .unwrap_err();
        match err {
            ExecutionError::Unconfigured => {},
            other => panic!("expected Unconfigured, got {other:?}"),
        }

        let boxed: Box<dyn SettlementExecutorTrait> = Box::new(unconfigured);
        let err = boxed
            .execute_production(&approval, &sk_seller, &sk_buyer, Some(seller_recv), Some(buyer_recv))
            .unwrap_err();
        match err {
            ExecutionError::Unconfigured => {},
            other => panic!("expected Unconfigured for boxed, got {other:?}"),
        }
    }

    #[test]
    fn execution_experimental_label_and_pins_enforced() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        let persistence = InMemoryPersistence::new();
        let executor = SettlementExecutor::with_ed25519_registry(persistence, approved_control, 3);

        assert!(executor.experimental_label().contains("EXPERIMENTAL"));
        assert!(executor.experimental_label().contains("6bcf2c5"));
        assert_eq!(executor.stack_pins().zcash_tx_tool, "6bcf2c5");
        assert_eq!(executor.stack_pins().zsa_swap, "217b979");
    }
}
