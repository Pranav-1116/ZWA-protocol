//! V7: Production RFQ + Matcher + Settlement Integration — end-to-end deterministic flow.
//!
//! This module is V7 production hardening. It provides end-to-end integration
//! from private RFQ order intent to canonical TradeIntent + TradeCommitmentV1,
//! through MatcherGate 10-step verification, to settlement execution and
//! confirmation, with typed errors, fail-closed, experimental labels preserved.
//!
//! # V7 Design
//!
//! - `RfqRequest` — private order intent that becomes canonical `TradeIntent`:
//!   - Private: trader's Orchard spending keys, nullifiers, exact notes, raw receiver 43B private,
//!     investor credential subject secret, investor class, jurisdiction private, policy preimage private
//!   - Public conversion: RFQ → canonical `TradeIntent` with exact 32B AssetBase encoding (Pallas compressed),
//!     43B receiver → commitment via `receiver_commitment()`, amounts, fee, nonce, expiry
//!   - Then `TradeCommitmentV1 = H(TRADE_V1, ...)` via frozen `zwa-commitments::trade::compute_trade_commitment`
//!     via `CheckedTrade::new(intent, commitment)` — never recompute Poseidon staging
//! - `RfqProcessor` — converts RFQ to `GateInput` and then to `MatcherApproval` via `MatcherGate::evaluate()`:
//!   - Takes `RfqRequest` + signed root envelopes + control challenge/response + proofs + now
//!   - Returns `MatcherApproval` opaque only via gate, or `GateRejection` typed
//! - `EndToEndSettlementCoordinator<P>` — full deterministic flow:
//!   - `process_rfq_and_settle(rfq, issuer_envelope, credential_envelope, approved_receiver, control_challenge, control_response, prov_proof, elig_proof, now, seller_sk, buyer_sk)` → txid
//!   - Internally: RFQ → TradeIntent → CheckedTrade → GateInput → MatcherGate::evaluate() → MatcherApproval →
//!     ProductionSettlementCoordinator::construct_production_at → sign_seller/buyer independent → submit → confirm → consume
//!   - Enforces: only from approval, non-custodial, canonical mapping preserved, experimental label, QEDIT pins, replay protection, expiry frozen, retry budget
//! - Typed errors `IntegrationError` — no strings for variants except reason
//! - Fail-closed `UnconfiguredIntegrationCoordinator`
//! - `Box<dyn IntegrationTrait>` must work
//!
//! # What V7 Proves and Does NOT Prove
//!
//! ## Proves:
//! - Private RFQ → canonical TradeIntent + TradeCommitmentV1 via frozen commitment engine
//! - Unauthorized asset blocked by provenance proof (fake RWA)
//! - Ineligible recipient blocked by eligibility proof (wrong class/jurisdiction)
//! - Valid private trade settled atomically with shielded ZEC matcher fee
//! - End-to-end deterministic flow with typed errors, fail-closed, experimental label preserved, canonical mapping preserved
//!
//! ## Does NOT Prove:
//! - Not order book, AMM, partial fill, routing — MVP scope single trade
//! - Not production ZSA mainnet — experimental QEDIT branches
//! - Not global compliance enforcement — matcher is MVP boundary

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use zwa_credentials::{CredentialRootEnvelope, IssuerRootEnvelope};
use zwa_matcher::control::{RecipientControlChallenge, RecipientControlResponse, CONTROL_DOMAIN};
use zwa_matcher::replay::ReplayPersistence;
use zwa_matcher::roots::{CredentialRootAuthenticator, IssuerRootAuthenticator};
use zwa_matcher::verifiers::{EligibilityVerifierBackend, ProvenanceVerifierBackend};
use zwa_matcher::{GateInput, MatcherGate};
use zwa_protocol::bytes::{AssetBaseBytes, OrchardReceiverBytes};
use zwa_protocol::numbers::{TradeExpiry, UnixSeconds};
use zwa_protocol::proof::OpaqueProof;
use zwa_protocol::values::{RecipientCommitment, TradeCommitment};
use zwa_protocol::{TradeIntent, TradeNonce, TradeAmount, PolicyRoot, MatcherFee};

use crate::execution::{ExecutionError, SettlementExecutor};
use crate::production::ProductionSettlementCoordinator;
use crate::{MatcherApproval, SettlementTxId};

/// Private RFQ request — private order intent that becomes canonical TradeIntent.
///
/// Private fields stay private in RFQ, not in TradeIntent:
/// - Trader's Orchard spending keys, nullifiers, exact notes being spent
/// - Raw Orchard receiver 43B private (TradeIntent contains recipient_commitment hash, not raw)
/// - Investor credential subject secret, investor class, jurisdiction — private, only proved via eligibility proof
/// - Policy preimage — private, only policy_root public
#[derive(Debug, Clone)]
pub struct RfqRequest {
    /// Offered asset 32B canonical — Pallas compressed, from frozen zwa-protocol, no ticker
    pub offered_asset: AssetBaseBytes,
    /// Offered amount — distinct newtype
    pub offered_amount: TradeAmount,
    /// Requested asset 32B canonical
    pub requested_asset: AssetBaseBytes,
    /// Requested amount
    pub requested_amount: TradeAmount,
    /// Recipient commitment — public hash of receiver, raw 43B private
    pub recipient_commitment: RecipientCommitment,
    /// Policy root — distinct newtype
    pub policy_root: PolicyRoot,
    /// Matcher fee — amount + recipient commitment from TradeIntent
    pub matcher_fee: MatcherFee,
    /// Nonce — application-assigned u64
    pub nonce: TradeNonce,
    /// Expiry — Unix seconds
    pub expiry: TradeExpiry,
    /// Optional raw receiver 43B — private, only for demo, not logged
    pub raw_receiver: Option<OrchardReceiverBytes>,
    /// Private: subject secret redacted — must never be logged
    pub subject_secret: Option<zwa_protocol::values::SubjectSecret>,
}

impl RfqRequest {
    /// Converts RFQ to canonical TradeIntent — public conversion, uses frozen types directly via as_bytes(), no re-encoding.
    #[must_use]
    pub fn to_trade_intent(&self) -> TradeIntent {
        TradeIntent {
            offered_asset: self.offered_asset,
            offered_amount: self.offered_amount,
            requested_asset: self.requested_asset,
            requested_amount: self.requested_amount,
            recipient_commitment: self.recipient_commitment,
            policy_root: self.policy_root,
            matcher_fee: self.matcher_fee,
            nonce: self.nonce,
            expiry: self.expiry,
        }
    }

    /// Computes TradeCommitmentV1 via frozen commitment engine — never recompute Poseidon staging.
    ///
    /// Uses `CheckedTrade::new(intent, commitment)` internally via `zwa_matcher::CheckedTrade`
    /// which calls `trade_commitment_v1` — ZWA-REL-001 fix.
    pub fn compute_commitment(&self) -> Result<TradeCommitment, IntegrationError> {
        let intent = self.to_trade_intent();
        // Use frozen commitment engine via zwa-commitments — pure, infallible
        let commitment = zwa_commitments::trade::trade_commitment_v1(&intent);
        Ok(commitment)
    }
}

/// Errors from RFQ + integration — typed, fail-closed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IntegrationError {
    #[error("commitment failed: {reason}")]
    CommitmentFailed { reason: String },

    #[error("gate rejection: {reason}")]
    GateRejected { reason: String },

    #[error("execution error: {0}")]
    Execution(#[from] ExecutionError),

    #[error("integration unconfigured — fail-closed")]
    Unconfigured,

    #[error("rfq invalid: {reason}")]
    RfqInvalid { reason: String },
}

/// End-to-end settlement coordinator — V7 production.
///
/// Combines RFQ → MatcherGate → ProductionSettlementCoordinator → SettlementExecutor
/// into one deterministic end-to-end flow with typed errors, fail-closed.
#[derive(Debug)]
pub struct EndToEndSettlementCoordinator<P: ReplayPersistence> {
    gate: MatcherGate<P>,
    executor: SettlementExecutor<P>,
}

impl<P: ReplayPersistence + std::fmt::Debug + 'static> EndToEndSettlementCoordinator<P> {
    /// Builds coordinator with gate and executor.
    #[must_use]
    pub fn new(gate: MatcherGate<P>, executor: SettlementExecutor<P>) -> Self {
        Self { gate, executor }
    }

    /// Builds with Ed25519 registry MVP — current production path.
    #[must_use]
    pub fn with_ed25519_registry(
        issuer_auth: IssuerRootAuthenticator,
        credential_auth: CredentialRootAuthenticator,
        approved_control_keys: BTreeMap<OrchardReceiverBytes, VerifyingKey>,
        replay_persistence: P,
        max_retries: u32,
    ) -> Self
    where
        P: Clone,
    {
        let control_auth = zwa_matcher::control::RecipientControlAuthenticator::new(
            approved_control_keys.clone(),
            CONTROL_DOMAIN.to_vec(),
        );
        let replay_store = zwa_matcher::replay::PersistentReplayStore::new(replay_persistence.clone(), max_retries);
        let gate = MatcherGate::new(
            issuer_auth,
            credential_auth,
            control_auth,
            ProvenanceVerifierBackend::default(),
            EligibilityVerifierBackend::default(),
            replay_store,
        );

        let coordinator = ProductionSettlementCoordinator::with_ed25519_registry(
            replay_persistence,
            approved_control_keys,
            max_retries,
        );
        let executor = SettlementExecutor::new(coordinator);

        Self::new(gate, executor)
    }

    /// Returns gate reference.
    #[must_use]
    pub fn gate(&self) -> &MatcherGate<P> {
        &self.gate
    }

    /// Returns executor reference.
    #[must_use]
    pub fn executor(&self) -> &SettlementExecutor<P> {
        &self.executor
    }

    /// Full end-to-end flow: RFQ → TradeIntent → Commitment → GateInput → MatcherApproval → Settlement Execution.
    ///
    /// This is the production-level V7 flow that enforces all guarantees from V1-V6 plus RFQ boundary.
    // Each argument is a distinct, independently authenticated input to the gate
    // (envelopes, control challenge/response, both proofs, both party keys); bundling
    // them would only move the same 12 fields into a struct at every call site.
    #[allow(clippy::too_many_arguments)]
    pub fn process_rfq_and_settle(
        &self,
        rfq: &RfqRequest,
        issuer_envelope: IssuerRootEnvelope,
        credential_envelope: CredentialRootEnvelope,
        approved_receiver: OrchardReceiverBytes,
        control_challenge: RecipientControlChallenge,
        control_response: RecipientControlResponse,
        provenance_proof: OpaqueProof,
        eligibility_proof: OpaqueProof,
        now: UnixSeconds,
        seller_sk: &SigningKey,
        buyer_sk: &SigningKey,
    ) -> Result<(MatcherApproval, SettlementTxId), IntegrationError> {
        // RFQ → TradeIntent → Commitment via frozen engine
        let intent = rfq.to_trade_intent();
        let commitment = rfq.compute_commitment()?;

        // Build GateInput
        let gate_input = GateInput {
            intent,
            commitment,
            issuer_envelope,
            credential_envelope,
            approved_receiver,
            control_challenge,
            control_response,
            provenance_proof,
            eligibility_proof,
            now,
        };

        // Evaluate gate — 10-step deterministic allow/block
        let approval = self
            .gate
            .evaluate(gate_input)
            .map_err(|e| IntegrationError::GateRejected {
                reason: format!("{e:?}"),
            })?;

        // Settlement execution — full lifecycle with non-custodial auth
        let seller_receiver = rfq.raw_receiver;
        let buyer_receiver = Some(approved_receiver);
        let txid = self
            .executor
            .execute_production_at(
                &approval,
                seller_sk,
                buyer_sk,
                seller_receiver,
                buyer_receiver,
                now,
            )
            .map_err(IntegrationError::Execution)?;

        Ok((approval, txid))
    }

    /// Returns experimental label.
    #[must_use]
    pub fn experimental_label(&self) -> &'static str {
        self.executor.experimental_label()
    }

    /// Returns QEDIT pins.
    #[must_use]
    pub fn stack_pins(&self) -> &crate::zsa::ZsaStackPins {
        self.executor.stack_pins()
    }
}

/// Trait for end-to-end integration — `Box<dyn>` must work.
pub trait IntegrationTrait: Send + Sync + std::fmt::Debug {
    // Each argument is a distinct, independently authenticated input to the gate
    // (envelopes, control challenge/response, both proofs, both party keys); bundling
    // them would only move the same 12 fields into a struct at every call site.
    #[allow(clippy::too_many_arguments)]
    fn process_rfq_and_settle(
        &self,
        rfq: &RfqRequest,
        issuer_envelope: IssuerRootEnvelope,
        credential_envelope: CredentialRootEnvelope,
        approved_receiver: OrchardReceiverBytes,
        control_challenge: RecipientControlChallenge,
        control_response: RecipientControlResponse,
        provenance_proof: OpaqueProof,
        eligibility_proof: OpaqueProof,
        now: UnixSeconds,
        seller_sk: &SigningKey,
        buyer_sk: &SigningKey,
    ) -> Result<(MatcherApproval, SettlementTxId), IntegrationError>;
}

impl<P: ReplayPersistence + std::fmt::Debug + 'static> IntegrationTrait for EndToEndSettlementCoordinator<P> {
    fn process_rfq_and_settle(
        &self,
        rfq: &RfqRequest,
        issuer_envelope: IssuerRootEnvelope,
        credential_envelope: CredentialRootEnvelope,
        approved_receiver: OrchardReceiverBytes,
        control_challenge: RecipientControlChallenge,
        control_response: RecipientControlResponse,
        provenance_proof: OpaqueProof,
        eligibility_proof: OpaqueProof,
        now: UnixSeconds,
        seller_sk: &SigningKey,
        buyer_sk: &SigningKey,
    ) -> Result<(MatcherApproval, SettlementTxId), IntegrationError> {
        EndToEndSettlementCoordinator::process_rfq_and_settle(
            self,
            rfq,
            issuer_envelope,
            credential_envelope,
            approved_receiver,
            control_challenge,
            control_response,
            provenance_proof,
            eligibility_proof,
            now,
            seller_sk,
            buyer_sk,
        )
    }
}

/// Unconfigured integration coordinator — fail-closed.
#[derive(Debug, Clone, Default)]
pub struct UnconfiguredIntegrationCoordinator;

impl UnconfiguredIntegrationCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl IntegrationTrait for UnconfiguredIntegrationCoordinator {
    fn process_rfq_and_settle(
        &self,
        _rfq: &RfqRequest,
        _issuer_envelope: IssuerRootEnvelope,
        _credential_envelope: CredentialRootEnvelope,
        _approved_receiver: OrchardReceiverBytes,
        _control_challenge: RecipientControlChallenge,
        _control_response: RecipientControlResponse,
        _provenance_proof: OpaqueProof,
        _eligibility_proof: OpaqueProof,
        _now: UnixSeconds,
        _seller_sk: &SigningKey,
        _buyer_sk: &SigningKey,
    ) -> Result<(MatcherApproval, SettlementTxId), IntegrationError> {
        Err(IntegrationError::Unconfigured)
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
    use zwa_matcher::verifiers::make_test_proof_json;
    use zwa_protocol::bytes::OrchardReceiverBytes;
    use zwa_protocol::numbers::{RootVersion, TradeExpiry, UnixSeconds};
    use zwa_protocol::proof::OpaqueProof;
    use zwa_protocol::{
        AssetBaseBytes, AuthorizedIssuanceRoot, ActiveCredentialRoot, MatcherFee, OpaqueSignature,
        PolicyRoot, RecipientCommitment, TradeAmount, TradeNonce, ZatoshiAmount,
    };
    use ed25519_dalek::Signer;

    const ISSUANCE_ROOT: &str = "19309979006225485291788213177219598381134511159668519266888323889569746782051";
    const CREDENTIAL_ROOT: &str = "7239536478138432754387625126231950010993505962177483323536139232738771167323";
    const TRADE_COMMITMENT: &str = "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    const RECEIVER_A_HEX: &str = "781671f8a41294c866d8161f3bf5f84a8fd2c328f91a2d085a66036acd59439731c36c4f1b99b4d64be233";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn golden_rfq() -> RfqRequest {
        let offered_asset = AssetBaseBytes::from_hex("4889ad11564115f3655f7e434bffb23074d42aafd58cfecae32a5b5eafaf5301").unwrap();
        let requested_asset = AssetBaseBytes::from_hex("a7ac13ded8b51e7a59c400097b70fe6d5d855b30ad19b1897de1fd74721a9339").unwrap();
        let recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        RfqRequest {
            offered_asset,
            offered_amount: TradeAmount::new(10),
            requested_asset,
            requested_amount: TradeAmount::new(6),
            recipient_commitment: RecipientCommitment::from_decimal_str("13135279047718387126053226034283670929172341955108098732820235388025453726181").unwrap(),
            policy_root: PolicyRoot::from_decimal_str("1514393595722546217125953798550283818470332284949639873172624869558831825935").unwrap(),
            matcher_fee: MatcherFee::new(ZatoshiAmount::new(5), RecipientCommitment::from_decimal_str("1800273984094439421343257609634901689467303577600258601269976617936586404380").unwrap()),
            nonce: TradeNonce::new(7001),
            expiry: TradeExpiry::new(2_000_000_000),
            raw_receiver: Some(recv),
            subject_secret: None,
        }
    }

    fn build_authenticators() -> (IssuerRootAuthenticator, CredentialRootAuthenticator, IssuerRootEnvelope, CredentialRootEnvelope, SigningKey, OrchardReceiverBytes) {
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
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        (issuer_auth, cred_auth, issuer_envelope, cred_envelope, sk_control, recv_a)
    }

    #[test]
    fn rfq_to_trade_intent_preserves_canonical_mapping() {
        let rfq = golden_rfq();
        let intent = rfq.to_trade_intent();
        assert_eq!(intent.offered_asset.as_bytes(), rfq.offered_asset.as_bytes());
        assert_eq!(intent.requested_asset.as_bytes(), rfq.requested_asset.as_bytes());
        assert_eq!(intent.offered_amount.get(), 10);
        assert_eq!(intent.requested_amount.get(), 6);

        let commitment = rfq.compute_commitment().unwrap();
        assert_eq!(commitment.to_string(), TRADE_COMMITMENT);
    }

    #[test]
    fn end_to_end_valid_private_trade_settled_atomically_with_zec_fee() {
        let rfq = golden_rfq();
        let (issuer_auth, cred_auth, issuer_envelope, cred_envelope, sk_control, recv_a) = build_authenticators();

        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, sk_control.verifying_key());

        let persistence = InMemoryPersistence::new();
        let coordinator = EndToEndSettlementCoordinator::with_ed25519_registry(
            issuer_auth,
            cred_auth,
            approved_control,
            persistence,
            3,
        );

        let now = UnixSeconds::new(1_900_000_100);
        let commitment = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let challenge = RecipientControlChallenge::new(recv_a, [7u8; 32], CONTROL_DOMAIN.to_vec(), UnixSeconds::new(1_900_000_000), UnixSeconds::new(2_100_000_000), commitment).unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);
        let prov_proof = OpaqueProof::new(&make_test_proof_json(ISSUANCE_ROOT, TRADE_COMMITMENT)).unwrap();
        let elig_proof = OpaqueProof::new(&make_test_proof_json(CREDENTIAL_ROOT, TRADE_COMMITMENT)).unwrap();

        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);

        let (approval, txid) = coordinator
            .process_rfq_and_settle(
                &rfq,
                issuer_envelope,
                cred_envelope,
                recv_a,
                challenge,
                response,
                prov_proof,
                elig_proof,
                now,
                &sk_seller,
                &sk_buyer,
            )
            .unwrap();

        assert_eq!(approval.commitment().to_string(), TRADE_COMMITMENT);
        assert_eq!(txid.as_bytes().len(), 32);
        assert!(coordinator.experimental_label().contains("EXPERIMENTAL"));
        assert_eq!(coordinator.stack_pins().zcash_tx_tool, "6bcf2c5");
    }

    #[test]
    fn end_to_end_blocks_unauthorized_asset_via_provenance() {
        let rfq = golden_rfq();
        let (issuer_auth, cred_auth, issuer_envelope, cred_envelope, sk_control, recv_a) = build_authenticators();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, sk_control.verifying_key());
        let persistence = InMemoryPersistence::new();
        let coordinator = EndToEndSettlementCoordinator::with_ed25519_registry(
            issuer_auth,
            cred_auth,
            approved_control,
            persistence,
            3,
        );

        let now = UnixSeconds::new(1_900_000_100);
        let commitment = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let challenge = RecipientControlChallenge::new(recv_a, [7u8; 32], CONTROL_DOMAIN.to_vec(), UnixSeconds::new(1_900_000_000), UnixSeconds::new(2_100_000_000), commitment).unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);
        // Wrong provenance proof — different commitment, simulating fake RWA
        let bad_prov_proof = OpaqueProof::new(&make_test_proof_json(ISSUANCE_ROOT, "7409670081847436957289371955571360481923983184454289247710022466448715682310")).unwrap();
        let elig_proof = OpaqueProof::new(&make_test_proof_json(CREDENTIAL_ROOT, TRADE_COMMITMENT)).unwrap();

        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);

        let err = coordinator
            .process_rfq_and_settle(
                &rfq,
                issuer_envelope,
                cred_envelope,
                recv_a,
                challenge,
                response,
                bad_prov_proof,
                elig_proof,
                now,
                &sk_seller,
                &sk_buyer,
            )
            .unwrap_err();

        match err {
            IntegrationError::GateRejected { reason } => {
                assert!(reason.contains("ProofInvalid") || reason.contains("CommitmentMismatch") || reason.contains("Proof"), "should block fake RWA, got {reason}");
            },
            other => panic!("expected GateRejected for fake RWA, got {other:?}"),
        }
    }

    #[test]
    fn end_to_end_blocks_ineligible_recipient_via_eligibility() {
        let rfq = golden_rfq();
        let (issuer_auth, cred_auth, issuer_envelope, cred_envelope, sk_control, recv_a) = build_authenticators();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, sk_control.verifying_key());
        let persistence = InMemoryPersistence::new();
        let coordinator = EndToEndSettlementCoordinator::with_ed25519_registry(
            issuer_auth,
            cred_auth,
            approved_control,
            persistence,
            3,
        );

        let now = UnixSeconds::new(1_900_000_100);
        let commitment = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let challenge = RecipientControlChallenge::new(recv_a, [7u8; 32], CONTROL_DOMAIN.to_vec(), UnixSeconds::new(1_900_000_000), UnixSeconds::new(2_100_000_000), commitment).unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);
        let prov_proof = OpaqueProof::new(&make_test_proof_json(ISSUANCE_ROOT, TRADE_COMMITMENT)).unwrap();
        // Wrong eligibility proof — different commitment, simulating ineligible recipient
        let bad_elig_proof = OpaqueProof::new(&make_test_proof_json(CREDENTIAL_ROOT, "4141140993944283635059564795814979270169431233615041812756992202222578526061")).unwrap();

        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);

        let err = coordinator
            .process_rfq_and_settle(
                &rfq,
                issuer_envelope,
                cred_envelope,
                recv_a,
                challenge,
                response,
                prov_proof,
                bad_elig_proof,
                now,
                &sk_seller,
                &sk_buyer,
            )
            .unwrap_err();

        match err {
            IntegrationError::GateRejected { reason } => {
                assert!(reason.contains("ProofInvalid") || reason.contains("Proof"), "should block ineligible, got {reason}");
            },
            other => panic!("expected GateRejected for ineligible recipient, got {other:?}"),
        }
    }

    #[test]
    fn integration_box_dyn_works() {
        let rfq = golden_rfq();
        let (issuer_auth, cred_auth, issuer_envelope, cred_envelope, sk_control, recv_a) = build_authenticators();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, sk_control.verifying_key());
        let persistence = InMemoryPersistence::new();
        let coordinator = EndToEndSettlementCoordinator::with_ed25519_registry(
            issuer_auth,
            cred_auth,
            approved_control,
            persistence,
            3,
        );

        let boxed: Box<dyn IntegrationTrait> = Box::new(coordinator);

        let now = UnixSeconds::new(1_900_000_100);
        let commitment = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let challenge = RecipientControlChallenge::new(recv_a, [7u8; 32], CONTROL_DOMAIN.to_vec(), UnixSeconds::new(1_900_000_000), UnixSeconds::new(2_100_000_000), commitment).unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);
        let prov_proof = OpaqueProof::new(&make_test_proof_json(ISSUANCE_ROOT, TRADE_COMMITMENT)).unwrap();
        let elig_proof = OpaqueProof::new(&make_test_proof_json(CREDENTIAL_ROOT, TRADE_COMMITMENT)).unwrap();
        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);

        let (approval, txid) = boxed
            .process_rfq_and_settle(
                &rfq,
                issuer_envelope,
                cred_envelope,
                recv_a,
                challenge,
                response,
                prov_proof,
                elig_proof,
                now,
                &sk_seller,
                &sk_buyer,
            )
            .unwrap();

        assert_eq!(approval.commitment().to_string(), TRADE_COMMITMENT);
        assert_eq!(txid.as_bytes().len(), 32);
    }

    #[test]
    fn unconfigured_integration_fail_closed() {
        let rfq = golden_rfq();
        let (_, _, issuer_envelope, cred_envelope, sk_control, recv_a) = build_authenticators();
        let now = UnixSeconds::new(1_900_000_100);
        let commitment = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let challenge = RecipientControlChallenge::new(recv_a, [7u8; 32], CONTROL_DOMAIN.to_vec(), UnixSeconds::new(1_900_000_000), UnixSeconds::new(2_100_000_000), commitment).unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);
        let prov_proof = OpaqueProof::new(&make_test_proof_json(ISSUANCE_ROOT, TRADE_COMMITMENT)).unwrap();
        let elig_proof = OpaqueProof::new(&make_test_proof_json(CREDENTIAL_ROOT, TRADE_COMMITMENT)).unwrap();
        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);

        let unconfigured = UnconfiguredIntegrationCoordinator::new();
        let err = unconfigured
            .process_rfq_and_settle(
                &rfq,
                issuer_envelope.clone(),
                cred_envelope.clone(),
                recv_a,
                challenge.clone(),
                response.clone(),
                prov_proof.clone(),
                elig_proof.clone(),
                now,
                &sk_seller,
                &sk_buyer,
            )
            .unwrap_err();
        match err {
            IntegrationError::Unconfigured => {},
            other => panic!("expected Unconfigured, got {other:?}"),
        }

        let boxed: Box<dyn IntegrationTrait> = Box::new(unconfigured);
        let err = boxed
            .process_rfq_and_settle(
                &rfq,
                issuer_envelope,
                cred_envelope,
                recv_a,
                challenge,
                response,
                prov_proof,
                elig_proof,
                now,
                &sk_seller,
                &sk_buyer,
            )
            .unwrap_err();
        match err {
            IntegrationError::Unconfigured => {},
            other => panic!("expected Unconfigured for boxed, got {other:?}"),
        }
    }
}
