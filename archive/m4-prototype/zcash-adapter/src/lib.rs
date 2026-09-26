//! Zcash experimental ZSA adapter boundary — QEDIT pinned stack.
//!
//! This crate is reserved for the pinned experimental settlement integration.
//! It must not imply production mainnet support. Every implementation must
//! preserve QEDIT pins and experimental label.
//!
//! # Pinned QEDIT Stack (ADR 0003 + user request)
//!
//! - `zcash_tx_tool 6bcf2c5 (ADR 217b979ee01afb844190a162fb77874135aef587)`
//! - `zsa-swap 217b979`
//! - Zebra `0aef55c (0aef55cea41b83f17610e6ea708e59995f9e739f)`
//! - librustzcash `5a55da9 (5a55da948498dd0995d0f438b4c8e9a3f0150154)`
//! - orchard `d91aaf1 (d91aaf146364a06de1653e64f93b56fac5b3ca0f)`
//!
//! # Production Guarantees
//!
//! - No `unwrap()` / `expect()` in non-test — `#[deny(clippy::unwrap_used)]`
//! - No `unsafe` — `#[forbid(unsafe_code)]`
//! - Typed errors, distinct newtypes, fail-closed, experimental label preserved
//! - Canonical mapping preserved via `as_bytes()` no re-encoding
//! - `Box<dyn ZcashAdapter>` must work — trait object boundary
//!
//! # What Proves / Does NOT Prove
//!
//! ## Proves:
//! - QEDIT pins documented and enforced
//! - Experimental label `EXPERIMENTAL — NOT PRODUCTION MAINNET` must be shown in demo
//! - Opaque boundary — only from `MatcherApproval`
//! - Fail-closed when real stack not configured
//!
//! ## Does NOT Prove:
//! - Not production ZSA mainnet — experimental QEDIT branches only
//! - Not consensus-validated on mainnet
//! - Not wallet spending-key beyond Ed25519 in MVP

#![cfg_attr(test, allow(clippy::unwrap_used))]
#![allow(missing_docs)]

use zwa_protocol::bytes::OrchardReceiverBytes;
use zwa_protocol::numbers::UnixSeconds;

pub use zwa_settlement::zsa::{
    AtomicZsaTransaction, ExperimentalZsaBuilder, ZSA_STACK_PINS, ZsaStackPins,
    EXPERIMENTAL_ZSA_LABEL, ZSA_DOMAIN, MockExperimentalZsaAdapter, RealQeditZsaAdapter,
    ExperimentalZsaAdapter,
};
pub use zwa_settlement::{MatcherApproval, SettlementError, SettlementTxId};

/// Domain for Zcash adapter — frozen.
pub const ZCASH_ADAPTER_DOMAIN: &[u8] = b"ZWA-ZCASH-ADAPTER-V1-EXPERIMENTAL";

/// Errors from Zcash adapter — typed, fail-closed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ZcashAdapterError {
    #[error("zcash adapter unconfigured — fail-closed")]
    Unconfigured,

    #[error("construction failed: {reason}")]
    ConstructionFailed { reason: String },

    #[error("settlement error: {0}")]
    Settlement(#[from] SettlementError),
}

/// Opaque trait for Zcash experimental adapter — production boundary.
///
/// Only from `MatcherApproval`, never raw intent. `Box<dyn ZcashAdapter>` must work.
pub trait ZcashAdapter: Send + Sync + std::fmt::Debug {
    /// Constructs experimental ZSA transaction from approval — only path.
    fn construct(
        &self,
        approval: &MatcherApproval,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<AtomicZsaTransaction, ZcashAdapterError>;

    /// Constructs with explicit now — production expiry-gated.
    fn construct_at(
        &self,
        approval: &MatcherApproval,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
        now: UnixSeconds,
    ) -> Result<AtomicZsaTransaction, ZcashAdapterError>;

    /// Verifies atomic balance + experimental label + QEDIT pins.
    fn verify_balance(&self, tx: &AtomicZsaTransaction) -> Result<(), ZcashAdapterError>;
}

/// Mock Zcash adapter — simulates QEDIT stack without real node, MVP.
#[derive(Debug, Clone, Default)]
pub struct MockZcashAdapter {
    builder: ExperimentalZsaBuilder,
}

impl MockZcashAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            builder: ExperimentalZsaBuilder::new(),
        }
    }
}

impl ZcashAdapter for MockZcashAdapter {
    fn construct(
        &self,
        approval: &MatcherApproval,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<AtomicZsaTransaction, ZcashAdapterError> {
        self.builder
            .build_from_approval(approval, seller_receiver, buyer_receiver)
            .map_err(ZcashAdapterError::Settlement)
    }

    fn construct_at(
        &self,
        approval: &MatcherApproval,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
        now: UnixSeconds,
    ) -> Result<AtomicZsaTransaction, ZcashAdapterError> {
        // Production expiry check — frozen predicate
        if now.get() > approval.intent().expiry.get() {
            return Err(ZcashAdapterError::ConstructionFailed {
                reason: format!(
                    "trade expired at {}, now {}",
                    approval.intent().expiry.get(),
                    now.get()
                ),
            });
        }
        self.construct(approval, seller_receiver, buyer_receiver)
    }

    fn verify_balance(&self, tx: &AtomicZsaTransaction) -> Result<(), ZcashAdapterError> {
        if !tx.is_atomic_balanced() {
            return Err(ZcashAdapterError::ConstructionFailed {
                reason: "atomic balance check failed".to_string(),
            });
        }
        if !tx.experimental_label().contains("EXPERIMENTAL") {
            return Err(ZcashAdapterError::ConstructionFailed {
                reason: "experimental label missing".to_string(),
            });
        }
        if tx.stack_pins().zcash_tx_tool != ZSA_STACK_PINS.zcash_tx_tool {
            return Err(ZcashAdapterError::ConstructionFailed {
                reason: "QEDIT pins mismatch".to_string(),
            });
        }
        Ok(())
    }
}

/// Real QEDIT Zcash adapter placeholder — fail-closed, experimental.
#[derive(Debug, Clone, Default)]
pub struct RealQeditZcashAdapter;

impl RealQeditZcashAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ZcashAdapter for RealQeditZcashAdapter {
    fn construct(
        &self,
        _approval: &MatcherApproval,
        _seller_receiver: Option<OrchardReceiverBytes>,
        _buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<AtomicZsaTransaction, ZcashAdapterError> {
        Err(ZcashAdapterError::ConstructionFailed {
            reason: format!(
                "Real QEDIT ZSA adapter not configured — requires experimental branches: {} — Use MockZcashAdapter for MVP",
                EXPERIMENTAL_ZSA_LABEL
            ),
        })
    }

    fn construct_at(
        &self,
        _approval: &MatcherApproval,
        _seller_receiver: Option<OrchardReceiverBytes>,
        _buyer_receiver: Option<OrchardReceiverBytes>,
        _now: UnixSeconds,
    ) -> Result<AtomicZsaTransaction, ZcashAdapterError> {
        Err(ZcashAdapterError::ConstructionFailed {
            reason: "Real QEDIT adapter not configured".to_string(),
        })
    }

    fn verify_balance(&self, _tx: &AtomicZsaTransaction) -> Result<(), ZcashAdapterError> {
        Err(ZcashAdapterError::ConstructionFailed {
            reason: "Real QEDIT adapter not configured".to_string(),
        })
    }
}

/// Unconfigured Zcash adapter — fail-closed.
#[derive(Debug, Clone, Default)]
pub struct UnconfiguredZcashAdapter;

impl UnconfiguredZcashAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ZcashAdapter for UnconfiguredZcashAdapter {
    fn construct(
        &self,
        _approval: &MatcherApproval,
        _seller_receiver: Option<OrchardReceiverBytes>,
        _buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<AtomicZsaTransaction, ZcashAdapterError> {
        Err(ZcashAdapterError::Unconfigured)
    }

    fn construct_at(
        &self,
        _approval: &MatcherApproval,
        _seller_receiver: Option<OrchardReceiverBytes>,
        _buyer_receiver: Option<OrchardReceiverBytes>,
        _now: UnixSeconds,
    ) -> Result<AtomicZsaTransaction, ZcashAdapterError> {
        Err(ZcashAdapterError::Unconfigured)
    }

    fn verify_balance(&self, _tx: &AtomicZsaTransaction) -> Result<(), ZcashAdapterError> {
        Err(ZcashAdapterError::Unconfigured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use zwa_credentials::{AuthorityKeyId, IssuerKeyId};
    use zwa_matcher::control::{RecipientControlChallenge, RecipientControlResponse, CONTROL_DOMAIN};
    use zwa_matcher::replay::{InMemoryPersistence, PersistentReplayStore};
    use zwa_matcher::roots::{CredentialRootAuthenticator, IssuerRootAuthenticator};
    use zwa_matcher::{GateInput, MatcherGate};
    use zwa_protocol::bytes::OrchardReceiverBytes;
    use zwa_protocol::numbers::{RootVersion, TradeExpiry, UnixSeconds};
    use zwa_protocol::proof::{
        EligibilityVerifier, OpaqueProof, ProvenanceVerifier, VerificationProblem, VerificationResult,
    };
    use zwa_protocol::{
        AssetBaseBytes, AuthorizedIssuanceRoot, ActiveCredentialRoot, MatcherFee, OpaqueSignature,
        PolicyRoot, RecipientCommitment, SubjectCommitment, TradeAmount, TradeCommitment, TradeNonce,
        ZatoshiAmount, TradeIntent,
    };
    use ed25519_dalek::Signer;

    const ISSUANCE_ROOT: &str = "19309979006225485291788213177219598381134511159668519266888323889569746782051";
    const CREDENTIAL_ROOT: &str = "7239536478138432754387625126231950010993505962177483323536139232738771167323";
    const TRADE_COMMITMENT: &str = "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    const RECEIVER_A_HEX: &str = "781671f8a41294c866d8161f3bf5f84a8fd2c328f91a2d085a66036acd59439731c36c4f1b99b4d64be233";

    /// Phase 0G subject commitment for the golden recipient (F-02 receiver binding).
    const SUBJECT_COMMITMENT: &str = "8182499163832458428983635402341439692935005683808059285091898351261831993662";

    /// Test-only proof verifier injected through the frozen traits (the matcher
    /// has no mock-proof fallback in any build — M2 remediation F-01). Accepts
    /// only `test_proof(root, commitment)` for the exact root and commitment.
    #[derive(Debug, Clone, Copy, Default)]
    struct TestProofVerifier;

    impl TestProofVerifier {
        fn check(root: String, commitment: TradeCommitment, proof: &OpaqueProof) -> VerificationResult {
            if proof.as_bytes() == test_proof(&root, &commitment.to_string()).as_slice() {
                VerificationResult::Valid
            } else {
                VerificationResult::Invalid {
                    reason: VerificationProblem::ProofRejected,
                }
            }
        }
    }

    impl ProvenanceVerifier for TestProofVerifier {
        fn verify(&self, root: AuthorizedIssuanceRoot, commitment: TradeCommitment, proof: &OpaqueProof) -> VerificationResult {
            Self::check(root.to_string(), commitment, proof)
        }
    }

    impl EligibilityVerifier for TestProofVerifier {
        fn verify(&self, root: ActiveCredentialRoot, commitment: TradeCommitment, proof: &OpaqueProof) -> VerificationResult {
            Self::check(root.to_string(), commitment, proof)
        }
    }

    fn test_proof(root: &str, commitment: &str) -> Vec<u8> {
        format!("zwa-adapter-test-proof|{root}|{commitment}").into_bytes()
    }

    type TestGate<P> = MatcherGate<P, TestProofVerifier, TestProofVerifier>;

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
        let replay = PersistentReplayStore::new(InMemoryPersistence::new(), 3).unwrap();
        let gate = MatcherGate::new(issuer_auth, cred_auth, control_auth, TestProofVerifier, TestProofVerifier, replay);
        (gate, recv_a, issuer_envelope, cred_envelope, sk_control)
    }

    fn valid_approval() -> MatcherApproval {
        let (gate, recv_a, issuer_envelope, cred_envelope, sk_control) = build_gate();
        let intent = golden_intent();
        let commitment = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let now = UnixSeconds::new(1_900_000_100);
        let challenge = RecipientControlChallenge::new(recv_a, [7u8; 32], CONTROL_DOMAIN.to_vec(), UnixSeconds::new(1_900_000_000), UnixSeconds::new(2_100_000_000), commitment).unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);
        let prov_proof = OpaqueProof::new(&test_proof(ISSUANCE_ROOT, TRADE_COMMITMENT)).unwrap();
        let elig_proof = OpaqueProof::new(&test_proof(CREDENTIAL_ROOT, TRADE_COMMITMENT)).unwrap();
        let input = GateInput { intent, commitment, issuer_envelope, credential_envelope: cred_envelope, approved_receiver: recv_a, recipient_subject_commitment: SubjectCommitment::from_decimal_str(SUBJECT_COMMITMENT).unwrap(), control_challenge: challenge, control_response: response, provenance_proof: prov_proof, eligibility_proof: elig_proof, now };
        gate.evaluate(input).unwrap()
    }

    #[test]
    fn mock_zcash_adapter_builds_atomic_balanced_with_pins_and_label() {
        let approval = valid_approval();
        let adapter = MockZcashAdapter::new();
        let recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let tx = adapter.construct(&approval, Some(recv), Some(recv)).unwrap();
        assert!(tx.is_atomic_balanced());
        assert!(tx.experimental_label().contains("EXPERIMENTAL"));
        assert_eq!(tx.stack_pins().zcash_tx_tool, "6bcf2c5");
        adapter.verify_balance(&tx).unwrap();
    }

    #[test]
    fn real_qedit_adapter_fail_closed_with_experimental_message() {
        let approval = valid_approval();
        let real = RealQeditZcashAdapter::new();
        let recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let err = real.construct(&approval, Some(recv), Some(recv)).unwrap_err();
        match err {
            ZcashAdapterError::ConstructionFailed { reason } => {
                assert!(reason.contains("QEDIT"));
                assert!(reason.contains("EXPERIMENTAL"));
            },
            other => panic!("expected ConstructionFailed, got {other:?}"),
        }
    }

    #[test]
    fn trait_object_works() {
        let approval = valid_approval();
        let mock = MockZcashAdapter::new();
        let boxed: Box<dyn ZcashAdapter> = Box::new(mock);
        let recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let tx = boxed.construct(&approval, Some(recv), Some(recv)).unwrap();
        assert!(tx.is_atomic_balanced());
    }

    #[test]
    fn unconfigured_fail_closed() {
        let approval = valid_approval();
        let unconfigured = UnconfiguredZcashAdapter::new();
        let recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let err = unconfigured.construct(&approval, Some(recv), Some(recv)).unwrap_err();
        match err {
            ZcashAdapterError::Unconfigured => {},
            other => panic!("expected Unconfigured, got {other:?}"),
        }
    }
}
