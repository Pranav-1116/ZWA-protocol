//! 10-step deterministic matcher gate — Task F.
//!
//! Combines Tasks A-E into a single allow/block decision per handbook Sec 15:
//!
//! 1. Parse canonical TradeIntent + TradeCommitmentV1 (already typed)
//! 2. Verify intent/commitment correspondence → CheckedTrade (Task A, ZWA-REL-001)
//! 3. Authenticate issuer + credential root signatures vs approved keyset (Task B)
//! 4. Require current version, freshness, trade_expiry ≤ root_expiry, combined min (Task B)
//! 5. Verify live wallet control of authority-approved receiver (Task C)
//! 6. Verify trade expiry + replay state permit verification (Task E)
//! 7. Verify provenance proof vs authorizedIssuanceRoot + checked commitment (Task D)
//! 8. Verify eligibility Phase1B proof vs activeCredentialRoot + same commitment (Task D)
//! 9. Acquire settlement construction only after 1-8 succeed (Task E compare-and-set)
//! 10. Return VerifiedTrade to settlement adapter (Phase 3 later)
//!
//! The matcher must not fork commitment logic, byte encodings, root serialization,
//! or replay semantics. Phase 1 remains single source of truth.

use zwa_credentials::{CredentialRootEnvelope, IssuerRootEnvelope};
use zwa_protocol::bytes::OrchardReceiverBytes;
use zwa_protocol::numbers::UnixSeconds;
use zwa_protocol::proof::{OpaqueProof, VerificationResult};
use zwa_protocol::{TradeCommitment, TradeIntent};

use crate::checked::CheckedTrade;
use crate::control::{ControlError, RecipientControlAuthenticator, RecipientControlChallenge, RecipientControlResponse, VerifiedRecipientControl};
use crate::replay::{PersistentReplayStore, ReplayError, ReplayPersistence};
use crate::roots::{
    check_combined_root_expiry, AuthenticatedCredentialRoot, AuthenticatedIssuerRoot,
    CredentialRootAuthenticator, IssuerRootAuthenticator, RootAuthError,
};
use crate::verifiers::{EligibilityVerifierBackend, MatcherProofGate, ProvenanceVerifierBackend};

/// Typed rejection reasons for deterministic allow/block decision.
///
/// Every failure path is a distinct variant — no untyped strings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GateRejection {
    #[error("commitment mismatch: expected {expected}, actual {actual}")]
    CommitmentMismatch { expected: String, actual: String },

    #[error("root authentication failed: {0}")]
    RootAuth(#[from] RootAuthError),

    #[error("recipient control failed: {0}")]
    Control(#[from] ControlError),

    #[error("replay error: {0}")]
    Replay(#[from] ReplayError),

    #[error("trade expired at {expiry}, now {now}")]
    ExpiredTrade { expiry: u64, now: u64 },

    #[error("proof invalid: {0:?}")]
    ProofInvalid(VerificationResult),

    #[error("trade already consumed")]
    AlreadyConsumed,

    #[error("trade already expired")]
    AlreadyExpired,

    #[error("trade in illegal state for verification: {state:?}")]
    IllegalState { state: String },

    #[error("approved receiver mismatch: expected {expected:?}, got {got:?}")]
    ApprovedReceiverMismatch {
        expected: OrchardReceiverBytes,
        got: OrchardReceiverBytes,
    },
}

/// A trade that has passed the full matcher gate and is ready for settlement construction.
#[derive(Debug, Clone)]
pub struct VerifiedTrade {
    /// Checked intent/commitment witness (Task A).
    pub checked_trade: CheckedTrade,
    /// Authenticated issuer root (Task B).
    pub authenticated_issuer_root: AuthenticatedIssuerRoot,
    /// Authenticated credential root (Task B).
    pub authenticated_credential_root: AuthenticatedCredentialRoot,
    /// Verified live control of approved receiver (Task C).
    pub verified_control: VerifiedRecipientControl,
}

/// Inputs for gate evaluation — bundles all data the matcher needs.
#[derive(Debug, Clone)]
pub struct GateInput {
    /// Canonical trade intent.
    pub intent: TradeIntent,
    /// Presented trade commitment.
    pub commitment: TradeCommitment,
    /// Issuer root envelope (signed).
    pub issuer_envelope: IssuerRootEnvelope,
    /// Credential root envelope (signed).
    pub credential_envelope: CredentialRootEnvelope,
    /// Authority-approved receiver from credential leaf (Phase 1B).
    pub approved_receiver: OrchardReceiverBytes,
    /// Control challenge issued by matcher.
    pub control_challenge: RecipientControlChallenge,
    /// Control response from wallet.
    pub control_response: RecipientControlResponse,
    /// Provenance proof (OpaqueProof).
    pub provenance_proof: OpaqueProof,
    /// Eligibility proof (OpaqueProof).
    pub eligibility_proof: OpaqueProof,
    /// Current time for freshness/expiry checks.
    pub now: UnixSeconds,
}

/// Matcher gate — deterministic allow/block decision combining A-E.
///
/// Holds all authenticators, verifiers, and persistent replay store.
///
/// # Thread safety
///
/// `PersistentReplayStore` is thread-safe via `Mutex<ReplayStore>`.
pub struct MatcherGate<P: ReplayPersistence> {
    issuer_authenticator: IssuerRootAuthenticator,
    credential_authenticator: CredentialRootAuthenticator,
    control_authenticator: RecipientControlAuthenticator,
    provenance_verifier: ProvenanceVerifierBackend,
    eligibility_verifier: EligibilityVerifierBackend,
    replay_store: PersistentReplayStore<P>,
}

impl<P: ReplayPersistence> MatcherGate<P> {
    /// Builds gate with all components.
    #[must_use]
    pub fn new(
        issuer_authenticator: IssuerRootAuthenticator,
        credential_authenticator: CredentialRootAuthenticator,
        control_authenticator: RecipientControlAuthenticator,
        provenance_verifier: ProvenanceVerifierBackend,
        eligibility_verifier: EligibilityVerifierBackend,
        replay_store: PersistentReplayStore<P>,
    ) -> Self {
        Self {
            issuer_authenticator,
            credential_authenticator,
            control_authenticator,
            provenance_verifier,
            eligibility_verifier,
            replay_store,
        }
    }

    /// Returns replay store reference (for inspection).
    #[must_use]
    pub fn replay_store(&self) -> &PersistentReplayStore<P> {
        &self.replay_store
    }

    /// Evaluates trade through 10-step gate.
    ///
    /// Returns `VerifiedTrade` on ALLOW, `GateRejection` on BLOCK.
    ///
    /// Steps:
    /// 1. Parse (already typed)
    /// 2. CheckedTrade::new — commitment correspondence (Task A)
    /// 3. Auth issuer + credential roots (Task B)
    /// 4. Current version, freshness, trade_expiry ≤ root_expiry, combined min (Task B)
    /// 5. Live wallet control of approved receiver (Task C)
    /// 6. Trade expiry + replay state (Task E)
    /// 7. Provenance proof vs issuer root + same commitment (Task D)
    /// 8. Eligibility proof vs credential root + same commitment (Task D)
    /// 9. Acquire construction (Task E)
    /// 10. Return VerifiedTrade
    pub fn evaluate(&self, input: GateInput) -> Result<VerifiedTrade, GateRejection> {
        // Step 1: Parse — already typed TradeIntent + TradeCommitment, no ticker/symbol fields.

        // Step 2: Checked trade context — fix ZWA-REL-001
        let checked_trade = CheckedTrade::new(input.intent, input.commitment).map_err(|e| {
            match e {
                zwa_protocol::error::ProtocolError::CommitmentMismatch { expected, actual } => {
                    GateRejection::CommitmentMismatch { expected, actual }
                }
                other => GateRejection::Replay(ReplayError::Protocol(other)),
            }
        })?;

        // Step 6a: Trade expiry check before any heavy work (frozen predicate now > expiry)
        if checked_trade.intent().is_expired_at(input.now) {
            return Err(GateRejection::ExpiredTrade {
                expiry: checked_trade.intent().expiry.get(),
                now: input.now.get(),
            });
        }

        // Step 3 & 4: Authenticate roots
        let auth_issuer = self
            .issuer_authenticator
            .authenticate(
                &input.issuer_envelope,
                input.now,
                checked_trade.intent().expiry,
            )
            .map_err(GateRejection::RootAuth)?;

        let auth_cred = self
            .credential_authenticator
            .authenticate(
                &input.credential_envelope,
                input.now,
                checked_trade.intent().expiry,
            )
            .map_err(GateRejection::RootAuth)?;

        // Combined expiry: trade_expiry ≤ min(issuer, credential)
        check_combined_root_expiry(
            checked_trade.intent().expiry,
            &auth_issuer,
            &auth_cred,
        )
        .map_err(GateRejection::RootAuth)?;

        // Step 5: Live wallet control of authority-approved receiver
        // 5a: Trade expiry vs challenge expiry
        RecipientControlAuthenticator::check_trade_expiry(
            checked_trade.intent().expiry,
            &input.control_challenge,
        )
        .map_err(GateRejection::Control)?;

        // 5b: Trade commitment binding — challenge must be bound to this trade
        RecipientControlAuthenticator::check_trade_commitment(
            checked_trade.commitment(),
            &input.control_challenge,
        )
        .map_err(GateRejection::Control)?;

        let verified_control = self
            .control_authenticator
            .verify_against_approved_receiver(
                &input.control_challenge,
                &input.control_response,
                &input.approved_receiver,
                input.now,
            )
            .map_err(GateRejection::Control)?;

        // Step 6b: Replay state — create or recover, then verify
        // Enforces canonical lifecycle, terminal CONSUMED/EXPIRED, retry budget
        let commitment = checked_trade.commitment();
        let state_opt = self.replay_store.state(commitment);

        match state_opt {
            None => {
                // No record — create via checked trade only
                self.replay_store
                    .create_checked(&checked_trade)
                    .map_err(GateRejection::Replay)?;
            }
            Some(s) => {
                use zwa_protocol::lifecycle::TradeLifecycleState;
                match s {
                    TradeLifecycleState::Created => {
                        // Will verify below
                    }
                    TradeLifecycleState::Failed => {
                        // For gate, we require caller to have retried? For simplicity,
                        // we attempt retry with acknowledged txid None if no prior txid,
                        // else need to handle. Here we try to retry with None and if it fails
                        // due to txid, we return IllegalState to force explicit retry handling
                        // outside gate. For MVP gate, we will attempt to retry with the
                        // persisted prior_txid if any.
                        let existing = self.replay_store.get(commitment);
                        let ack = existing.and_then(|r| r.prior_txid());
                        // If retry fails, propagate as Replay error
                        match self.replay_store.retry_after_failure(commitment, ack, input.now) {
                            Ok(_) => {}
                            Err(e) => return Err(GateRejection::Replay(e)),
                        }
                    }
                    TradeLifecycleState::Verified => {
                        // Already verified — proceed to proof checks
                    }
                    TradeLifecycleState::SettlementConstructed
                    | TradeLifecycleState::Submitted
                    | TradeLifecycleState::Confirmed => {
                        return Err(GateRejection::IllegalState {
                            state: format!("{s:?}"),
                        });
                    }
                    TradeLifecycleState::Consumed => {
                        return Err(GateRejection::AlreadyConsumed);
                    }
                    TradeLifecycleState::Expired => {
                        return Err(GateRejection::AlreadyExpired);
                    }
                }
            }
        }

        // Now ensure state is CREATED then verify, or already VERIFIED
        let current_state = self.replay_store.state(commitment);
        if let Some(zwa_protocol::lifecycle::TradeLifecycleState::Created) = current_state {
            self.replay_store
                .verify(commitment, input.now)
                .map_err(GateRejection::Replay)?;
        }

        // Verify state is now VERIFIED before proof checks
        match self.replay_store.state(commitment) {
            Some(zwa_protocol::lifecycle::TradeLifecycleState::Verified) => {}
            Some(s) => {
                return Err(GateRejection::IllegalState {
                    state: format!("{s:?} after verify"),
                })
            }
            None => {
                return Err(GateRejection::IllegalState {
                    state: "no record after create".to_string(),
                })
            }
        }

        // Step 7 & 8: Proof verification against same checked commitment
        let proof_gate = MatcherProofGate::new(
            checked_trade,
            self.provenance_verifier.clone(),
            self.eligibility_verifier.clone(),
        );

        proof_gate
            .verify_both(
                &auth_issuer,
                &auth_cred,
                &input.provenance_proof,
                &input.eligibility_proof,
            )
            .map_err(GateRejection::ProofInvalid)?;

        // Step 9: Acquire settlement construction — compare-and-set lock, expiry-gated
        self.replay_store
            .acquire_construction(commitment, input.now)
            .map_err(GateRejection::Replay)?;

        // Step 10: Return verified trade ready for settlement adapter
        Ok(VerifiedTrade {
            checked_trade,
            authenticated_issuer_root: auth_issuer,
            authenticated_credential_root: auth_cred,
            verified_control,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{RecipientControlChallenge, RecipientControlResponse, CONTROL_DOMAIN};
    use crate::replay::{InMemoryPersistence, PersistentReplayStore};
    use crate::roots::{CredentialRootAuthenticator, IssuerRootAuthenticator};
    use crate::verifiers::{EligibilityVerifierBackend, ProvenanceVerifierBackend, make_test_proof_json};
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use zwa_credentials::{AuthorityKeyId, IssuerKeyId};
    use zwa_protocol::bytes::OrchardReceiverBytes;
    use zwa_protocol::numbers::{RootVersion, TradeExpiry, UnixSeconds};
    use zwa_protocol::proof::OpaqueProof;
    use zwa_protocol::{
        AssetBaseBytes, AuthorizedIssuanceRoot, ActiveCredentialRoot, MatcherFee, OpaqueSignature,
        PolicyRoot, RecipientCommitment, TradeAmount, TradeNonce, ZatoshiAmount, TradeIntent,
    };

    const ISSUANCE_ROOT: &str =
        "19309979006225485291788213177219598381134511159668519266888323889569746782051";
    const CREDENTIAL_ROOT: &str =
        "7239536478138432754387625126231950010993505962177483323536139232738771167323";
    const TRADE_COMMITMENT: &str =
        "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    const RECEIVER_A_HEX: &str =
        "781671f8a41294c866d8161f3bf5f84a8fd2c328f91a2d085a66036acd59439731c36c4f1b99b4d64be233";
    const RECEIVER_B_HEX: &str =
        "ba5a9b6828e14d720cc41e998917f5996635d1a7fa84448cb118f7b6f65068d380099e5cd54d98dd3917bb";

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

    fn build_gate() -> (
        MatcherGate<InMemoryPersistence>,
        OrchardReceiverBytes,
        IssuerRootEnvelope,
        CredentialRootEnvelope,
        SigningKey,
    ) {
        // Issuer keys
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

        // Credential keys
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

        // Control keys — receiver A controlled by sk_control
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        let control_auth = crate::control::RecipientControlAuthenticator::new(approved_control, CONTROL_DOMAIN.to_vec());

        let replay = PersistentReplayStore::new(InMemoryPersistence::new(), 3);

        let gate = MatcherGate::new(
            issuer_auth,
            cred_auth,
            control_auth,
            ProvenanceVerifierBackend::default(),
            EligibilityVerifierBackend::default(),
            replay,
        );

        (gate, recv_a, issuer_envelope, cred_envelope, sk_control)
    }

    fn valid_gate_input() -> (
        GateInput,
        MatcherGate<InMemoryPersistence>,
    ) {
        let (gate, recv_a, issuer_envelope, cred_envelope, sk_control) = build_gate();
        let intent = golden_intent();
        let commitment = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();

        let now = UnixSeconds::new(1_900_000_100);
        let challenge = RecipientControlChallenge::new(
            recv_a,
            [7u8; 32],
            CONTROL_DOMAIN.to_vec(),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(1_900_000_300),
            commitment,
        )
        .unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);

        let prov_proof = OpaqueProof::new(&make_test_proof_json(ISSUANCE_ROOT, TRADE_COMMITMENT)).unwrap();
        let elig_proof = OpaqueProof::new(&make_test_proof_json(CREDENTIAL_ROOT, TRADE_COMMITMENT)).unwrap();

        let input = GateInput {
            intent,
            commitment,
            issuer_envelope,
            credential_envelope: cred_envelope,
            approved_receiver: recv_a,
            control_challenge: challenge,
            control_response: response,
            provenance_proof: prov_proof,
            eligibility_proof: elig_proof,
            now,
        };

        (input, gate)
    }

    #[test]
    fn gate_allows_valid_private_trade() {
        let (input, gate) = valid_gate_input();
        let verified = gate.evaluate(input).unwrap();
        assert_eq!(verified.checked_trade.commitment().to_string(), TRADE_COMMITMENT);
        assert_eq!(verified.authenticated_issuer_root.root().to_string(), ISSUANCE_ROOT);
        assert_eq!(verified.authenticated_credential_root.root().to_string(), CREDENTIAL_ROOT);
    }

    #[test]
    fn gate_blocks_unauthorized_asset_commitment_mismatch() {
        // Authorized asset with convincing name but wrong AssetBase → commitment mismatch
        let (mut input, gate) = valid_gate_input();
        input.intent.offered_amount = TradeAmount::new(999); // mutate committed field
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::CommitmentMismatch { .. } => {}
            other => panic!("expected CommitmentMismatch, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_wrong_investor_class_via_eligibility_proof() {
        // Valid asset, wrong investor class → eligibility proof has wrong public inputs
        let (mut input, gate) = valid_gate_input();
        // Make eligibility proof for different commitment (simulating wrong class proof)
        let bad_proof = OpaqueProof::new(&make_test_proof_json(CREDENTIAL_ROOT, "7409670081847436957289371955571360481923983184454289247710022466448715682310")).unwrap();
        input.eligibility_proof = bad_proof;
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::ProofInvalid(_) => {}
            other => panic!("expected ProofInvalid, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_valid_credential_but_receiver_not_approved() {
        // Credential approves A, but trade tries to settle to B → control challenge for B vs approved A
        let (mut input, gate) = valid_gate_input();
        let recv_b = OrchardReceiverBytes::from_hex(RECEIVER_B_HEX).unwrap();
        // Challenge for B, but approved is A
        let commitment_b = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let challenge_b = RecipientControlChallenge::new(
            recv_b,
            [8u8; 32],
            CONTROL_DOMAIN.to_vec(),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(1_900_000_300),
            commitment_b,
        ).unwrap();
        let sk_b = signing_key(9);
        let response_b = RecipientControlResponse::sign(&challenge_b, &sk_b);
        input.control_challenge = challenge_b;
        input.control_response = response_b;
        // approved_receiver still A, so mismatch
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::Control(ControlError::ApprovedReceiverMismatch { .. }) => {}
            other => panic!("expected ApprovedReceiverMismatch, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_approved_receiver_without_wallet_control() {
        // Approved A, but no control key for A (or invalid sig)
        let (mut input, gate) = valid_gate_input();
        // Use different signing key not in approved_control_keys
        let sk_other = signing_key(99);
        let response_bad = RecipientControlResponse::sign(&input.control_challenge, &sk_other);
        input.control_response = response_bad;
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::Control(ControlError::SignatureVerificationFailed { .. }) => {}
            other => panic!("expected SignatureVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_expired_trade_and_stale_root() {
        let (mut input, gate) = valid_gate_input();
        // Expired trade
        input.now = UnixSeconds::new(2_000_000_001);
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::ExpiredTrade { .. } => {}
            other => panic!("expected ExpiredTrade, got {other:?}"),
        }

        // Stale root tested in Task B, but gate also blocks via RootAuth
        let (mut input2, gate2) = valid_gate_input();
        // Make issuer envelope version 2 while authenticator expects 1? Actually build_gate expects 1, so version 2 is stale? No, current is 1, version 2 != current → VersionNotCurrent
        // We need to build a new envelope with version 2
        let sk_issuer = signing_key(1);
        let issuer_payload_v2 = zwa_credentials::IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap(),
            IssuerKeyId::new(b"issuer-atlas").unwrap(),
            RootVersion::new(2),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        ).unwrap();
        let sig = sk_issuer.sign(&issuer_payload_v2.canonical_bytes());
        let envelope_v2 = zwa_credentials::IssuerRootEnvelope::new(issuer_payload_v2, OpaqueSignature::new(&sig.to_bytes()).unwrap());
        input2.issuer_envelope = envelope_v2;
        let err = gate2.evaluate(input2).unwrap_err();
        match err {
            GateRejection::RootAuth(RootAuthError::VersionNotCurrent { .. }) => {}
            other => panic!("expected VersionNotCurrent, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_proof_splicing_from_different_trades() {
        // Proof A from trade A, proof B from trade B with different commitment → must fail
        let (mut input, gate) = valid_gate_input();
        let spliced_elig = OpaqueProof::new(&make_test_proof_json(CREDENTIAL_ROOT, "4141140993944283635059564795814979270169431233615041812756992202222578526061")).unwrap();
        input.eligibility_proof = spliced_elig;
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::ProofInvalid(_) => {}
            other => panic!("expected ProofInvalid for splicing, got {other:?}"),
        }
    }

    #[test]
    fn gate_acquires_construction_only_after_all_gates_pass() {
        let (input, gate) = valid_gate_input();
        let commitment = input.commitment;
        // Before evaluate, no record
        assert!(gate.replay_store().state(commitment).is_none());

        let _verified = gate.evaluate(input).unwrap();

        // After evaluate, state must be SETTLEMENT_CONSTRUCTED (acquired)
        assert_eq!(
            gate.replay_store().state(commitment),
            Some(zwa_protocol::lifecycle::TradeLifecycleState::SettlementConstructed)
        );

        // Second evaluate must fail — already in SETTLEMENT_CONSTRUCTED, not allowed to re-verify
        let (input2, _) = valid_gate_input();
        // Need new gate with same replay store that already has SETTLEMENT_CONSTRUCTED
        // For this test, we reuse same gate which already has that state
        let err = gate.evaluate(input2).unwrap_err();
        match err {
            GateRejection::IllegalState { .. } => {}
            other => panic!("expected IllegalState for double construction, got {other:?}"),
        }
    }
}
