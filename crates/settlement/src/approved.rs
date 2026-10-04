//! `ApprovedSettlement`: the M3 output and the M3/M4 handoff (§7).
//!
//! ```text
//! MatcherApproval (M2, consumed) + negotiated RfqRequest
//!   + seller PartyKeyAttestation + buyer PartyKeyAttestation
//!     (verified against the configured PartyAttestationTrustRoot)
//!   + seller PartyAuthorization + buyer PartyAuthorization
//!     (each signed by the attested key for its role)
//!         ── SettlementAuthorizer::approve ──▶ ApprovedSettlement ──▶ M4
//! ```
//!
//! M3 verifies credential-authority-attested party consent for the exact
//! M2-approved trade. M3 does not hold spending authority. M4 requires each
//! party's wallet to authorize its own Zcash spend.
//!
//! M3 stops here. It constructs, signs, submits and confirms nothing on Zcash.

use sha2::{Digest, Sha256};
use zwa_matcher::MatcherApproval;
use zwa_protocol::bytes::{AssetBaseBytes, OrchardReceiverBytes};
use zwa_protocol::numbers::{TradeAmount, TradeExpiry, TradeNonce, UnixSeconds, ZatoshiAmount};
use zwa_protocol::{PolicyRoot, RecipientCommitment, TradeCommitment, TradeIntent};

use crate::attestation::{
    AttestationError, AttestedPartyIdentity, PartyAttestationTrustRoot, PartyKeyAttestation,
};
use crate::party_auth::{
    verify_party_authorization, ExpectedParties, PartyAuthError, PartyAuthorization,
    PartyAuthorizationRequest, PartyRole, VerifiedPartyAuthorization,
};
use crate::rfq::RfqRequest;

/// Domain tag of the handoff digest.
pub const APPROVED_SETTLEMENT_DOMAIN: &[u8] = b"ZWA1APPROVEDSETTLEMENT";
/// Version byte of the handoff digest.
///
/// Version 2 adds the authority-attested party identities (DR-M3-01).
pub const APPROVED_SETTLEMENT_VERSION: u8 = 2;

/// Reasons `approve` refuses to produce an `ApprovedSettlement` (fail closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ApprovalError {
    /// The M2 approval is internally inconsistent (defence in depth).
    #[error("M2 approval is inconsistent: {reason}")]
    InconsistentApproval {
        /// What did not match.
        reason: &'static str,
    },
    /// A negotiated term differs from the M2-approved trade.
    #[error("negotiated term `{field}` differs from the M2-approved trade")]
    TermsMismatch {
        /// First differing field.
        field: &'static str,
    },
    /// `now > trade expiry`.
    #[error("trade expired: now {now} > expiry {expiry}")]
    TradeExpired {
        /// Evaluation time.
        now: u64,
        /// Trade expiry.
        expiry: u64,
    },
    /// No seller authorization submitted.
    #[error("seller authorization missing")]
    MissingSellerAuthorization,
    /// No buyer authorization submitted.
    #[error("buyer authorization missing")]
    MissingBuyerAuthorization,
    /// The seller's party-key attestation was rejected.
    #[error("seller party-key attestation rejected: {0}")]
    SellerAttestation(AttestationError),
    /// The buyer's party-key attestation was rejected.
    #[error("buyer party-key attestation rejected: {0}")]
    BuyerAttestation(AttestationError),
    /// Both attestations name the same party id.
    #[error("seller and buyer attestations name the same party")]
    SamePartyForBothRoles,
    /// The attested keys cannot form a valid seller/buyer pair (for example
    /// both attestations carry the same key).
    #[error("attested party keys are unusable: {0}")]
    Identity(PartyAuthError),
    /// The seller authorization was rejected.
    #[error("seller authorization rejected: {0}")]
    Seller(PartyAuthError),
    /// The buyer authorization was rejected.
    #[error("buyer authorization rejected: {0}")]
    Buyer(PartyAuthError),
    /// Integrity re-check failed.
    #[error("approved settlement integrity check failed: {reason}")]
    IntegrityViolation {
        /// What failed.
        reason: &'static str,
    },
}

/// One party's submission: the request the server issued, the party's
/// authority-signed key attestation and the party's returned authorization.
#[derive(Debug, Clone, Copy)]
pub struct PartySubmission<'a> {
    /// Authority-signed attestation of this party's authorization key.
    pub attestation: &'a PartyKeyAttestation,
    /// The request the server issued (server-side record, not client data).
    pub issued: &'a PartyAuthorizationRequest,
    /// The party's returned authorization.
    pub authorization: &'a PartyAuthorization,
}

/// Produces `ApprovedSettlement`s. Holds only the operator-configured
/// party-key trust root (public authority keys): no private keys, no replay
/// state, no settlement adapter.
#[derive(Debug, Clone)]
pub struct SettlementAuthorizer {
    trust_root: PartyAttestationTrustRoot,
}

impl SettlementAuthorizer {
    /// Authorizer that accepts party keys attested by an authority in
    /// `trust_root`. An empty trust root fails closed.
    #[must_use]
    pub const fn new(trust_root: PartyAttestationTrustRoot) -> Self {
        Self { trust_root }
    }

    /// The configured party-key trust root.
    #[must_use]
    pub const fn trust_root(&self) -> &PartyAttestationTrustRoot {
        &self.trust_root
    }

    /// The only way to obtain an [`ApprovedSettlement`].
    ///
    /// Consumes the M2 `approval`, so one approval yields at most one
    /// settlement. Checks, in order:
    ///
    /// 1. the approval is self-consistent: `TradeCommitmentV1(intent) ==
    ///    commitment`, and M2's recipient control is bound to the same trade;
    /// 2. the negotiated `terms` equal the approved intent exactly;
    /// 3. the trade is not expired (`now > expiry`);
    /// 4. both submissions are present;
    /// 5. the seller attestation verifies against the trust root for the
    ///    `Seller` role at `now`, then the buyer attestation for `Buyer`;
    /// 6. the two attestations name different parties and different keys;
    /// 7. the seller submission is a `Seller` request for this trade, signed by
    ///    the attested seller key; the buyer submission likewise.
    ///
    /// # Errors
    ///
    /// The first failing check as an [`ApprovalError`].
    pub fn approve(
        &self,
        approval: MatcherApproval,
        terms: &RfqRequest,
        seller: Option<PartySubmission<'_>>,
        buyer: Option<PartySubmission<'_>>,
        now: UnixSeconds,
    ) -> Result<ApprovedSettlement, ApprovalError> {
        let trade_commitment = approval.commitment();
        let intent = approval.intent();
        if zwa_commitments::trade::trade_commitment_v1(&intent) != trade_commitment {
            return Err(ApprovalError::InconsistentApproval {
                reason: "intent does not recompute to the approved commitment",
            });
        }
        let control = approval.verified_control();
        if control.trade_commitment() != trade_commitment {
            return Err(ApprovalError::InconsistentApproval {
                reason: "recipient control is bound to another trade",
            });
        }
        let settlement_receiver = *control.receiver();

        terms
            .ensure_matches(&intent)
            .map_err(|m| ApprovalError::TermsMismatch { field: m.field })?;

        if intent.is_expired_at(now) {
            return Err(ApprovalError::TradeExpired {
                now: now.get(),
                expiry: intent.expiry.get(),
            });
        }

        let seller = seller.ok_or(ApprovalError::MissingSellerAuthorization)?;
        let buyer = buyer.ok_or(ApprovalError::MissingBuyerAuthorization)?;

        let seller_identity = self
            .trust_root
            .verify(seller.attestation, PartyRole::Seller, now)
            .map_err(ApprovalError::SellerAttestation)?;
        let buyer_identity = self
            .trust_root
            .verify(buyer.attestation, PartyRole::Buyer, now)
            .map_err(ApprovalError::BuyerAttestation)?;
        if seller_identity.party() == buyer_identity.party() {
            return Err(ApprovalError::SamePartyForBothRoles);
        }
        // The expected keys come only from the verified attestations.
        let expected =
            ExpectedParties::new(*seller_identity.party_key(), *buyer_identity.party_key())
                .map_err(ApprovalError::Identity)?;

        let seller_evidence =
            verify_slot(PartyRole::Seller, trade_commitment, seller, &expected, now)
                .map_err(ApprovalError::Seller)?;
        let buyer_evidence = verify_slot(PartyRole::Buyer, trade_commitment, buyer, &expected, now)
            .map_err(ApprovalError::Buyer)?;

        let digest = handoff_digest(
            trade_commitment,
            &settlement_receiver,
            now,
            [
                (&seller_identity, &seller_evidence),
                (&buyer_identity, &buyer_evidence),
            ],
        );
        // The M2 approval is dropped here: M4 receives a snapshot, not matcher state.
        Ok(ApprovedSettlement {
            trade_commitment,
            intent,
            settlement_receiver,
            seller_identity,
            buyer_identity,
            seller_authorization: seller_evidence,
            buyer_authorization: buyer_evidence,
            approved_at: now,
            handoff_digest: digest,
        })
    }
}

/// Verifies one slot: the issued request must be for `role` and this trade,
/// and the signature must come from the expected key for `role`.
fn verify_slot(
    role: PartyRole,
    trade_commitment: TradeCommitment,
    submission: PartySubmission<'_>,
    expected: &ExpectedParties,
    now: UnixSeconds,
) -> Result<VerifiedPartyAuthorization, PartyAuthError> {
    if submission.issued.role() != role {
        return Err(PartyAuthError::WrongRole {
            expected: role,
            got: submission.issued.role(),
        });
    }
    if submission.issued.trade_commitment() != trade_commitment {
        return Err(PartyAuthError::WrongTrade);
    }
    verify_party_authorization(
        submission.authorization,
        submission.issued,
        expected.key_for(role),
        now,
    )
}

fn handoff_digest(
    trade_commitment: TradeCommitment,
    receiver: &OrchardReceiverBytes,
    approved_at: UnixSeconds,
    parties: [(&AttestedPartyIdentity, &VerifiedPartyAuthorization); 2],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(APPROVED_SETTLEMENT_DOMAIN);
    h.update([APPROVED_SETTLEMENT_VERSION]);
    h.update(trade_commitment.to_be_bytes());
    h.update(receiver.as_bytes());
    h.update(approved_at.get().to_be_bytes());
    for (identity, evidence) in parties {
        let attestation = identity.attestation();
        let attested = attestation.signing_bytes();
        // Length prefix: attestation messages are variable length (<= 197 bytes).
        h.update((attested.len() as u16).to_be_bytes());
        h.update(attested);
        h.update(attestation.signature());
        h.update(identity.authority_key());
        h.update(evidence.request().signing_bytes());
        h.update(evidence.signer().to_bytes());
        h.update(evidence.signature());
    }
    h.finalize().into()
}

/// Immutable, M2-approved and party-authorized settlement: the only M3 output.
///
/// It records which approved authority attested each party's key and the
/// consent each party signed with that key. It is not spend authority: M4
/// requires each party's wallet to authorize its own Zcash spend.
///
/// - Every field is private, and there is no setter or public constructor.
///   It is obtainable only from [`SettlementAuthorizer::approve`], which needs a
///   `MatcherApproval` (mintable only by a fully passing M2 gate) plus
///   authority-attested seller and buyer keys and the consents signed by them.
/// - It is not `Clone` and not serializable, so it cannot be duplicated or
///   rehydrated with edited values. [`verify_integrity`](Self::verify_integrity)
///   and [`handoff_digest`](Self::handoff_digest) let M4 detect any
///   inconsistency at its boundary.
/// - It contains only public trade data, the M2-verified receiver and public
///   authorization evidence. Intentionally absent: private or spending keys,
///   seeds, Orchard or IVK material, credential and Groth16 witnesses, the
///   subject secret, RFQ server internals, and matcher internal state (root
///   envelopes, proofs, replay records).
#[derive(Debug)]
pub struct ApprovedSettlement {
    trade_commitment: TradeCommitment,
    intent: TradeIntent,
    settlement_receiver: OrchardReceiverBytes,
    seller_identity: AttestedPartyIdentity,
    buyer_identity: AttestedPartyIdentity,
    seller_authorization: VerifiedPartyAuthorization,
    buyer_authorization: VerifiedPartyAuthorization,
    approved_at: UnixSeconds,
    handoff_digest: [u8; 32],
}

impl ApprovedSettlement {
    /// Approved `TradeCommitmentV1`.
    #[must_use]
    pub const fn trade_commitment(&self) -> TradeCommitment {
        self.trade_commitment
    }

    /// Snapshot of the approved canonical intent.
    #[must_use]
    pub const fn intent(&self) -> TradeIntent {
        self.intent
    }

    /// Offered asset identity.
    #[must_use]
    pub const fn offered_asset(&self) -> AssetBaseBytes {
        self.intent.offered_asset
    }

    /// Offered amount.
    #[must_use]
    pub const fn offered_amount(&self) -> TradeAmount {
        self.intent.offered_amount
    }

    /// Requested asset identity.
    #[must_use]
    pub const fn requested_asset(&self) -> AssetBaseBytes {
        self.intent.requested_asset
    }

    /// Requested amount.
    #[must_use]
    pub const fn requested_amount(&self) -> TradeAmount {
        self.intent.requested_amount
    }

    /// Committed recipient (`TradeIntent.recipient_commitment`).
    #[must_use]
    pub const fn recipient_commitment(&self) -> RecipientCommitment {
        self.intent.recipient_commitment
    }

    /// Settlement receiver: the raw Orchard receiver whose control M2 verified
    /// and bound to `recipient_commitment` (F-02).
    #[must_use]
    pub const fn settlement_receiver(&self) -> &OrchardReceiverBytes {
        &self.settlement_receiver
    }

    /// Policy root.
    #[must_use]
    pub const fn policy_root(&self) -> PolicyRoot {
        self.intent.policy_root
    }

    /// Matcher fee amount (native ZEC).
    #[must_use]
    pub const fn matcher_fee_amount(&self) -> ZatoshiAmount {
        self.intent.matcher_fee.amount
    }

    /// Matcher fee recipient commitment.
    #[must_use]
    pub const fn matcher_fee_recipient_commitment(&self) -> RecipientCommitment {
        self.intent.matcher_fee.recipient_commitment
    }

    /// Trade nonce.
    #[must_use]
    pub const fn trade_nonce(&self) -> TradeNonce {
        self.intent.nonce
    }

    /// Trade expiry.
    #[must_use]
    pub const fn expiry(&self) -> TradeExpiry {
        self.intent.expiry
    }

    /// Authority-attested seller identity (whose key signed the consent).
    #[must_use]
    pub const fn seller_identity(&self) -> &AttestedPartyIdentity {
        &self.seller_identity
    }

    /// Authority-attested buyer identity (whose key signed the consent).
    #[must_use]
    pub const fn buyer_identity(&self) -> &AttestedPartyIdentity {
        &self.buyer_identity
    }

    /// Verified seller authorization evidence.
    #[must_use]
    pub const fn seller_authorization(&self) -> &VerifiedPartyAuthorization {
        &self.seller_authorization
    }

    /// Verified buyer authorization evidence.
    #[must_use]
    pub const fn buyer_authorization(&self) -> &VerifiedPartyAuthorization {
        &self.buyer_authorization
    }

    /// Time of approval.
    #[must_use]
    pub const fn approved_at(&self) -> UnixSeconds {
        self.approved_at
    }

    /// SHA-256 over `"ZWA1APPROVEDSETTLEMENT" | version (2) | commitment |
    /// receiver | approved_at`, then for the seller and then the buyer:
    /// `attestation_len u16 | attestation bytes | attestation signature |
    /// authority key | consent signing bytes | party key | consent signature`.
    /// It is a stable correlation and integrity reference for M4.
    #[must_use]
    pub const fn handoff_digest(&self) -> &[u8; 32] {
        &self.handoff_digest
    }

    /// Re-checks every invariant. M4 can call this at its boundary.
    ///
    /// It re-verifies both authority signatures with the recorded authority
    /// keys; whether those authorities are still trusted is for the caller's
    /// own trust root to decide (compare
    /// [`AttestedPartyIdentity::authority_key`]).
    ///
    /// # Errors
    ///
    /// [`ApprovalError::IntegrityViolation`].
    pub fn verify_integrity(&self) -> Result<(), ApprovalError> {
        let fail = |reason| Err(ApprovalError::IntegrityViolation { reason });
        if zwa_commitments::trade::trade_commitment_v1(&self.intent) != self.trade_commitment {
            return fail("intent does not recompute to the trade commitment");
        }
        for (identity, evidence, role) in [
            (
                &self.seller_identity,
                &self.seller_authorization,
                PartyRole::Seller,
            ),
            (
                &self.buyer_identity,
                &self.buyer_authorization,
                PartyRole::Buyer,
            ),
        ] {
            if identity.role() != role || !identity.signature_is_valid() {
                return fail("party-key attestation does not verify for its role");
            }
            if identity.party_key() != evidence.signer() {
                return fail("authorization not signed by the attested party key");
            }
            if evidence.role() != role || evidence.trade_commitment() != self.trade_commitment {
                return fail("authorization evidence bound to another role or trade");
            }
            if !evidence.signature_is_valid() {
                return fail("authorization signature does not verify");
            }
        }
        if self.seller_authorization.signer() == self.buyer_authorization.signer() {
            return fail("seller and buyer keys are identical");
        }
        if self.seller_identity.party() == self.buyer_identity.party() {
            return fail("seller and buyer are the same party");
        }
        let digest = handoff_digest(
            self.trade_commitment,
            &self.settlement_receiver,
            self.approved_at,
            [
                (&self.seller_identity, &self.seller_authorization),
                (&self.buyer_identity, &self.buyer_authorization),
            ],
        );
        if digest != self.handoff_digest {
            return fail("handoff digest mismatch");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationError;
    use crate::party_auth::PartyAuthorizationRequest;
    use crate::test_support::{
        approval_for, buyer_attestation, golden_intent, other_intent, party_key,
        seller_attestation, sign_locally, signing_key, trust_root, TermsEdit, BUYER_SEED,
        GOLDEN_TRADE_COMMITMENT, RECEIVER_A_HEX, SELLER_SEED, T_ISSUED, T_NOW,
    };

    #[derive(Clone)]
    struct Flow {
        seller_att: PartyKeyAttestation,
        buyer_att: PartyKeyAttestation,
        seller_req: PartyAuthorizationRequest,
        buyer_req: PartyAuthorizationRequest,
        seller_auth: PartyAuthorization,
        buyer_auth: PartyAuthorization,
    }

    fn flow(intent: &TradeIntent) -> Flow {
        let window = |role: PartyRole, n: u8| {
            PartyAuthorizationRequest::new(
                role,
                intent,
                [n; 32],
                UnixSeconds::new(T_ISSUED),
                UnixSeconds::new(intent.expiry.get()),
            )
            .unwrap()
        };
        let seller_req = window(PartyRole::Seller, 1);
        let buyer_req = window(PartyRole::Buyer, 2);
        Flow {
            seller_att: seller_attestation(),
            buyer_att: buyer_attestation(),
            seller_auth: sign_locally(&seller_req, &signing_key(SELLER_SEED)),
            buyer_auth: sign_locally(&buyer_req, &signing_key(BUYER_SEED)),
            seller_req,
            buyer_req,
        }
    }

    fn seller(f: &Flow) -> Option<PartySubmission<'_>> {
        Some(PartySubmission {
            attestation: &f.seller_att,
            issued: &f.seller_req,
            authorization: &f.seller_auth,
        })
    }

    fn buyer(f: &Flow) -> Option<PartySubmission<'_>> {
        Some(PartySubmission {
            attestation: &f.buyer_att,
            issued: &f.buyer_req,
            authorization: &f.buyer_auth,
        })
    }

    fn now() -> UnixSeconds {
        UnixSeconds::new(T_NOW)
    }

    fn authorizer() -> SettlementAuthorizer {
        SettlementAuthorizer::new(trust_root())
    }

    #[test]
    fn valid_flow_produces_immutable_snapshot_for_m4() {
        let intent = golden_intent();
        let f = flow(&intent);
        let terms = RfqRequest::from_trade_intent(&intent);
        let s = authorizer()
            .approve(approval_for(&intent), &terms, seller(&f), buyer(&f), now())
            .unwrap();
        assert_eq!(s.trade_commitment().to_string(), GOLDEN_TRADE_COMMITMENT);
        assert_eq!(s.intent(), intent);
        assert_eq!(s.offered_asset(), intent.offered_asset);
        assert_eq!(s.offered_amount(), intent.offered_amount);
        assert_eq!(s.requested_asset(), intent.requested_asset);
        assert_eq!(s.requested_amount(), intent.requested_amount);
        assert_eq!(s.recipient_commitment(), intent.recipient_commitment);
        assert_eq!(s.policy_root(), intent.policy_root);
        assert_eq!(s.matcher_fee_amount(), intent.matcher_fee.amount);
        assert_eq!(
            s.matcher_fee_recipient_commitment(),
            intent.matcher_fee.recipient_commitment
        );
        assert_eq!(s.trade_nonce(), intent.nonce);
        assert_eq!(s.expiry(), intent.expiry);
        assert_eq!(
            s.settlement_receiver(),
            &OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap(),
            "receiver comes from M2's verified recipient control"
        );
        assert_eq!(s.seller_authorization().role(), PartyRole::Seller);
        assert_eq!(s.seller_authorization().signer(), &party_key(SELLER_SEED));
        assert_eq!(s.buyer_authorization().role(), PartyRole::Buyer);
        assert_eq!(s.buyer_authorization().signer(), &party_key(BUYER_SEED));
        assert_eq!(s.seller_identity().party_key(), &party_key(SELLER_SEED));
        assert_eq!(s.seller_identity().party().as_bytes(), b"party:seller-0001");
        assert_eq!(s.seller_identity().authority().as_bytes(), b"issuer-atlas");
        assert_eq!(s.buyer_identity().party_key(), &party_key(BUYER_SEED));
        assert_eq!(s.buyer_identity().authority().as_bytes(), b"cred-auth-1");
        assert_eq!(s.approved_at(), now());
        assert_eq!(s.verify_integrity(), Ok(()));
        // Deterministic digest over the same inputs.
        let s2 = authorizer()
            .approve(approval_for(&intent), &terms, seller(&f), buyer(&f), now())
            .unwrap();
        assert_eq!(s.handoff_digest(), s2.handoff_digest());
    }

    #[test]
    fn missing_seller_or_buyer_authorization_rejects() {
        let intent = golden_intent();
        let f = flow(&intent);
        let terms = RfqRequest::from_trade_intent(&intent);
        let a = authorizer();
        assert_eq!(
            a.approve(approval_for(&intent), &terms, None, buyer(&f), now())
                .unwrap_err(),
            ApprovalError::MissingSellerAuthorization
        );
        assert_eq!(
            a.approve(approval_for(&intent), &terms, seller(&f), None, now())
                .unwrap_err(),
            ApprovalError::MissingBuyerAuthorization
        );
    }

    #[test]
    fn empty_trust_root_fails_closed() {
        let intent = golden_intent();
        let f = flow(&intent);
        let err = SettlementAuthorizer::new(PartyAttestationTrustRoot::new())
            .approve(
                approval_for(&intent),
                &RfqRequest::from_trade_intent(&intent),
                seller(&f),
                buyer(&f),
                now(),
            )
            .unwrap_err();
        assert_eq!(
            err,
            ApprovalError::SellerAttestation(AttestationError::UnknownAuthority)
        );
    }

    #[test]
    fn self_generated_and_matcher_generated_keys_reject() {
        let intent = golden_intent();
        let terms = RfqRequest::from_trade_intent(&intent);
        let f = flow(&intent);
        // Matcher/coordinator generates both keys and signs both sides.
        // Real attestations are reused, but the consents are signed by keys
        // the matcher generated.
        let forged = Flow {
            seller_auth: sign_locally(&f.seller_req, &signing_key(0xB1)),
            buyer_auth: sign_locally(&f.buyer_req, &signing_key(0xB2)),
            ..f.clone()
        };
        assert_eq!(
            authorizer()
                .approve(
                    approval_for(&intent),
                    &terms,
                    seller(&forged),
                    buyer(&f),
                    now()
                )
                .unwrap_err(),
            ApprovalError::Seller(PartyAuthError::UnexpectedSigner)
        );
        assert_eq!(
            authorizer()
                .approve(
                    approval_for(&intent),
                    &terms,
                    seller(&f),
                    buyer(&forged),
                    now()
                )
                .unwrap_err(),
            ApprovalError::Buyer(PartyAuthError::UnexpectedSigner)
        );
        // A coordinator cannot register its own keys: there is no registry,
        // and a self-signed attestation is from an unknown authority.
        let self_attested = Flow {
            seller_att: crate::test_support::attest(
                0xC1,
                b"matcher-authority",
                PartyRole::Seller,
                b"matcher-seller",
                0xB1,
            ),
            buyer_att: crate::test_support::attest(
                0xC1,
                b"matcher-authority",
                PartyRole::Buyer,
                b"matcher-buyer",
                0xB2,
            ),
            ..forged.clone()
        };
        assert_eq!(
            authorizer()
                .approve(
                    approval_for(&intent),
                    &terms,
                    seller(&self_attested),
                    buyer(&self_attested),
                    now()
                )
                .unwrap_err(),
            ApprovalError::SellerAttestation(AttestationError::UnknownAuthority)
        );
    }

    #[test]
    fn swapped_roles_reject() {
        let intent = golden_intent();
        let f = flow(&intent);
        let terms = RfqRequest::from_trade_intent(&intent);
        // Buyer submission placed in the seller slot and vice versa.
        assert_eq!(
            authorizer()
                .approve(approval_for(&intent), &terms, buyer(&f), seller(&f), now())
                .unwrap_err(),
            ApprovalError::SellerAttestation(AttestationError::WrongRole {
                expected: PartyRole::Seller,
                got: PartyRole::Buyer
            })
        );
        // Seller and buyer sign each other's requests (keys swapped).
        let swapped = Flow {
            seller_auth: sign_locally(&f.seller_req, &signing_key(BUYER_SEED)),
            buyer_auth: sign_locally(&f.buyer_req, &signing_key(SELLER_SEED)),
            ..f.clone()
        };
        assert_eq!(
            authorizer()
                .approve(
                    approval_for(&intent),
                    &terms,
                    seller(&swapped),
                    buyer(&swapped),
                    now()
                )
                .unwrap_err(),
            ApprovalError::Seller(PartyAuthError::UnexpectedSigner)
        );
    }

    #[test]
    fn authorizations_for_another_trade_reject() {
        let a = golden_intent();
        let b_flow = flow(&other_intent());
        let a_flow = flow(&a);
        let terms = RfqRequest::from_trade_intent(&a);
        assert_eq!(
            authorizer()
                .approve(
                    approval_for(&a),
                    &terms,
                    seller(&b_flow),
                    buyer(&a_flow),
                    now()
                )
                .unwrap_err(),
            ApprovalError::Seller(PartyAuthError::WrongTrade)
        );
        assert_eq!(
            authorizer()
                .approve(
                    approval_for(&a),
                    &terms,
                    seller(&a_flow),
                    buyer(&b_flow),
                    now()
                )
                .unwrap_err(),
            ApprovalError::Buyer(PartyAuthError::WrongTrade)
        );
        // An approval for trade B cannot be combined with trade A's terms.
        assert!(matches!(
            authorizer().approve(
                approval_for(&other_intent()),
                &terms,
                seller(&a_flow),
                buyer(&a_flow),
                now()
            ),
            Err(ApprovalError::TermsMismatch { field: "nonce" })
        ));
    }

    #[test]
    fn terms_changed_after_approval_reject() {
        let intent = golden_intent();
        let f = flow(&intent);
        let changes: Vec<(&str, TermsEdit)> = vec![
            (
                "recipient_commitment",
                Box::new(|t: &mut RfqRequest| {
                    t.recipient_commitment = t.matcher_fee.recipient_commitment
                }),
            ),
            (
                "matcher_fee.amount",
                Box::new(|t: &mut RfqRequest| t.matcher_fee.amount = ZatoshiAmount::new(0)),
            ),
            (
                "matcher_fee.recipient_commitment",
                Box::new(|t: &mut RfqRequest| {
                    t.matcher_fee.recipient_commitment = t.recipient_commitment
                }),
            ),
            (
                "offered_amount",
                Box::new(|t: &mut RfqRequest| t.offered_amount = TradeAmount::new(1)),
            ),
            (
                "requested_amount",
                Box::new(|t: &mut RfqRequest| t.requested_amount = TradeAmount::new(600)),
            ),
            (
                "expiry",
                Box::new(|t: &mut RfqRequest| t.expiry = TradeExpiry::new(2_100_000_000)),
            ),
        ];
        for (field, change) in changes {
            let mut terms = RfqRequest::from_trade_intent(&intent);
            change(&mut terms);
            assert_eq!(
                authorizer()
                    .approve(approval_for(&intent), &terms, seller(&f), buyer(&f), now())
                    .unwrap_err(),
                ApprovalError::TermsMismatch { field },
                "{field}"
            );
        }
    }

    #[test]
    fn party_authorizations_over_modified_terms_reject() {
        // Parties signed a trade whose fee / recipient / amount differ from the
        // approved one: the commitment differs, so the slot rejects.
        let approved = golden_intent();
        let terms = RfqRequest::from_trade_intent(&approved);
        let mut fee = approved;
        fee.matcher_fee.amount = ZatoshiAmount::new(500);
        let mut recipient = approved;
        recipient.recipient_commitment = approved.matcher_fee.recipient_commitment;
        let mut amount = approved;
        amount.offered_amount = TradeAmount::new(1);
        for modified in [fee, recipient, amount] {
            let m = flow(&modified);
            let ok = flow(&approved);
            assert_eq!(
                authorizer()
                    .approve(
                        approval_for(&approved),
                        &terms,
                        seller(&m),
                        buyer(&ok),
                        now()
                    )
                    .unwrap_err(),
                ApprovalError::Seller(PartyAuthError::WrongTrade)
            );
        }
    }

    #[test]
    fn expired_trade_and_expired_authorization_reject() {
        let intent = golden_intent();
        let f = flow(&intent);
        let terms = RfqRequest::from_trade_intent(&intent);
        let after = UnixSeconds::new(intent.expiry.get() + 1);
        assert_eq!(
            authorizer()
                .approve(approval_for(&intent), &terms, seller(&f), buyer(&f), after)
                .unwrap_err(),
            ApprovalError::TradeExpired {
                now: intent.expiry.get() + 1,
                expiry: intent.expiry.get()
            }
        );
        // now == trade expiry is still valid.
        let at = UnixSeconds::new(intent.expiry.get());
        assert!(authorizer()
            .approve(approval_for(&intent), &terms, seller(&f), buyer(&f), at)
            .is_ok());
        // A short-lived seller authorization that has lapsed rejects.
        let short = PartyAuthorizationRequest::new(
            PartyRole::Seller,
            &intent,
            [3; 32],
            UnixSeconds::new(T_ISSUED),
            UnixSeconds::new(T_NOW - 1),
        )
        .unwrap();
        let short_auth = sign_locally(&short, &signing_key(SELLER_SEED));
        assert!(matches!(
            authorizer().approve(
                approval_for(&intent),
                &terms,
                Some(PartySubmission {
                    attestation: &f.seller_att,
                    issued: &short,
                    authorization: &short_auth
                }),
                buyer(&f),
                now()
            ),
            Err(ApprovalError::Seller(PartyAuthError::Expired { .. }))
        ));
    }

    #[test]
    fn malformed_signature_rejects() {
        let intent = golden_intent();
        let f = flow(&intent);
        let mut sig = *f.buyer_auth.signature();
        sig[10] ^= 0x40;
        let buyer_key = party_key(BUYER_SEED).to_bytes();
        let bad = PartyAuthorization::new(f.buyer_req.clone(), buyer_key, sig);
        assert_eq!(
            authorizer()
                .approve(
                    approval_for(&intent),
                    &RfqRequest::from_trade_intent(&intent),
                    seller(&f),
                    Some(PartySubmission {
                        attestation: &f.buyer_att,
                        issued: &f.buyer_req,
                        authorization: &bad
                    }),
                    now()
                )
                .unwrap_err(),
            ApprovalError::Buyer(PartyAuthError::BadSignature)
        );
    }

    #[test]
    fn approved_settlement_has_no_public_constructor_or_mutable_fields() {
        // `ApprovedSettlement { .. }` is built in exactly one place, and none of
        // its fields is public. It cannot be made without `approve`, which needs
        // a `MatcherApproval` (only mintable by M2's `MatcherGate::evaluate`).
        let src = include_str!("approved.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert_eq!(prod.matches("Ok(ApprovedSettlement {").count(), 1);
        let body = prod
            .split("pub struct ApprovedSettlement {")
            .nth(1)
            .unwrap()
            .split('}')
            .next()
            .unwrap();
        assert!(
            !body.contains("pub "),
            "ApprovedSettlement fields must be private"
        );
        assert!(!prod.contains("&mut self"), "no mutators");
        let derive = prod
            .split("pub struct ApprovedSettlement {")
            .next()
            .unwrap()
            .rsplit("#[derive(")
            .next()
            .unwrap();
        assert!(!derive.contains("Clone") && !derive.contains("Serialize"));
    }

    // -----------------------------------------------------------------------
    // Adversarial party-key attestation and consent coverage (DR-M3-01).
    // -----------------------------------------------------------------------

    use crate::test_support::{
        attest, attest_window, BUYER_ATTESTOR_ID, BUYER_ATTESTOR_SEED, BUYER_PARTY_ID,
        SELLER_ATTESTOR_ID, SELLER_ATTESTOR_SEED, SELLER_PARTY_ID,
    };

    fn approve_golden(f: &Flow) -> Result<ApprovedSettlement, ApprovalError> {
        let intent = golden_intent();
        authorizer().approve(
            approval_for(&intent),
            &RfqRequest::from_trade_intent(&intent),
            seller(f),
            buyer(f),
            now(),
        )
    }

    fn buyer_attested(party_id: &[u8], party_seed: u8) -> PartyKeyAttestation {
        attest(
            BUYER_ATTESTOR_SEED,
            BUYER_ATTESTOR_ID,
            PartyRole::Buyer,
            party_id,
            party_seed,
        )
    }

    #[test]
    fn forged_authority_signature_rejects() {
        let f = flow(&golden_intent());
        let a = &f.seller_att;
        let mut sig = *a.signature();
        sig[0] ^= 0x01;
        let tampered = PartyKeyAttestation::new(
            a.authority().clone(),
            a.role(),
            a.party().clone(),
            *a.party_key(),
            a.valid_from(),
            a.expires_at(),
            sig,
        )
        .unwrap();
        let forged = Flow {
            seller_att: tampered,
            ..f.clone()
        };
        assert_eq!(
            approve_golden(&forged).unwrap_err(),
            ApprovalError::SellerAttestation(AttestationError::BadSignature)
        );
        // The real authority id, signed with a key the attacker controls.
        let impostor = Flow {
            buyer_att: attest(
                0xC2,
                BUYER_ATTESTOR_ID,
                PartyRole::Buyer,
                BUYER_PARTY_ID,
                BUYER_SEED,
            ),
            ..f
        };
        assert_eq!(
            approve_golden(&impostor).unwrap_err(),
            ApprovalError::BuyerAttestation(AttestationError::BadSignature)
        );
    }

    #[test]
    fn wrong_credential_authority_rejects() {
        let f = flow(&golden_intent());
        // An authority that is not in the trust root.
        let unknown = Flow {
            buyer_att: attest(
                BUYER_ATTESTOR_SEED,
                b"cred-auth-2",
                PartyRole::Buyer,
                BUYER_PARTY_ID,
                BUYER_SEED,
            ),
            ..f.clone()
        };
        assert_eq!(
            approve_golden(&unknown).unwrap_err(),
            ApprovalError::BuyerAttestation(AttestationError::UnknownAuthority)
        );
        // The issuer (seller-only) attesting the buyer.
        let issuer_for_buyer = Flow {
            buyer_att: attest(
                SELLER_ATTESTOR_SEED,
                SELLER_ATTESTOR_ID,
                PartyRole::Buyer,
                BUYER_PARTY_ID,
                BUYER_SEED,
            ),
            ..f.clone()
        };
        assert_eq!(
            approve_golden(&issuer_for_buyer).unwrap_err(),
            ApprovalError::BuyerAttestation(AttestationError::RoleNotAllowed {
                role: PartyRole::Buyer
            })
        );
        // The credential authority (buyer-only) attesting the seller.
        let authority_for_seller = Flow {
            seller_att: attest(
                BUYER_ATTESTOR_SEED,
                BUYER_ATTESTOR_ID,
                PartyRole::Seller,
                SELLER_PARTY_ID,
                SELLER_SEED,
            ),
            ..f
        };
        assert_eq!(
            approve_golden(&authority_for_seller).unwrap_err(),
            ApprovalError::SellerAttestation(AttestationError::RoleNotAllowed {
                role: PartyRole::Seller
            })
        );
    }

    #[test]
    fn seller_credential_as_buyer_and_buyer_credential_as_seller_reject() {
        let f = flow(&golden_intent());
        let seller_as_buyer = Flow {
            buyer_att: f.seller_att.clone(),
            ..f.clone()
        };
        assert_eq!(
            approve_golden(&seller_as_buyer).unwrap_err(),
            ApprovalError::BuyerAttestation(AttestationError::WrongRole {
                expected: PartyRole::Buyer,
                got: PartyRole::Seller
            })
        );
        let buyer_as_seller = Flow {
            seller_att: f.buyer_att.clone(),
            ..f
        };
        assert_eq!(
            approve_golden(&buyer_as_seller).unwrap_err(),
            ApprovalError::SellerAttestation(AttestationError::WrongRole {
                expected: PartyRole::Seller,
                got: PartyRole::Buyer
            })
        );
    }

    #[test]
    fn expired_or_not_yet_valid_attestation_rejects() {
        let f = flow(&golden_intent());
        let expired = Flow {
            seller_att: attest_window(
                SELLER_ATTESTOR_SEED,
                SELLER_ATTESTOR_ID,
                PartyRole::Seller,
                SELLER_PARTY_ID,
                SELLER_SEED,
                T_ISSUED,
                T_NOW - 1,
            ),
            ..f.clone()
        };
        assert_eq!(
            approve_golden(&expired).unwrap_err(),
            ApprovalError::SellerAttestation(AttestationError::Expired {
                now: T_NOW,
                expires_at: T_NOW - 1
            })
        );
        let early = Flow {
            buyer_att: attest_window(
                BUYER_ATTESTOR_SEED,
                BUYER_ATTESTOR_ID,
                PartyRole::Buyer,
                BUYER_PARTY_ID,
                BUYER_SEED,
                T_NOW + 1,
                T_NOW + 1_000,
            ),
            ..f
        };
        assert_eq!(
            approve_golden(&early).unwrap_err(),
            ApprovalError::BuyerAttestation(AttestationError::NotYetValid {
                now: T_NOW,
                valid_from: T_NOW + 1
            })
        );
    }

    #[test]
    fn same_party_or_same_key_in_both_roles_rejects() {
        let f = flow(&golden_intent());
        // The buyer slot claims the seller's party id.
        let same_party = Flow {
            buyer_att: buyer_attested(SELLER_PARTY_ID, BUYER_SEED),
            ..f.clone()
        };
        assert_eq!(
            approve_golden(&same_party).unwrap_err(),
            ApprovalError::SamePartyForBothRoles
        );
        // Two party ids, one key: one signer would consent for both sides.
        let same_key = Flow {
            buyer_att: buyer_attested(b"party:buyer-0002", SELLER_SEED),
            buyer_auth: sign_locally(&f.buyer_req, &signing_key(SELLER_SEED)),
            ..f.clone()
        };
        assert_eq!(
            approve_golden(&same_key).unwrap_err(),
            ApprovalError::Identity(PartyAuthError::SameKeyForBothRoles)
        );
    }

    #[test]
    fn consent_must_come_from_the_attested_key() {
        let f = flow(&golden_intent());
        // Valid buyer attestation, consent signed by a matcher key.
        let wrong_signer = Flow {
            buyer_auth: sign_locally(&f.buyer_req, &signing_key(0xB2)),
            ..f.clone()
        };
        assert_eq!(
            approve_golden(&wrong_signer).unwrap_err(),
            ApprovalError::Buyer(PartyAuthError::UnexpectedSigner)
        );
        // A valid attestation of a different buyer moved next to the real
        // buyer's consent.
        let moved = Flow {
            buyer_att: buyer_attested(b"party:buyer-0002", 0xB3),
            ..f
        };
        assert_eq!(
            approve_golden(&moved).unwrap_err(),
            ApprovalError::Buyer(PartyAuthError::UnexpectedSigner)
        );
    }

    #[test]
    fn altered_consent_nonce_or_expiry_rejects() {
        let intent = golden_intent();
        let f = flow(&intent);
        let echo = |nonce: u8, expires_at: u64| {
            let altered = PartyAuthorizationRequest::new(
                PartyRole::Seller,
                &intent,
                [nonce; 32],
                UnixSeconds::new(T_ISSUED),
                UnixSeconds::new(expires_at),
            )
            .unwrap();
            sign_locally(&altered, &signing_key(SELLER_SEED))
        };
        let expiry = intent.expiry.get();
        for (auth, field) in [
            (echo(9, expiry), "nonce"),
            (echo(1, T_NOW + 50), "expires_at"),
        ] {
            let altered = Flow {
                seller_auth: auth,
                ..f.clone()
            };
            assert_eq!(
                approve_golden(&altered).unwrap_err(),
                ApprovalError::Seller(PartyAuthError::RequestMismatch { field }),
                "{field}"
            );
        }
    }

    #[test]
    fn altered_trade_nonce_rejects() {
        let intent = golden_intent();
        let f = flow(&intent);
        let mut terms = RfqRequest::from_trade_intent(&intent);
        terms.nonce = TradeNonce::new(intent.nonce.get() + 1);
        assert_eq!(
            authorizer()
                .approve(approval_for(&intent), &terms, seller(&f), buyer(&f), now())
                .unwrap_err(),
            ApprovalError::TermsMismatch { field: "nonce" }
        );
    }

    #[test]
    fn attested_identities_are_bound_into_the_handoff() {
        assert_eq!(APPROVED_SETTLEMENT_VERSION, 2);
        let f = flow(&golden_intent());
        let a = approve_golden(&f).unwrap();
        // Same consents, buyer key attested under another party id.
        let other_party = Flow {
            buyer_att: buyer_attested(b"party:buyer-0002", BUYER_SEED),
            ..f
        };
        let b = approve_golden(&other_party).unwrap();
        assert_eq!(b.verify_integrity(), Ok(()));
        assert_ne!(a.handoff_digest(), b.handoff_digest());
    }

    #[test]
    fn verify_integrity_detects_identity_tampering() {
        let f = flow(&golden_intent());
        let identity =
            |att: &PartyKeyAttestation, role| trust_root().verify(att, role, now()).unwrap();
        let violation = |reason: &'static str| -> Result<(), ApprovalError> {
            Err(ApprovalError::IntegrityViolation { reason })
        };

        let mut s = approve_golden(&f).unwrap();
        s.seller_identity = identity(&f.buyer_att, PartyRole::Buyer);
        assert_eq!(
            s.verify_integrity(),
            violation("party-key attestation does not verify for its role")
        );

        let mut s = approve_golden(&f).unwrap();
        s.buyer_identity = identity(&buyer_attested(b"party:buyer-0002", 0xB3), PartyRole::Buyer);
        assert_eq!(
            s.verify_integrity(),
            violation("authorization not signed by the attested party key")
        );

        let mut s = approve_golden(&f).unwrap();
        s.buyer_identity = identity(
            &buyer_attested(SELLER_PARTY_ID, BUYER_SEED),
            PartyRole::Buyer,
        );
        assert_eq!(
            s.verify_integrity(),
            violation("seller and buyer are the same party")
        );

        let mut s = approve_golden(&f).unwrap();
        s.buyer_identity = identity(
            &buyer_attested(b"party:buyer-0002", BUYER_SEED),
            PartyRole::Buyer,
        );
        assert_eq!(s.verify_integrity(), violation("handoff digest mismatch"));
    }
}
