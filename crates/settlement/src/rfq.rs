//! RFQ / negotiated terms → canonical `TradeIntent` (M3, §11).
//!
//! [`RfqRequest`] is exactly the ten negotiated values that make up the frozen
//! [`TradeIntent`]. Nothing else rides along:
//!
//! - There is no raw Orchard receiver override. The settlement receiver is the
//!   one M2 verified and bound to `recipient_commitment` (F-02), and it is taken
//!   from the `MatcherApproval` only.
//! - There is no subject secret or other credential witness; those stay with the
//!   investor and are only proved inside the eligibility proof.
//!
//! The mapping is field-for-field with no re-encoding. The commitment is
//! computed only by the frozen engine (`zwa_commitments::trade::trade_commitment_v1`).
//! After M2 approval the terms cannot be independently overridden:
//! [`RfqRequest::ensure_matches`] rejects any field that differs from the
//! approved intent, and `SettlementAuthorizer::approve` calls it.

use zwa_protocol::bytes::AssetBaseBytes;
use zwa_protocol::numbers::{TradeAmount, TradeExpiry, TradeNonce};
use zwa_protocol::{MatcherFee, PolicyRoot, RecipientCommitment, TradeCommitment, TradeIntent};

/// The negotiated trade terms: a one-to-one mirror of the frozen `TradeIntent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfqRequest {
    /// Canonical `AssetBase` of the offered asset (32 bytes, no ticker).
    pub offered_asset: AssetBaseBytes,
    /// Offered amount, raw asset units.
    pub offered_amount: TradeAmount,
    /// Canonical `AssetBase` of the requested asset.
    pub requested_asset: AssetBaseBytes,
    /// Requested amount, raw asset units.
    pub requested_amount: TradeAmount,
    /// Commitment to the intended recipient (the raw receiver is never part of the RFQ).
    pub recipient_commitment: RecipientCommitment,
    /// Policy root the recipient's credential must satisfy.
    pub policy_root: PolicyRoot,
    /// Matcher fee: ZEC amount and fee-recipient commitment.
    pub matcher_fee: MatcherFee,
    /// Application-assigned nonce.
    pub nonce: TradeNonce,
    /// Trade expiry (unsigned Unix seconds).
    pub expiry: TradeExpiry,
}

/// A negotiated term differs from the M2-approved trade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("negotiated term `{field}` differs from the approved trade")]
pub struct TermsMismatch {
    /// Name of the first differing field.
    pub field: &'static str,
}

impl RfqRequest {
    /// Canonical `TradeIntent`: a direct field copy with no re-encoding.
    #[must_use]
    pub const fn to_trade_intent(&self) -> TradeIntent {
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

    /// Terms of an existing canonical intent.
    #[must_use]
    pub const fn from_trade_intent(intent: &TradeIntent) -> Self {
        Self {
            offered_asset: intent.offered_asset,
            offered_amount: intent.offered_amount,
            requested_asset: intent.requested_asset,
            requested_amount: intent.requested_amount,
            recipient_commitment: intent.recipient_commitment,
            policy_root: intent.policy_root,
            matcher_fee: intent.matcher_fee,
            nonce: intent.nonce,
            expiry: intent.expiry,
        }
    }

    /// `TradeCommitmentV1` of these terms, computed only by the frozen engine.
    #[must_use]
    pub fn trade_commitment(&self) -> TradeCommitment {
        zwa_commitments::trade::trade_commitment_v1(&self.to_trade_intent())
    }

    /// Requires exact agreement with the approved intent, field by field.
    ///
    /// # Errors
    ///
    /// [`TermsMismatch`] naming the first field that differs.
    pub fn ensure_matches(&self, approved: &TradeIntent) -> Result<(), TermsMismatch> {
        // Exhaustive destructuring: adding a field to the frozen intent is a
        // compile error here rather than a silently unchecked term.
        let TradeIntent {
            offered_asset,
            offered_amount,
            requested_asset,
            requested_amount,
            recipient_commitment,
            policy_root,
            matcher_fee,
            nonce,
            expiry,
        } = *approved;
        let checks = [
            ("offered_asset", self.offered_asset == offered_asset),
            ("offered_amount", self.offered_amount == offered_amount),
            ("requested_asset", self.requested_asset == requested_asset),
            ("requested_amount", self.requested_amount == requested_amount),
            (
                "recipient_commitment",
                self.recipient_commitment == recipient_commitment,
            ),
            ("policy_root", self.policy_root == policy_root),
            (
                "matcher_fee.amount",
                self.matcher_fee.amount == matcher_fee.amount,
            ),
            (
                "matcher_fee.recipient_commitment",
                self.matcher_fee.recipient_commitment == matcher_fee.recipient_commitment,
            ),
            ("nonce", self.nonce == nonce),
            ("expiry", self.expiry == expiry),
        ];
        match checks.iter().find(|(_, equal)| !equal) {
            Some((field, _)) => Err(TermsMismatch { field }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{golden_intent, TermsEdit, GOLDEN_TRADE_COMMITMENT};
    use zwa_protocol::ZatoshiAmount;

    #[test]
    fn rfq_maps_one_to_one_onto_trade_intent_and_golden_commitment() {
        let intent = golden_intent();
        let rfq = RfqRequest::from_trade_intent(&intent);
        assert_eq!(rfq.to_trade_intent(), intent);
        assert_eq!(rfq.trade_commitment().to_string(), GOLDEN_TRADE_COMMITMENT);
        assert_eq!(rfq.ensure_matches(&intent), Ok(()));
    }

    #[test]
    fn every_term_must_agree_exactly() {
        let approved = golden_intent();
        let other_rc = RecipientCommitment::from_decimal_str("42").unwrap();
        let mutations: Vec<(&str, TermsEdit)> = vec![
            (
                "offered_asset",
                Box::new(|r: &mut RfqRequest| r.offered_asset = r.requested_asset),
            ),
            (
                "offered_amount",
                Box::new(|r: &mut RfqRequest| r.offered_amount = TradeAmount::new(11)),
            ),
            (
                "requested_asset",
                Box::new(|r: &mut RfqRequest| r.requested_asset = r.offered_asset),
            ),
            (
                "requested_amount",
                Box::new(|r: &mut RfqRequest| r.requested_amount = TradeAmount::new(7)),
            ),
            (
                "recipient_commitment",
                Box::new(move |r: &mut RfqRequest| r.recipient_commitment = other_rc),
            ),
            (
                "policy_root",
                Box::new(|r: &mut RfqRequest| {
                    r.policy_root = PolicyRoot::from_decimal_str("1").unwrap()
                }),
            ),
            (
                "matcher_fee.amount",
                Box::new(|r: &mut RfqRequest| r.matcher_fee.amount = ZatoshiAmount::new(6)),
            ),
            (
                "matcher_fee.recipient_commitment",
                Box::new(move |r: &mut RfqRequest| r.matcher_fee.recipient_commitment = other_rc),
            ),
            ("nonce", Box::new(|r: &mut RfqRequest| r.nonce = TradeNonce::new(7002))),
            (
                "expiry",
                Box::new(|r: &mut RfqRequest| r.expiry = TradeExpiry::new(2_000_000_001)),
            ),
        ];
        for (field, mutate) in mutations {
            let mut rfq = RfqRequest::from_trade_intent(&approved);
            mutate(&mut rfq);
            assert_eq!(rfq.ensure_matches(&approved), Err(TermsMismatch { field }));
            assert_ne!(
                rfq.trade_commitment(),
                RfqRequest::from_trade_intent(&approved).trade_commitment(),
                "{field} is bound by TradeCommitmentV1"
            );
        }
    }
}
