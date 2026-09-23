//! Checked trade witness — mandatory intent/commitment correspondence.
//!
//! This module implements Task A. It is the fix for audit finding ZWA-REL-001:
//! `ReplayStore::create` does not prove intent/commitment correspondence.
//!
//! The matcher must never call `ReplayStore::create` with an unchecked pair.
//! Instead, it must first construct `CheckedTrade`, which internally calls
//! `zwa_commitments::verify_trade_commitment`.

use zwa_commitments::{trade_commitment_parts, verify_trade_commitment, TradeCommitmentParts};
use zwa_protocol::error::Result;
use zwa_protocol::{ReplayStore, TradeCommitment, TradeIntent, TradeRecord};

/// A trade intent and commitment that have been proven to correspond.
///
/// This is the matcher-level checked trade witness required by the final
/// Phase 1 audit (ZWA-REL-001). Construction verifies:
///
/// ```text
/// recomputed = H(TRADE_V1, H(TRDA_V1,...), H(TRDB_V1,...), H(TRDM_V1,...))
/// recomputed == presented commitment
/// ```
///
/// If verification fails, construction returns `ProtocolError::CommitmentMismatch`.
///
/// After construction, the same `TradeCommitmentV1` is available as
/// `commitment()`, the canonical intent as `intent()`, and all intermediate
/// hashes as `parts()`. The matcher must use this single commitment value for
/// both `ProvenanceVerifier` and `EligibilityVerifier` calls, preventing proof
/// splicing from different trades.
///
/// # Security
///
/// - The commitment is frozen. Changing field order, domain, arity, or limb
///   order breaks compatibility with circuits and Phase 0 vectors.
/// - This type does not check expiry, root authenticity, or proofs. Those are
///   later gate steps (Task B onward).
/// - `TradeIntent` contains `recipient_commitment` which itself is
///   `H(RCPBIND1, SubjectCommitment, ReceiverCommitment)` — Phase 0G + Phase 1B
///   binding. The check here ensures the matcher uses the exact recipient that
///   was committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedTrade {
    intent: TradeIntent,
    commitment: TradeCommitment,
    parts: TradeCommitmentParts,
}

impl CheckedTrade {
    /// Constructs a checked trade after verifying intent/commitment correspondence.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolError::CommitmentMismatch` when the recomputed
    /// commitment differs from `commitment`. The error carries both decimal
    /// strings for diagnostics.
    ///
    /// This is the **only** constructor. No `new_unchecked` exists by design.
    pub fn new(intent: TradeIntent, commitment: TradeCommitment) -> Result<Self> {
        // SECURITY: This is the mandatory gate. Every matcher path must go
        // through here before replay creation. See ZWA-REL-001.
        verify_trade_commitment(&intent, commitment)?;

        // Safe: verify succeeded, so parts.trade_commitment == commitment.
        // We recompute parts once for later use (diagnostics, logging, fee checks).
        let parts = trade_commitment_parts(&intent);

        // Defensive assert — should never fire if verify succeeded, but makes
        // the invariant explicit and protects against future divergence.
        debug_assert_eq!(parts.trade_commitment, commitment);

        Ok(Self {
            intent,
            commitment,
            parts,
        })
    }

    /// Canonical trade intent that was verified.
    #[must_use]
    pub const fn intent(&self) -> TradeIntent {
        self.intent
    }

    /// The frozen `TradeCommitmentV1` that both proofs must expose.
    #[must_use]
    pub const fn commitment(&self) -> TradeCommitment {
        self.commitment
    }

    /// All intermediate commitment stages for diagnostics.
    #[must_use]
    pub const fn parts(&self) -> TradeCommitmentParts {
        self.parts
    }

    /// Creates a replay record from this checked trade.
    ///
    /// This is the **only** approved way to create a `CREATED` record in Phase 2.
    /// It takes `&mut ReplayStore` and delegates to `ReplayStore::create` after
    /// correspondence has been proven. Callers cannot bypass the check because
    /// `ReplayStore::create` requires the same commitment that this type holds.
    ///
    /// # Errors
    ///
    /// Propagates `ProtocolError::AlreadyConsumed` if the commitment was already
    /// consumed, or `InvalidStateTransition` if a record already exists.
    pub fn create_replay_record(
        &self,
        store: &mut ReplayStore,
    ) -> Result<TradeRecord> {
        store.create(self.commitment, self.intent)
    }

    /// Returns the intent and commitment as a tuple for verifier calls.
    ///
    /// The matcher gate must use `commitment` for both provenance and
    /// eligibility verification (same-commitment invariant).
    #[must_use]
    pub const fn as_parts(&self) -> (TradeIntent, TradeCommitment) {
        (self.intent, self.commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zwa_protocol::{
        AssetBaseBytes, FieldElement, MatcherFee, PolicyRoot, RecipientCommitment, TradeAmount,
        TradeExpiry, TradeNonce, ZatoshiAmount,
    };

    const PHASE_0G_GOLDEN: &str =
        "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    const PHASE_0F_GOLDEN: &str =
        "7409670081847436957289371955571360481923983184454289247710022466448715682310";

    fn golden_intent() -> TradeIntent {
        // Reconstructs the Phase 0G eligible-reference-trade-v1 intent.
        // Values taken from tests/fixtures/eligible-reference-trade-v1.json
        let offered_asset =
            AssetBaseBytes::from_hex("4889ad11564115f3655f7e434bffb23074d42aafd58cfecae32a5b5eafaf5301")
                .unwrap();
        let requested_asset =
            AssetBaseBytes::from_hex("a7ac13ded8b51e7a59c400097b70fe6d5d855b30ad19b1897de1fd74721a9339")
                .unwrap();
        TradeIntent {
            offered_asset,
            offered_amount: TradeAmount::new(10),
            requested_asset,
            requested_amount: TradeAmount::new(6),
            recipient_commitment: RecipientCommitment::from_decimal_str(
                "13135279047718387126053226034283670929172341955108098732820235388025453726181",
            )
            .unwrap(),
            policy_root: PolicyRoot::from_decimal_str(
                "1514393595722546217125953798550283818470332284949639873172624869558831825935",
            )
            .unwrap(),
            matcher_fee: MatcherFee::new(
                ZatoshiAmount::new(5),
                RecipientCommitment::from_decimal_str(
                    "1800273984094439421343257609634901689467303577600258601269976617936586404380",
                )
                .unwrap(),
            ),
            nonce: TradeNonce::new(7001),
            expiry: TradeExpiry::new(2_000_000_000),
        }
    }

    #[test]
    fn checked_trade_accepts_golden_vector() {
        let intent = golden_intent();
        let commitment = TradeCommitment::from_decimal_str(PHASE_0G_GOLDEN).unwrap();
        let checked = CheckedTrade::new(intent, commitment).unwrap();
        assert_eq!(checked.commitment().to_string(), PHASE_0G_GOLDEN);
        assert_eq!(checked.parts().trade_commitment.to_string(), PHASE_0G_GOLDEN);
    }

    #[test]
    fn checked_trade_rejects_mismatched_commitment() {
        let intent = golden_intent();
        let wrong_commitment = TradeCommitment::from_decimal_str(PHASE_0F_GOLDEN).unwrap();
        let err = CheckedTrade::new(intent, wrong_commitment).unwrap_err();
        // Must be CommitmentMismatch, not a generic error.
        match err {
            zwa_protocol::error::ProtocolError::CommitmentMismatch { expected, actual } => {
                assert_eq!(expected, PHASE_0F_GOLDEN);
                assert_eq!(actual, PHASE_0G_GOLDEN);
            }
            other => panic!("expected CommitmentMismatch, got {other:?}"),
        }
    }

    #[test]
    fn checked_trade_prevents_intent_substitution_before_replay() {
        // This is the exact footgun ZWA-REL-001 describes: pairing a real
        // commitment with a different intent would make expiry enforcement
        // use the wrong intent. CheckedTrade must block it.
        let mut intent = golden_intent();
        let commitment = TradeCommitment::from_decimal_str(PHASE_0G_GOLDEN).unwrap();

        // Mutate expiry — would be an attempt to bypass expiry gate.
        intent.expiry = TradeExpiry::new(1_000_000_000);
        assert!(CheckedTrade::new(intent, commitment).is_err());

        // Mutate amount.
        let mut intent2 = golden_intent();
        intent2.offered_amount = TradeAmount::new(999);
        assert!(CheckedTrade::new(intent2, commitment).is_err());
    }

    fn flip_first_asset_byte(asset: AssetBaseBytes) -> AssetBaseBytes {
        let mut bytes = *asset.as_bytes();
        bytes[0] ^= 1;
        AssetBaseBytes::new(bytes)
    }

    #[test]
    fn checked_trade_every_field_mutation_fails() {
        // Spec A1 requires every committed field to be bound into TradeCommitmentV1.
        // This mirrors crates/commitments/tests/phase0_vectors.rs::phase0g_golden_trade_field_mutations_change_the_commitment
        // but at the CheckedTrade boundary — each mutation must be rejected before replay.
        let original = golden_intent();
        let original_commitment =
            TradeCommitment::from_decimal_str(PHASE_0G_GOLDEN).unwrap();

        // Sanity: original passes
        assert!(CheckedTrade::new(original, original_commitment).is_ok());

        let mutated_recipient = RecipientCommitment::new(FieldElement::from_u64(1));
        let mutated_fee_recipient = RecipientCommitment::new(FieldElement::from_u64(2));
        let mutated_policy = PolicyRoot::new(FieldElement::from_u64(1));

        let cases: [(&str, TradeIntent); 10] = [
            (
                "offered amount 10 → 11",
                {
                    let mut intent = original;
                    intent.offered_amount = TradeAmount::new(11);
                    intent
                },
            ),
            (
                "requested amount 6 → 7",
                {
                    let mut intent = original;
                    intent.requested_amount = TradeAmount::new(7);
                    intent
                },
            ),
            (
                "matcher fee 5 → 6",
                {
                    let mut intent = original;
                    intent.matcher_fee.amount = ZatoshiAmount::new(6);
                    intent
                },
            ),
            (
                "recipient commitment mutation",
                {
                    let mut intent = original;
                    intent.recipient_commitment = mutated_recipient;
                    intent
                },
            ),
            (
                "matcher fee recipient mutation",
                {
                    let mut intent = original;
                    intent.matcher_fee.recipient_commitment = mutated_fee_recipient;
                    intent
                },
            ),
            (
                "policy root mutation",
                {
                    let mut intent = original;
                    intent.policy_root = mutated_policy;
                    intent
                },
            ),
            (
                "nonce mutation",
                {
                    let mut intent = original;
                    intent.nonce = TradeNonce::new(7002);
                    intent
                },
            ),
            (
                "expiry mutation",
                {
                    let mut intent = original;
                    intent.expiry = TradeExpiry::new(2_000_000_001);
                    intent
                },
            ),
            (
                "offered AssetBase mutation",
                {
                    let mut intent = original;
                    intent.offered_asset = flip_first_asset_byte(original.offered_asset);
                    intent
                },
            ),
            (
                "requested AssetBase mutation",
                {
                    let mut intent = original;
                    intent.requested_asset = flip_first_asset_byte(original.requested_asset);
                    intent
                },
            ),
        ];

        for (label, mutated) in cases {
            let err = CheckedTrade::new(mutated, original_commitment);
            assert!(
                err.is_err(),
                "{label} must be rejected by CheckedTrade — intent no longer matches commitment"
            );
            // Ensure error is CommitmentMismatch, not generic
            match err.unwrap_err() {
                zwa_protocol::error::ProtocolError::CommitmentMismatch { expected, actual } => {
                    assert_eq!(expected, PHASE_0G_GOLDEN, "{label} expected should be golden");
                    assert_ne!(actual, PHASE_0G_GOLDEN, "{label} actual must not be golden");
                    assert_eq!(
                        actual,
                        zwa_commitments::trade_commitment_v1(&mutated).to_string(),
                        "{label} actual must equal recomputed commitment"
                    );
                }
                other => panic!("{label} expected CommitmentMismatch, got {other:?}"),
            }
        }
    }

    #[test]
    fn checked_trade_creates_replay_record_only_after_verification() {
        let intent = golden_intent();
        let commitment = TradeCommitment::from_decimal_str(PHASE_0G_GOLDEN).unwrap();
        let checked = CheckedTrade::new(intent, commitment).unwrap();

        let mut store = ReplayStore::new();
        let record = checked.create_replay_record(&mut store).unwrap();
        assert_eq!(record.commitment(), commitment);
        assert_eq!(record.intent(), intent);

        // Second creation must fail — duplicate.
        assert!(checked.create_replay_record(&mut store).is_err());
    }

    #[test]
    fn checked_trade_as_parts_preserves_same_commitment_invariant() {
        let intent = golden_intent();
        let commitment = TradeCommitment::from_decimal_str(PHASE_0G_GOLDEN).unwrap();
        let checked = CheckedTrade::new(intent, commitment).unwrap();
        let (i, c) = checked.as_parts();
        assert_eq!(i, intent);
        assert_eq!(c, commitment);
        // Both verifiers must receive `c`.
    }
}
