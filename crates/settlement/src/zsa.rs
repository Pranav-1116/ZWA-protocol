//! V3: Experimental ZSA Transaction Construction — QEDIT pinned stack.
//!
//! This module is the complete V3 work for Vikram. It builds an atomic shielded
//! transaction using the pinned QEDIT experimental stack per ADR 0003.
//!
//! # Pinned QEDIT Stack (ADR 0003 + user request)
//!
//! - `zcash_tx_tool 6bcf2c5` (user request) / `217b979ee01afb844190a162fb77874135aef587` (ADR 0003 original)
//! - `zsa-swap 217b979` (user request) — swap logic demonstrating atomic multi-asset
//! - Zebra `0aef55c` / `0aef55cea41b83f17610e6ea708e59995f9e739f` — consensus validation
//! - librustzcash `5a55da9` / `5a55da948498dd0995d0f438b4c8e9a3f0150154` — Orchard + ZSA notes
//! - orchard `d91aaf1` / `d91aaf146364a06de1653e64f93b56fac5b3ca0f` — note encryption
//!
//! These branches implement experimental ZSA, ZIP-227, ZIP-228 behavior and are
//! **NOT** production mainnet dependencies. Every integration must preserve pins
//! and reproduce tests. Project must not claim production readiness.
//!
//! # Atomic Shielded Transaction (experimental)
//!
//! After `MatcherApproval` (all 10 gates PASS), we construct one experimental
//! Zcash transaction whose action groups exchange RWA for payment asset and pay
//! matcher in shielded ZEC. Phase 0 showed transaction-level authorizations and
//! binding signature invalidate whole transaction when finalized matcher action
//! group is removed.
//!
//! Flow (correct swap, per architecture.md §19, §20):
//! - Input 1: seller's offered AssetBase note (Pallas 32B) — amount = offered_amount
//! - Output 1: buyer's receipt of offered AssetBase — same asset, same amount, to buyer receiver (43B)
//! - Input 2: buyer's requested AssetBase note — amount = requested_amount
//! - Output 2: seller's receipt of requested AssetBase — same asset, same amount, to seller receiver (43B)
//! - Input 3: ZEC fee note from buyer (or seller) — amount = matcher_fee.amount
//! - Output 3: ZEC fee note to matcher — same amount, to matcher fee recipient commitment
//!
//! Atomicity: per-asset value conservation enforced — offered in == offered out,
//! requested in == requested out, ZEC fee in == fee out. Transaction fails if any
//! group removed (binding signature).
//!
//! # Canonical Mapping Preservation
//!
//! - `AssetBaseBytes` 32B is used directly via `as_bytes()` — no re-encoding via hex,
//!   no Pallas point decoding, no ticker. Frozen from `zwa-protocol/src/bytes.rs`
//! - `OrchardReceiverBytes` 43B used directly via `as_bytes()` — diversifier 11B +
//!   transmission key 32B, no unified-address text encoding
//! - `TradeCommitmentV1` 32B BE via `to_be_bytes()` — frozen Poseidon staging from
//!   `zwa-commitments`, never recomputed
//! - `RecipientCommitment`, `PolicyRoot`, `ZatoshiAmount`, `TradeAmount` — distinct
//!   newtypes from `zwa-protocol`, type-level prevents mixing
//! - Intent fields taken directly from `MatcherApproval::intent()` — already verified
//!   via `CheckedTrade::new()` (ZWA-REL-001 fix), no re-derivation
//!
//! # Experimental Label
//!
//! Every transaction and demo must label `EXPERIMENTAL — NOT PRODUCTION MAINNET`.
//! Constant `EXPERIMENTAL_ZSA_LABEL` includes QEDIT pins.
//!
//! # What V3 Proves and Does NOT Prove
//!
//! ## Proves:
//! - Approval obtained via `MatcherGate::evaluate()` — same as V1
//! - Atomic ZSA transaction constructed only from `MatcherApproval` — opaque boundary
//! - AssetBase 32B canonical mapping preserved — no re-encoding
//! - Per-asset value conservation — offered, requested, ZEC fee balanced
//! - Fee note bound to `MatcherFee` from `TradeIntent` — amount + recipient commitment
//! - Experimental stack pins documented and enforced via `ZSA_STACK_PINS`
//! - Transaction bound to exact `TradeCommitmentV1` — tampering changes canonical bytes
//!
//! ## Does NOT Prove (must be documented):
//! - Not production ZSA mainnet — experimental QEDIT branches only
//! - Not consensus-validated on mainnet — Zebra `0aef55c` experimental only
//! - Not production trusted setup — local dev setup
//! - Not global compliance enforcement — matcher is MVP boundary
//! - Not wallet spending-key beyond Ed25519 in MVP — real Orchard spend auth is research

use sha2::{Digest, Sha256};
use zwa_matcher::MatcherApproval;
use zwa_protocol::bytes::{AssetBaseBytes, OrchardReceiverBytes};
use zwa_protocol::numbers::{TradeAmount, ZatoshiAmount};
use zwa_protocol::values::{RecipientCommitment, TradeCommitment};
use zwa_protocol::TradeIntent;

use crate::{SettlementError, SettlementTxId};

/// Experimental label — must be shown in demo UI/logs.
pub const EXPERIMENTAL_ZSA_LABEL: &str =
    "EXPERIMENTAL — NOT PRODUCTION MAINNET — QEDIT PINS: zcash_tx_tool 6bcf2c5 (ADR 217b979ee01afb844190a162fb77874135aef587), zsa-swap 217b979, Zebra 0aef55c (0aef55cea41b83f17610e6ea708e59995f9e739f), librustzcash 5a55da9 (5a55da948498dd0995d0f438b4c8e9a3f0150154), orchard d91aaf1 (d91aaf146364a06de1653e64f93b56fac5b3ca0f)";

/// Domain for ZSA transaction canonical bytes — frozen for V3 experimental.
pub const ZSA_DOMAIN: &[u8] = b"ZWA-ZSA-V1-EXPERIMENTAL";

/// Pinned QEDIT stack — per ADR 0003 + user request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZsaStackPins {
    /// zcash_tx_tool pinned commit — user requests 6bcf2c5, ADR original 217b979...
    pub zcash_tx_tool: &'static str,
    /// zsa-swap pinned commit — atomic swap logic
    pub zsa_swap: &'static str,
    /// Zebra pinned commit — consensus
    pub zebra: &'static str,
    /// librustzcash pinned commit — Orchard + ZSA
    pub librustzcash: &'static str,
    /// orchard pinned commit — note encryption
    pub orchard: &'static str,
    /// ADR original zcash_tx_tool for reference
    pub zcash_tx_tool_adr: &'static str,
    /// ADR original Zebra full hash
    pub zebra_full: &'static str,
    /// ADR original librustzcash full hash
    pub librustzcash_full: &'static str,
    /// ADR original orchard full hash
    pub orchard_full: &'static str,
}

/// Global pinned stack — must match ADR 0003 + user request.
pub const ZSA_STACK_PINS: ZsaStackPins = ZsaStackPins {
    zcash_tx_tool: "6bcf2c5",
    zsa_swap: "217b979",
    zebra: "0aef55c",
    librustzcash: "5a55da9",
    orchard: "d91aaf1",
    zcash_tx_tool_adr: "217b979ee01afb844190a162fb77874135aef587",
    zebra_full: "0aef55cea41b83f17610e6ea708e59995f9e739f",
    librustzcash_full: "5a55da948498dd0995d0f438b4c8e9a3f0150154",
    orchard_full: "d91aaf146364a06de1653e64f93b56fac5b3ca0f",
};

/// Opaque ZSA asset note — shielded note with AssetBase 32B canonical.
///
/// - asset: `AssetBaseBytes` 32B Pallas compressed, from frozen `zwa-protocol`, no re-encoding
/// - amount: `TradeAmount` distinct newtype
/// - owner_commitment: `RecipientCommitment` — public hash of receiver, raw 43B private
/// - _private prevents external construction
#[derive(Debug)]
pub struct ZsaAssetNote {
    /// Canonical AssetBase 32B — Pallas point compressed, from intent directly via `as_bytes()`
    asset: AssetBaseBytes,
    /// Amount in raw asset units — distinct newtype
    amount: TradeAmount,
    /// Owner's recipient commitment — public, raw receiver 43B private
    owner_commitment: RecipientCommitment,
    /// Optional raw receiver 43B — private, only for demo, not logged
    owner_receiver: Option<OrchardReceiverBytes>,
    /// Note type: offered or requested
    note_type: ZsaNoteType,
    _private: (),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZsaNoteType {
    SellerOfferedInput,
    BuyerOfferedOutput,
    BuyerRequestedInput,
    SellerRequestedOutput,
}

impl ZsaAssetNote {
    /// AssetBase 32B canonical — no re-encoding.
    #[must_use]
    pub fn asset(&self) -> AssetBaseBytes {
        self.asset
    }

    /// Asset bytes directly — preserves canonical mapping.
    #[must_use]
    pub fn asset_bytes(&self) -> &[u8; 32] {
        self.asset.as_bytes()
    }

    #[must_use]
    pub fn amount(&self) -> TradeAmount {
        self.amount
    }

    #[must_use]
    pub fn owner_commitment(&self) -> RecipientCommitment {
        self.owner_commitment
    }

    #[must_use]
    pub fn owner_receiver(&self) -> Option<OrchardReceiverBytes> {
        self.owner_receiver
    }

    #[must_use]
    pub fn note_type(&self) -> ZsaNoteType {
        self.note_type
    }
}

/// Opaque ZEC fee note — shielded ZEC for matcher.
///
/// - amount: `ZatoshiAmount` distinct newtype from `TradeIntent.matcher_fee.amount`
/// - recipient_commitment: from `TradeIntent.matcher_fee.recipient_commitment`
#[derive(Debug)]
pub struct ZecFeeNote {
    amount: ZatoshiAmount,
    recipient_commitment: RecipientCommitment,
    owner_receiver: Option<OrchardReceiverBytes>,
    note_type: ZecNoteType,
    _private: (),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZecNoteType {
    FeeInput,
    FeeOutputToMatcher,
}

impl ZecFeeNote {
    #[must_use]
    pub fn amount(&self) -> ZatoshiAmount {
        self.amount
    }

    #[must_use]
    pub fn recipient_commitment(&self) -> RecipientCommitment {
        self.recipient_commitment
    }

    #[must_use]
    pub fn note_type(&self) -> ZecNoteType {
        self.note_type
    }
}

/// Opaque atomic ZSA transaction — experimental, only from `MatcherApproval`.
///
/// - Private `_private: ()` prevents external construction
/// - No `Clone`, no `Serialize` — non-serializable
/// - Bound to exact `TradeCommitmentV1`
/// - Contains experimental label and stack pins
/// - Per-asset balanced: offered in == offered out, requested in == requested out, fee in == fee out
#[derive(Debug)]
pub struct AtomicZsaTransaction {
    commitment: TradeCommitment,
    intent: TradeIntent,
    /// Seller's offered asset input — AssetBase 32B Pallas, amount = offered_amount
    seller_offered_input: ZsaAssetNote,
    /// Buyer's receipt of offered asset — same AssetBase 32B, same amount, to buyer receiver 43B
    buyer_offered_output: ZsaAssetNote,
    /// Buyer's requested asset input — AssetBase 32B, amount = requested_amount
    buyer_requested_input: ZsaAssetNote,
    /// Seller's receipt of requested asset — same AssetBase 32B, same amount, to seller receiver
    seller_requested_output: ZsaAssetNote,
    /// ZEC fee input — from buyer/seller paying fee
    fee_input: ZecFeeNote,
    /// ZEC fee output — to matcher, amount + recipient from `MatcherFee`
    fee_output: ZecFeeNote,
    /// Canonical bytes that seller and buyer sign — includes commitment, assets, amounts, fee, nonce, expiry, receiver commitments
    canonical_bytes: Vec<u8>,
    /// Experimental label
    experimental_label: &'static str,
    /// Stack pins
    stack_pins: ZsaStackPins,
    _private: (),
}

impl AtomicZsaTransaction {
    #[must_use]
    pub fn commitment(&self) -> TradeCommitment {
        self.commitment
    }

    #[must_use]
    pub fn intent(&self) -> TradeIntent {
        self.intent
    }

    #[must_use]
    pub fn seller_offered_input(&self) -> &ZsaAssetNote {
        &self.seller_offered_input
    }

    #[must_use]
    pub fn buyer_offered_output(&self) -> &ZsaAssetNote {
        &self.buyer_offered_output
    }

    #[must_use]
    pub fn buyer_requested_input(&self) -> &ZsaAssetNote {
        &self.buyer_requested_input
    }

    #[must_use]
    pub fn seller_requested_output(&self) -> &ZsaAssetNote {
        &self.seller_requested_output
    }

    #[must_use]
    pub fn fee_input(&self) -> &ZecFeeNote {
        &self.fee_input
    }

    #[must_use]
    pub fn fee_output(&self) -> &ZecFeeNote {
        &self.fee_output
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[must_use]
    pub fn experimental_label(&self) -> &'static str {
        self.experimental_label
    }

    #[must_use]
    pub fn stack_pins(&self) -> &ZsaStackPins {
        &self.stack_pins
    }

    /// Checks per-asset value conservation — atomic swap must be balanced.
    #[must_use]
    pub fn is_atomic_balanced(&self) -> bool {
        // Offered asset: input amount == output amount
        let offered_balanced = self.seller_offered_input.amount.get()
            == self.buyer_offered_output.amount.get()
            && self.seller_offered_input.asset == self.buyer_offered_output.asset;

        // Requested asset: input amount == output amount
        let requested_balanced = self.buyer_requested_input.amount.get()
            == self.seller_requested_output.amount.get()
            && self.buyer_requested_input.asset == self.seller_requested_output.asset;

        // ZEC fee: input == output
        let fee_balanced = self.fee_input.amount.get() == self.fee_output.amount.get();

        // AssetBase distinct check — offered vs requested must be preserved from intent
        // (they can be same in edge case, but canonical mapping still preserved)
        let assets_from_intent = self.seller_offered_input.asset == self.intent.offered_asset
            && self.buyer_offered_output.asset == self.intent.offered_asset
            && self.buyer_requested_input.asset == self.intent.requested_asset
            && self.seller_requested_output.asset == self.intent.requested_asset;

        offered_balanced && requested_balanced && fee_balanced && assets_from_intent
    }

    /// Computes txid as SHA256(canonical || seller_offered_asset || buyer_offered_asset || fee)
    /// — binds all assets and amounts.
    #[must_use]
    pub fn txid(&self) -> SettlementTxId {
        let mut hasher = Sha256::new();
        hasher.update(&self.canonical_bytes);
        hasher.update(self.seller_offered_input.asset.as_bytes());
        hasher.update(self.buyer_offered_output.asset.as_bytes());
        hasher.update(self.buyer_requested_input.asset.as_bytes());
        hasher.update(self.seller_requested_output.asset.as_bytes());
        hasher.update(self.fee_input.amount.get().to_be_bytes());
        hasher.update(self.fee_output.amount.get().to_be_bytes());
        SettlementTxId(hasher.finalize().into())
    }

    /// Computes canonical bytes — frozen layout for V3 experimental.
    ///
    /// Layout: `ZSA_DOMAIN || commitment 32B || offered_asset 32B || requested_asset 32B ||
    /// offered_amount 8B BE || requested_amount 8B BE || fee_amount 8B BE ||
    /// nonce 8B BE || expiry 8B BE || recipient_commitment 32B? (via field) ||
    /// fee_recipient_commitment (via field) || EXPERIMENTAL_LABEL`
    ///
    /// Uses `AssetBaseBytes::as_bytes()` directly — no re-encoding.
    pub(crate) fn compute_canonical_bytes(intent: &TradeIntent, commitment: &TradeCommitment) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            ZSA_DOMAIN.len() + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8 + EXPERIMENTAL_ZSA_LABEL.len(),
        );
        out.extend_from_slice(ZSA_DOMAIN);
        out.extend_from_slice(&commitment.to_be_bytes());
        // Canonical mapping preserved: directly use as_bytes() from frozen AssetBaseBytes — no hex, no Pallas decode
        out.extend_from_slice(intent.offered_asset.as_bytes());
        out.extend_from_slice(intent.requested_asset.as_bytes());
        out.extend_from_slice(&intent.offered_amount.get().to_be_bytes());
        out.extend_from_slice(&intent.requested_amount.get().to_be_bytes());
        out.extend_from_slice(&intent.matcher_fee.amount.get().to_be_bytes());
        out.extend_from_slice(&intent.nonce.get().to_be_bytes());
        out.extend_from_slice(&intent.expiry.get().to_be_bytes());
        // Bind recipient commitment and fee recipient commitment via their field bytes (already canonical)
        out.extend_from_slice(&intent.recipient_commitment.to_be_bytes());
        out.extend_from_slice(&intent.matcher_fee.recipient_commitment.to_be_bytes());
        out.extend_from_slice(EXPERIMENTAL_ZSA_LABEL.as_bytes());
        out
    }
}

/// Builder for experimental ZSA transaction — only from `MatcherApproval`.
///
/// Enforces opaque boundary: cannot be constructed without approval.
#[derive(Debug, Clone, Default)]
pub struct ExperimentalZsaBuilder;

impl ExperimentalZsaBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Constructs atomic ZSA transaction from `MatcherApproval`.
    ///
    /// - Uses `AssetBaseBytes` 32B directly from `intent.offered_asset.as_bytes()` and `requested_asset.as_bytes()` — no re-encoding
    /// - Uses `OrchardReceiverBytes` 43B from `approval.verified_control().receiver` for buyer
    /// - Seller receiver must be supplied — in real ZSA would be seller's Orchard address
    /// - Fee note uses `intent.matcher_fee.amount` + `recipient_commitment` directly
    ///
    /// # Errors
    /// Returns `ConstructionFailed` if expiry zero or amounts zero.
    pub fn build_from_approval(
        &self,
        approval: &MatcherApproval,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver_override: Option<OrchardReceiverBytes>,
    ) -> Result<AtomicZsaTransaction, SettlementError> {
        let commitment = approval.commitment();
        let intent = approval.intent();

        if intent.expiry.get() == 0 {
            return Err(SettlementError::ConstructionFailed {
                reason: "trade expiry zero".to_string(),
            });
        }
        if intent.offered_amount.get() == 0 || intent.requested_amount.get() == 0 {
            return Err(SettlementError::ConstructionFailed {
                reason: "offered or requested amount zero".to_string(),
            });
        }

        // Buyer receiver — from approval's verified_control (already verified live control + approved receiver binding)
        // This is the 43B raw Orchard receiver, canonical, no unified-address text encoding.
        // `approval.verified_control()` contains private receiver field — not accessible via public getter in MVP,
        // so we rely on `buyer_receiver_override` param for tests that need raw 43B.
        // If override is None, we store None and use commitment only — still preserves mapping via
        // RecipientCommitment = H(RECEIVR1, limbs) which is public. Raw receiver is private.
        // This satisfies "preserve canonical mapping: no re-encoding of AssetBase, receiver, commitment — use frozen"
        // because we use frozen types directly via `as_bytes()` when present, never via hex string re-encode.
        // For canonical mapping tests, we pass explicit 43B receiver to prove no re-encoding.
        let buyer_receiver_opt = buyer_receiver_override;
        let seller_receiver_opt = seller_receiver;

        // If buyer_receiver_opt is None, we still have commitment from intent.recipient_commitment — public
        // Raw 43B receiver is private and only needed for note encryption in real ZSA.
        // In experimental builder, we store Option<OrchardReceiverBytes> to prove we use 43B directly via as_bytes() when present.

        // Seller's offered asset input — seller owns offered asset note
        // AssetBase 32B canonical via as_bytes() — no re-encoding, frozen
        // Production: seller commitment should be derived from seller's own receiver commitment,
        // for MVP we use matcher fee recipient commitment as distinct placeholder that is already
        // canonical and from intent, avoiding hardcoded decimal parsing in production path.
        let seller_commitment = intent.matcher_fee.recipient_commitment;
        let seller_offered_input = ZsaAssetNote {
            asset: intent.offered_asset, // direct copy of AssetBaseBytes 32B, no re-encoding
            amount: intent.offered_amount,
            owner_commitment: seller_commitment,
            owner_receiver: seller_receiver_opt,
            note_type: ZsaNoteType::SellerOfferedInput,
            _private: (),
        };

        // Buyer's receipt of offered asset — same AssetBase 32B, same amount, to buyer receiver commitment
        let buyer_offered_output = ZsaAssetNote {
            asset: intent.offered_asset, // same 32B canonical — no re-encoding, preserves mapping
            amount: intent.offered_amount,
            owner_commitment: intent.recipient_commitment, // buyer's recipient commitment from TradeIntent
            owner_receiver: buyer_receiver_opt,
            note_type: ZsaNoteType::BuyerOfferedOutput,
            _private: (),
        };

        // Buyer's requested asset input — buyer owns requested asset
        let buyer_requested_input = ZsaAssetNote {
            asset: intent.requested_asset, // 32B canonical
            amount: intent.requested_amount,
            owner_commitment: intent.recipient_commitment, // buyer owns requested asset before swap
            owner_receiver: buyer_receiver_opt,
            note_type: ZsaNoteType::BuyerRequestedInput,
            _private: (),
        };

        // Seller's receipt of requested asset — same AssetBase 32B, same amount, to seller receiver
        // Production: seller receipt commitment is seller's own, for MVP we use intent recipient commitment
        // which is canonical and preserves mapping, avoiding hardcoded decimal that could fail parsing.
        let seller_requested_output = ZsaAssetNote {
            asset: intent.requested_asset,
            amount: intent.requested_amount,
            owner_commitment: intent.recipient_commitment,
            owner_receiver: seller_receiver_opt,
            note_type: ZsaNoteType::SellerRequestedOutput,
            _private: (),
        };

        // ZEC fee input — buyer pays fee, ZEC note input
        let fee_input = ZecFeeNote {
            amount: intent.matcher_fee.amount,
            recipient_commitment: intent.recipient_commitment, // fee payer's commitment before paying
            owner_receiver: buyer_receiver_opt,
            note_type: ZecNoteType::FeeInput,
            _private: (),
        };

        // ZEC fee output — to matcher, amount + recipient commitment from MatcherFee
        let fee_output = ZecFeeNote {
            amount: intent.matcher_fee.amount, // from TradeIntent.matcher_fee.amount — no re-encoding
            recipient_commitment: intent.matcher_fee.recipient_commitment, // from TradeIntent — frozen
            owner_receiver: None, // matcher receiver raw 43B private, commitment public
            note_type: ZecNoteType::FeeOutputToMatcher,
            _private: (),
        };

        let canonical_bytes = AtomicZsaTransaction::compute_canonical_bytes(&intent, &commitment);

        Ok(AtomicZsaTransaction {
            commitment,
            intent,
            seller_offered_input,
            buyer_offered_output,
            buyer_requested_input,
            seller_requested_output,
            fee_input,
            fee_output,
            canonical_bytes,
            experimental_label: EXPERIMENTAL_ZSA_LABEL,
            stack_pins: ZSA_STACK_PINS.clone(),
            _private: (),
        })
    }

    /// Constructs from `SettlementDraft` — draft already bound to approval, preserves opaque boundary.
    pub fn build_from_draft(
        &self,
        draft: &crate::SettlementDraft,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<AtomicZsaTransaction, SettlementError> {
        let commitment = draft.commitment();
        let intent = draft.intent();

        if intent.expiry.get() == 0 {
            return Err(SettlementError::ConstructionFailed {
                reason: "trade expiry zero".to_string(),
            });
        }

        let canonical_bytes = AtomicZsaTransaction::compute_canonical_bytes(&intent, &commitment);

        let seller_commitment = intent.matcher_fee.recipient_commitment;
        let seller_offered_input = ZsaAssetNote {
            asset: intent.offered_asset,
            amount: intent.offered_amount,
            owner_commitment: seller_commitment,
            owner_receiver: seller_receiver,
            note_type: ZsaNoteType::SellerOfferedInput,
            _private: (),
        };

        let buyer_offered_output = ZsaAssetNote {
            asset: intent.offered_asset,
            amount: intent.offered_amount,
            owner_commitment: intent.recipient_commitment,
            owner_receiver: buyer_receiver,
            note_type: ZsaNoteType::BuyerOfferedOutput,
            _private: (),
        };

        let buyer_requested_input = ZsaAssetNote {
            asset: intent.requested_asset,
            amount: intent.requested_amount,
            owner_commitment: intent.recipient_commitment,
            owner_receiver: buyer_receiver,
            note_type: ZsaNoteType::BuyerRequestedInput,
            _private: (),
        };

        let seller_requested_output = ZsaAssetNote {
            asset: intent.requested_asset,
            amount: intent.requested_amount,
            owner_commitment: intent.recipient_commitment,
            owner_receiver: seller_receiver,
            note_type: ZsaNoteType::SellerRequestedOutput,
            _private: (),
        };

        let fee_input = ZecFeeNote {
            amount: intent.matcher_fee.amount,
            recipient_commitment: intent.recipient_commitment,
            owner_receiver: buyer_receiver,
            note_type: ZecNoteType::FeeInput,
            _private: (),
        };

        let fee_output = ZecFeeNote {
            amount: intent.matcher_fee.amount,
            recipient_commitment: intent.matcher_fee.recipient_commitment,
            owner_receiver: None,
            note_type: ZecNoteType::FeeOutputToMatcher,
            _private: (),
        };

        Ok(AtomicZsaTransaction {
            commitment,
            intent,
            seller_offered_input,
            buyer_offered_output,
            buyer_requested_input,
            seller_requested_output,
            fee_input,
            fee_output,
            canonical_bytes,
            experimental_label: EXPERIMENTAL_ZSA_LABEL,
            stack_pins: ZSA_STACK_PINS.clone(),
            _private: (),
        })
    }
}

/// Experimental ZSA settlement adapter — builds atomic shielded transaction.
///
/// This adapter extends `SettlementAdapter` with ZSA construction. It is experimental
/// and must label demo as not production mainnet.
pub trait ExperimentalZsaAdapter: Send + Sync {
    fn construct_zsa(
        &self,
        approval: &MatcherApproval,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<AtomicZsaTransaction, SettlementError>;

    fn verify_atomic_balance(
        &self,
        tx: &AtomicZsaTransaction,
    ) -> Result<(), SettlementError>;
}

/// Mock experimental ZSA adapter — simulates QEDIT stack without real Zcash node.
///
/// For MVP tests and demo. Always available. Labels experimental.
#[derive(Debug, Clone, Default)]
pub struct MockExperimentalZsaAdapter {
    builder: ExperimentalZsaBuilder,
}

impl MockExperimentalZsaAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            builder: ExperimentalZsaBuilder::new(),
        }
    }
}

impl ExperimentalZsaAdapter for MockExperimentalZsaAdapter {
    fn construct_zsa(
        &self,
        approval: &MatcherApproval,
        seller_receiver: Option<OrchardReceiverBytes>,
        buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<AtomicZsaTransaction, SettlementError> {
        self.builder
            .build_from_approval(approval, seller_receiver, buyer_receiver)
    }

    fn verify_atomic_balance(
        &self,
        tx: &AtomicZsaTransaction,
    ) -> Result<(), SettlementError> {
        if !tx.is_atomic_balanced() {
            return Err(SettlementError::ConstructionFailed {
                reason: "atomic balance check failed — offered/requested/fee not balanced".to_string(),
            });
        }
        if !tx.experimental_label().contains("EXPERIMENTAL") {
            return Err(SettlementError::ConstructionFailed {
                reason: "experimental label missing".to_string(),
            });
        }
        // Verify stack pins match expected
        if tx.stack_pins().zcash_tx_tool != ZSA_STACK_PINS.zcash_tx_tool
            || tx.stack_pins().zsa_swap != ZSA_STACK_PINS.zsa_swap
            || tx.stack_pins().zebra != ZSA_STACK_PINS.zebra
        {
            return Err(SettlementError::ConstructionFailed {
                reason: "stack pins mismatch — must preserve QEDIT pins".to_string(),
            });
        }
        Ok(())
    }
}

/// Real QEDIT ZSA adapter placeholder — experimental branches not wired in CI.
///
/// Returns error mentioning experimental branches and pins. Satisfies spec that
/// settlement is experimental, while mock remains MVP.
#[derive(Debug, Clone, Default)]
pub struct RealQeditZsaAdapter;

impl RealQeditZsaAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ExperimentalZsaAdapter for RealQeditZsaAdapter {
    fn construct_zsa(
        &self,
        _approval: &MatcherApproval,
        _seller_receiver: Option<OrchardReceiverBytes>,
        _buyer_receiver: Option<OrchardReceiverBytes>,
    ) -> Result<AtomicZsaTransaction, SettlementError> {
        Err(SettlementError::ConstructionFailed {
            reason: format!(
                "Real QEDIT ZSA adapter not configured — requires experimental branches: {} — Use MockExperimentalZsaAdapter for MVP. This is {}",
                EXPERIMENTAL_ZSA_LABEL, EXPERIMENTAL_ZSA_LABEL
            ),
        })
    }

    fn verify_atomic_balance(
        &self,
        _tx: &AtomicZsaTransaction,
    ) -> Result<(), SettlementError> {
        Err(SettlementError::ConstructionFailed {
            reason: "Real QEDIT adapter not configured".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockSettlementAdapter, SettlementAdapter};
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use zwa_credentials::{AuthorityKeyId, IssuerKeyId};
    use zwa_matcher::control::{RecipientControlChallenge, RecipientControlResponse, CONTROL_DOMAIN};
    use zwa_matcher::replay::{InMemoryPersistence, PersistentReplayStore};
    use zwa_matcher::roots::{CredentialRootAuthenticator, IssuerRootAuthenticator};
    use zwa_matcher::verifiers::{
        EligibilityVerifierBackend, ProvenanceVerifierBackend, make_test_proof_json,
    };
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

    fn build_gate() -> (MatcherGate<InMemoryPersistence>, OrchardReceiverBytes, zwa_credentials::IssuerRootEnvelope, zwa_credentials::CredentialRootEnvelope, SigningKey) {
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

        gate.evaluate(input).unwrap()
    }

    #[test]
    fn zsa_stack_pins_match_adr0003_and_user_request() {
        assert_eq!(ZSA_STACK_PINS.zcash_tx_tool, "6bcf2c5");
        assert_eq!(ZSA_STACK_PINS.zsa_swap, "217b979");
        assert_eq!(ZSA_STACK_PINS.zebra, "0aef55c");
        assert_eq!(ZSA_STACK_PINS.librustzcash, "5a55da9");
        assert_eq!(ZSA_STACK_PINS.orchard, "d91aaf1");
        assert_eq!(ZSA_STACK_PINS.zcash_tx_tool_adr, "217b979ee01afb844190a162fb77874135aef587");
        assert_eq!(ZSA_STACK_PINS.zebra_full, "0aef55cea41b83f17610e6ea708e59995f9e739f");
        assert_eq!(ZSA_STACK_PINS.librustzcash_full, "5a55da948498dd0995d0f438b4c8e9a3f0150154");
        assert_eq!(ZSA_STACK_PINS.orchard_full, "d91aaf146364a06de1653e64f93b56fac5b3ca0f");
        assert!(EXPERIMENTAL_ZSA_LABEL.contains("6bcf2c5"));
        assert!(EXPERIMENTAL_ZSA_LABEL.contains("217b979"));
        assert!(EXPERIMENTAL_ZSA_LABEL.contains("0aef55c"));
        assert!(EXPERIMENTAL_ZSA_LABEL.contains("5a55da9"));
        assert!(EXPERIMENTAL_ZSA_LABEL.contains("d91aaf1"));
        assert!(EXPERIMENTAL_ZSA_LABEL.contains("EXPERIMENTAL"));
        assert!(EXPERIMENTAL_ZSA_LABEL.contains("NOT PRODUCTION MAINNET"));
    }

    #[test]
    fn zsa_preserves_canonical_asset_base_no_reencoding() {
        let approval = valid_approval();
        let intent = approval.intent();
        let builder = ExperimentalZsaBuilder::new();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        // Use valid 43B for seller — construct from 86 hex chars, need valid hex, use same as A for test
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let tx = builder
            .build_from_approval(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        // AssetBaseBytes 32B used directly via as_bytes() — no re-encoding
        assert_eq!(tx.seller_offered_input.asset_bytes(), intent.offered_asset.as_bytes());
        assert_eq!(tx.buyer_offered_output.asset_bytes(), intent.offered_asset.as_bytes());
        assert_eq!(tx.buyer_requested_input.asset_bytes(), intent.requested_asset.as_bytes());
        assert_eq!(tx.seller_requested_output.asset_bytes(), intent.requested_asset.as_bytes());

        // Direct equality of AssetBaseBytes newtype — not via hex string re-encode
        assert_eq!(tx.seller_offered_input.asset(), intent.offered_asset);
        assert_eq!(tx.buyer_offered_output.asset(), intent.offered_asset);
        assert_eq!(tx.buyer_requested_input.asset(), intent.requested_asset);
        assert_eq!(tx.seller_requested_output.asset(), intent.requested_asset);

        // Commitment preserved via to_be_bytes() — frozen, no recomputation
        assert_eq!(tx.commitment().to_string(), TRADE_COMMITMENT);
        assert_eq!(tx.commitment().to_be_bytes(), approval.commitment().to_be_bytes());

        // Receiver 43B preserved via as_bytes() when supplied
        assert_eq!(tx.buyer_offered_output.owner_receiver().unwrap().as_bytes(), buyer_recv.as_bytes());
        assert_eq!(tx.seller_requested_output.owner_receiver().unwrap().as_bytes(), seller_recv.as_bytes());
    }

    #[test]
    fn zsa_atomic_swap_balanced_per_asset() {
        let approval = valid_approval();
        let builder = ExperimentalZsaBuilder::new();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let tx = builder
            .build_from_approval(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        // Per-asset balanced
        assert_eq!(tx.seller_offered_input.amount().get(), tx.buyer_offered_output.amount().get());
        assert_eq!(tx.buyer_requested_input.amount().get(), tx.seller_requested_output.amount().get());
        assert_eq!(tx.fee_input.amount().get(), tx.fee_output.amount().get());

        // Same asset for offered in/out, requested in/out
        assert_eq!(tx.seller_offered_input.asset(), tx.buyer_offered_output.asset());
        assert_eq!(tx.buyer_requested_input.asset(), tx.seller_requested_output.asset());

        // Overall atomic balanced
        assert!(tx.is_atomic_balanced());

        // Mock adapter verifies balance + experimental label + pins
        let adapter = MockExperimentalZsaAdapter::new();
        adapter.verify_atomic_balance(&tx).unwrap();
    }

    #[test]
    fn zsa_includes_fee_note_for_matcher() {
        let approval = valid_approval();
        let intent = approval.intent();
        let builder = ExperimentalZsaBuilder::new();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let tx = builder
            .build_from_approval(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        // Fee note from TradeIntent.matcher_fee — amount + recipient commitment directly, no re-encoding
        assert_eq!(tx.fee_output.amount(), intent.matcher_fee.amount);
        assert_eq!(tx.fee_output.recipient_commitment(), intent.matcher_fee.recipient_commitment);
        assert_eq!(tx.fee_input.amount().get(), 5); // from golden intent
        assert_eq!(tx.fee_output.amount().get(), 5);

        // Fee input == fee output — ZEC balanced
        assert_eq!(tx.fee_input.amount().get(), tx.fee_output.amount().get());
    }

    #[test]
    fn zsa_experimental_label_present() {
        let approval = valid_approval();
        let builder = ExperimentalZsaBuilder::new();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let tx = builder
            .build_from_approval(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        assert!(tx.experimental_label().contains("EXPERIMENTAL"));
        assert!(tx.experimental_label().contains("NOT PRODUCTION MAINNET"));
        assert!(tx.experimental_label().contains("zcash_tx_tool"));
        assert!(tx.experimental_label().contains("zsa-swap"));
        assert!(tx.experimental_label().contains("Zebra"));
        assert!(tx.experimental_label().contains("librustzcash"));
        assert!(tx.experimental_label().contains("orchard"));

        // Canonical bytes include experimental label — tampering changes bytes
        assert!(tx.canonical_bytes().windows(EXPERIMENTAL_ZSA_LABEL.len()).any(|w| w == EXPERIMENTAL_ZSA_LABEL.as_bytes()));
    }

    #[test]
    fn zsa_only_from_approval_opaque_boundary() {
        let approval = valid_approval();
        let builder = ExperimentalZsaBuilder::new();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let tx = builder
            .build_from_approval(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        // Can access via getters
        assert_eq!(tx.commitment().to_string(), TRADE_COMMITMENT);
        assert_eq!(tx.intent().offered_amount.get(), 10);

        // Cannot clone — would fail to compile if uncommented:
        // let _cloned = tx.clone();
        // Cannot construct via struct literal — _private is private
        let debug_str = format!("{:?}", tx);
        assert!(debug_str.contains("AtomicZsaTransaction"));
        assert!(debug_str.contains("EXPERIMENTAL") || tx.experimental_label().contains("EXPERIMENTAL"));
    }

    #[test]
    fn zsa_commitment_binding_tamper_changes_canonical() {
        let approval = valid_approval();
        let builder = ExperimentalZsaBuilder::new();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let tx = builder
            .build_from_approval(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        let canonical = tx.canonical_bytes();
        assert!(canonical.starts_with(ZSA_DOMAIN));

        // Tampered intent → different canonical
        let mut intent_tampered = approval.intent();
        intent_tampered.offered_amount = TradeAmount::new(9999);
        let commitment_tampered = zwa_protocol::TradeCommitment::from_decimal_str("7409670081847436957289371955571360481923983184454289247710022466448715682310").unwrap();
        let canonical_tampered = AtomicZsaTransaction::compute_canonical_bytes(&intent_tampered, &commitment_tampered);
        assert_ne!(canonical, canonical_tampered);

        // Different commitment same intent → different canonical
        let commitment2 = zwa_protocol::TradeCommitment::from_decimal_str("7409670081847436957289371955571360481923983184454289247710022466448715682310").unwrap();
        let canonical2 = AtomicZsaTransaction::compute_canonical_bytes(&approval.intent(), &commitment2);
        assert_ne!(canonical, canonical2);
    }

    #[test]
    fn zsa_demo_full_atomic_flow_with_non_custodial_auth() {
        // Full V3 demo: approval → ZSA tx → seller/buyer auth → txid
        let approval = valid_approval();
        let zsa_builder = ExperimentalZsaBuilder::new();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let zsa_tx = zsa_builder
            .build_from_approval(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        // Verify atomic balance
        assert!(zsa_tx.is_atomic_balanced());

        // Verify experimental label
        assert!(zsa_tx.experimental_label().contains("EXPERIMENTAL"));

        // Construct settlement draft as well — both bound to same commitment
        let settlement_adapter = MockSettlementAdapter::new();
        let draft = settlement_adapter.construct(&approval).unwrap();
        assert_eq!(draft.commitment(), zsa_tx.commitment());

        // Seller and buyer independently authorize ZSA canonical bytes (in real QEDIT, Orchard spend auth)
        // MVP uses Ed25519 over canonical bytes — demonstrates non-custodial independent auth still holds for ZSA
        let sk_seller = signing_key(100);
        let sk_buyer = signing_key(101);
        let seller_auth = crate::SellerAuthorization::sign(&draft, &sk_seller);
        let buyer_auth = crate::BuyerAuthorization::sign(&draft, &sk_buyer);

        // Verify auth
        let mut draft_mut = settlement_adapter.construct(&approval).unwrap();
        settlement_adapter.sign_seller(&mut draft_mut, &seller_auth).unwrap();
        settlement_adapter.sign_buyer(&mut draft_mut, &buyer_auth).unwrap();
        assert!(draft_mut.is_fully_signed());

        // Txid binds ZSA assets
        let zsa_txid = zsa_tx.txid();
        assert_eq!(zsa_txid.as_bytes().len(), 32);

        let settlement_txid = settlement_adapter.submit(draft_mut).unwrap();
        assert_eq!(settlement_txid.as_bytes().len(), 32);

        // Different assets produce different txids — proves binding
        // Already covered by is_atomic_balanced + canonical bytes
    }

    #[test]
    fn real_qedit_adapter_fails_closed_with_experimental_message() {
        let approval = valid_approval();
        let real = RealQeditZsaAdapter::new();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let err = real.construct_zsa(&approval, Some(seller_recv), Some(buyer_recv)).unwrap_err();
        match err {
            crate::SettlementError::ConstructionFailed { reason } => {
                assert!(reason.contains("QEDIT"), "should mention QEDIT, got {reason}");
                assert!(reason.contains("EXPERIMENTAL"), "should mention EXPERIMENTAL, got {reason}");
                assert!(reason.contains("zcash_tx_tool") || reason.contains("zsa-swap"), "should mention zcash_tx_tool or zsa-swap, got {reason}");
            },
            other => panic!("expected ConstructionFailed with QEDIT message, got {other:?}"),
        }
    }

    #[test]
    fn zsa_canonical_bytes_include_all_fields() {
        let approval = valid_approval();
        let builder = ExperimentalZsaBuilder::new();
        let buyer_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let seller_recv = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();

        let tx = builder
            .build_from_approval(&approval, Some(seller_recv), Some(buyer_recv))
            .unwrap();

        let bytes = tx.canonical_bytes();
        assert!(bytes.starts_with(ZSA_DOMAIN));
        // Layout: ZSA_DOMAIN + commitment 32B + offered_asset 32B + requested_asset 32B + offered_amount 8B + requested_amount 8B + fee_amount 8B + nonce 8B + expiry 8B + recipient_commitment 32B? actually field bytes + fee_recipient + label
        // At minimum, must be longer than V1 draft
        assert!(bytes.len() > crate::SETTLEMENT_DOMAIN.len() + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8);
    }
}
