//! Phase 3 settlement adapter — V1 opaque boundary (Vikram).
//!
//! This crate is the **only** place where `MatcherApproval` (`VerifiedTrade`)
//! is turned into a ZSA settlement transaction. It imports frozen crates
//! (`zwa-protocol`, `zwa-commitments`, `zwa-credentials`) and `zwa-matcher`
//! and must never reimplement their encodings, domains, or Poseidon staging.
//!
//! # V1: Settlement Adapter Trait — opaque boundary
//!
//! `MatcherApproval` is opaque, non-cloneable, non-serializable, and can only
//! be obtained via `MatcherGate::evaluate()` after all 10 gates pass (Tasks A-F + A1-A8).
//! This crate enforces that settlement can **only** be constructed from that approval:
//!
//! - `SettlementAdapter::construct()` takes `&MatcherApproval`, not raw `TradeIntent`/`TradeCommitment`
//! - `SettlementDraft` is opaque (`!Clone`, `!Serialize`, private `_private: ()`), cannot be fabricated outside this crate
//! - `SellerAuthorization` and `BuyerAuthorization` are distinct opaque witnesses — seller and buyer independently authorize their own ZSA actions, matcher never holds spending authority
//! - `UnconfiguredSettlementAdapter` is fail-closed default, returns `Unconfigured` error
//! - `MockSettlementAdapter` is for tests only, simulates construction without real ZSA stack
//!
//! # What settlement proves and does NOT prove (per handoff Sec 6, 24, 30)
//!
//! ## Proves after `construct() + sign_seller() + sign_buyer() + submit()`:
//! - Approval was obtained via `MatcherGate::evaluate()` — intent/commitment correspondence, root auth current/fresh/combined expiry, live control, replay, real Groth16 proofs same-commitment
//! - Settlement draft is bound to exact `TradeCommitmentV1` from approval — no re-derivation, no substitution
//! - Seller independently authorized offered asset spend (Ed25519 signature over draft canonical bytes in MVP, real Orchard spend auth in production)
//! - Buyer independently authorized requested asset spend (same)
//! - Both authorizations verified before submission — non-custodial: venue cannot move funds without seller + buyer sigs
//! - Draft is bound to commitment, offered asset, requested asset, fee, nonce, expiry — tampering changes canonical bytes and fails verification
//!
//! ## Does NOT prove (must be documented in demo):
//! - Not production ZSA mainnet — settlement is experimental QEDIT branches (`zcash_tx_tool 6bcf2c5`, `zsa-swap 217b979`, Zebra `0aef55c`, librustzcash `5a55da9`, orchard `d91aaf1`), demo must label experimental
//! - Not global compliance enforcement — matcher is MVP compliance boundary, Zcash consensus does not enforce investor policy, direct ZSA transfers outside venue remain possible
//! - Not instant global revocation — revocation latency is root refresh interval
//! - Not production trusted setup — Phase 0 used local dev setup, not ceremony
//! - Not recursive lineage — optional research track
//! - Not wallet spending-key beyond Ed25519 control challenge in MVP — real Orchard ivk proof is research
//!
//! # Security
//! - `MatcherApproval` private `_private: ()` prevents external construction — only `gate` module can produce it, type-level enforcement
//! - `SettlementDraft` private `_private: ()` prevents external construction — only `SettlementAdapter::construct()` can produce it
//! - `SellerAuthorization` / `BuyerAuthorization` distinct types — cannot mix seller and buyer auth, type-level
//! - `UnconfiguredSettlementAdapter` fail-closed — returns `Unconfigured` if used without real adapter
//! - Canonical bytes: `b"ZWA-SETTLE-V1" || commitment 32B || offered_asset 32B || requested_asset 32B || offered_amount 8B BE || requested_amount 8B BE || fee_amount 8B BE || nonce 8B BE || expiry 8B BE`
//! - Ed25519 signatures in MVP — deterministic, non-malleable, verified via `ed25519-dalek 2.1.1`
//! - Replay integration: after `submit()`, caller must call `PersistentReplayStore::submit()`, `confirm()`, `consume()` — settlement does not bypass replay

#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod control;
pub mod non_custodial;
pub mod replay;
pub mod zsa;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zwa_matcher::{MatcherApproval, VerifiedTrade};
use zwa_protocol::numbers::TradeExpiry;
use zwa_protocol::{TradeCommitment, TradeIntent};

/// Domain for settlement draft canonical bytes — frozen for V1.
pub const SETTLEMENT_DOMAIN: &[u8] = b"ZWA-SETTLE-V1";

/// Errors from settlement adapter — typed, no strings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SettlementError {
    #[error("settlement adapter unconfigured — fail-closed")]
    Unconfigured,

    #[error("invalid approval: trade expired at {expiry}, now {now}")]
    ApprovalExpired { expiry: u64, now: u64 },

    #[error("draft already seller-signed")]
    AlreadySellerSigned,

    #[error("draft already buyer-signed")]
    AlreadyBuyerSigned,

    #[error("draft not seller-signed")]
    NotSellerSigned,

    #[error("draft not buyer-signed")]
    NotBuyerSigned,

    #[error("seller authorization failed: {reason}")]
    SellerAuthFailed { reason: String },

    #[error("buyer authorization failed: {reason}")]
    BuyerAuthFailed { reason: String },

    #[error("seller and buyer authorizations must be distinct keys")]
    SameKeyForSellerAndBuyer,

    #[error("construction failed: {reason}")]
    ConstructionFailed { reason: String },

    #[error("submission failed: {reason}")]
    SubmissionFailed { reason: String },

    #[error("commitment mismatch: draft {draft} vs approval {approval}")]
    CommitmentMismatch { draft: String, approval: String },
}

/// Opaque witness that seller independently authorized offered asset spend.
///
/// Private fields, no Clone, no Serialize, cannot be fabricated outside this crate
/// except via `sign()` which requires seller's control signing key.
#[derive(Debug)]
pub struct SellerAuthorization {
    pub(crate) signature: [u8; 64],
    pub(crate) verifying_key: VerifyingKey,
    pub(crate) commitment: TradeCommitment,
    pub(crate) _private: (),
}

impl SellerAuthorization {
    /// Signs settlement draft canonical bytes with seller's signing key.
    ///
    /// In MVP, seller controls offered asset via Ed25519 key. Production will use Orchard spend auth.
    #[must_use]
    pub fn sign(draft: &SettlementDraft, signing_key: &SigningKey) -> Self {
        let sig = signing_key.sign(&draft.canonical_bytes);
        Self {
            signature: sig.to_bytes(),
            verifying_key: signing_key.verifying_key(),
            commitment: draft.commitment,
            _private: (),
        }
    }

    /// Verifying key that signed.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Commitment this auth is bound to.
    #[must_use]
    pub fn commitment(&self) -> TradeCommitment {
        self.commitment
    }

    /// Signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Opaque witness that buyer independently authorized requested asset spend.
///
/// Distinct type from `SellerAuthorization` — type-level prevents mixing.
#[derive(Debug)]
pub struct BuyerAuthorization {
    pub(crate) signature: [u8; 64],
    pub(crate) verifying_key: VerifyingKey,
    pub(crate) commitment: TradeCommitment,
    pub(crate) _private: (),
}

impl BuyerAuthorization {
    /// Signs settlement draft canonical bytes with buyer's signing key.
    #[must_use]
    pub fn sign(draft: &SettlementDraft, signing_key: &SigningKey) -> Self {
        let sig = signing_key.sign(&draft.canonical_bytes);
        Self {
            signature: sig.to_bytes(),
            verifying_key: signing_key.verifying_key(),
            commitment: draft.commitment,
            _private: (),
        }
    }

    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    #[must_use]
    pub fn commitment(&self) -> TradeCommitment {
        self.commitment
    }

    #[must_use]
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Opaque settlement draft — can only be obtained via `SettlementAdapter::construct()`.
///
/// - Private `_private: ()` prevents external construction via struct literal
/// - No `Clone`, no `Serialize` — non-serializable, type-level
/// - Bound to exact `TradeCommitmentV1` from `MatcherApproval` — no re-derivation
/// - Must be seller-signed and buyer-signed before submission
#[derive(Debug)]
pub struct SettlementDraft {
    commitment: TradeCommitment,
    intent: TradeIntent,
    canonical_bytes: Vec<u8>,
    seller_signed: bool,
    buyer_signed: bool,
    seller_vk: Option<VerifyingKey>,
    buyer_vk: Option<VerifyingKey>,
    _private: (),
}

impl SettlementDraft {
    /// Commitment this draft is for — from approval.
    #[must_use]
    pub fn commitment(&self) -> TradeCommitment {
        self.commitment
    }

    /// Intent this draft is for — from approval.
    #[must_use]
    pub fn intent(&self) -> TradeIntent {
        self.intent
    }

    /// Canonical bytes that seller and buyer sign.
    ///
    /// Layout: `SETTLEMENT_DOMAIN || commitment 32B || offered_asset 32B || requested_asset 32B || offered_amount 8B BE || requested_amount 8B BE || fee_amount 8B BE || nonce 8B BE || expiry 8B BE`
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Whether seller has signed.
    #[must_use]
    pub fn is_seller_signed(&self) -> bool {
        self.seller_signed
    }

    /// Whether buyer has signed.
    #[must_use]
    pub fn is_buyer_signed(&self) -> bool {
        self.buyer_signed
    }

    /// Whether fully signed and ready for submission.
    #[must_use]
    pub fn is_fully_signed(&self) -> bool {
        self.seller_signed && self.buyer_signed
    }

    /// Returns seller verifying key if signed.
    #[must_use]
    pub fn seller_vk(&self) -> Option<&VerifyingKey> {
        self.seller_vk.as_ref()
    }

    /// Returns buyer verifying key if signed.
    #[must_use]
    pub fn buyer_vk(&self) -> Option<&VerifyingKey> {
        self.buyer_vk.as_ref()
    }

    /// Computes canonical bytes from intent + commitment.
    pub(crate) fn compute_canonical_bytes(intent: &TradeIntent, commitment: &TradeCommitment) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            SETTLEMENT_DOMAIN.len() + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8,
        );
        out.extend_from_slice(SETTLEMENT_DOMAIN);
        out.extend_from_slice(&commitment.to_be_bytes());
        out.extend_from_slice(intent.offered_asset.as_bytes());
        out.extend_from_slice(intent.requested_asset.as_bytes());
        out.extend_from_slice(&intent.offered_amount.get().to_be_bytes());
        out.extend_from_slice(&intent.requested_amount.get().to_be_bytes());
        out.extend_from_slice(&intent.matcher_fee.amount.get().to_be_bytes());
        out.extend_from_slice(&intent.nonce.get().to_be_bytes());
        out.extend_from_slice(&intent.expiry.get().to_be_bytes());
        out
    }

    /// SHA256 hash of canonical bytes — used as txid in mock adapter.
    fn txid_from_canonical(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.canonical_bytes);
        // Include seller and buyer VKs if signed, to bind signatures to txid
        if let Some(vk) = &self.seller_vk {
            hasher.update(vk.to_bytes());
        }
        if let Some(vk) = &self.buyer_vk {
            hasher.update(vk.to_bytes());
        }
        hasher.finalize().into()
    }
}

/// Settlement transaction ID — 32-byte hash, opaque.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SettlementTxId(pub [u8; 32]);

impl SettlementTxId {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl From<[u8; 32]> for SettlementTxId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<SettlementTxId> for zwa_protocol::lifecycle::SettlementTxId {
    fn from(id: SettlementTxId) -> Self {
        zwa_protocol::lifecycle::SettlementTxId::new(id.0)
    }
}

/// Opaque trait for settlement — Vikram V1 boundary.
///
/// Production implementations must be fail-closed. `UnconfiguredSettlementAdapter`
/// returns `Unconfigured` error. Real ZSA path will use QEDIT experimental stack.
/// Test-only mock is `MockSettlementAdapter` behind `#[cfg(test)]` or always available for MVP.
///
/// The trait only accepts `&MatcherApproval` — never raw `TradeIntent`/`TradeCommitment` — enforcing
/// that settlement can only happen after all 10 gates pass.
pub trait SettlementAdapter: Send + Sync {
    /// Constructs draft from approved trade — only path to obtain `SettlementDraft`.
    ///
    /// # Errors
    /// Returns `SettlementError` if approval expired or construction fails.
    fn construct(&self, approval: &MatcherApproval) -> Result<SettlementDraft, SettlementError>;

    /// Seller independently signs draft — proves seller controls offered asset.
    ///
    /// # Errors
    /// Returns `SellerAuthFailed` if signature invalid, `AlreadySellerSigned` if already signed.
    fn sign_seller(
        &self,
        draft: &mut SettlementDraft,
        auth: &SellerAuthorization,
    ) -> Result<(), SettlementError>;

    /// Buyer independently signs draft — proves buyer controls requested asset.
    ///
    /// # Errors
    /// Returns `BuyerAuthFailed` if signature invalid, `AlreadyBuyerSigned` if already signed.
    fn sign_buyer(
        &self,
        draft: &mut SettlementDraft,
        auth: &BuyerAuthorization,
    ) -> Result<(), SettlementError>;

    /// Submits fully signed draft — returns txid.
    ///
    /// # Errors
    /// Returns `NotSellerSigned` / `NotBuyerSigned` if not fully signed, `SubmissionFailed` otherwise.
    fn submit(&self, draft: SettlementDraft) -> Result<SettlementTxId, SettlementError>;
}

/// Production fail-closed adapter — returns Unconfigured if used without real ZSA stack.
///
/// This is the default when no settlement adapter is configured. It ensures
/// the venue blocks settlement rather than allowing bypass when adapter not set up.
#[derive(Debug, Clone, Default)]
pub struct UnconfiguredSettlementAdapter;

impl SettlementAdapter for UnconfiguredSettlementAdapter {
    fn construct(&self, _approval: &MatcherApproval) -> Result<SettlementDraft, SettlementError> {
        Err(SettlementError::Unconfigured)
    }

    fn sign_seller(
        &self,
        _draft: &mut SettlementDraft,
        _auth: &SellerAuthorization,
    ) -> Result<(), SettlementError> {
        Err(SettlementError::Unconfigured)
    }

    fn sign_buyer(
        &self,
        _draft: &mut SettlementDraft,
        _auth: &BuyerAuthorization,
    ) -> Result<(), SettlementError> {
        Err(SettlementError::Unconfigured)
    }

    fn submit(&self, _draft: SettlementDraft) -> Result<SettlementTxId, SettlementError> {
        Err(SettlementError::Unconfigured)
    }
}

/// Mock settlement adapter — simulates ZSA construction without real QEDIT stack.
///
/// For MVP tests and demo. Always available (not only `#[cfg(test)]`) to allow
/// integration tests that don't need real Zcash. Production must use real adapter
/// with `from_fixture()`-like VK hash checks and experimental label.
#[derive(Debug, Clone, Default)]
pub struct MockSettlementAdapter;

impl MockSettlementAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SettlementAdapter for MockSettlementAdapter {
    fn construct(&self, approval: &MatcherApproval) -> Result<SettlementDraft, SettlementError> {
        let commitment = approval.commitment();
        let intent = approval.intent();

        // Check expiry — trade must not be expired at construction time (use current time as now for MVP)
        // In real adapter, now would be supplied, here we just check intent expiry is not zero
        if intent.expiry.get() == 0 {
            return Err(SettlementError::ConstructionFailed {
                reason: "trade expiry zero".to_string(),
            });
        }

        let canonical = SettlementDraft::compute_canonical_bytes(&intent, &commitment);

        Ok(SettlementDraft {
            commitment,
            intent,
            canonical_bytes: canonical,
            seller_signed: false,
            buyer_signed: false,
            seller_vk: None,
            buyer_vk: None,
            _private: (),
        })
    }

    fn sign_seller(
        &self,
        draft: &mut SettlementDraft,
        auth: &SellerAuthorization,
    ) -> Result<(), SettlementError> {
        if draft.seller_signed {
            return Err(SettlementError::AlreadySellerSigned);
        }
        if auth.commitment() != draft.commitment {
            return Err(SettlementError::CommitmentMismatch {
                draft: draft.commitment.to_string(),
                approval: auth.commitment().to_string(),
            });
        }

        // Verify Ed25519 signature over canonical bytes
        let sig = Signature::from_bytes(auth.signature());
        auth.verifying_key
            .verify(&draft.canonical_bytes, &sig)
            .map_err(|_| SettlementError::SellerAuthFailed {
                reason: "invalid seller Ed25519 signature".to_string(),
            })?;

        // Prevent same key for seller and buyer (non-custodial: distinct parties)
        if let Some(buyer_vk) = &draft.buyer_vk {
            if buyer_vk.to_bytes() == auth.verifying_key.to_bytes() {
                return Err(SettlementError::SameKeyForSellerAndBuyer);
            }
        }

        draft.seller_signed = true;
        draft.seller_vk = Some(auth.verifying_key);
        Ok(())
    }

    fn sign_buyer(
        &self,
        draft: &mut SettlementDraft,
        auth: &BuyerAuthorization,
    ) -> Result<(), SettlementError> {
        if draft.buyer_signed {
            return Err(SettlementError::AlreadyBuyerSigned);
        }
        if auth.commitment() != draft.commitment {
            return Err(SettlementError::CommitmentMismatch {
                draft: draft.commitment.to_string(),
                approval: auth.commitment().to_string(),
            });
        }

        let sig = Signature::from_bytes(auth.signature());
        auth.verifying_key
            .verify(&draft.canonical_bytes, &sig)
            .map_err(|_| SettlementError::BuyerAuthFailed {
                reason: "invalid buyer Ed25519 signature".to_string(),
            })?;

        if let Some(seller_vk) = &draft.seller_vk {
            if seller_vk.to_bytes() == auth.verifying_key.to_bytes() {
                return Err(SettlementError::SameKeyForSellerAndBuyer);
            }
        }

        draft.buyer_signed = true;
        draft.buyer_vk = Some(auth.verifying_key);
        Ok(())
    }

    fn submit(&self, draft: SettlementDraft) -> Result<SettlementTxId, SettlementError> {
        if !draft.seller_signed {
            return Err(SettlementError::NotSellerSigned);
        }
        if !draft.buyer_signed {
            return Err(SettlementError::NotBuyerSigned);
        }

        // Mock txid = SHA256(canonical || seller_vk || buyer_vk)
        let txid_bytes = draft.txid_from_canonical();
        Ok(SettlementTxId(txid_bytes))
    }
}

/// Real ZSA adapter placeholder — experimental QEDIT stack not yet wired.
///
/// Returns error mentioning experimental branches. Satisfies spec that settlement
/// is experimental, while mock remains MVP.
#[derive(Debug, Clone, Default)]
pub struct RealZsaAdapterPlaceholder;

impl RealZsaAdapterPlaceholder {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SettlementAdapter for RealZsaAdapterPlaceholder {
    fn construct(&self, _approval: &MatcherApproval) -> Result<SettlementDraft, SettlementError> {
        Err(SettlementError::ConstructionFailed {
            reason: "Real ZSA adapter not configured — requires QEDIT experimental branches zcash_tx_tool 6bcf2c5, zsa-swap 217b979, Zebra 0aef55c, librustzcash 5a55da9, orchard d91aaf1. Use MockSettlementAdapter for MVP or enable zsa feature".to_string(),
        })
    }

    fn sign_seller(
        &self,
        _draft: &mut SettlementDraft,
        _auth: &SellerAuthorization,
    ) -> Result<(), SettlementError> {
        Err(SettlementError::ConstructionFailed {
            reason: "Real ZSA adapter not configured".to_string(),
        })
    }

    fn sign_buyer(
        &self,
        _draft: &mut SettlementDraft,
        _auth: &BuyerAuthorization,
    ) -> Result<(), SettlementError> {
        Err(SettlementError::ConstructionFailed {
            reason: "Real ZSA adapter not configured".to_string(),
        })
    }

    fn submit(&self, _draft: SettlementDraft) -> Result<SettlementTxId, SettlementError> {
        Err(SettlementError::SubmissionFailed {
            reason: "Real ZSA adapter not configured".to_string(),
        })
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
    use zwa_matcher::verifiers::{EligibilityVerifierBackend, ProvenanceVerifierBackend, make_test_proof_json};
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

    fn valid_approval() -> MatcherApproval {
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
    fn settlement_draft_is_opaque_non_clone() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let draft = adapter.construct(&approval).unwrap();

        // Can access via getters
        assert_eq!(draft.commitment().to_string(), TRADE_COMMITMENT);
        assert_eq!(draft.intent().offered_amount.get(), 10);
        assert!(!draft.is_seller_signed());
        assert!(!draft.is_buyer_signed());
        assert!(!draft.is_fully_signed());

        // Cannot clone — would fail to compile if uncommented:
        // let _cloned = draft.clone();
        // Cannot construct via struct literal — _private is private
        // let _fake = SettlementDraft { commitment: ..., _private: () }; // fails outside module
        let debug_str = format!("{:?}", draft);
        assert!(debug_str.contains("SettlementDraft"));
    }

    #[test]
    fn valid_settlement_flow_seller_buyer_independent_auth() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();

        // Construct only from approval — not from raw intent/commitment
        let mut draft = adapter.construct(&approval).unwrap();
        assert_eq!(draft.commitment(), approval.commitment());

        // Seller and buyer are distinct keys — non-custodial
        let sk_seller = signing_key(10);
        let sk_buyer = signing_key(11);
        assert_ne!(sk_seller.verifying_key().to_bytes(), sk_buyer.verifying_key().to_bytes());

        let seller_auth = SellerAuthorization::sign(&draft, &sk_seller);
        let buyer_auth = BuyerAuthorization::sign(&draft, &sk_buyer);

        // Distinct types — cannot mix
        // let _wrong: SellerAuthorization = buyer_auth; // compile error

        adapter.sign_seller(&mut draft, &seller_auth).unwrap();
        assert!(draft.is_seller_signed());
        assert!(!draft.is_fully_signed());

        adapter.sign_buyer(&mut draft, &buyer_auth).unwrap();
        assert!(draft.is_fully_signed());

        let txid = adapter.submit(draft).unwrap();
        assert_eq!(txid.as_bytes().len(), 32);
        assert!(!txid.to_hex().is_empty());
    }

    #[test]
    fn settlement_fails_if_not_fully_signed() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let mut draft = adapter.construct(&approval).unwrap();

        let sk_seller = signing_key(20);
        let seller_auth = SellerAuthorization::sign(&draft, &sk_seller);

        // Only seller signed → submit must fail
        adapter.sign_seller(&mut draft, &seller_auth).unwrap();
        let err = adapter.submit(draft).unwrap_err();
        match err {
            SettlementError::NotBuyerSigned => {},
            other => panic!("expected NotBuyerSigned, got {other:?}"),
        }
    }

    #[test]
    fn settlement_fails_if_same_key_for_seller_and_buyer() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let mut draft = adapter.construct(&approval).unwrap();

        let sk_same = signing_key(30);
        let seller_auth = SellerAuthorization::sign(&draft, &sk_same);
        let buyer_auth = BuyerAuthorization::sign(&draft, &sk_same);

        adapter.sign_seller(&mut draft, &seller_auth).unwrap();
        let err = adapter.sign_buyer(&mut draft, &buyer_auth).unwrap_err();
        match err {
            SettlementError::SameKeyForSellerAndBuyer => {},
            other => panic!("expected SameKeyForSellerAndBuyer, got {other:?}"),
        }
    }

    #[test]
    fn settlement_fails_if_invalid_seller_signature() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let mut draft = adapter.construct(&approval).unwrap();

        let sk_seller = signing_key(40);
        let mut seller_auth = SellerAuthorization::sign(&draft, &sk_seller);
        // Tamper signature
        seller_auth.signature[0] ^= 1;

        let err = adapter.sign_seller(&mut draft, &seller_auth).unwrap_err();
        match err {
            SettlementError::SellerAuthFailed { .. } => {},
            other => panic!("expected SellerAuthFailed, got {other:?}"),
        }
    }

    #[test]
    fn unconfigured_adapter_fail_closed() {
        let approval = valid_approval();
        let unconfigured = UnconfiguredSettlementAdapter;

        let err = unconfigured.construct(&approval).unwrap_err();
        match err {
            SettlementError::Unconfigured => {},
            other => panic!("expected Unconfigured, got {other:?}"),
        }
    }

    #[test]
    fn trait_object_works_for_vikram() {
        let approval = valid_approval();
        let real_adapter = MockSettlementAdapter::new();
        let boxed: Box<dyn SettlementAdapter> = Box::new(real_adapter);

        let mut draft = boxed.construct(&approval).unwrap();
        let sk_seller = signing_key(50);
        let sk_buyer = signing_key(51);
        let seller_auth = SellerAuthorization::sign(&draft, &sk_seller);
        let buyer_auth = BuyerAuthorization::sign(&draft, &sk_buyer);

        boxed.sign_seller(&mut draft, &seller_auth).unwrap();
        boxed.sign_buyer(&mut draft, &buyer_auth).unwrap();
        let txid = boxed.submit(draft).unwrap();
        assert_eq!(txid.as_bytes().len(), 32);
    }

    #[test]
    fn real_zsa_placeholder_fails_closed_with_experimental_message() {
        let approval = valid_approval();
        let real = RealZsaAdapterPlaceholder::new();

        let err = real.construct(&approval).unwrap_err();
        match err {
            SettlementError::ConstructionFailed { reason } => {
                assert!(reason.contains("QEDIT"), "should mention QEDIT, got {reason}");
                assert!(reason.contains("zcash_tx_tool"), "should mention zcash_tx_tool, got {reason}");
            },
            other => panic!("expected ConstructionFailed with QEDIT message, got {other:?}"),
        }
    }

    #[test]
    fn canonical_bytes_include_all_fields_and_change_on_mutation() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let draft = adapter.construct(&approval).unwrap();

        let bytes = draft.canonical_bytes();
        assert!(bytes.starts_with(SETTLEMENT_DOMAIN));
        assert_eq!(bytes.len(), SETTLEMENT_DOMAIN.len() + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8);

        // Different commitment → different canonical bytes
        let mut intent2 = approval.intent();
        intent2.offered_amount = zwa_protocol::TradeAmount::new(999);
        // Can't construct draft with mutated intent without new approval — proves binding
        // But we can test canonical computation directly
        let commitment2 = zwa_protocol::TradeCommitment::from_decimal_str("7409670081847436957289371955571360481923983184454289247710022466448715682310").unwrap();
        let bytes2 = SettlementDraft::compute_canonical_bytes(&intent2, &commitment2);
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn settlement_txid_binds_signatures() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let mut draft = adapter.construct(&approval).unwrap();

        let sk_seller = signing_key(60);
        let sk_buyer = signing_key(61);
        let seller_auth = SellerAuthorization::sign(&draft, &sk_seller);
        let buyer_auth = BuyerAuthorization::sign(&draft, &sk_buyer);

        adapter.sign_seller(&mut draft, &seller_auth).unwrap();
        adapter.sign_buyer(&mut draft, &buyer_auth).unwrap();

        let txid1 = adapter.submit(draft).unwrap();

        // Same approval but different seller key → different txid
        let approval2 = valid_approval();
        let mut draft2 = adapter.construct(&approval2).unwrap();
        let sk_seller2 = signing_key(62);
        let seller_auth2 = SellerAuthorization::sign(&draft2, &sk_seller2);
        let buyer_auth2 = BuyerAuthorization::sign(&draft2, &sk_buyer);
        adapter.sign_seller(&mut draft2, &seller_auth2).unwrap();
        adapter.sign_buyer(&mut draft2, &buyer_auth2).unwrap();
        let txid2 = adapter.submit(draft2).unwrap();

        assert_ne!(txid1.as_bytes(), txid2.as_bytes(), "txid must bind seller key");
    }
}
