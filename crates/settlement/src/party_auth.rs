//! Independent party authorization (M3 remediation F-03, F-04, §5).
//!
//! # Trust anchor (F-03)
//!
//! The key that must have signed for each role is **never** taken from the
//! authorization object. It comes from a [`PartyIdentitySource`], which the
//! integrator must back with an independently authenticated source (for
//! example an authenticated client session, a wallet identity established
//! during the RFQ, or an externally registered authorization key). The
//! product architecture does not yet define that source, so M3 defines the
//! interface and ships:
//!
//! - [`UnconfiguredPartyIdentitySource`]: the fail-closed default; every
//!   lookup fails.
//! - [`RegisteredPartyKeys`]: an explicit registry of expected keys per trade.
//!   It must only be populated from an authenticated channel; it does not
//!   decide by itself who the parties are.
//!
//! # No private keys on the server (F-04)
//!
//! The server issues a [`PartyAuthorizationRequest`]. Each party signs
//! [`PartyAuthorizationRequest::signing_bytes`] locally with Ed25519
//! (RFC 8032) and returns only the public [`PartyAuthorization`]: the request
//! echo, the claimed public key and the 64-byte signature. No function in this
//! crate accepts a signing key, seed, spending key or Orchard key.
//!
//! # Signed message (95 bytes, all integers big-endian)
//!
//! ```text
//! "ZWA1PARTYAUTH" (13) | version u8 = 1 | role u8 (1 seller, 2 buyer)
//! | TradeCommitmentV1 (32) | authorization_nonce (32) | issued_at u64 | expires_at u64
//! ```
//!
//! The message is domain separated (distinct from the matcher's control and
//! root domains) and role separated: a seller signature is never a buyer
//! signature. It is bound to one trade through the frozen `TradeCommitmentV1`,
//! which itself covers assets, amounts, recipient, fee, nonce and expiry.
//!
//! # Replay semantics
//!
//! - A signature is valid only for the exact issued request: role, trade,
//!   32-byte server nonce and window. Presenting it against any other request
//!   (another trade, another role, a fresh nonce) fails.
//! - Inside its window, re-verifying the same authorization against the same
//!   request is idempotent and deliberately not tracked here. It can only ever
//!   contribute to the single `ApprovedSettlement` that the single M2
//!   `MatcherApproval` for the trade allows: `approve` consumes the approval by
//!   value, and M2's replay store never mints a second approval for the same
//!   commitment. M3 keeps no protocol replay state of its own (F-09).
//! - Expiry: `now > expires_at` fails and `now == expires_at` is valid, the
//!   same predicate as the frozen trade expiry. A request may not outlive its
//!   trade.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use zwa_protocol::numbers::UnixSeconds;
use zwa_protocol::{TradeCommitment, TradeIntent};

/// Domain tag of the party-authorization message.
pub const PARTY_AUTH_DOMAIN: &[u8; 13] = b"ZWA1PARTYAUTH";
/// Version byte of the party-authorization message.
pub const PARTY_AUTH_VERSION: u8 = 1;
/// Length of the server-chosen authorization nonce.
pub const PARTY_AUTH_NONCE_LEN: usize = 32;
/// Length of the signed party-authorization message.
pub const PARTY_AUTH_MESSAGE_LEN: usize = 13 + 1 + 1 + 32 + PARTY_AUTH_NONCE_LEN + 8 + 8;

/// Role of a settlement party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PartyRole {
    /// Delivers the offered asset.
    Seller,
    /// Delivers the requested asset.
    Buyer,
}

impl PartyRole {
    /// Role byte in the signed message.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Seller => 1,
            Self::Buyer => 2,
        }
    }
}

/// Party-authorization failures (all fail closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PartyAuthError {
    /// No identity source configured.
    #[error("party identity source is not configured (fail closed)")]
    IdentitySourceUnconfigured,
    /// The identity source knows no parties for this trade.
    #[error("no expected party keys are registered for this trade")]
    UnknownTrade,
    /// A different key pair is already registered for this trade.
    #[error("different party keys are already registered for this trade")]
    ConflictingRegistration,
    /// Seller and buyer keys are identical.
    #[error("seller and buyer must have distinct authorization keys")]
    SameKeyForBothRoles,
    /// Not a valid, non-weak Ed25519 public key.
    #[error("invalid party verification key")]
    InvalidKey,
    /// `issued_at > expires_at`.
    #[error("invalid authorization window: issued_at {issued_at} > expires_at {expires_at}")]
    InvalidWindow {
        /// Start of the window.
        issued_at: u64,
        /// End of the window.
        expires_at: u64,
    },
    /// The request would outlive the trade.
    #[error("authorization expires at {expires_at}, after the trade expiry {trade_expiry}")]
    OutlivesTrade {
        /// Requested end of the window.
        expires_at: u64,
        /// Trade expiry.
        trade_expiry: u64,
    },
    /// OS randomness unavailable for the nonce.
    #[error("randomness unavailable for the authorization nonce")]
    RandomnessUnavailable,
    /// The authorization was signed for a different role.
    #[error("authorization is for role {got:?}, expected {expected:?}")]
    WrongRole {
        /// Role of the issued request.
        expected: PartyRole,
        /// Role in the authorization.
        got: PartyRole,
    },
    /// The authorization was signed for a different trade.
    #[error("authorization is bound to a different trade")]
    WrongTrade,
    /// The authorization echoes a different request than the one issued.
    #[error("authorization does not match the issued request ({field})")]
    RequestMismatch {
        /// First differing request field.
        field: &'static str,
    },
    /// `now < issued_at`.
    #[error("authorization not yet valid: now {now} < issued_at {issued_at}")]
    NotYetValid {
        /// Verification time.
        now: u64,
        /// Start of the window.
        issued_at: u64,
    },
    /// `now > expires_at`.
    #[error("authorization expired: now {now} > expires_at {expires_at}")]
    Expired {
        /// Verification time.
        now: u64,
        /// End of the window.
        expires_at: u64,
    },
    /// The claimed signer is not the independently expected key.
    #[error("authorization is not from the expected party key")]
    UnexpectedSigner,
    /// The signature does not verify under the expected key.
    #[error("invalid authorization signature")]
    BadSignature,
}

/// A party's Ed25519 authorization public key (valid, non-weak point).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PartyVerificationKey(VerifyingKey);

impl PartyVerificationKey {
    /// Parses a 32-byte Ed25519 public key; small-order (weak) keys are rejected.
    ///
    /// # Errors
    ///
    /// [`PartyAuthError::InvalidKey`].
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, PartyAuthError> {
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| PartyAuthError::InvalidKey)?;
        if key.is_weak() {
            return Err(PartyAuthError::InvalidKey);
        }
        Ok(Self(key))
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl std::fmt::Debug for PartyVerificationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PartyVerificationKey(")?;
        for byte in self.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// The keys that must authorize a trade, known before any signature is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedParties {
    seller: PartyVerificationKey,
    buyer: PartyVerificationKey,
}

impl ExpectedParties {
    /// Expected seller and buyer keys; they must differ.
    ///
    /// # Errors
    ///
    /// [`PartyAuthError::SameKeyForBothRoles`].
    pub fn new(
        seller: PartyVerificationKey,
        buyer: PartyVerificationKey,
    ) -> Result<Self, PartyAuthError> {
        if seller == buyer {
            return Err(PartyAuthError::SameKeyForBothRoles);
        }
        Ok(Self { seller, buyer })
    }

    /// Expected key for `role`.
    #[must_use]
    pub const fn key_for(&self, role: PartyRole) -> &PartyVerificationKey {
        match role {
            PartyRole::Seller => &self.seller,
            PartyRole::Buyer => &self.buyer,
        }
    }

    /// Expected seller key.
    #[must_use]
    pub const fn seller(&self) -> &PartyVerificationKey {
        &self.seller
    }

    /// Expected buyer key.
    #[must_use]
    pub const fn buyer(&self) -> &PartyVerificationKey {
        &self.buyer
    }
}

/// Independently authenticated source of the expected party keys (F-03).
///
/// Implementations must derive the answer from their own authenticated
/// records, never from anything inside a `PartyAuthorization`.
pub trait PartyIdentitySource: Send + Sync {
    /// Expected seller and buyer keys for `trade_commitment`.
    ///
    /// # Errors
    ///
    /// Any error; callers fail closed.
    fn expected_parties(
        &self,
        trade_commitment: TradeCommitment,
    ) -> Result<ExpectedParties, PartyAuthError>;
}

/// Default identity source: always fails closed until a real one is supplied.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredPartyIdentitySource;

impl PartyIdentitySource for UnconfiguredPartyIdentitySource {
    fn expected_parties(&self, _: TradeCommitment) -> Result<ExpectedParties, PartyAuthError> {
        Err(PartyAuthError::IdentitySourceUnconfigured)
    }
}

/// Explicit registry of externally registered authorization keys per trade.
///
/// Populate it only from an authenticated channel (for example the
/// authenticated RFQ sessions of both counterparties). A registration cannot
/// be silently replaced by a different key pair.
#[derive(Debug, Clone, Default)]
pub struct RegisteredPartyKeys {
    entries: BTreeMap<TradeCommitment, ExpectedParties>,
}

impl RegisteredPartyKeys {
    /// Empty registry (every lookup fails with `UnknownTrade`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the expected parties of a trade. Re-registering the same pair
    /// is a no-op.
    ///
    /// # Errors
    ///
    /// [`PartyAuthError::ConflictingRegistration`] if a different pair is registered.
    pub fn register(
        &mut self,
        trade_commitment: TradeCommitment,
        parties: ExpectedParties,
    ) -> Result<(), PartyAuthError> {
        match self.entries.get(&trade_commitment) {
            Some(existing) if *existing != parties => Err(PartyAuthError::ConflictingRegistration),
            Some(_) => Ok(()),
            None => {
                self.entries.insert(trade_commitment, parties);
                Ok(())
            }
        }
    }
}

impl PartyIdentitySource for RegisteredPartyKeys {
    fn expected_parties(
        &self,
        trade_commitment: TradeCommitment,
    ) -> Result<ExpectedParties, PartyAuthError> {
        self.entries
            .get(&trade_commitment)
            .copied()
            .ok_or(PartyAuthError::UnknownTrade)
    }
}

/// Server-issued, canonical request for one party's authorization of one trade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyAuthorizationRequest {
    role: PartyRole,
    trade_commitment: TradeCommitment,
    nonce: [u8; PARTY_AUTH_NONCE_LEN],
    issued_at: UnixSeconds,
    expires_at: UnixSeconds,
}

impl PartyAuthorizationRequest {
    /// Request for `role` over the canonical `intent`. The commitment is
    /// recomputed by the frozen engine, never supplied by the caller.
    ///
    /// # Errors
    ///
    /// `InvalidWindow` if `issued_at > expires_at`; `OutlivesTrade` if
    /// `expires_at` is after the trade expiry.
    pub fn new(
        role: PartyRole,
        intent: &TradeIntent,
        nonce: [u8; PARTY_AUTH_NONCE_LEN],
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Self, PartyAuthError> {
        if issued_at > expires_at {
            return Err(PartyAuthError::InvalidWindow {
                issued_at: issued_at.get(),
                expires_at: expires_at.get(),
            });
        }
        if expires_at.get() > intent.expiry.get() {
            return Err(PartyAuthError::OutlivesTrade {
                expires_at: expires_at.get(),
                trade_expiry: intent.expiry.get(),
            });
        }
        Ok(Self {
            role,
            trade_commitment: zwa_commitments::trade::trade_commitment_v1(intent),
            nonce,
            issued_at,
            expires_at,
        })
    }

    /// Like [`new`](Self::new) with a fresh 32-byte nonce from OS randomness.
    ///
    /// # Errors
    ///
    /// As `new`, plus `RandomnessUnavailable`.
    pub fn issue(
        role: PartyRole,
        intent: &TradeIntent,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Result<Self, PartyAuthError> {
        let mut nonce = [0u8; PARTY_AUTH_NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| PartyAuthError::RandomnessUnavailable)?;
        Self::new(role, intent, nonce, issued_at, expires_at)
    }

    /// Party role.
    #[must_use]
    pub const fn role(&self) -> PartyRole {
        self.role
    }

    /// Bound `TradeCommitmentV1`.
    #[must_use]
    pub const fn trade_commitment(&self) -> TradeCommitment {
        self.trade_commitment
    }

    /// Server-chosen nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; PARTY_AUTH_NONCE_LEN] {
        &self.nonce
    }

    /// Start of the validity window.
    #[must_use]
    pub const fn issued_at(&self) -> UnixSeconds {
        self.issued_at
    }

    /// End of the validity window (inclusive).
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    /// The exact bytes the party signs (see the module docs for the layout).
    #[must_use]
    pub fn signing_bytes(&self) -> [u8; PARTY_AUTH_MESSAGE_LEN] {
        let mut out = [0u8; PARTY_AUTH_MESSAGE_LEN];
        let parts: [&[u8]; 7] = [
            PARTY_AUTH_DOMAIN,
            &[PARTY_AUTH_VERSION],
            &[self.role.tag()],
            &self.trade_commitment.to_be_bytes(),
            &self.nonce,
            &self.issued_at.get().to_be_bytes(),
            &self.expires_at.get().to_be_bytes(),
        ];
        let mut offset = 0;
        for part in parts {
            out[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        out
    }
}

/// A party's returned authorization: untrusted wire data.
///
/// It carries only public material. `claimed_signer` is informational: it
/// must equal the independently expected key and is never used as a trust
/// anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyAuthorization {
    request: PartyAuthorizationRequest,
    claimed_signer: [u8; 32],
    signature: [u8; 64],
}

impl PartyAuthorization {
    /// Assembles an authorization received from a client.
    #[must_use]
    pub const fn new(
        request: PartyAuthorizationRequest,
        claimed_signer: [u8; 32],
        signature: [u8; 64],
    ) -> Self {
        Self {
            request,
            claimed_signer,
            signature,
        }
    }

    /// The request the party says it signed.
    #[must_use]
    pub const fn request(&self) -> &PartyAuthorizationRequest {
        &self.request
    }

    /// Public key the party claims to have signed with.
    #[must_use]
    pub const fn claimed_signer(&self) -> &[u8; 32] {
        &self.claimed_signer
    }

    /// Ed25519 signature over the request's signing bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Evidence that the expected party authorized the issued request.
///
/// It can only be produced by [`verify_party_authorization`] and contains only
/// public material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPartyAuthorization {
    request: PartyAuthorizationRequest,
    signer: PartyVerificationKey,
    signature: [u8; 64],
}

impl VerifiedPartyAuthorization {
    /// Role authorized.
    #[must_use]
    pub const fn role(&self) -> PartyRole {
        self.request.role
    }

    /// Trade authorized.
    #[must_use]
    pub const fn trade_commitment(&self) -> TradeCommitment {
        self.request.trade_commitment
    }

    /// The issued request that was signed.
    #[must_use]
    pub const fn request(&self) -> &PartyAuthorizationRequest {
        &self.request
    }

    /// The independently expected key that signed.
    #[must_use]
    pub const fn signer(&self) -> &PartyVerificationKey {
        &self.signer
    }

    /// The verified signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Re-verifies the stored signature under the stored key.
    pub(crate) fn signature_is_valid(&self) -> bool {
        self.signer
            .0
            .verify_strict(
                &self.request.signing_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .is_ok()
    }
}

/// Verifies `authorization` against the request the server issued (`issued`)
/// and the independently expected key for that role.
///
/// Check order: role, trade, the rest of the request echo, window, signer
/// identity, then the Ed25519 signature (`verify_strict`: canonical `S`, no
/// small-order components) over `issued.signing_bytes()`.
///
/// # Errors
///
/// The first failing check as a [`PartyAuthError`].
pub fn verify_party_authorization(
    authorization: &PartyAuthorization,
    issued: &PartyAuthorizationRequest,
    expected_key: &PartyVerificationKey,
    now: UnixSeconds,
) -> Result<VerifiedPartyAuthorization, PartyAuthError> {
    let echoed = &authorization.request;
    if echoed.role != issued.role {
        return Err(PartyAuthError::WrongRole {
            expected: issued.role,
            got: echoed.role,
        });
    }
    if echoed.trade_commitment != issued.trade_commitment {
        return Err(PartyAuthError::WrongTrade);
    }
    for (field, equal) in [
        ("nonce", echoed.nonce == issued.nonce),
        ("issued_at", echoed.issued_at == issued.issued_at),
        ("expires_at", echoed.expires_at == issued.expires_at),
    ] {
        if !equal {
            return Err(PartyAuthError::RequestMismatch { field });
        }
    }
    if now < issued.issued_at {
        return Err(PartyAuthError::NotYetValid {
            now: now.get(),
            issued_at: issued.issued_at.get(),
        });
    }
    if now > issued.expires_at {
        return Err(PartyAuthError::Expired {
            now: now.get(),
            expires_at: issued.expires_at.get(),
        });
    }
    if authorization.claimed_signer != expected_key.to_bytes() {
        return Err(PartyAuthError::UnexpectedSigner);
    }
    expected_key
        .0
        .verify_strict(
            &issued.signing_bytes(),
            &Signature::from_bytes(&authorization.signature),
        )
        .map_err(|_| PartyAuthError::BadSignature)?;
    Ok(VerifiedPartyAuthorization {
        request: issued.clone(),
        signer: *expected_key,
        signature: authorization.signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        golden_intent, other_intent, party_key, sign_locally, signing_key, BUYER_SEED, SELLER_SEED,
        T_ISSUED, T_NOW,
    };

    fn request(role: PartyRole, intent: &TradeIntent, nonce: u8) -> PartyAuthorizationRequest {
        PartyAuthorizationRequest::new(
            role,
            intent,
            [nonce; 32],
            UnixSeconds::new(T_ISSUED),
            UnixSeconds::new(intent.expiry.get()),
        )
        .unwrap()
    }

    fn now() -> UnixSeconds {
        UnixSeconds::new(T_NOW)
    }

    #[test]
    fn signing_bytes_layout_is_domain_role_and_trade_bound() {
        let intent = golden_intent();
        let seller = request(PartyRole::Seller, &intent, 9);
        let bytes = seller.signing_bytes();
        assert_eq!(bytes.len(), 95);
        assert_eq!(&bytes[..13], b"ZWA1PARTYAUTH");
        assert_eq!(bytes[13], 1, "version");
        assert_eq!(bytes[14], 1, "seller role tag");
        assert_eq!(
            &bytes[15..47],
            &zwa_commitments::trade::trade_commitment_v1(&intent).to_be_bytes()
        );
        assert_eq!(&bytes[47..79], &[9u8; 32]);
        assert_eq!(&bytes[79..87], &T_ISSUED.to_be_bytes());
        assert_eq!(&bytes[87..95], &intent.expiry.get().to_be_bytes());
        let buyer = request(PartyRole::Buyer, &intent, 9);
        assert_eq!(buyer.signing_bytes()[14], 2, "buyer role tag");
        assert_ne!(buyer.signing_bytes(), bytes, "role separation");
    }

    #[test]
    fn correct_seller_and_buyer_keys_pass() {
        let intent = golden_intent();
        for (role, seed) in [(PartyRole::Seller, SELLER_SEED), (PartyRole::Buyer, BUYER_SEED)] {
            let issued = request(role, &intent, 1);
            let auth = sign_locally(&issued, &signing_key(seed));
            let verified =
                verify_party_authorization(&auth, &issued, &party_key(seed), now()).unwrap();
            assert_eq!(verified.role(), role);
            assert_eq!(verified.trade_commitment(), issued.trade_commitment());
            assert_eq!(verified.signer(), &party_key(seed));
        }
    }

    #[test]
    fn attacker_self_generated_key_inserted_into_authorization_is_rejected() {
        let intent = golden_intent();
        let slots = [(PartyRole::Seller, SELLER_SEED), (PartyRole::Buyer, BUYER_SEED)];
        for (role, expected_seed) in slots {
            let issued = request(role, &intent, 1);
            // Attacker generates a fresh key pair, signs the valid trade and
            // inserts its own public key into the authorization.
            let attacker = signing_key(0xA7);
            let forged = sign_locally(&issued, &attacker);
            assert_eq!(forged.claimed_signer(), &attacker.verifying_key().to_bytes());
            assert_eq!(
                verify_party_authorization(&forged, &issued, &party_key(expected_seed), now()),
                Err(PartyAuthError::UnexpectedSigner)
            );
            // Claiming the expected key while signing with its own key fails too.
            let relabelled = PartyAuthorization::new(
                issued.clone(),
                party_key(expected_seed).to_bytes(),
                *forged.signature(),
            );
            assert_eq!(
                verify_party_authorization(&relabelled, &issued, &party_key(expected_seed), now()),
                Err(PartyAuthError::BadSignature)
            );
        }
    }

    #[test]
    fn matcher_generated_key_pair_signing_both_sides_is_rejected() {
        let intent = golden_intent();
        let (m_seller, m_buyer) = (signing_key(0xB1), signing_key(0xB2));
        let expected = ExpectedParties::new(party_key(SELLER_SEED), party_key(BUYER_SEED)).unwrap();
        for (role, key) in [(PartyRole::Seller, &m_seller), (PartyRole::Buyer, &m_buyer)] {
            let issued = request(role, &intent, 2);
            let auth = sign_locally(&issued, key);
            assert_eq!(
                verify_party_authorization(&auth, &issued, expected.key_for(role), now()),
                Err(PartyAuthError::UnexpectedSigner)
            );
        }
    }

    #[test]
    fn swapped_seller_and_buyer_keys_fail() {
        let intent = golden_intent();
        let expected = ExpectedParties::new(party_key(SELLER_SEED), party_key(BUYER_SEED)).unwrap();
        // Buyer's key signs the seller request and vice versa.
        let swapped = [(PartyRole::Seller, BUYER_SEED), (PartyRole::Buyer, SELLER_SEED)];
        for (role, wrong_seed) in swapped {
            let issued = request(role, &intent, 3);
            let auth = sign_locally(&issued, &signing_key(wrong_seed));
            assert_eq!(
                verify_party_authorization(&auth, &issued, expected.key_for(role), now()),
                Err(PartyAuthError::UnexpectedSigner)
            );
        }
    }

    #[test]
    fn seller_signature_cannot_be_used_as_buyer_authorization() {
        let intent = golden_intent();
        let seller_req = request(PartyRole::Seller, &intent, 4);
        let buyer_req = request(PartyRole::Buyer, &intent, 4);
        let seller_auth = sign_locally(&seller_req, &signing_key(SELLER_SEED));
        // Presented as-is for the buyer slot: the role differs.
        assert_eq!(
            verify_party_authorization(&seller_auth, &buyer_req, &party_key(SELLER_SEED), now()),
            Err(PartyAuthError::WrongRole {
                expected: PartyRole::Buyer,
                got: PartyRole::Seller
            })
        );
        // Re-wrapped as a buyer authorization: the signature is over the seller message.
        let rewrapped = PartyAuthorization::new(
            buyer_req.clone(),
            party_key(SELLER_SEED).to_bytes(),
            *seller_auth.signature(),
        );
        assert_eq!(
            verify_party_authorization(&rewrapped, &buyer_req, &party_key(SELLER_SEED), now()),
            Err(PartyAuthError::BadSignature)
        );
    }

    #[test]
    fn authorization_for_trade_a_cannot_authorize_trade_b() {
        let (a, b) = (golden_intent(), other_intent());
        let req_a = request(PartyRole::Seller, &a, 5);
        let req_b = request(PartyRole::Seller, &b, 5);
        assert_ne!(req_a.trade_commitment(), req_b.trade_commitment());
        let auth_a = sign_locally(&req_a, &signing_key(SELLER_SEED));
        assert_eq!(
            verify_party_authorization(&auth_a, &req_b, &party_key(SELLER_SEED), now()),
            Err(PartyAuthError::WrongTrade)
        );
        let seller_key = party_key(SELLER_SEED).to_bytes();
        let rewrapped = PartyAuthorization::new(req_b.clone(), seller_key, *auth_a.signature());
        assert_eq!(
            verify_party_authorization(&rewrapped, &req_b, &party_key(SELLER_SEED), now()),
            Err(PartyAuthError::BadSignature)
        );
    }

    #[test]
    fn replay_against_a_fresh_request_fails_and_same_request_is_idempotent() {
        let intent = golden_intent();
        let first = request(PartyRole::Buyer, &intent, 6);
        let fresh = request(PartyRole::Buyer, &intent, 7);
        let auth = sign_locally(&first, &signing_key(BUYER_SEED));
        assert_eq!(
            verify_party_authorization(&auth, &fresh, &party_key(BUYER_SEED), now()),
            Err(PartyAuthError::RequestMismatch { field: "nonce" })
        );
        // Documented semantics: the same auth against the same issued request
        // re-verifies (idempotent); single use is enforced by the single M2 approval.
        let key = party_key(BUYER_SEED);
        let once = verify_party_authorization(&auth, &first, &key, now()).unwrap();
        let twice = verify_party_authorization(&auth, &first, &key, now()).unwrap();
        assert_eq!(once, twice);
        // Issued nonces are random and distinct.
        let n1 = PartyAuthorizationRequest::issue(
            PartyRole::Buyer,
            &intent,
            UnixSeconds::new(T_ISSUED),
            UnixSeconds::new(T_NOW),
        )
        .unwrap();
        let n2 = PartyAuthorizationRequest::issue(
            PartyRole::Buyer,
            &intent,
            UnixSeconds::new(T_ISSUED),
            UnixSeconds::new(T_NOW),
        )
        .unwrap();
        assert_ne!(n1.nonce(), n2.nonce());
    }

    #[test]
    fn authorization_window_expiry_is_enforced() {
        let intent = golden_intent();
        let issued = PartyAuthorizationRequest::new(
            PartyRole::Seller,
            &intent,
            [8; 32],
            UnixSeconds::new(T_ISSUED),
            UnixSeconds::new(T_NOW),
        )
        .unwrap();
        let auth = sign_locally(&issued, &signing_key(SELLER_SEED));
        let key = party_key(SELLER_SEED);
        assert!(verify_party_authorization(&auth, &issued, &key, UnixSeconds::new(T_NOW)).is_ok());
        assert_eq!(
            verify_party_authorization(&auth, &issued, &key, UnixSeconds::new(T_NOW + 1)),
            Err(PartyAuthError::Expired {
                now: T_NOW + 1,
                expires_at: T_NOW
            })
        );
        assert_eq!(
            verify_party_authorization(&auth, &issued, &key, UnixSeconds::new(T_ISSUED - 1)),
            Err(PartyAuthError::NotYetValid {
                now: T_ISSUED - 1,
                issued_at: T_ISSUED
            })
        );
        // Requests cannot outlive the trade or have an inverted window.
        let past_trade = UnixSeconds::new(intent.expiry.get() + 1);
        assert!(matches!(
            PartyAuthorizationRequest::new(
                PartyRole::Seller,
                &intent,
                [0; 32],
                UnixSeconds::new(T_ISSUED),
                past_trade
            ),
            Err(PartyAuthError::OutlivesTrade { .. })
        ));
        assert!(matches!(
            PartyAuthorizationRequest::new(
                PartyRole::Seller,
                &intent,
                [0; 32],
                UnixSeconds::new(T_NOW),
                UnixSeconds::new(T_ISSUED)
            ),
            Err(PartyAuthError::InvalidWindow { .. })
        ));
    }

    #[test]
    fn malformed_signatures_and_keys_fail() {
        let intent = golden_intent();
        let issued = request(PartyRole::Seller, &intent, 10);
        let key = party_key(SELLER_SEED);
        let good = sign_locally(&issued, &signing_key(SELLER_SEED));
        let mut flipped = *good.signature();
        flipped[0] ^= 1;
        let mut non_canonical_s = *good.signature();
        non_canonical_s[63] |= 0xF0; // S >= group order
        for bad in [[0u8; 64], [0xFF; 64], flipped, non_canonical_s] {
            let auth = PartyAuthorization::new(issued.clone(), key.to_bytes(), bad);
            assert_eq!(
                verify_party_authorization(&auth, &issued, &key, now()),
                Err(PartyAuthError::BadSignature)
            );
        }
        // Weak (small-order) public keys are not accepted as expected keys.
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        assert_eq!(
            PartyVerificationKey::from_bytes(&identity_point),
            Err(PartyAuthError::InvalidKey)
        );
    }

    #[test]
    fn wrong_external_expected_key_fails() {
        let intent = golden_intent();
        let issued = request(PartyRole::Buyer, &intent, 11);
        let auth = sign_locally(&issued, &signing_key(BUYER_SEED));
        assert_eq!(
            verify_party_authorization(&auth, &issued, &party_key(0x55), now()),
            Err(PartyAuthError::UnexpectedSigner)
        );
    }

    #[test]
    fn identity_sources_fail_closed_and_registrations_are_not_replaceable() {
        let c = zwa_commitments::trade::trade_commitment_v1(&golden_intent());
        assert_eq!(
            UnconfiguredPartyIdentitySource.expected_parties(c),
            Err(PartyAuthError::IdentitySourceUnconfigured)
        );
        let mut registry = RegisteredPartyKeys::new();
        assert_eq!(registry.expected_parties(c), Err(PartyAuthError::UnknownTrade));
        let parties = ExpectedParties::new(party_key(SELLER_SEED), party_key(BUYER_SEED)).unwrap();
        registry.register(c, parties).unwrap();
        registry.register(c, parties).unwrap();
        let attacker = ExpectedParties::new(party_key(0xA7), party_key(BUYER_SEED)).unwrap();
        assert_eq!(
            registry.register(c, attacker),
            Err(PartyAuthError::ConflictingRegistration)
        );
        assert_eq!(registry.expected_parties(c), Ok(parties));
        assert_eq!(
            ExpectedParties::new(party_key(SELLER_SEED), party_key(SELLER_SEED)),
            Err(PartyAuthError::SameKeyForBothRoles)
        );
    }
}
