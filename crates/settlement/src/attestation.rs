//! Authority-attested party keys (M3, owner decision B + C; DR-M3-01).
//!
//! # Claim
//!
//! M3 verifies credential-authority-attested party consent for the exact
//! M2-approved trade. M3 does not hold spending authority. M4 requires each
//! party's wallet to authorize its own Zcash spend.
//!
//! # Trust model
//!
//! - **Trust root:** a [`PartyAttestationTrustRoot`] configured by the
//!   operator with the Ed25519 public keys of the approved party-key
//!   authorities (the credential authority and/or the issuer), in the same way
//!   M2 is configured with approved root-signing keys. Each authority is
//!   restricted to the roles it may attest (for example: issuer → seller,
//!   credential authority → buyer).
//! - **Attestation:** an authority signs a [`PartyKeyAttestation`] binding
//!   `(authority id, role, party id, party authorization key, validity window)`.
//!   The party key that must sign the trade consent is taken **only** from a
//!   verified attestation, never from the consent object itself, and never
//!   from a registry the coordinator can fill on its own. A matcher therefore
//!   cannot introduce two keys it controls without an authority signature.
//! - **Separation:** an attestation says *who* may consent for a role. The
//!   per-trade consent signature ([`crate::party_auth`]) says *what* that
//!   party agreed to. The two use different domains and keys.
//! - **Non-claims:** an attestation is not custody and not spend authority.
//!   It is not bound to a trade; party ids must be globally unique
//!   identifiers assigned by the authority. There is no per-attestation
//!   revocation list: before `expires_at`, an attestation is revoked only by
//!   rebuilding the trust root without (or with a rotated key for) its
//!   authority. Short windows are recommended.
//!
//! # Signed attestation message (all integers big-endian)
//!
//! ```text
//! "ZWA1PARTYKEYATTEST" (18) | version u8 = 1 | role u8 (1 seller, 2 buyer)
//! | authority_id_len u8 | authority_id (1..=64)
//! | party_id_len u8 | party_id (1..=64)
//! | party_key (32) | valid_from u64 | expires_at u64
//! ```
//!
//! The domain differs from the matcher's root (`ZWA1ROOT`) and control
//! domains and from the consent domain (`ZWA1PARTYAUTH`), so an authority may
//! reuse its root-signing key without cross-protocol confusion. Validity is
//! inclusive: `now < valid_from` and `now > expires_at` fail.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use zwa_protocol::numbers::UnixSeconds;

use crate::party_auth::{PartyRole, PartyVerificationKey};

/// Domain tag of the party-key attestation message.
pub const PARTY_ATTESTATION_DOMAIN: &[u8; 18] = b"ZWA1PARTYKEYATTEST";
/// Version byte of the party-key attestation message.
pub const PARTY_ATTESTATION_VERSION: u8 = 1;
/// Maximum length of an authority id or a party id, in bytes.
pub const MAX_ATTESTATION_ID_LEN: usize = 64;

/// Party-key attestation failures (all fail closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// An authority id or party id is empty or longer than 64 bytes.
    #[error("identifier must be 1..=64 bytes, got {len}")]
    InvalidIdentifier {
        /// Rejected length.
        len: usize,
    },
    /// `valid_from > expires_at`.
    #[error("invalid attestation window: valid_from {valid_from} > expires_at {expires_at}")]
    InvalidWindow {
        /// Start of the window.
        valid_from: u64,
        /// End of the window.
        expires_at: u64,
    },
    /// The configured authority key is not a valid, non-weak Ed25519 key.
    #[error("invalid party-key authority verification key")]
    InvalidAuthorityKey,
    /// The same authority id is configured twice.
    #[error("party-key authority is already configured")]
    DuplicateAuthority,
    /// An authority must be allowed to attest at least one role.
    #[error("party-key authority must be allowed to attest at least one role")]
    NoRolesAllowed,
    /// The attestation is for the other role.
    #[error("attestation is for role {got:?}, expected {expected:?}")]
    WrongRole {
        /// Role of the slot being verified.
        expected: PartyRole,
        /// Role in the attestation.
        got: PartyRole,
    },
    /// The attestation names an authority that is not in the trust root.
    #[error("attestation authority is not a configured party-key authority")]
    UnknownAuthority,
    /// The authority is configured but may not attest this role.
    #[error("authority may not attest role {role:?}")]
    RoleNotAllowed {
        /// Role that was attested.
        role: PartyRole,
    },
    /// `now < valid_from`.
    #[error("attestation not yet valid: now {now} < valid_from {valid_from}")]
    NotYetValid {
        /// Verification time.
        now: u64,
        /// Start of the window.
        valid_from: u64,
    },
    /// `now > expires_at`.
    #[error("attestation expired: now {now} > expires_at {expires_at}")]
    Expired {
        /// Verification time.
        now: u64,
        /// End of the window.
        expires_at: u64,
    },
    /// The attested party key is not a valid, non-weak Ed25519 key.
    #[error("attested party key is not a valid Ed25519 key")]
    InvalidPartyKey,
    /// The authority signature does not verify.
    #[error("invalid attestation signature")]
    BadSignature,
}

fn check_identifier(bytes: &[u8]) -> Result<Vec<u8>, AttestationError> {
    if bytes.is_empty() || bytes.len() > MAX_ATTESTATION_ID_LEN {
        return Err(AttestationError::InvalidIdentifier { len: bytes.len() });
    }
    Ok(bytes.to_vec())
}

/// Identifier of a party-key authority (1..=64 bytes).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityId(Vec<u8>);

impl AuthorityId {
    /// Validated authority id.
    ///
    /// # Errors
    ///
    /// [`AttestationError::InvalidIdentifier`].
    pub fn new(bytes: &[u8]) -> Result<Self, AttestationError> {
        check_identifier(bytes).map(Self)
    }

    /// Raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Authority-assigned, globally unique identifier of a party (1..=64 bytes).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartyId(Vec<u8>);

impl PartyId {
    /// Validated party id.
    ///
    /// # Errors
    ///
    /// [`AttestationError::InvalidIdentifier`].
    pub fn new(bytes: &[u8]) -> Result<Self, AttestationError> {
        check_identifier(bytes).map(Self)
    }

    /// Raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The exact bytes a party-key authority signs (see the module docs).
///
/// Authorities use this to produce attestations; verifiers recompute it.
#[must_use]
pub fn attestation_message(
    authority: &AuthorityId,
    role: PartyRole,
    party: &PartyId,
    party_key: &[u8; 32],
    valid_from: UnixSeconds,
    expires_at: UnixSeconds,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + 1 + 1 + 1 + 64 + 1 + 64 + 32 + 8 + 8);
    out.extend_from_slice(PARTY_ATTESTATION_DOMAIN);
    out.push(PARTY_ATTESTATION_VERSION);
    out.push(role.tag());
    // Identifier lengths are bounded by MAX_ATTESTATION_ID_LEN (64) at construction.
    out.push(authority.as_bytes().len() as u8);
    out.extend_from_slice(authority.as_bytes());
    out.push(party.as_bytes().len() as u8);
    out.extend_from_slice(party.as_bytes());
    out.extend_from_slice(party_key);
    out.extend_from_slice(&valid_from.get().to_be_bytes());
    out.extend_from_slice(&expires_at.get().to_be_bytes());
    out
}

/// An authority's statement that `party_key` is the authorization key of
/// `party` for `role`: untrusted wire data until verified by a
/// [`PartyAttestationTrustRoot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyKeyAttestation {
    authority: AuthorityId,
    role: PartyRole,
    party: PartyId,
    party_key: [u8; 32],
    valid_from: UnixSeconds,
    expires_at: UnixSeconds,
    signature: [u8; 64],
}

impl PartyKeyAttestation {
    /// Assembles an attestation received from an authority or a party.
    ///
    /// # Errors
    ///
    /// [`AttestationError::InvalidWindow`] if `valid_from > expires_at`.
    pub fn new(
        authority: AuthorityId,
        role: PartyRole,
        party: PartyId,
        party_key: [u8; 32],
        valid_from: UnixSeconds,
        expires_at: UnixSeconds,
        signature: [u8; 64],
    ) -> Result<Self, AttestationError> {
        if valid_from > expires_at {
            return Err(AttestationError::InvalidWindow {
                valid_from: valid_from.get(),
                expires_at: expires_at.get(),
            });
        }
        Ok(Self {
            authority,
            role,
            party,
            party_key,
            valid_from,
            expires_at,
            signature,
        })
    }

    /// Attesting authority.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityId {
        &self.authority
    }

    /// Attested role.
    #[must_use]
    pub const fn role(&self) -> PartyRole {
        self.role
    }

    /// Attested party.
    #[must_use]
    pub const fn party(&self) -> &PartyId {
        &self.party
    }

    /// Attested party authorization key (raw, unvalidated).
    #[must_use]
    pub const fn party_key(&self) -> &[u8; 32] {
        &self.party_key
    }

    /// Start of the validity window (inclusive).
    #[must_use]
    pub const fn valid_from(&self) -> UnixSeconds {
        self.valid_from
    }

    /// End of the validity window (inclusive).
    #[must_use]
    pub const fn expires_at(&self) -> UnixSeconds {
        self.expires_at
    }

    /// Authority signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// The exact signed bytes ([`attestation_message`]).
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        attestation_message(
            &self.authority,
            self.role,
            &self.party,
            &self.party_key,
            self.valid_from,
            self.expires_at,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthorityEntry {
    key: VerifyingKey,
    may_attest_seller: bool,
    may_attest_buyer: bool,
}

impl AuthorityEntry {
    const fn allows(&self, role: PartyRole) -> bool {
        match role {
            PartyRole::Seller => self.may_attest_seller,
            PartyRole::Buyer => self.may_attest_buyer,
        }
    }
}

/// Operator-configured set of approved party-key authorities.
///
/// Empty by default: every verification then fails with
/// [`AttestationError::UnknownAuthority`] (fail closed).
#[derive(Debug, Clone, Default)]
pub struct PartyAttestationTrustRoot {
    authorities: BTreeMap<AuthorityId, AuthorityEntry>,
}

impl PartyAttestationTrustRoot {
    /// Empty trust root (fails closed).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Approves `authority` with Ed25519 public key `key` for `roles`.
    ///
    /// # Errors
    ///
    /// `NoRolesAllowed`, `InvalidAuthorityKey` (malformed or small-order key)
    /// or `DuplicateAuthority`.
    pub fn add_authority(
        &mut self,
        authority: AuthorityId,
        key: &[u8; 32],
        roles: &[PartyRole],
    ) -> Result<(), AttestationError> {
        if roles.is_empty() {
            return Err(AttestationError::NoRolesAllowed);
        }
        let key =
            VerifyingKey::from_bytes(key).map_err(|_| AttestationError::InvalidAuthorityKey)?;
        if key.is_weak() {
            return Err(AttestationError::InvalidAuthorityKey);
        }
        if self.authorities.contains_key(&authority) {
            return Err(AttestationError::DuplicateAuthority);
        }
        self.authorities.insert(
            authority,
            AuthorityEntry {
                key,
                may_attest_seller: roles.contains(&PartyRole::Seller),
                may_attest_buyer: roles.contains(&PartyRole::Buyer),
            },
        );
        Ok(())
    }

    /// Whether no authority is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.authorities.is_empty()
    }

    /// Verifies `attestation` for the slot `expected_role` at `now`.
    ///
    /// Check order: role, authority known, authority allowed for the role,
    /// window, party key well formed, then the authority's Ed25519 signature
    /// (`verify_strict`) over [`PartyKeyAttestation::signing_bytes`].
    ///
    /// # Errors
    ///
    /// The first failing check as an [`AttestationError`].
    pub fn verify(
        &self,
        attestation: &PartyKeyAttestation,
        expected_role: PartyRole,
        now: UnixSeconds,
    ) -> Result<AttestedPartyIdentity, AttestationError> {
        if attestation.role != expected_role {
            return Err(AttestationError::WrongRole {
                expected: expected_role,
                got: attestation.role,
            });
        }
        let entry = self
            .authorities
            .get(&attestation.authority)
            .ok_or(AttestationError::UnknownAuthority)?;
        if !entry.allows(expected_role) {
            return Err(AttestationError::RoleNotAllowed {
                role: expected_role,
            });
        }
        if now < attestation.valid_from {
            return Err(AttestationError::NotYetValid {
                now: now.get(),
                valid_from: attestation.valid_from.get(),
            });
        }
        if now > attestation.expires_at {
            return Err(AttestationError::Expired {
                now: now.get(),
                expires_at: attestation.expires_at.get(),
            });
        }
        let party_key = PartyVerificationKey::from_bytes(&attestation.party_key)
            .map_err(|_| AttestationError::InvalidPartyKey)?;
        entry
            .key
            .verify_strict(
                &attestation.signing_bytes(),
                &Signature::from_bytes(&attestation.signature),
            )
            .map_err(|_| AttestationError::BadSignature)?;
        Ok(AttestedPartyIdentity {
            attestation: attestation.clone(),
            authority_key: entry.key,
            party_key,
        })
    }
}

/// A verified attestation: the party key for a role, vouched for by an
/// approved authority. Only [`PartyAttestationTrustRoot::verify`] creates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedPartyIdentity {
    attestation: PartyKeyAttestation,
    authority_key: VerifyingKey,
    party_key: PartyVerificationKey,
}

impl AttestedPartyIdentity {
    /// Attested role.
    #[must_use]
    pub const fn role(&self) -> PartyRole {
        self.attestation.role
    }

    /// Attesting authority.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityId {
        &self.attestation.authority
    }

    /// Public key of the attesting authority (from the trust root).
    #[must_use]
    pub fn authority_key(&self) -> [u8; 32] {
        self.authority_key.to_bytes()
    }

    /// Attested party.
    #[must_use]
    pub const fn party(&self) -> &PartyId {
        &self.attestation.party
    }

    /// Attested party authorization key: the only key accepted for this
    /// party's trade consent.
    #[must_use]
    pub const fn party_key(&self) -> &PartyVerificationKey {
        &self.party_key
    }

    /// The verified attestation.
    #[must_use]
    pub const fn attestation(&self) -> &PartyKeyAttestation {
        &self.attestation
    }

    /// Re-verifies the stored authority signature and key binding.
    pub(crate) fn signature_is_valid(&self) -> bool {
        self.attestation.party_key == self.party_key.to_bytes()
            && self
                .authority_key
                .verify_strict(
                    &self.attestation.signing_bytes(),
                    &Signature::from_bytes(&self.attestation.signature),
                )
                .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        attest, attestor_key, buyer_attestation, party_key, seller_attestation, trust_root,
        BUYER_ATTESTOR_ID, BUYER_ATTESTOR_SEED, BUYER_PARTY_ID, BUYER_SEED, SELLER_ATTESTOR_ID,
        SELLER_ATTESTOR_SEED, SELLER_PARTY_ID, SELLER_SEED, T_ATTEST_FROM, T_ATTEST_UNTIL, T_NOW,
    };

    fn now() -> UnixSeconds {
        UnixSeconds::new(T_NOW)
    }

    /// Same fields as `a`, different signature bytes.
    fn with_signature(a: &PartyKeyAttestation, signature: [u8; 64]) -> PartyKeyAttestation {
        PartyKeyAttestation::new(
            a.authority().clone(),
            a.role(),
            a.party().clone(),
            *a.party_key(),
            a.valid_from(),
            a.expires_at(),
            signature,
        )
        .unwrap()
    }

    #[test]
    fn attestation_message_layout_is_domain_role_authority_party_and_key_bound() {
        let a = seller_attestation();
        let bytes = a.signing_bytes();
        let mut offset = 0;
        let mut take = |n: usize| {
            let part = bytes[offset..offset + n].to_vec();
            offset += n;
            part
        };
        assert_eq!(take(18), b"ZWA1PARTYKEYATTEST");
        assert_eq!(take(1), [1], "version");
        assert_eq!(take(1), [1], "seller role tag");
        assert_eq!(take(1), [SELLER_ATTESTOR_ID.len() as u8]);
        assert_eq!(take(SELLER_ATTESTOR_ID.len()), SELLER_ATTESTOR_ID);
        assert_eq!(take(1), [SELLER_PARTY_ID.len() as u8]);
        assert_eq!(take(SELLER_PARTY_ID.len()), SELLER_PARTY_ID);
        assert_eq!(take(32), party_key(SELLER_SEED).to_bytes());
        assert_eq!(take(8), T_ATTEST_FROM.to_be_bytes());
        assert_eq!(take(8), T_ATTEST_UNTIL.to_be_bytes());
        assert_eq!(offset, bytes.len());
        // Role separation: the same party and key attested as buyer differ.
        let as_buyer = attestation_message(
            a.authority(),
            PartyRole::Buyer,
            a.party(),
            a.party_key(),
            a.valid_from(),
            a.expires_at(),
        );
        assert_ne!(as_buyer, bytes);
        assert_eq!(as_buyer[19], 2, "buyer role tag");
    }

    #[test]
    fn valid_attestations_yield_the_attested_party_keys() {
        let root = trust_root();
        let seller = root
            .verify(&seller_attestation(), PartyRole::Seller, now())
            .unwrap();
        assert_eq!(seller.role(), PartyRole::Seller);
        assert_eq!(seller.party().as_bytes(), SELLER_PARTY_ID);
        assert_eq!(seller.authority().as_bytes(), SELLER_ATTESTOR_ID);
        assert_eq!(seller.party_key(), &party_key(SELLER_SEED));
        assert!(seller.signature_is_valid());
        assert_eq!(
            seller.authority_key(),
            attestor_key(SELLER_ATTESTOR_SEED).to_bytes()
        );
        let buyer = root
            .verify(&buyer_attestation(), PartyRole::Buyer, now())
            .unwrap();
        assert_eq!(buyer.party_key(), &party_key(BUYER_SEED));
        assert!(buyer.signature_is_valid());
    }

    #[test]
    fn empty_trust_root_fails_closed() {
        let root = PartyAttestationTrustRoot::new();
        assert!(root.is_empty());
        assert_eq!(
            root.verify(&seller_attestation(), PartyRole::Seller, now()),
            Err(AttestationError::UnknownAuthority)
        );
    }

    #[test]
    fn matcher_self_attested_key_is_rejected() {
        // The matcher invents an authority key and attests a key it controls,
        // under its own authority id and under the real authority's id.
        let root = trust_root();
        let rogue_own_id = attest(0xC1, b"matcher-authority", PartyRole::Seller, b"m", 0xB1);
        assert_eq!(
            root.verify(&rogue_own_id, PartyRole::Seller, now()),
            Err(AttestationError::UnknownAuthority)
        );
        let rogue_real_id = attest(
            0xC1,
            SELLER_ATTESTOR_ID,
            PartyRole::Seller,
            SELLER_PARTY_ID,
            0xB1,
        );
        assert_eq!(
            root.verify(&rogue_real_id, PartyRole::Seller, now()),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn wrong_role_and_role_not_allowed_are_rejected() {
        let root = trust_root();
        // A seller attestation presented for the buyer slot.
        assert_eq!(
            root.verify(&seller_attestation(), PartyRole::Buyer, now()),
            Err(AttestationError::WrongRole {
                expected: PartyRole::Buyer,
                got: PartyRole::Seller
            })
        );
        // The buyer-only authority attests a seller: not allowed.
        let cross = attest(
            BUYER_ATTESTOR_SEED,
            BUYER_ATTESTOR_ID,
            PartyRole::Seller,
            SELLER_PARTY_ID,
            SELLER_SEED,
        );
        assert_eq!(
            root.verify(&cross, PartyRole::Seller, now()),
            Err(AttestationError::RoleNotAllowed {
                role: PartyRole::Seller
            })
        );
        // The seller-only authority attests a buyer: not allowed.
        let cross = attest(
            SELLER_ATTESTOR_SEED,
            SELLER_ATTESTOR_ID,
            PartyRole::Buyer,
            BUYER_PARTY_ID,
            BUYER_SEED,
        );
        assert_eq!(
            root.verify(&cross, PartyRole::Buyer, now()),
            Err(AttestationError::RoleNotAllowed {
                role: PartyRole::Buyer
            })
        );
    }

    #[test]
    fn attestation_window_is_inclusive_and_enforced() {
        let root = trust_root();
        let a = seller_attestation();
        for t in [T_ATTEST_FROM, T_ATTEST_UNTIL] {
            assert!(root
                .verify(&a, PartyRole::Seller, UnixSeconds::new(t))
                .is_ok());
        }
        assert_eq!(
            root.verify(&a, PartyRole::Seller, UnixSeconds::new(T_ATTEST_FROM - 1)),
            Err(AttestationError::NotYetValid {
                now: T_ATTEST_FROM - 1,
                valid_from: T_ATTEST_FROM
            })
        );
        assert_eq!(
            root.verify(&a, PartyRole::Seller, UnixSeconds::new(T_ATTEST_UNTIL + 1)),
            Err(AttestationError::Expired {
                now: T_ATTEST_UNTIL + 1,
                expires_at: T_ATTEST_UNTIL
            })
        );
        assert!(matches!(
            PartyKeyAttestation::new(
                a.authority().clone(),
                a.role(),
                a.party().clone(),
                *a.party_key(),
                UnixSeconds::new(T_ATTEST_UNTIL),
                UnixSeconds::new(T_ATTEST_FROM),
                *a.signature(),
            ),
            Err(AttestationError::InvalidWindow { .. })
        ));
    }

    #[test]
    fn forged_or_altered_attestations_are_rejected() {
        let root = trust_root();
        let a = seller_attestation();
        let mut flipped = *a.signature();
        flipped[5] ^= 1;
        let mut non_canonical_s = *a.signature();
        non_canonical_s[63] |= 0xF0;
        for bad in [[0u8; 64], [0xFF; 64], flipped, non_canonical_s] {
            assert_eq!(
                root.verify(&with_signature(&a, bad), PartyRole::Seller, now()),
                Err(AttestationError::BadSignature)
            );
        }
        // Moving the authority signature onto another party key fails.
        let moved_key = PartyKeyAttestation::new(
            a.authority().clone(),
            a.role(),
            a.party().clone(),
            party_key(0xB1).to_bytes(),
            a.valid_from(),
            a.expires_at(),
            *a.signature(),
        )
        .unwrap();
        assert_eq!(
            root.verify(&moved_key, PartyRole::Seller, now()),
            Err(AttestationError::BadSignature)
        );
        // Moving it onto another party id fails.
        let moved_party = PartyKeyAttestation::new(
            a.authority().clone(),
            a.role(),
            PartyId::new(b"someone-else").unwrap(),
            *a.party_key(),
            a.valid_from(),
            a.expires_at(),
            *a.signature(),
        )
        .unwrap();
        assert_eq!(
            root.verify(&moved_party, PartyRole::Seller, now()),
            Err(AttestationError::BadSignature)
        );
        // Extending the window fails.
        let extended = PartyKeyAttestation::new(
            a.authority().clone(),
            a.role(),
            a.party().clone(),
            *a.party_key(),
            a.valid_from(),
            UnixSeconds::new(T_ATTEST_UNTIL + 1),
            *a.signature(),
        )
        .unwrap();
        assert_eq!(
            root.verify(&extended, PartyRole::Seller, now()),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn weak_party_key_and_bad_configuration_are_rejected() {
        let root = trust_root();
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        let weak = PartyKeyAttestation::new(
            AuthorityId::new(SELLER_ATTESTOR_ID).unwrap(),
            PartyRole::Seller,
            PartyId::new(SELLER_PARTY_ID).unwrap(),
            identity_point,
            UnixSeconds::new(T_ATTEST_FROM),
            UnixSeconds::new(T_ATTEST_UNTIL),
            [0; 64],
        )
        .unwrap();
        assert_eq!(
            root.verify(&weak, PartyRole::Seller, now()),
            Err(AttestationError::InvalidPartyKey)
        );

        let id = AuthorityId::new(b"authority").unwrap();
        let good_key = attestor_key(0x31).to_bytes();
        let mut config = PartyAttestationTrustRoot::new();
        assert_eq!(
            config.add_authority(id.clone(), &good_key, &[]),
            Err(AttestationError::NoRolesAllowed)
        );
        assert_eq!(
            config.add_authority(id.clone(), &identity_point, &[PartyRole::Seller]),
            Err(AttestationError::InvalidAuthorityKey)
        );
        config
            .add_authority(id.clone(), &good_key, &[PartyRole::Seller])
            .unwrap();
        assert_eq!(
            config.add_authority(id, &good_key, &[PartyRole::Buyer]),
            Err(AttestationError::DuplicateAuthority)
        );
        assert_eq!(
            AuthorityId::new(b""),
            Err(AttestationError::InvalidIdentifier { len: 0 })
        );
        assert_eq!(
            PartyId::new(&[7u8; 65]),
            Err(AttestationError::InvalidIdentifier { len: 65 })
        );
        assert!(PartyId::new(&[7u8; 64]).is_ok());
    }
}
