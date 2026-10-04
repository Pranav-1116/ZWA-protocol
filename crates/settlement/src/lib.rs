//! Milestone 3: RFQ terms, independent party authorization and the
//! [`ApprovedSettlement`] handoff to Milestone 4 (owner: Vikram).
//!
//! ```text
//! RfqRequest ──(exact mapping)──▶ TradeIntent ──▶ TradeCommitmentV1 (frozen M1)
//!                                     │
//!                         M2 MatcherGate::evaluate ──▶ MatcherApproval
//!                                     │
//!     seller + buyer PartyKeyAttestation (signed by a configured
//!     credential authority / issuer; verified by PartyAttestationTrustRoot)
//!                                     │
//!     seller + buyer PartyAuthorization (signed locally by each party with
//!     the attested key)
//!                                     │
//!                  SettlementAuthorizer::approve ──▶ ApprovedSettlement ──▶ M4
//! ```
//!
//! # Claim
//!
//! M3 verifies credential-authority-attested party consent for the exact
//! M2-approved trade. M3 does not hold spending authority. M4 requires each
//! party's wallet to authorize its own Zcash spend.
//!
//! # Scope boundary
//!
//! M3 stops at [`ApprovedSettlement`]. This crate does **not** construct,
//! sign, prove, submit or confirm any Zcash/ZSA transaction, and it holds no
//! private, spending, wallet, seed or Orchard key. The earlier M4 prototype
//! (ZSA builder, executor, mock adapter, simulated Orchard control, duplicate
//! replay coordinator, zcash adapter) is archived, not compiled, under
//! `archive/m4-prototype/`.
//!
//! # Handoff integrity, checked by the compiler (M3-T1)
//!
//! External code cannot build, copy, default or deserialize an M2 approval,
//! an M3 settlement or its verified evidence. Each `compile_fail` block has a
//! compiling twin below that differs only in the forbidden expression, so the
//! blocks fail for the stated reason and not because a path is wrong.
//!
//! Struct literals and `..base` updates are rejected (private fields):
//!
//! ```compile_fail,E0451
//! fn forge(a: zwa_matcher::MatcherApproval) -> zwa_matcher::MatcherApproval {
//!     zwa_matcher::MatcherApproval { ..a }
//! }
//! ```
//!
//! ```compile_fail,E0451
//! use zwa_settlement::ApprovedSettlement;
//! fn forge(s: ApprovedSettlement) -> ApprovedSettlement {
//!     ApprovedSettlement { ..s }
//! }
//! ```
//!
//! ```compile_fail,E0451
//! use zwa_settlement::AttestedPartyIdentity;
//! fn forge(i: AttestedPartyIdentity) -> AttestedPartyIdentity {
//!     AttestedPartyIdentity { ..i }
//! }
//! ```
//!
//! ```compile_fail,E0451
//! use zwa_settlement::VerifiedPartyAuthorization;
//! fn forge(v: VerifiedPartyAuthorization) -> VerifiedPartyAuthorization {
//!     VerifiedPartyAuthorization { ..v }
//! }
//! ```
//!
//! ```compile_fail,E0451
//! use zwa_settlement::PartyAttestationTrustRoot;
//! fn forge(r: PartyAttestationTrustRoot) -> PartyAttestationTrustRoot {
//!     PartyAttestationTrustRoot { ..r }
//! }
//! ```
//!
//! The same signatures without the literal compile:
//!
//! ```
//! use zwa_matcher::MatcherApproval;
//! use zwa_settlement::{
//!     ApprovedSettlement, AttestedPartyIdentity, PartyAttestationTrustRoot,
//!     VerifiedPartyAuthorization,
//! };
//! fn pass_a(a: MatcherApproval) -> MatcherApproval { a }
//! fn pass_s(s: ApprovedSettlement) -> ApprovedSettlement { s }
//! fn pass_i(i: AttestedPartyIdentity) -> AttestedPartyIdentity { i }
//! fn pass_v(v: VerifiedPartyAuthorization) -> VerifiedPartyAuthorization { v }
//! fn pass_r(r: PartyAttestationTrustRoot) -> PartyAttestationTrustRoot { r }
//! ```
//!
//! `ApprovedSettlement` and `MatcherApproval` are not `Clone`, not `Default`
//! and not deserializable:
//!
//! ```compile_fail,E0277
//! fn need_clone<T: Clone>() {}
//! need_clone::<zwa_settlement::ApprovedSettlement>();
//! ```
//!
//! ```compile_fail,E0277
//! fn need_clone<T: Clone>() {}
//! need_clone::<zwa_matcher::MatcherApproval>();
//! ```
//!
//! ```compile_fail,E0277
//! fn need_default<T: Default>() {}
//! need_default::<zwa_settlement::ApprovedSettlement>();
//! ```
//!
//! ```compile_fail,E0277
//! fn need_de<T: serde::de::DeserializeOwned>() {}
//! need_de::<zwa_settlement::ApprovedSettlement>();
//! ```
//!
//! ```compile_fail,E0277
//! fn need_de<T: serde::de::DeserializeOwned>() {}
//! need_de::<zwa_matcher::MatcherApproval>();
//! ```
//!
//! The same helpers accept types that do implement the traits:
//!
//! ```
//! fn need_clone<T: Clone>() {}
//! fn need_default<T: Default>() {}
//! fn need_de<T: serde::de::DeserializeOwned>() {}
//! need_clone::<zwa_settlement::RfqRequest>();
//! need_default::<zwa_settlement::PartyAttestationTrustRoot>();
//! need_de::<String>();
//! ```
//!
//! # Dependencies on M2
//!
//! Only public M2 types are used: `MatcherApproval::{commitment, intent,
//! verified_control}` and `VerifiedRecipientControl::{receiver,
//! trade_commitment}`. M3 never constructs or fakes an approval; replay
//! protection is M2's `PersistentReplayStore`, and `approve` consumes the
//! approval by value.

#![allow(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod approved;
pub mod attestation;
pub mod party_auth;
pub mod rfq;

pub use approved::{
    ApprovalError, ApprovedSettlement, PartySubmission, SettlementAuthorizer,
    APPROVED_SETTLEMENT_DOMAIN, APPROVED_SETTLEMENT_VERSION,
};
pub use attestation::{
    attestation_message, AttestationError, AttestedPartyIdentity, AuthorityId,
    PartyAttestationTrustRoot, PartyId, PartyKeyAttestation, MAX_ATTESTATION_ID_LEN,
    PARTY_ATTESTATION_DOMAIN, PARTY_ATTESTATION_VERSION,
};
pub use party_auth::{
    verify_party_authorization, ExpectedParties, PartyAuthError, PartyAuthorization,
    PartyAuthorizationRequest, PartyRole, PartyVerificationKey, VerifiedPartyAuthorization,
    PARTY_AUTH_DOMAIN, PARTY_AUTH_MESSAGE_LEN, PARTY_AUTH_NONCE_LEN, PARTY_AUTH_VERSION,
};
pub use rfq::{RfqRequest, TermsMismatch};

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod boundary_tests {
    //! Static boundary checks over the production sources (§8, §13, F-04,
    //! F-09, F-11, F-12). Line based, comments skipped, CRLF safe.

    const PRODUCTION_SOURCES: [(&str, &str); 5] = [
        ("lib.rs", include_str!("lib.rs")),
        ("rfq.rs", include_str!("rfq.rs")),
        ("party_auth.rs", include_str!("party_auth.rs")),
        ("approved.rs", include_str!("approved.rs")),
        ("attestation.rs", include_str!("attestation.rs")),
    ];

    /// Non-comment lines before the first test module, lowercased.
    fn production_code(src: &str) -> Vec<String> {
        src.split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_ascii_lowercase())
            .filter(|l| !l.starts_with("//"))
            .collect()
    }

    fn assert_absent(tokens: &[&str], why: &str) {
        for (file, src) in PRODUCTION_SOURCES {
            for line in production_code(src) {
                for token in tokens {
                    assert!(!line.contains(token), "{why}: `{token}` in {file}: {line}");
                }
            }
        }
    }

    #[test]
    fn coordinator_accepts_no_private_key_material() {
        assert_absent(
            &[
                "signingkey",
                "secretkey",
                "expandedsecretkey",
                "keypair",
                "spendingkey",
                "spending_key",
                "spendauth",
                "seed",
                "mnemonic",
                "ivk",
                "fullviewingkey",
                "private_key",
                "privatekey",
                "zeroize",
            ],
            "M3 must never receive private key material (F-04)",
        );
    }

    #[test]
    fn no_mock_or_m4_code_on_the_production_path() {
        assert_absent(
            &[
                "mocksettlementadapter",
                "mock",
                "fake",
                "simulat",
                "txid",
                "zsa",
                "zcash_",
                "zebra",
                "qedit",
                "submit(",
                "broadcast",
                "construct(",
                "confirm(",
                "sqlite",
            ],
            "M4/mock code must stay out of M3 (§8)",
        );
    }

    #[test]
    fn no_duplicate_replay_coordinator() {
        assert_absent(
            &[
                "replay",
                "persistentreplaystore",
                "tradelifecyclestate",
                "hashset",
                "mutex",
            ],
            "M3 consumes M2 replay state and keeps none of its own (F-09)",
        );
    }

    #[test]
    fn no_raw_receiver_override_in_rfq() {
        for line in production_code(include_str!("rfq.rs")) {
            assert!(
                !line.contains("orchardreceiverbytes") && !line.contains("receiver_override"),
                "RFQ must map exactly into TradeIntent (§11): {line}"
            );
        }
    }

    #[test]
    fn workspace_does_not_build_archived_m4_code() {
        let manifest = include_str!("../../../Cargo.toml");
        for line in manifest.lines().map(str::trim) {
            assert!(
                !line.contains("zcash-adapter"),
                "zcash-adapter is archived: {line}"
            );
            assert!(
                !line.contains("archive/"),
                "archive must not be compiled: {line}"
            );
        }
    }

    #[test]
    fn archived_ivk_is_redacted_zeroized_and_not_copy() {
        // F-11: the only IVK type left in the repository is in the archived
        // (uncompiled) prototype; keep it safe if it is ever revived.
        let src = include_str!("../../../archive/m4-prototype/settlement/src/control.rs");
        let lines: Vec<&str> = src.lines().map(str::trim).collect();
        let decl = lines
            .iter()
            .position(|l| l.starts_with("pub struct OrchardIvkBytes"))
            .expect("archived OrchardIvkBytes");
        let derive = lines[..decl]
            .iter()
            .rev()
            .find(|l| l.starts_with("#[derive("))
            .expect("derive");
        assert!(!derive.contains("Copy"), "IVK must not be Copy: {derive}");
        assert!(
            !derive.contains("Debug"),
            "IVK Debug must be manual/redacted: {derive}"
        );
        assert!(
            derive.contains("ZeroizeOnDrop"),
            "IVK must zeroize: {derive}"
        );
        assert!(lines
            .iter()
            .any(|l| l.contains("OrchardIvkBytes(<redacted>)")));
        assert!(
            !lines.iter().any(|l| l.contains("RealOrchard")),
            "simulated control must not be named Real (F-12)"
        );
    }
}
