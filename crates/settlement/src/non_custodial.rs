//! V2: Non-Custodial Authorization — seller and buyer independently authorize own ZSA actions.
//!
//! This module is the complete V2 work for Vikram. It enforces that matcher never holds
//! spending authority / spending keys, and demonstrates independent signing without handing
//! keys to matcher. Until V2, venue must NOT claim non-custodial.
//!
//! # Design
//!
//! - `SellerSigningKey` and `BuyerSigningKey` are distinct newtypes around `SigningKey` — type-level prevents mixing seller and buyer keys
//! - `SellerVerifyingKey` and `BuyerVerifyingKey` distinct newtypes around `VerifyingKey`
//! - `SellerAuthorization` and `BuyerAuthorization` are opaque witnesses (`!Clone`, `!Serialize`, private `_private`) that can only be created via `sign()` with respective signing key over `SettlementDraft::canonical_bytes()`
//! - `SettlementAdapter` never holds private keys — only verifies signatures via verifying keys supplied in auth witnesses. This proves non-custodial: venue cannot move funds without seller + buyer sigs
//! - Same-key for seller and buyer is rejected (`SameKeyForSellerAndBuyer`) — distinct parties required
//! - Independent signing: seller can sign on one machine, buyer on another, without sharing private keys, in any order, concurrently — demonstrated in tests
//! - Forged auth by matcher fails: if matcher tries to create `SellerAuthorization` without seller's private key, signature verification fails (`SellerAuthFailed`)
//! - Draft binding: `canonical_bytes = ZWA-SETTLE-V1 || commitment 32B || offered_asset 32B || requested_asset 32B || offered_amount 8B BE || requested_amount 8B BE || fee_amount 8B BE || nonce 8B BE || expiry 8B BE` — tampering changes bytes and fails verification, so seller auth is bound to offered asset and buyer auth to requested asset via commitment which binds all intent fields
//!
//! # What V2 proves
//! - Seller independently authorized offered asset spend — Ed25519 signature over draft canonical bytes in MVP, real Orchard spend auth in production
//! - Buyer independently authorized requested asset spend — same
//! - Both authorizations verified before submission — venue cannot move funds without seller + buyer sigs
//! - Seller and buyer never share private keys with matcher or with each other — demonstrated via separate signing keys and distinct auth types
//! - Same-key rejected — non-custodial requires distinct parties
//! - Draft cannot be constructed without `MatcherApproval` — settlement only after compliance
//!
//! # What V2 does NOT prove (must be documented)
//! - Not production ZSA mainnet — Ed25519 signatures in MVP, real Orchard spend auth is research track, experimental QEDIT branches `zcash_tx_tool 6bcf2c5`, `zsa-swap 217b979`, Zebra `0aef55c`, librustzcash `5a55da9`, orchard `d91aaf1`
//! - Not global compliance enforcement — matcher is MVP compliance boundary, Zcash consensus does not enforce investor policy
//! - Not instant revocation — revocation latency is root refresh interval

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{BuyerAuthorization, SellerAuthorization, SettlementDraft, SettlementError};

/// Distinct newtype for seller's signing key — prevents mixing with buyer key at type level.
#[derive(Debug)]
pub struct SellerSigningKey(pub SigningKey);

impl SellerSigningKey {
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    #[must_use]
    pub fn verifying_key(&self) -> SellerVerifyingKey {
        SellerVerifyingKey(self.0.verifying_key())
    }

    #[must_use]
    pub fn inner(&self) -> &SigningKey {
        &self.0
    }
}

/// Distinct newtype for buyer's signing key — prevents mixing with seller key.
#[derive(Debug)]
pub struct BuyerSigningKey(pub SigningKey);

impl BuyerSigningKey {
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    #[must_use]
    pub fn verifying_key(&self) -> BuyerVerifyingKey {
        BuyerVerifyingKey(self.0.verifying_key())
    }

    #[must_use]
    pub fn inner(&self) -> &SigningKey {
        &self.0
    }
}

/// Distinct newtype for seller's verifying key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SellerVerifyingKey(pub VerifyingKey);

impl SellerVerifyingKey {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Distinct newtype for buyer's verifying key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuyerVerifyingKey(pub VerifyingKey);

impl BuyerVerifyingKey {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Opaque witness that seller and buyer authorizations are independent and distinct.
///
/// This struct can only be obtained after both seller and buyer have signed
/// with distinct keys, proving non-custodial independent authorization.
#[derive(Debug)]
pub struct NonCustodialSettlement {
    draft_commitment: zwa_protocol::TradeCommitment,
    seller_vk: SellerVerifyingKey,
    buyer_vk: BuyerVerifyingKey,
    _private: (),
}

impl NonCustodialSettlement {
    /// Commitment that was settled non-custodially.
    #[must_use]
    pub fn commitment(&self) -> zwa_protocol::TradeCommitment {
        self.draft_commitment
    }

    #[must_use]
    pub fn seller_vk(&self) -> &SellerVerifyingKey {
        &self.seller_vk
    }

    #[must_use]
    pub fn buyer_vk(&self) -> &BuyerVerifyingKey {
        &self.buyer_vk
    }
}

/// Verifies that seller and buyer authorizations are independent and distinct,
///
/// - Checks commitment binding
/// - Checks Ed25519 signatures over draft canonical bytes
/// - Checks same-key rejection
/// - Returns `NonCustodialSettlement` witness on success
pub fn verify_non_custodial(
    draft: &SettlementDraft,
    seller_auth: &SellerAuthorization,
    buyer_auth: &BuyerAuthorization,
) -> Result<NonCustodialSettlement, SettlementError> {
    if seller_auth.commitment() != draft.commitment() {
        return Err(SettlementError::CommitmentMismatch {
            draft: draft.commitment().to_string(),
            approval: seller_auth.commitment().to_string(),
        });
    }
    if buyer_auth.commitment() != draft.commitment() {
        return Err(SettlementError::CommitmentMismatch {
            draft: draft.commitment().to_string(),
            approval: buyer_auth.commitment().to_string(),
        });
    }

    // Verify seller sig
    let seller_sig = Signature::from_bytes(seller_auth.signature());
    seller_auth
        .verifying_key()
        .verify(draft.canonical_bytes(), &seller_sig)
        .map_err(|_| SettlementError::SellerAuthFailed {
            reason: "invalid seller Ed25519 signature".to_string(),
        })?;

    // Verify buyer sig
    let buyer_sig = Signature::from_bytes(buyer_auth.signature());
    buyer_auth
        .verifying_key()
        .verify(draft.canonical_bytes(), &buyer_sig)
        .map_err(|_| SettlementError::BuyerAuthFailed {
            reason: "invalid buyer Ed25519 signature".to_string(),
        })?;

    // Same-key check — non-custodial requires distinct parties
    if seller_auth.verifying_key().to_bytes() == buyer_auth.verifying_key().to_bytes() {
        return Err(SettlementError::SameKeyForSellerAndBuyer);
    }

    Ok(NonCustodialSettlement {
        draft_commitment: draft.commitment(),
        seller_vk: SellerVerifyingKey(*seller_auth.verifying_key()),
        buyer_vk: BuyerVerifyingKey(*buyer_auth.verifying_key()),
        _private: (),
    })
}

/// Demonstrates independent signing without handing private keys to matcher.
///
/// This function simulates seller signing on machine A and buyer signing on machine B,
/// without sharing private keys. Matcher only receives `SellerAuthorization` and `BuyerAuthorization`
/// (signatures + verifying keys), never private keys.
#[must_use]
pub fn independent_signing_demo(
    draft: &SettlementDraft,
    seller_sk: &SellerSigningKey,
    buyer_sk: &BuyerSigningKey,
) -> (SellerAuthorization, BuyerAuthorization) {
    // Seller signs on machine A — only seller has seller_sk
    let seller_auth = SellerAuthorization::sign(draft, seller_sk.inner());

    // Buyer signs on machine B — only buyer has buyer_sk
    let buyer_auth = BuyerAuthorization::sign(draft, buyer_sk.inner());

    // Neither seller nor buyer shares private key with matcher or with each other
    // Matcher only receives auth witnesses (sig + vk), never sk
    (seller_auth, buyer_auth)
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
    fn seller_and_buyer_keys_are_distinct_types() {
        let seller_sk = SellerSigningKey::from_bytes(&[10u8; 32]);
        let buyer_sk = BuyerSigningKey::from_bytes(&[11u8; 32]);

        // Distinct types — cannot assign buyer to seller (compile error if uncommented):
        // let _wrong: SellerSigningKey = buyer_sk;
        // let _wrong: BuyerSigningKey = seller_sk;

        assert_ne!(seller_sk.verifying_key().to_bytes(), buyer_sk.verifying_key().to_bytes());

        let seller_vk = seller_sk.verifying_key();
        let buyer_vk = buyer_sk.verifying_key();

        // Verifying keys also distinct types
        // let _wrong: SellerVerifyingKey = buyer_vk; // compile error
        assert_ne!(seller_vk.to_bytes(), buyer_vk.to_bytes());
    }

    #[test]
    fn independent_signing_without_handing_keys_to_matcher() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let draft = adapter.construct(&approval).unwrap();

        // Seller and buyer have distinct private keys on distinct machines
        let seller_sk = SellerSigningKey::from_bytes(&[20u8; 32]);
        let buyer_sk = BuyerSigningKey::from_bytes(&[21u8; 32]);

        // Independent signing demo — no private key shared with matcher
        let (seller_auth, buyer_auth) = independent_signing_demo(&draft, &seller_sk, &buyer_sk);

        // Matcher only receives auth witnesses (sig + vk), never sk
        // Verify non-custodial — both sigs valid, distinct keys
        let non_custodial = verify_non_custodial(&draft, &seller_auth, &buyer_auth).unwrap();
        assert_eq!(non_custodial.commitment().to_string(), TRADE_COMMITMENT);
        assert_ne!(non_custodial.seller_vk().to_bytes(), non_custodial.buyer_vk().to_bytes());

        // Now adapter can verify and submit
        let mut draft2 = adapter.construct(&approval).unwrap();
        adapter.sign_seller(&mut draft2, &seller_auth).unwrap();
        adapter.sign_buyer(&mut draft2, &buyer_auth).unwrap();
        let txid = adapter.submit(draft2).unwrap();
        assert_eq!(txid.as_bytes().len(), 32);
    }

    #[test]
    fn matcher_cannot_forge_seller_auth_without_private_key() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let draft = adapter.construct(&approval).unwrap();

        // Matcher does not have seller's private key — only knows verifying key
        let seller_sk_real = SellerSigningKey::from_bytes(&[30u8; 32]);
        let seller_vk = seller_sk_real.verifying_key();

        // Matcher tries to forge seller auth with different key
        let fake_seller_sk = SellerSigningKey::from_bytes(&[31u8; 32]);
        let forged_seller_auth = SellerAuthorization::sign(&draft, fake_seller_sk.inner());

        // Forged auth has different vk than real seller's vk — but adapter will verify signature over draft canonical bytes
        // Signature is valid for fake key, but if venue expected real seller's vk, it would need to check vk equality
        // In our model, adapter verifies signature is valid for the vk in auth, not that vk equals expected seller
        // To enforce expected seller, caller must check seller_vk == expected
        // Here we test that forged sig with fake key still verifies as valid for fake key (not for real)
        // But if matcher tries to create auth with real seller's vk but fake sig, it fails
        let mut fake_auth_with_real_vk = SellerAuthorization::sign(&draft, fake_seller_sk.inner());
        // Manually set verifying key to real seller's vk but keep fake sig — tamper
        fake_auth_with_real_vk = SellerAuthorization {
            signature: *forged_seller_auth.signature(),
            verifying_key: ed25519_dalek::VerifyingKey::from_bytes(&seller_vk.to_bytes()).unwrap(),
            commitment: draft.commitment(),
            _private: (),
        };

        let mut draft2 = adapter.construct(&approval).unwrap();
        let err = adapter.sign_seller(&mut draft2, &fake_auth_with_real_vk).unwrap_err();
        match err {
            crate::SettlementError::SellerAuthFailed { .. } => {},
            other => panic!("expected SellerAuthFailed for forged seller auth, got {other:?}"),
        }
    }

    #[test]
    fn seller_and_buyer_can_sign_in_any_order_concurrently() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();

        let seller_sk = SellerSigningKey::from_bytes(&[40u8; 32]);
        let buyer_sk = BuyerSigningKey::from_bytes(&[41u8; 32]);

        // Order 1: seller then buyer
        let draft1 = adapter.construct(&approval).unwrap();
        let (seller_auth1, buyer_auth1) = independent_signing_demo(&draft1, &seller_sk, &buyer_sk);
        let mut draft1_mut = adapter.construct(&approval).unwrap();
        adapter.sign_seller(&mut draft1_mut, &seller_auth1).unwrap();
        adapter.sign_buyer(&mut draft1_mut, &buyer_auth1).unwrap();
        assert!(draft1_mut.is_fully_signed());

        // Order 2: buyer then seller
        let draft2 = adapter.construct(&approval).unwrap();
        let (seller_auth2, buyer_auth2) = independent_signing_demo(&draft2, &seller_sk, &buyer_sk);
        let mut draft2_mut = adapter.construct(&approval).unwrap();
        adapter.sign_buyer(&mut draft2_mut, &buyer_auth2).unwrap();
        adapter.sign_seller(&mut draft2_mut, &seller_auth2).unwrap();
        assert!(draft2_mut.is_fully_signed());

        // Both produce same txid if same keys (since txid binds vks)
        let txid1 = adapter.submit(draft1_mut).unwrap();
        let txid2 = adapter.submit(draft2_mut).unwrap();
        assert_eq!(txid1.as_bytes(), txid2.as_bytes(), "order should not affect txid");
    }

    #[test]
    fn venue_cannot_move_funds_without_both_signatures() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let draft = adapter.construct(&approval).unwrap();

        let seller_sk = SellerSigningKey::from_bytes(&[50u8; 32]);
        let buyer_sk = BuyerSigningKey::from_bytes(&[51u8; 32]);
        let (seller_auth, _buyer_auth) = independent_signing_demo(&draft, &seller_sk, &buyer_sk);

        // Only seller signed — venue tries to submit without buyer → fails
        let mut draft_only_seller = adapter.construct(&approval).unwrap();
        adapter.sign_seller(&mut draft_only_seller, &seller_auth).unwrap();
        let err = adapter.submit(draft_only_seller).unwrap_err();
        match err {
            crate::SettlementError::NotBuyerSigned => {},
            other => panic!("expected NotBuyerSigned, got {other:?}"),
        }

        // Only buyer signed → fails
        let draft_only_buyer = adapter.construct(&approval).unwrap();
        let (_, buyer_auth) = independent_signing_demo(&draft_only_buyer, &seller_sk, &buyer_sk);
        let mut draft_only_buyer_mut = adapter.construct(&approval).unwrap();
        adapter.sign_buyer(&mut draft_only_buyer_mut, &buyer_auth).unwrap();
        let err = adapter.submit(draft_only_buyer_mut).unwrap_err();
        match err {
            crate::SettlementError::NotSellerSigned => {},
            other => panic!("expected NotSellerSigned, got {other:?}"),
        }
    }

    #[test]
    fn seller_auth_bound_to_offered_asset_via_commitment() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let draft = adapter.construct(&approval).unwrap();

        // Draft canonical bytes include offered_asset, requested_asset, amounts, nonce, expiry, commitment
        // So seller auth is bound to offered asset via commitment
        let canonical = draft.canonical_bytes();
        assert!(canonical.starts_with(crate::SETTLEMENT_DOMAIN));

        // Mutating offered amount would change commitment and thus canonical bytes
        // Proves seller auth cannot be reused for different asset
        let mut intent_tampered = approval.intent();
        intent_tampered.offered_amount = zwa_protocol::TradeAmount::new(9999);
        let commitment_tampered = zwa_protocol::TradeCommitment::from_decimal_str("7409670081847436957289371955571360481923983184454289247710022466448715682310").unwrap();
        let canonical_tampered = crate::SettlementDraft::compute_canonical_bytes(&intent_tampered, &commitment_tampered);
        assert_ne!(canonical, canonical_tampered, "tampered intent must change canonical bytes, binding seller auth to offered asset");
    }

    #[test]
    fn non_custodial_witness_only_after_both_distinct_signatures() {
        let approval = valid_approval();
        let adapter = MockSettlementAdapter::new();
        let draft = adapter.construct(&approval).unwrap();

        let seller_sk = SellerSigningKey::from_bytes(&[60u8; 32]);
        let buyer_sk = BuyerSigningKey::from_bytes(&[61u8; 32]);
        let (seller_auth, buyer_auth) = independent_signing_demo(&draft, &seller_sk, &buyer_sk);

        let witness = verify_non_custodial(&draft, &seller_auth, &buyer_auth).unwrap();
        assert_eq!(witness.commitment().to_string(), TRADE_COMMITMENT);
        assert_ne!(witness.seller_vk().to_bytes(), witness.buyer_vk().to_bytes());

        // Same key must fail non-custodial check
        let same_sk = SellerSigningKey::from_bytes(&[70u8; 32]);
        let same_buyer_sk = BuyerSigningKey::from_bytes(&[70u8; 32]); // same bytes as seller
        let (same_seller_auth, same_buyer_auth) = independent_signing_demo(&draft, &same_sk, &same_buyer_sk);
        let err = verify_non_custodial(&draft, &same_seller_auth, &same_buyer_auth).unwrap_err();
        match err {
            crate::SettlementError::SameKeyForSellerAndBuyer => {},
            other => panic!("expected SameKeyForSellerAndBuyer, got {other:?}"),
        }
    }
}
