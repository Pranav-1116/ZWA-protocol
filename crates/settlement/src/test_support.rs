//! Test-only support for M3 tests (M2 remediation F-01 / F-02, M3 remediation).
//!
//! The matcher no longer accepts JSON "mock proofs" in any build. Settlement
//! tests that need a `MatcherApproval` therefore inject an explicit fake proof
//! verifier through the frozen `ProvenanceVerifier` / `EligibilityVerifier`
//! traits. This module is compiled only under `cfg(test)`, so no production
//! build or feature combination can reach it.

use zwa_matcher::MatcherGate;
use zwa_protocol::proof::{
    EligibilityVerifier, OpaqueProof, ProvenanceVerifier, VerificationProblem, VerificationResult,
};
use zwa_protocol::{
    ActiveCredentialRoot, AuthorizedIssuanceRoot, SubjectCommitment, TradeCommitment,
};

/// Phase 0G subject commitment `H(SUBJECT1, subjectSecret)` of the golden
/// trade's recipient binding. Required by the matcher's F-02 receiver binding.
pub(crate) const SUBJECT_COMMITMENT: &str =
    "8182499163832458428983635402341439692935005683808059285091898351261831993662";

/// Accepts exactly the bytes produced by [`test_proof`] for the root and
/// commitment the gate asks about, so wrong-root and wrong-commitment
/// (splicing) proofs are still rejected.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TestProofVerifier;

impl TestProofVerifier {
    fn check(root: String, commitment: TradeCommitment, proof: &OpaqueProof) -> VerificationResult {
        let expected = format!("zwa-settlement-test-proof|{root}|{commitment}");
        if proof.as_bytes() == expected.as_bytes() {
            VerificationResult::Valid
        } else {
            VerificationResult::Invalid {
                reason: VerificationProblem::ProofRejected,
            }
        }
    }
}

impl ProvenanceVerifier for TestProofVerifier {
    fn verify(
        &self,
        root: AuthorizedIssuanceRoot,
        commitment: TradeCommitment,
        proof: &OpaqueProof,
    ) -> VerificationResult {
        Self::check(root.to_string(), commitment, proof)
    }
}

impl EligibilityVerifier for TestProofVerifier {
    fn verify(
        &self,
        root: ActiveCredentialRoot,
        commitment: TradeCommitment,
        proof: &OpaqueProof,
    ) -> VerificationResult {
        Self::check(root.to_string(), commitment, proof)
    }
}


/// Test proof bytes accepted by [`TestProofVerifier`] for `(root, commitment)`.
pub(crate) fn test_proof(root: &str, commitment: &str) -> Vec<u8> {
    format!("zwa-settlement-test-proof|{root}|{commitment}").into_bytes()
}

/// Subject commitment for the golden trade (F-02 receiver binding input).
pub(crate) fn subject_commitment() -> SubjectCommitment {
    SubjectCommitment::from_decimal_str(SUBJECT_COMMITMENT)
        .expect("golden subject commitment is a canonical field element")
}

// ---------------------------------------------------------------------------
// M3 fixtures: golden trade, M2 approvals, party keys, client-side signing.
// ---------------------------------------------------------------------------

use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeMap;
use zwa_credentials::{AuthorityKeyId, IssuerKeyId};
use zwa_matcher::control::{
    RecipientControlAuthenticator, RecipientControlChallenge, RecipientControlResponse,
    CONTROL_DOMAIN,
};
use zwa_matcher::replay::{InMemoryPersistence, PersistentReplayStore};
use zwa_matcher::roots::{CredentialRootAuthenticator, IssuerRootAuthenticator};
use zwa_matcher::{GateInput, MatcherApproval};
use zwa_protocol::bytes::{AssetBaseBytes, OrchardReceiverBytes};
use zwa_protocol::numbers::{RootVersion, TradeAmount, TradeExpiry, TradeNonce, UnixSeconds};
use zwa_protocol::{
    MatcherFee, OpaqueSignature, PolicyRoot, RecipientCommitment, TradeIntent, ZatoshiAmount,
};

use crate::party_auth::{
    ExpectedParties, PartyAuthorization, PartyAuthorizationRequest, PartyVerificationKey,
    RegisteredPartyKeys,
};

pub(crate) const ISSUANCE_ROOT: &str =
    "19309979006225485291788213177219598381134511159668519266888323889569746782051";
pub(crate) const CREDENTIAL_ROOT: &str =
    "7239536478138432754387625126231950010993505962177483323536139232738771167323";
/// Phase 0G golden `TradeCommitmentV1`.
pub(crate) const GOLDEN_TRADE_COMMITMENT: &str =
    "10187400613857124614980227259922066295752635539032972479692659299555113110306";
pub(crate) const RECEIVER_A_HEX: &str =
    "781671f8a41294c866d8161f3bf5f84a8fd2c328f91a2d085a66036acd59439731c36c4f1b99b4d64be233";

/// Seeds of the independently registered party keys.
pub(crate) const SELLER_SEED: u8 = 10;
pub(crate) const BUYER_SEED: u8 = 11;
/// Authorization issue time and evaluation time.
pub(crate) const T_ISSUED: u64 = 1_900_000_000;
pub(crate) const T_NOW: u64 = 1_900_000_100;

pub(crate) fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(crate) fn party_key(seed: u8) -> PartyVerificationKey {
    PartyVerificationKey::from_bytes(&signing_key(seed).verifying_key().to_bytes())
        .expect("valid ed25519 key")
}

/// What a party's own wallet/client does: sign the issued request locally and
/// return only public material. Test-only; production M3 never holds keys.
pub(crate) fn sign_locally(
    request: &PartyAuthorizationRequest,
    key: &SigningKey,
) -> PartyAuthorization {
    let signature = key.sign(&request.signing_bytes());
    PartyAuthorization::new(
        request.clone(),
        key.verifying_key().to_bytes(),
        signature.to_bytes(),
    )
}

/// Golden Phase 0G trade (commitment `GOLDEN_TRADE_COMMITMENT`).
pub(crate) fn golden_intent() -> TradeIntent {
    TradeIntent {
        offered_asset: AssetBaseBytes::from_hex(
            "4889ad11564115f3655f7e434bffb23074d42aafd58cfecae32a5b5eafaf5301",
        )
        .expect("asset"),
        offered_amount: TradeAmount::new(10),
        requested_asset: AssetBaseBytes::from_hex(
            "a7ac13ded8b51e7a59c400097b70fe6d5d855b30ad19b1897de1fd74721a9339",
        )
        .expect("asset"),
        requested_amount: TradeAmount::new(6),
        recipient_commitment: RecipientCommitment::from_decimal_str(
            "13135279047718387126053226034283670929172341955108098732820235388025453726181",
        )
        .expect("recipient commitment"),
        policy_root: PolicyRoot::from_decimal_str(
            "1514393595722546217125953798550283818470332284949639873172624869558831825935",
        )
        .expect("policy root"),
        matcher_fee: MatcherFee::new(
            ZatoshiAmount::new(5),
            RecipientCommitment::from_decimal_str(
                "1800273984094439421343257609634901689467303577600258601269976617936586404380",
            )
            .expect("fee recipient"),
        ),
        nonce: TradeNonce::new(7001),
        expiry: TradeExpiry::new(2_000_000_000),
    }
}

/// A second valid trade (same recipient binding, different nonce/commitment).
pub(crate) fn other_intent() -> TradeIntent {
    TradeIntent {
        nonce: TradeNonce::new(7002),
        ..golden_intent()
    }
}

/// Real M2 approval for `intent`: real Ed25519 roots and recipient control,
/// persistent replay, with only the Groth16 verifiers replaced by the injected
/// test fake.
pub(crate) fn approval_for(intent: &TradeIntent) -> MatcherApproval {
    let commitment = zwa_commitments::trade::trade_commitment_v1(intent);
    let c = commitment.to_string();

    let sk_issuer = signing_key(1);
    let issuer_id = IssuerKeyId::new(b"issuer-atlas").expect("issuer id");
    let issuer_auth = IssuerRootAuthenticator::new(
        BTreeMap::from([(issuer_id.clone(), sk_issuer.verifying_key())]),
        RootVersion::new(1),
    );
    let issuer_payload = zwa_credentials::IssuerRootPayload::new(
        zwa_protocol::AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).expect("root"),
        issuer_id,
        RootVersion::new(1),
        UnixSeconds::new(1_900_000_000),
        UnixSeconds::new(2_100_000_000),
    )
    .expect("issuer payload");
    let issuer_sig = sk_issuer.sign(&issuer_payload.canonical_bytes());
    let issuer_envelope = zwa_credentials::IssuerRootEnvelope::new(
        issuer_payload,
        OpaqueSignature::new(&issuer_sig.to_bytes()).expect("sig"),
    );

    let sk_cred = signing_key(2);
    let auth_id = AuthorityKeyId::new(b"cred-auth-1").expect("authority id");
    let cred_auth = CredentialRootAuthenticator::new(
        BTreeMap::from([(auth_id.clone(), sk_cred.verifying_key())]),
        RootVersion::new(1),
    );
    let cred_payload = zwa_credentials::CredentialRootPayload::new(
        zwa_protocol::ActiveCredentialRoot::from_decimal_str(CREDENTIAL_ROOT).expect("root"),
        auth_id,
        RootVersion::new(1),
        UnixSeconds::new(1_900_000_000),
        UnixSeconds::new(2_100_000_000),
    )
    .expect("credential payload");
    let cred_sig = sk_cred.sign(&cred_payload.canonical_bytes());
    let cred_envelope = zwa_credentials::CredentialRootEnvelope::new(
        cred_payload,
        OpaqueSignature::new(&cred_sig.to_bytes()).expect("sig"),
    );

    let sk_control = signing_key(3);
    let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).expect("receiver");
    let control_auth = RecipientControlAuthenticator::new(
        BTreeMap::from([(recv_a, sk_control.verifying_key())]),
        CONTROL_DOMAIN.to_vec(),
    );
    let gate = MatcherGate::new(
        issuer_auth,
        cred_auth,
        control_auth,
        TestProofVerifier,
        TestProofVerifier,
        PersistentReplayStore::new(InMemoryPersistence::new(), 3).expect("replay store"),
    );

    let challenge = RecipientControlChallenge::new(
        recv_a,
        [7u8; 32],
        CONTROL_DOMAIN.to_vec(),
        UnixSeconds::new(1_900_000_000),
        UnixSeconds::new(2_100_000_000),
        commitment,
    )
    .expect("challenge");
    let response = RecipientControlResponse::sign(&challenge, &sk_control);
    gate.evaluate(GateInput {
        intent: *intent,
        commitment,
        issuer_envelope,
        credential_envelope: cred_envelope,
        approved_receiver: recv_a,
        recipient_subject_commitment: subject_commitment(),
        control_challenge: challenge,
        control_response: response,
        provenance_proof: OpaqueProof::new(&test_proof(ISSUANCE_ROOT, &c)).expect("proof"),
        eligibility_proof: OpaqueProof::new(&test_proof(CREDENTIAL_ROOT, &c)).expect("proof"),
        now: UnixSeconds::new(T_NOW),
    })
    .expect("M2 gate must approve the fixture trade")
}

/// Registry with the independently known seller/buyer keys for each intent.
pub(crate) fn registry_for(intents: &[TradeIntent]) -> RegisteredPartyKeys {
    let mut registry = RegisteredPartyKeys::new();
    let parties =
        ExpectedParties::new(party_key(SELLER_SEED), party_key(BUYER_SEED)).expect("distinct");
    for intent in intents {
        registry
            .register(zwa_commitments::trade::trade_commitment_v1(intent), parties)
            .expect("register");
    }
    registry
}
