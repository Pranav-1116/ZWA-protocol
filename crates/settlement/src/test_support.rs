//! Test-only support for settlement tests (M2 remediation F-01 / F-02).
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
use zwa_protocol::{ActiveCredentialRoot, AuthorizedIssuanceRoot, SubjectCommitment, TradeCommitment};

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

/// Matcher gate with injected test proof verifiers.
pub(crate) type TestGate<P> = MatcherGate<P, TestProofVerifier, TestProofVerifier>;

/// Test proof bytes accepted by [`TestProofVerifier`] for `(root, commitment)`.
pub(crate) fn test_proof(root: &str, commitment: &str) -> Vec<u8> {
    format!("zwa-settlement-test-proof|{root}|{commitment}").into_bytes()
}

/// Subject commitment for the golden trade (F-02 receiver binding input).
pub(crate) fn subject_commitment() -> SubjectCommitment {
    SubjectCommitment::from_decimal_str(SUBJECT_COMMITMENT)
        .expect("golden subject commitment is a canonical field element")
}
