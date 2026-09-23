//! Real Groth16 verifier backends — Task A4 complete.
//!
//! This module wires **real Circom Groth16 proofs** to Rust using exact public-input order
//! `[root, trade_commitment]` per handbook Sec 14. It replaces the earlier JSON-mock with
//! cryptographic verification via `ark-groth16` + `ark-bn254` (BN128/BN254 same curve).
//!
//! # Design
//!
//! - Verification keys are generated outside the repo via `circom` + `snarkjs` (see `scripts/`)
//!   and stored as frozen fixtures in `tests/fixtures/groth16/` — `provenance-vkey.json`,
//!   `eligibility-vkey.json`. They are **not** generated artifacts in `circuits/`.
//! - Proofs are real Groth16 proofs generated from `reference-trade-v1.json` and
//!   `phase1b-eligibility-v2.json` fixtures. Public inputs are exactly
//!   `[authorizedIssuanceRoot, tradeCommitment]` and `[activeCredentialRoot, tradeCommitment]`
//!   in that order — frozen per circuit.
//! - VK identity is checked via SHA256 hash to prevent substitution (Sec 23 threat).
//! - Both verifiers consume the exact same `TradeCommitmentV1` from `CheckedTrade`
//!   via `MatcherProofGate` — type-level anti-splicing.
//! - No mock verifier is reachable in default (non-test) build. Mock helpers are
//!   `#[cfg(test)]` only.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use serde::Deserialize;
use zwa_protocol::proof::{
    EligibilityVerifier, OpaqueProof, ProvenanceVerifier, VerificationProblem, VerificationResult,
};
use zwa_protocol::{ActiveCredentialRoot, AuthorizedIssuanceRoot, TradeCommitment};

use crate::checked::CheckedTrade;
use crate::roots::{AuthenticatedCredentialRoot, AuthenticatedIssuerRoot};

/// Errors from Groth16 verification.
#[derive(Debug, thiserror::Error)]
pub enum Groth16VerificationError {
    #[error("vkey json malformed: {0}")]
    VKeyMalformed(String),
    #[error("proof json malformed: {0}")]
    ProofMalformed(String),
    #[error("field element parse failed for '{value}': {reason}")]
    FieldParse { value: String, reason: String },
    #[error("G1 point parse failed: {0}")]
    G1Parse(String),
    #[error("G2 point parse failed: {0}")]
    G2Parse(String),
    #[error("vk hash mismatch: expected {expected}, got {got}")]
    VkHashMismatch { expected: String, got: String },
    #[error("public inputs length mismatch: expected {expected}, got {got}")]
    PublicInputsLength { expected: usize, got: usize },
    #[error("ark verification failed: {0}")]
    ArkVerification(String),
}

/// SHA256 hash of vkey JSON — used to prevent substitution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkHash(pub String);

impl VkHash {
    pub fn from_json_str(json_str: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(json_str.as_bytes());
        Self(hex::encode(hasher.finalize()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hex::encode(hasher.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SnarkJS G1 point in JSON: [x, y, z] decimal strings.
type SnarkjsG1Json = [String; 3];
/// SnarkJS G2 point: [[x_c0, x_c1], [y_c0, y_c1], [z_c0, z_c1]] — each inner 2 strings.
type SnarkjsG2Json = [[String; 2]; 3];

#[derive(Debug, Clone, Deserialize)]
struct SnarkjsVKeyJson {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    n_public: usize,
    vk_alpha_1: SnarkjsG1Json,
    vk_beta_2: SnarkjsG2Json,
    vk_gamma_2: SnarkjsG2Json,
    vk_delta_2: SnarkjsG2Json,
    #[serde(rename = "IC")]
    ic: Vec<SnarkjsG1Json>,
}

#[derive(Debug, Clone, Deserialize)]
struct SnarkjsProofJson {
    pi_a: SnarkjsG1Json,
    pi_b: SnarkjsG2Json,
    pi_c: SnarkjsG1Json,
    protocol: String,
    curve: String,
}

// --- Field parsing ---

fn fq_from_decimal(s: &str) -> Result<Fq, Groth16VerificationError> {
    // Parse decimal string via BigUint then to Fq via from_be_bytes_mod_order
    let bigint = BigUint::parse_bytes(s.as_bytes(), 10).ok_or_else(|| Groth16VerificationError::FieldParse {
        value: s.to_string(),
        reason: "invalid decimal".to_string(),
    })?;
    let bytes = bigint.to_bytes_be();
    // ark-ff 0.5.0: Fq::from_be_bytes_mod_order
    Ok(Fq::from_be_bytes_mod_order(&bytes))
}

fn fr_from_decimal(s: &str) -> Result<Fr, Groth16VerificationError> {
    let bigint = BigUint::parse_bytes(s.as_bytes(), 10).ok_or_else(|| Groth16VerificationError::FieldParse {
        value: s.to_string(),
        reason: "invalid decimal".to_string(),
    })?;
    let bytes = bigint.to_bytes_be();
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

fn g1_from_snarkjs(point: &SnarkjsG1Json) -> Result<G1Affine, Groth16VerificationError> {
    // [x, y, z] — if [0,1,0] => infinity
    let x_str = &point[0];
    let y_str = &point[1];
    let z_str = &point[2];

    // Infinity check: [0,1,0] or [0,0,0]
    if (x_str == "0" && y_str == "1" && z_str == "0") || (x_str == "0" && y_str == "0" && z_str == "0") {
        return Ok(G1Affine::zero());
    }

    // For affine, z should be "1"
    let x = fq_from_decimal(x_str).map_err(|e| Groth16VerificationError::G1Parse(format!("x {x_str}: {e}")))?;
    let y = fq_from_decimal(y_str).map_err(|e| Groth16VerificationError::G1Parse(format!("y {y_str}: {e}")))?;

    // ark-bn254 G1Affine::new(x,y) checks on curve
    // Use new_unchecked for performance, but we want checked.
    // In ark 0.5, G1Affine::new(x,y) returns Self, panics if not on curve? Actually it checks.
    // We'll use new_unchecked and then check is_on_curve and in_correct_subgroup_assuming_on_curve
    let p = G1Affine::new_unchecked(x, y);
    // Verify on curve
    if !p.is_on_curve() {
        return Err(Groth16VerificationError::G1Parse(format!("point not on curve: {x_str}, {y_str}")));
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Groth16VerificationError::G1Parse(format!("point not in subgroup: {x_str}, {y_str}")));
    }
    Ok(p)
}

fn fq2_from_c0_c1(c0_str: &str, c1_str: &str) -> Result<Fq2, Groth16VerificationError> {
    let c0 = fq_from_decimal(c0_str).map_err(|e| Groth16VerificationError::G2Parse(format!("c0 {c0_str}: {e}")))?;
    let c1 = fq_from_decimal(c1_str).map_err(|e| Groth16VerificationError::G2Parse(format!("c1 {c1_str}: {e}")))?;
    Ok(Fq2::new(c0, c1))
}

fn g2_from_snarkjs(point: &SnarkjsG2Json) -> Result<G2Affine, Groth16VerificationError> {
    // [[x_c0, x_c1], [y_c0, y_c1], [z_c0, z_c1]]
    let x_c0 = &point[0][0];
    let x_c1 = &point[0][1];
    let y_c0 = &point[1][0];
    let y_c1 = &point[1][1];
    let z_c0 = &point[2][0];
    let z_c1 = &point[2][1];

    // Infinity check: all zeros or z = [0,0]
    if (x_c0 == "0" && x_c1 == "0" && y_c0 == "0" && y_c1 == "0" && z_c0 == "0" && z_c1 == "0")
        || (z_c0 == "0" && z_c1 == "0")
    {
        return Ok(G2Affine::zero());
    }

    let x = fq2_from_c0_c1(x_c0, x_c1)?;
    let y = fq2_from_c0_c1(y_c0, y_c1)?;

    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(Groth16VerificationError::G2Parse(format!(
            "G2 not on curve: x [{x_c0},{x_c1}] y [{y_c0},{y_c1}]"
        )));
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Groth16VerificationError::G2Parse(format!(
            "G2 not in subgroup: x [{x_c0},{x_c1}]"
        )));
    }
    Ok(p)
}

// --- VKey and Proof conversion ---

fn vkey_from_snarkjs_json(json_str: &str) -> Result<VerifyingKey<Bn254>, Groth16VerificationError> {
    let vkey_json: SnarkjsVKeyJson = serde_json::from_str(json_str)
        .map_err(|e| Groth16VerificationError::VKeyMalformed(format!("json parse: {e}")))?;

    if vkey_json.protocol != "groth16" {
        return Err(Groth16VerificationError::VKeyMalformed(format!(
            "expected groth16, got {}",
            vkey_json.protocol
        )));
    }
    if vkey_json.curve != "bn128" && vkey_json.curve != "bn254" {
        return Err(Groth16VerificationError::VKeyMalformed(format!(
            "expected bn128/bn254, got {}",
            vkey_json.curve
        )));
    }

    let alpha_g1 = g1_from_snarkjs(&vkey_json.vk_alpha_1)?;
    let beta_g2 = g2_from_snarkjs(&vkey_json.vk_beta_2)?;
    let gamma_g2 = g2_from_snarkjs(&vkey_json.vk_gamma_2)?;
    let delta_g2 = g2_from_snarkjs(&vkey_json.vk_delta_2)?;

    let mut gamma_abc_g1 = Vec::with_capacity(vkey_json.ic.len());
    for (i, ic_point) in vkey_json.ic.iter().enumerate() {
        let p = g1_from_snarkjs(ic_point)
            .map_err(|e| Groth16VerificationError::VKeyMalformed(format!("IC[{i}]: {e}")))?;
        gamma_abc_g1.push(p);
    }

    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

fn proof_from_snarkjs_json(json_str: &str) -> Result<Proof<Bn254>, Groth16VerificationError> {
    let proof_json: SnarkjsProofJson = serde_json::from_str(json_str)
        .map_err(|e| Groth16VerificationError::ProofMalformed(format!("json parse: {e}")))?;

    if proof_json.protocol != "groth16" {
        return Err(Groth16VerificationError::ProofMalformed(format!(
            "expected groth16, got {}",
            proof_json.protocol
        )));
    }

    let a = g1_from_snarkjs(&proof_json.pi_a)?;
    let b = g2_from_snarkjs(&proof_json.pi_b)?;
    let c = g1_from_snarkjs(&proof_json.pi_c)?;

    Ok(Proof { a, b, c })
}

fn public_inputs_from_json(json_str: &str) -> Result<Vec<Fr>, Groth16VerificationError> {
    // SnarkJS public.json is array of decimal strings
    let public_json: Vec<String> = serde_json::from_str(json_str)
        .map_err(|e| Groth16VerificationError::ProofMalformed(format!("public json: {e}")))?;
    let mut inputs = Vec::with_capacity(public_json.len());
    for s in public_json {
        inputs.push(fr_from_decimal(&s)?);
    }
    Ok(inputs)
}

/// Real Groth16 verifier that holds a verifying key and its hash.
#[derive(Debug, Clone)]
pub struct Groth16Verifier {
    pub vk: VerifyingKey<Bn254>,
    pub vk_hash: VkHash,
    pub label: String,
}

impl Groth16Verifier {
    /// Builds from snarkjs vkey JSON string and checks hash.
    pub fn from_vkey_json(
        vkey_json_str: &str,
        expected_hash: Option<&str>,
        label: impl Into<String>,
    ) -> Result<Self, Groth16VerificationError> {
        let computed_hash = VkHash::from_json_str(vkey_json_str);
        if let Some(expected) = expected_hash {
            if computed_hash.as_str() != expected {
                return Err(Groth16VerificationError::VkHashMismatch {
                    expected: expected.to_string(),
                    got: computed_hash.0.clone(),
                });
            }
        }
        let vk = vkey_from_snarkjs_json(vkey_json_str)?;
        Ok(Self {
            vk,
            vk_hash: computed_hash,
            label: label.into(),
        })
    }

    /// Verifies a snarkjs proof JSON against public inputs (Fr).
    pub fn verify_proof_json(
        &self,
        proof_json_str: &str,
        public_inputs_json_str: &str,
    ) -> Result<bool, Groth16VerificationError> {
        let proof = proof_from_snarkjs_json(proof_json_str)?;
        let public_inputs = public_inputs_from_json(public_inputs_json_str)?;

        // Check public inputs length matches vkey
        if public_inputs.len() + 1 != self.vk.gamma_abc_g1.len() {
            return Err(Groth16VerificationError::PublicInputsLength {
                expected: self.vk.gamma_abc_g1.len() - 1,
                got: public_inputs.len(),
            });
        }

        // Use ark-groth16 verification
        let pvk = ark_groth16::prepare_verifying_key(&self.vk);
        let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs)
            .map_err(|e| Groth16VerificationError::ArkVerification(format!("{e:?}")))?;
        Ok(verified)
    }

    /// Verifies OpaqueProof where proof bytes are snarkjs proof JSON and public inputs are supplied separately.
    /// For our fixtures, OpaqueProof contains proof JSON, and public inputs are [root, commitment] as Fr.
    pub fn verify_opaque_proof(
        &self,
        expected_public: &[Fr; 2],
        opaque_proof: &OpaqueProof,
    ) -> Result<bool, Groth16VerificationError> {
        let proof_json_str = std::str::from_utf8(opaque_proof.as_bytes())
            .map_err(|e| Groth16VerificationError::ProofMalformed(format!("utf8: {e}")))?;

        let proof = proof_from_snarkjs_json(proof_json_str)?;

        let pvk = ark_groth16::prepare_verifying_key(&self.vk);
        let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, expected_public)
            .map_err(|e| Groth16VerificationError::ArkVerification(format!("{e:?}")))?;
        Ok(verified)
    }

    pub fn vk_hash(&self) -> &str {
        self.vk_hash.as_str()
    }
}

// --- Concrete backends ---

/// Real Groth16 provenance verifier backend.
///
/// - Public inputs order frozen: `[authorizedIssuanceRoot, tradeCommitment]`
/// - VK hash checked to prevent substitution
/// - No mock reachable in default build — this is cryptographic verification
#[derive(Debug, Clone)]
pub struct ProvenanceVerifierBackend {
    verifier: Groth16Verifier,
}

impl ProvenanceVerifierBackend {
    /// Builds from vkey JSON string.
    pub fn from_vkey_json(
        vkey_json: &str,
        expected_hash: Option<&str>,
    ) -> Result<Self, Groth16VerificationError> {
        Ok(Self {
            verifier: Groth16Verifier::from_vkey_json(vkey_json, expected_hash, "provenance-v1")?,
        })
    }

    /// Loads from embedded fixture `tests/fixtures/groth16/provenance-vkey.json`
    /// with hash check.
    pub fn from_fixture() -> Result<Self, Groth16VerificationError> {
        // Embedded vkey — generated via circom2 + snarkjs from rwa_trade_provenance_v1.circom
        // with quadratic binding fix for IC non-zero.
        const VKEY_JSON: &str = include_str!("../../tests/fixtures/groth16/provenance-vkey.json");
        // Expected hash computed from fixture — prevents substitution
        const EXPECTED_HASH: &str = "4831d3eef9575ef7daf318eb8767e1a39ef1e26da20339ddda137b1e246f1350";
        Self::from_vkey_json(VKEY_JSON, Some(EXPECTED_HASH))
    }

    /// For testing with custom vkey.
    #[cfg(test)]
    pub fn from_vkey_json_unchecked(vkey_json: &str) -> Result<Self, Groth16VerificationError> {
        Ok(Self {
            verifier: Groth16Verifier::from_vkey_json(vkey_json, None, "provenance-v1")?,
        })
    }

    pub fn vk_hash(&self) -> &str {
        self.verifier.vk_hash()
    }
}

impl Default for ProvenanceVerifierBackend {
    fn default() -> Self {
        Self::from_fixture().expect("provenance vkey fixture must be valid")
    }
}

impl ProvenanceVerifier for ProvenanceVerifierBackend {
    fn verify(
        &self,
        authorized_issuance_root: AuthorizedIssuanceRoot,
        trade_commitment: TradeCommitment,
        proof: &OpaqueProof,
    ) -> VerificationResult {
        // Public inputs must be exactly [root, commitment] in order
        let root_fr = match fr_from_decimal(&authorized_issuance_root.to_string()) {
            Ok(fr) => fr,
            Err(_) => {
                return VerificationResult::Invalid {
                    reason: VerificationProblem::ProofMalformed,
                }
            }
        };
        let commitment_fr = match fr_from_decimal(&trade_commitment.to_string()) {
            Ok(fr) => fr,
            Err(_) => {
                return VerificationResult::Invalid {
                    reason: VerificationProblem::ProofMalformed,
                }
            }
        };

        let expected = [root_fr, commitment_fr];

        match self.verifier.verify_opaque_proof(&expected, proof) {
            Ok(true) => VerificationResult::Valid,
            Ok(false) => VerificationResult::Invalid {
                reason: VerificationProblem::ProofRejected,
            },
            Err(_) => {
                // In test builds, allow mock JSON format for gate tests that don't need real crypto
                #[cfg(test)]
                {
                    if let Ok(mock) = try_parse_mock_proof(proof) {
                        if mock[0] == authorized_issuance_root.to_string()
                            && mock[1] == trade_commitment.to_string()
                        {
                            return VerificationResult::Valid;
                        } else {
                            return VerificationResult::Invalid {
                                reason: VerificationProblem::PublicInputMismatch,
                            };
                        }
                    }
                }
                VerificationResult::Invalid {
                    reason: VerificationProblem::ProofMalformed,
                }
            }
        }
    }
}

#[cfg(test)]
fn try_parse_mock_proof(proof: &OpaqueProof) -> Result<[String; 2], ()> {
    // Mock format: {"public_inputs": [root, commitment], ...}
    let s = std::str::from_utf8(proof.as_bytes()).map_err(|_| ())?;
    let v: serde_json::Value = serde_json::from_str(s).map_err(|_| ())?;
    let arr = v
        .get("public_inputs")
        .and_then(|x| x.as_array())
        .ok_or(())?;
    if arr.len() != 2 {
        return Err(());
    }
    let a = arr[0].as_str().ok_or(())?.to_string();
    let b = arr[1].as_str().ok_or(())?.to_string();
    Ok([a, b])
}

/// Real Groth16 eligibility verifier backend — Phase1B CRED_V2.
///
/// - Public inputs order frozen: `[activeCredentialRoot, tradeCommitment]`
/// - Same commitment invariant enforced via `MatcherProofGate`
#[derive(Debug, Clone)]
pub struct EligibilityVerifierBackend {
    verifier: Groth16Verifier,
}

impl EligibilityVerifierBackend {
    pub fn from_vkey_json(
        vkey_json: &str,
        expected_hash: Option<&str>,
    ) -> Result<Self, Groth16VerificationError> {
        Ok(Self {
            verifier: Groth16Verifier::from_vkey_json(vkey_json, expected_hash, "eligibility-v1")?,
        })
    }

    pub fn from_fixture() -> Result<Self, Groth16VerificationError> {
        const VKEY_JSON: &str = include_str!("../../tests/fixtures/groth16/eligibility-vkey.json");
        const EXPECTED_HASH: &str = "879d427a16f334edc163e78614c94dfe00c3ae3cb657c3ef4d7d82c39e4f5e75";
        Self::from_vkey_json(VKEY_JSON, Some(EXPECTED_HASH))
    }

    #[cfg(test)]
    pub fn from_vkey_json_unchecked(vkey_json: &str) -> Result<Self, Groth16VerificationError> {
        Ok(Self {
            verifier: Groth16Verifier::from_vkey_json(vkey_json, None, "eligibility-v1")?,
        })
    }

    pub fn vk_hash(&self) -> &str {
        self.verifier.vk_hash()
    }
}

impl Default for EligibilityVerifierBackend {
    fn default() -> Self {
        Self::from_fixture().expect("eligibility vkey fixture must be valid")
    }
}

impl EligibilityVerifier for EligibilityVerifierBackend {
    fn verify(
        &self,
        active_credential_root: ActiveCredentialRoot,
        trade_commitment: TradeCommitment,
        proof: &OpaqueProof,
    ) -> VerificationResult {
        let root_fr = match fr_from_decimal(&active_credential_root.to_string()) {
            Ok(fr) => fr,
            Err(_) => {
                return VerificationResult::Invalid {
                    reason: VerificationProblem::ProofMalformed,
                }
            }
        };
        let commitment_fr = match fr_from_decimal(&trade_commitment.to_string()) {
            Ok(fr) => fr,
            Err(_) => {
                return VerificationResult::Invalid {
                    reason: VerificationProblem::ProofMalformed,
                }
            }
        };

        let expected = [root_fr, commitment_fr];

        match self.verifier.verify_opaque_proof(&expected, proof) {
            Ok(true) => VerificationResult::Valid,
            Ok(false) => VerificationResult::Invalid {
                reason: VerificationProblem::ProofRejected,
            },
            Err(_) => {
                #[cfg(test)]
                {
                    if let Ok(mock) = try_parse_mock_proof(proof) {
                        if mock[0] == active_credential_root.to_string()
                            && mock[1] == trade_commitment.to_string()
                        {
                            return VerificationResult::Valid;
                        } else {
                            return VerificationResult::Invalid {
                                reason: VerificationProblem::PublicInputMismatch,
                            };
                        }
                    }
                }
                VerificationResult::Invalid {
                    reason: VerificationProblem::ProofMalformed,
                }
            }
        }
    }
}

// --- Same-commitment gate ---

/// Matcher proof gate that enforces same-commitment invariant.
///
/// Holds a `CheckedTrade` (Task A) and both authenticated roots (Task B) and
/// verifies both proofs against the **exact same** `TradeCommitmentV1`.
#[derive(Debug, Clone)]
pub struct MatcherProofGate {
    checked_trade: CheckedTrade,
    provenance_verifier: ProvenanceVerifierBackend,
    eligibility_verifier: EligibilityVerifierBackend,
}

impl MatcherProofGate {
    #[must_use]
    pub fn new(
        checked_trade: CheckedTrade,
        provenance_verifier: ProvenanceVerifierBackend,
        eligibility_verifier: EligibilityVerifierBackend,
    ) -> Self {
        Self {
            checked_trade,
            provenance_verifier,
            eligibility_verifier,
        }
    }

    #[must_use]
    pub fn checked_trade(&self) -> &CheckedTrade {
        &self.checked_trade
    }

    /// Verifies both proofs against authenticated roots and same commitment.
    pub fn verify_both(
        &self,
        issuer_root: &AuthenticatedIssuerRoot,
        credential_root: &AuthenticatedCredentialRoot,
        provenance_proof: &OpaqueProof,
        eligibility_proof: &OpaqueProof,
    ) -> Result<(), VerificationResult> {
        let commitment = self.checked_trade.commitment();

        // Ensure roots match the ones that were authenticated — prevents swapped inputs
        // (The verifiers themselves check public inputs, but we also ensure the gate uses the authenticated roots)

        let prov_result = self.provenance_verifier.verify(
            issuer_root.root(),
            commitment,
            provenance_proof,
        );

        if !prov_result.is_valid() {
            return Err(prov_result);
        }

        let elig_result = self.eligibility_verifier.verify(
            credential_root.root(),
            commitment,
            eligibility_proof,
        );

        if !elig_result.is_valid() {
            return Err(elig_result);
        }

        Ok(())
    }
}

// --- Test helpers ---

/// Helper to create a test proof JSON with given public inputs — mock format
/// for unit tests that don't need real Groth16. Real proofs are in fixtures.
#[cfg(test)]
#[must_use]
pub fn make_test_proof_json(root_decimal: &str, commitment_decimal: &str) -> Vec<u8> {
    let obj = serde_json::json!({
        "public_inputs": [root_decimal, commitment_decimal],
        "proof": { "a": "dummy", "b": "dummy", "c": "dummy" },
        "protocol": "groth16",
        "curve": "bn128"
    });
    serde_json::to_vec(&obj).unwrap()
}

/// Loads real provenance proof from fixture `tests/fixtures/groth16/provenance-proof.json`
#[cfg(test)]
pub fn load_real_provenance_proof() -> OpaqueProof {
    const PROOF_JSON: &str = include_str!("../../tests/fixtures/groth16/provenance-proof.json");
    OpaqueProof::new(PROOF_JSON.as_bytes()).unwrap()
}

/// Loads real eligibility proof from fixture
#[cfg(test)]
pub fn load_real_eligibility_proof() -> OpaqueProof {
    const PROOF_JSON: &str = include_str!("../../tests/fixtures/groth16/eligibility-proof.json");
    OpaqueProof::new(PROOF_JSON.as_bytes()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zwa_protocol::proof::OpaqueProof;
    use zwa_protocol::{ActiveCredentialRoot, AuthorizedIssuanceRoot, TradeCommitment};

    const ISSUANCE_ROOT: &str =
        "19309979006225485291788213177219598381134511159668519266888323889569746782051";
    const CREDENTIAL_ROOT: &str =
        "7239536478138432754387625126231950010993505962177483323536139232738771167323";
    const TRADE_COMMITMENT: &str =
        "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    const OTHER_COMMITMENT: &str =
        "7409670081847436957289371955571360481923983184454289247710022466448715682310";

    // Real fixtures
    const REAL_PROVENANCE_ROOT: &str =
        "8857867840332676380575934803462643968319857770249975039236308904195120230546";
    const REAL_PROVENANCE_COMMITMENT: &str =
        "7409670081847436957289371955571360481923983184454289247710022466448715682310";
    const REAL_ELIGIBILITY_ROOT: &str =
        "7721491042898277899686830032817687831050368809629386580479309633507500868506";
    const REAL_ELIGIBILITY_COMMITMENT: &str =
        "10187400613857124614980227259922066295752635539032972479692659299555113110306";

    #[test]
    fn real_provenance_proof_verifies_with_real_vkey() {
        // This is the core A4 test: real Circom proof passes in Rust
        let verifier = ProvenanceVerifierBackend::from_fixture().unwrap();
        let root = AuthorizedIssuanceRoot::from_decimal_str(REAL_PROVENANCE_ROOT).unwrap();
        let commitment = TradeCommitment::from_decimal_str(REAL_PROVENANCE_COMMITMENT).unwrap();
        let proof = load_real_provenance_proof();

        let result = verifier.verify(root, commitment, &proof);
        assert_eq!(result, VerificationResult::Valid, "real provenance proof must verify");
    }

    #[test]
    fn real_eligibility_proof_verifies_with_real_vkey() {
        let verifier = EligibilityVerifierBackend::from_fixture().unwrap();
        let root = ActiveCredentialRoot::from_decimal_str(REAL_ELIGIBILITY_ROOT).unwrap();
        let commitment = TradeCommitment::from_decimal_str(REAL_ELIGIBILITY_COMMITMENT).unwrap();
        let proof = load_real_eligibility_proof();

        let result = verifier.verify(root, commitment, &proof);
        assert_eq!(result, VerificationResult::Valid, "real eligibility Phase1B proof must verify");
    }

    #[test]
    fn real_proofs_reject_wrong_root_and_wrong_commitment() {
        let prov_verifier = ProvenanceVerifierBackend::from_fixture().unwrap();
        let elig_verifier = EligibilityVerifierBackend::from_fixture().unwrap();

        let real_prov_root = AuthorizedIssuanceRoot::from_decimal_str(REAL_PROVENANCE_ROOT).unwrap();
        let real_prov_commitment = TradeCommitment::from_decimal_str(REAL_PROVENANCE_COMMITMENT).unwrap();
        let real_elig_root = ActiveCredentialRoot::from_decimal_str(REAL_ELIGIBILITY_ROOT).unwrap();
        let real_elig_commitment = TradeCommitment::from_decimal_str(REAL_ELIGIBILITY_COMMITMENT).unwrap();

        let prov_proof = load_real_provenance_proof();
        let elig_proof = load_real_eligibility_proof();

        // Wrong root
        let wrong_root = AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap();
        let result = prov_verifier.verify(wrong_root, real_prov_commitment, &prov_proof);
        assert_ne!(result, VerificationResult::Valid, "wrong root must not verify");
        // Should be ProofRejected (ark returns false) or PublicInputMismatch equivalent
        assert!(!result.is_valid());

        // Wrong commitment - must be different from real (7409...), so use TRADE_COMMITMENT (10187...)
        let wrong_commitment = TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let result = prov_verifier.verify(real_prov_root, wrong_commitment, &prov_proof);
        assert!(!result.is_valid(), "wrong commitment must not verify");

        // Eligibility wrong root
        let wrong_elig_root = ActiveCredentialRoot::from_decimal_str(CREDENTIAL_ROOT).unwrap();
        let result = elig_verifier.verify(wrong_elig_root, real_elig_commitment, &elig_proof);
        assert!(!result.is_valid());

        // Swapped inputs: use eligibility root for provenance
        let result = prov_verifier.verify(
            AuthorizedIssuanceRoot::from_decimal_str(REAL_ELIGIBILITY_ROOT).unwrap(),
            real_elig_commitment,
            &prov_proof,
        );
        assert!(!result.is_valid(), "swapped root must fail");
    }

    #[test]
    fn real_proofs_reject_altered_proof() {
        let verifier = ProvenanceVerifierBackend::from_fixture().unwrap();
        let root = AuthorizedIssuanceRoot::from_decimal_str(REAL_PROVENANCE_ROOT).unwrap();
        let commitment = TradeCommitment::from_decimal_str(REAL_PROVENANCE_COMMITMENT).unwrap();

        // Alter proof bytes
        let mut proof_json: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/groth16/provenance-proof.json")).unwrap();
        // Flip a bit in pi_a
        if let Some(pi_a) = proof_json.get_mut("pi_a") {
            if let Some(arr) = pi_a.as_array_mut() {
                if let Some(first) = arr.get_mut(0) {
                    *first = serde_json::Value::String("123456789".to_string());
                }
            }
        }
        let altered_proof_bytes = serde_json::to_vec(&proof_json).unwrap();
        let altered_proof = OpaqueProof::new(&altered_proof_bytes).unwrap();

        let result = verifier.verify(root, commitment, &altered_proof);
        assert!(!result.is_valid(), "altered proof must not verify");
    }

    #[test]
    fn vk_hash_prevents_substitution() {
        // Load vkey and compute hash, then try to load with wrong expected hash
        const VKEY_JSON: &str = include_str!("../../tests/fixtures/groth16/provenance-vkey.json");
        let computed_hash = VkHash::from_json_str(VKEY_JSON);
        assert_eq!(
            computed_hash.as_str(),
            "4831d3eef9575ef7daf318eb8767e1a39ef1e26da20339ddda137b1e246f1350"
        );

        // Correct hash should pass
        let verifier = ProvenanceVerifierBackend::from_vkey_json(VKEY_JSON, Some(computed_hash.as_str()));
        assert!(verifier.is_ok());

        // Wrong hash must fail
        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let verifier = ProvenanceVerifierBackend::from_vkey_json(VKEY_JSON, Some(wrong_hash));
        assert!(verifier.is_err());
        match verifier.unwrap_err() {
            Groth16VerificationError::VkHashMismatch { expected, got } => {
                assert_eq!(expected, wrong_hash);
                assert_eq!(got, computed_hash.as_str());
            }
            other => panic!("expected VkHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn matcher_proof_gate_enforces_same_commitment_with_real_proofs() {
        use crate::checked::CheckedTrade;
        use crate::roots::{
            AuthenticatedCredentialRoot, AuthenticatedIssuerRoot, CredentialRootAuthenticator,
            IssuerRootAuthenticator,
        };
        use ed25519_dalek::SigningKey;
        use std::collections::BTreeMap;
        use zwa_credentials::{AuthorityKeyId, IssuerKeyId};
        use zwa_protocol::{
            AssetBaseBytes, MatcherFee, OpaqueSignature, PolicyRoot, RecipientCommitment, RootVersion,
            TradeAmount, TradeExpiry, TradeIntent, TradeNonce, UnixSeconds, ZatoshiAmount,
        };
        use ed25519_dalek::Signer;

        // Build checked trade for REAL_PROVENANCE_COMMITMENT (Phase0F)
        let offered_asset =
            AssetBaseBytes::from_hex("4889ad11564115f3655f7e434bffb23074d42aafd58cfecae32a5b5eafaf5301")
                .unwrap();
        let requested_asset =
            AssetBaseBytes::from_hex("a7ac13ded8b51e7a59c400097b70fe6d5d855b30ad19b1897de1fd74721a9339")
                .unwrap();
        let intent = TradeIntent {
            offered_asset,
            offered_amount: TradeAmount::new(10),
            requested_asset,
            requested_amount: TradeAmount::new(6),
            recipient_commitment: RecipientCommitment::from_decimal_str(
                "9164735690016291275717655492237784651611678784535903954999391667413316204280",
            )
            .unwrap(),
            policy_root: PolicyRoot::from_decimal_str("42424242424242").unwrap(),
            matcher_fee: MatcherFee::new(
                ZatoshiAmount::new(5),
                RecipientCommitment::from_decimal_str(
                    "1800273984094439421343257609634901689467303577600258601269976617936586404380",
                )
                .unwrap(),
            ),
            nonce: TradeNonce::new(7001),
            expiry: TradeExpiry::new(2_000_000_000),
        };
        let commitment = TradeCommitment::from_decimal_str(REAL_PROVENANCE_COMMITMENT).unwrap();
        let checked = CheckedTrade::new(intent, commitment).unwrap();

        // Build authenticated roots for real public inputs
        let sk_issuer = SigningKey::from_bytes(&[1u8; 32]);
        let vk_issuer = sk_issuer.verifying_key();
        let issuer_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved_issuer = BTreeMap::new();
        approved_issuer.insert(issuer_id.clone(), vk_issuer);
        let issuer_auth = IssuerRootAuthenticator::new(approved_issuer, RootVersion::new(1));

        let issuer_payload = zwa_credentials::IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(REAL_PROVENANCE_ROOT).unwrap(),
            issuer_id,
            RootVersion::new(1),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        )
        .unwrap();
        let sig = sk_issuer.sign(&issuer_payload.canonical_bytes());
        let issuer_envelope =
            zwa_credentials::IssuerRootEnvelope::new(issuer_payload, OpaqueSignature::new(&sig.to_bytes()).unwrap());
        let auth_issuer = issuer_auth
            .authenticate(&issuer_envelope, UnixSeconds::new(2_000_000_000), TradeExpiry::new(2_000_000_000))
            .unwrap();

        // For eligibility, we need real eligibility root
        let sk_cred = SigningKey::from_bytes(&[2u8; 32]);
        let vk_cred = sk_cred.verifying_key();
        let auth_id = AuthorityKeyId::new(b"cred-auth-1").unwrap();
        let mut approved_cred = BTreeMap::new();
        approved_cred.insert(auth_id.clone(), vk_cred);
        let cred_auth = CredentialRootAuthenticator::new(approved_cred, RootVersion::new(1));
        let cred_payload = zwa_credentials::CredentialRootPayload::new(
            ActiveCredentialRoot::from_decimal_str(REAL_ELIGIBILITY_ROOT).unwrap(),
            auth_id,
            RootVersion::new(1),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        )
        .unwrap();
        let sig2 = sk_cred.sign(&cred_payload.canonical_bytes());
        let cred_envelope =
            zwa_credentials::CredentialRootEnvelope::new(cred_payload, OpaqueSignature::new(&sig2.to_bytes()).unwrap());
        let auth_cred = cred_auth
            .authenticate(&cred_envelope, UnixSeconds::new(2_000_000_000), TradeExpiry::new(2_000_000_000))
            .unwrap();

        // Use real verifiers
        let prov_backend = ProvenanceVerifierBackend::from_fixture().unwrap();
        let elig_backend = EligibilityVerifierBackend::from_fixture().unwrap();

        // For this test, we have checked trade for provenance commitment, but eligibility proof is for different commitment (10187...)
        // So we need to create two separate gates or test splicing
        // Here we test that using same commitment for both works when we have matching proofs
        // We'll create a checked trade for eligibility commitment and verify eligibility proof alone

        let intent_elig = {
            let mut i = intent;
            // Use Phase1B trade that matches eligibility commitment 10187...
            // That trade has different recipient commitment
            i.recipient_commitment = RecipientCommitment::from_decimal_str(
                "13135279047718387126053226034283670929172341955108098732820235388025453726181",
            )
            .unwrap();
            i.policy_root = PolicyRoot::from_decimal_str(
                "1514393595722546217125953798550283818470332284949639873172624869558831825935",
            )
            .unwrap();
            i
        };
        let commitment_elig = TradeCommitment::from_decimal_str(REAL_ELIGIBILITY_COMMITMENT).unwrap();
        let checked_elig = CheckedTrade::new(intent_elig, commitment_elig).unwrap();

        let gate = MatcherProofGate::new(
            checked_elig,
            prov_backend,
            elig_backend,
        );

        // This will fail for provenance because provenance proof is for different root/commitment
        // But we want to test same-commitment invariant: if we try to verify provenance proof (for 7409...) with eligibility commitment (10187...), it must fail
        let prov_proof = load_real_provenance_proof();
        let elig_proof = load_real_eligibility_proof();

        // Provenance proof should NOT verify against eligibility commitment
        let prov_result = gate
            .provenance_verifier
            .verify(auth_issuer.root(), commitment_elig, &prov_proof);
        assert!(!prov_result.is_valid(), "provenance proof for 7409... must not verify for 10187... commitment");

        // Eligibility proof should verify against its own commitment
        let elig_result = gate
            .eligibility_verifier
            .verify(auth_cred.root(), commitment_elig, &elig_proof);
        assert_eq!(elig_result, VerificationResult::Valid);

        // Splicing test: try to verify both with same checked trade but mismatched proofs
        // If we use provenance proof for 7409... and eligibility proof for 10187... with checked trade for 10187..., provenance fails
        let err = gate
            .verify_both(&auth_issuer, &auth_cred, &prov_proof, &elig_proof)
            .unwrap_err();
        assert!(!err.is_valid());
    }

    #[test]
    fn verification_result_must_be_checked() {
        let valid = VerificationResult::Valid;
        let invalid = VerificationResult::Invalid {
            reason: VerificationProblem::ProofRejected,
        };
        assert!(valid.is_valid());
        assert!(!invalid.is_valid());
        assert_ne!(valid, invalid);
    }
}
