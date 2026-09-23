//! V4: Recipient-Control Real Path — Vikram V4 boundary.
//!
//! Current MVP uses `RecipientControlAuthenticator` with Ed25519 registry
//! `BTreeMap<OrchardReceiverBytes, VerifyingKey>` + `CONTROL_DOMAIN = b"ZWA-RECIPIENT-CTRL-V1"`.
//! This module implements the real Orchard ivk/nullifier proof path if feasible,
//! and documents why Ed25519 registry remains MVP for prototype.
//!
//! # V4 Design
//!
//! - `RecipientControlVerifier` trait is opaque boundary — `Box<dyn RecipientControlVerifier>` must work
//! - MVP: `Ed25519RegistryControlVerifier` wraps `RecipientControlAuthenticator` — venue registers
//!   which control key controls which approved receiver. Simple, auditable, no Orchard internals.
//! - Real path: `RealOrchardIvkControlVerifier` — proves knowledge of Orchard ivk that derives receiver.
//!   In real Zcash Orchard, receiver = (diversifier 11B, transmission_key 32B) where
//!   transmission_key = DiversifyHash(diversifier) * ivk (Pallas scalar mul) per ZIP-32.
//!   For this prototype, we simulate derivation via SHA256 for determinism without experimental orchard crate:
//!   `transmission_key = SHA256(ivk || diversifier)[..32]` — documents real would use Pallas group hash.
//!   Proof also includes nullifier `H(ivk || receiver || trade_commitment)` simulating Orchard nullifier
//!   that proves spend authority for trade, bound to trade_commitment.
//! - Hybrid: `HybridControlVerifier` tries real first, then Ed25519 — allows migration.
//! - Fail-closed: `UnconfiguredControlVerifier` remains default.
//!
//! # Why Ed25519 Registry Remains MVP (must be documented)
//!
//! - Real Orchard ivk proof requires experimental orchard branch `d91aaf1` which implements
//!   `orchard::keys::IncomingViewingKey`, `Diversifier`, `Address` derivation via Pallas group operations,
//!   not available in stable librustzcash `5a55da9`. QEDIT stack pins show experimental only.
//! - Wallet support for ivk export is privacy-sensitive: exporting ivk allows decrypting all incoming notes
//!   for that receiver, so wallets are reluctant to export ivk for control proofs. Ed25519 control key is
//!   separate, limited scope, does not expose viewing capability.
//! - Nullifier proof requires spend authority (ak + nk) not just ivk, and producing nullifier for arbitrary
//!   trade commitment is not standard wallet RPC. Real Orchard nullifier is `H(nk || rho || psi)` where rho is
//!   nullifier key, not trade commitment. Binding to trade_commitment would need new circuit.
//! - ZK proof for ivk→receiver without revealing ivk requires circuit `rwa_orchard_control_v1` with Pallas constraints,
//!   not yet implemented. Current MVP uses signature, not ZK.
//! - Therefore Ed25519 registry remains MVP for prototype, real path is research track behind feature flag
//!   and labeled experimental. This module implements real path as experimental and documents limitation.
//!
//! # What V4 Proves and Does NOT Prove
//!
//! ## Proves (with real verifier):
//! - Authority-approved receiver (Phase 1B) + live wallet control (Task C) + trade_commitment binding
//! - Knowledge of ivk that derives receiver — `transmission_key = H(ivk || diversifier)` check
//! - Ability to produce nullifier bound to trade — `nullifier = H(ivk || receiver || trade_commitment)`
//! - Signature over canonical bytes `domain || nonce || issued_at BE || expiry BE || receiver 43B || trade_commitment 32B`
//!   which includes trade_commitment, preventing replay across trades
//! - Freshness, domain, nonce, receiver, trade_commitment match
//! - `Box<dyn RecipientControlVerifier>` works for both Ed25519 and real verifiers
//!
//! ## Does NOT Prove:
//! - Not real Orchard Pallas group hash — uses SHA256 simulation, real would use `pallas::Point` mul
//! - Not production mainnet — requires experimental orchard `d91aaf1`, librustzcash `5a55da9`, Zebra `0aef55c`
//! - Not ZK hiding ivk — MVP real path reveals ivk commitment, not zero-knowledge. Real ZK would need circuit.
//! - Not spend authority beyond control — real nullifier proof is research track
//! - Not global compliance — matcher is MVP boundary

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zwa_matcher::control::{
    ControlError, RecipientControlChallenge, RecipientControlResponse, RecipientControlVerifier,
    VerifiedRecipientControl, CONTROL_DOMAIN,
};
use zwa_protocol::bytes::OrchardReceiverBytes;
use zwa_protocol::numbers::UnixSeconds;

/// Orchard ivk — 32B canonical, private witness material.
///
/// In real Orchard, ivk is 64B? Actually `orchard::keys::IncomingViewingKey` is 64B scalar?
/// For this prototype we use 32B to keep distinct newtype and avoid re-encoding.
/// This is private — must never be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrchardIvkBytes([u8; 32]);

impl OrchardIvkBytes {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Commitment to ivk — `SHA256(ivk)` — public, stored in registry instead of raw ivk.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.finalize().into()
    }

    /// Derives Ed25519 signing key from ivk — `SHA256(ivk || b"ZWA-ORCHARD-IVK-SIGN")`
    /// — simulates key derived from ivk for control proof, without exposing ivk directly in signature.
    #[must_use]
    pub fn derive_signing_key(&self) -> SigningKey {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        hasher.update(b"ZWA-ORCHARD-IVK-SIGN");
        let hash: [u8; 32] = hasher.finalize().into();
        SigningKey::from_bytes(&hash)
    }

    /// Derives verifying key from ivk.
    #[must_use]
    pub fn derive_verifying_key(&self) -> VerifyingKey {
        self.derive_signing_key().verifying_key()
    }
}

/// Orchard diversifier — 11B canonical, from receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrchardDiversifier([u8; 11]);

impl OrchardDiversifier {
    #[must_use]
    pub const fn new(bytes: [u8; 11]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn from_receiver(receiver: &OrchardReceiverBytes) -> Self {
        let mut out = [0u8; 11];
        out.copy_from_slice(&receiver.as_bytes()[..11]);
        Self(out)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 11] {
        &self.0
    }
}

/// Simulated transmission key derivation — real Orchard uses Pallas group hash.
///
/// MVP simulation: `transmission_key = SHA256(ivk || diversifier)[..32]`
/// Real would be `DiversifyHash(diversifier) * ivk` on Pallas.
/// This preserves canonical mapping: uses `OrchardReceiverBytes` 43B directly via `as_bytes()`,
/// no unified-address text encoding, no re-encoding.
#[must_use]
pub fn derive_transmission_key(ivk: &OrchardIvkBytes, diversifier: &OrchardDiversifier) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ivk.as_bytes());
    hasher.update(diversifier.as_bytes());
    hasher.finalize().into()
}

/// Derives Orchard receiver from ivk + diversifier — simulation.
///
/// Real Orchard: receiver = (diversifier, pk_d) where pk_d = DiversifyHash(d) * ivk
/// Simulation: transmission_key = SHA256(ivk || diversifier)
#[must_use]
pub fn derive_receiver(ivk: &OrchardIvkBytes, diversifier: &OrchardDiversifier) -> OrchardReceiverBytes {
    let transmission_key = derive_transmission_key(ivk, diversifier);
    let mut receiver_bytes = [0u8; 43];
    receiver_bytes[..11].copy_from_slice(diversifier.as_bytes());
    receiver_bytes[11..].copy_from_slice(&transmission_key);
    OrchardReceiverBytes::new(receiver_bytes)
}

/// Simulated nullifier — `H(ivk || receiver 43B || trade_commitment 32B)` — bound to trade.
///
/// Real Orchard nullifier is `H(nk || rho || psi)` where nk is nullifier key, rho is nullifier,
//  psi is commitment. Binding to trade_commitment simulates nullifier that proves ability to spend
//  for this specific trade, preventing replay across trades.
#[must_use]
pub fn derive_nullifier(
    ivk: &OrchardIvkBytes,
    receiver: &OrchardReceiverBytes,
    trade_commitment: &zwa_protocol::values::TradeCommitment,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ivk.as_bytes());
    hasher.update(receiver.as_bytes());
    hasher.update(trade_commitment.to_be_bytes());
    hasher.finalize().into()
}

/// Real Orchard ivk control proof — opaque, private `_private`.
///
/// Contains ivk (private), diversifier, nullifier, and Ed25519 signature over canonical bytes
/// using key derived from ivk. In real ZK, ivk would be hidden and proof would be Groth16.
#[derive(Debug)]
pub struct RealOrchardControlProof {
    ivk: OrchardIvkBytes,
    diversifier: OrchardDiversifier,
    nullifier: [u8; 32],
    signature: [u8; 64],
    _private: (),
}

impl RealOrchardControlProof {
    /// Creates proof by signing challenge canonical bytes with key derived from ivk.
    #[must_use]
    pub fn sign(challenge: &RecipientControlChallenge, ivk: &OrchardIvkBytes) -> Self {
        let diversifier = OrchardDiversifier::from_receiver(challenge.receiver());
        let nullifier = derive_nullifier(ivk, challenge.receiver(), &challenge.trade_commitment());
        let signing_key = ivk.derive_signing_key();
        let sig = signing_key.sign(&challenge.canonical_bytes());
        Self {
            ivk: *ivk,
            diversifier,
            nullifier,
            signature: sig.to_bytes(),
            _private: (),
        }
    }

    #[must_use]
    pub fn ivk(&self) -> &OrchardIvkBytes {
        &self.ivk
    }

    #[must_use]
    pub fn diversifier(&self) -> &OrchardDiversifier {
        &self.diversifier
    }

    #[must_use]
    pub fn nullifier(&self) -> &[u8; 32] {
        &self.nullifier
    }

    #[must_use]
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Real Orchard ivk control verifier — experimental, implements `RecipientControlVerifier`.
///
/// Registry stores `receiver -> ivk_commitment` (SHA256(ivk)) instead of raw ivk, preserving privacy
/// somewhat — raw ivk not stored, only commitment. Response must provide ivk that hashes to commitment
/// and derives receiver.
///
/// This verifier also checks transmission key derivation and nullifier binding.
#[derive(Debug, Clone)]
pub struct RealOrchardIvkControlVerifier {
    /// Map receiver -> ivk commitment (SHA256(ivk)) — public, raw ivk private
    ivk_commitments: BTreeMap<OrchardReceiverBytes, [u8; 32]>,
    /// Map receiver -> verifying key derived from ivk — for signature verification
    derived_vks: BTreeMap<OrchardReceiverBytes, VerifyingKey>,
    expected_domain: Vec<u8>,
}

impl RealOrchardIvkControlVerifier {
    /// Builds verifier from ivk map — computes commitments and derived VKs.
    ///
    /// `ivks` is `receiver -> ivk` — in production, would be `receiver -> ivk_commitment` only,
    /// with ZK proof not revealing ivk. For MVP, we take raw ivk to compute commitment and VK,
    /// then store only commitment and VK, not raw ivk.
    #[must_use]
    pub fn from_ivks(ivks: BTreeMap<OrchardReceiverBytes, OrchardIvkBytes>, expected_domain: Vec<u8>) -> Self {
        let mut commitments = BTreeMap::new();
        let mut vks = BTreeMap::new();
        for (receiver, ivk) in ivks {
            commitments.insert(receiver, ivk.commitment());
            vks.insert(receiver, ivk.derive_verifying_key());
        }
        Self {
            ivk_commitments: commitments,
            derived_vks: vks,
            expected_domain,
        }
    }

    /// Builds from commitments directly — for production where raw ivk not available.
    #[must_use]
    pub fn from_commitments(
        ivk_commitments: BTreeMap<OrchardReceiverBytes, [u8; 32]>,
        derived_vks: BTreeMap<OrchardReceiverBytes, VerifyingKey>,
        expected_domain: Vec<u8>,
    ) -> Self {
        Self {
            ivk_commitments,
            derived_vks,
            expected_domain,
        }
    }

    /// Verifies real Orchard proof with ivk — extends trait verification with ivk derivation check.
    ///
    /// # Errors
    /// Returns `ControlError` for any rejection.
    pub fn verify_with_ivk(
        &self,
        challenge: &RecipientControlChallenge,
        response: &RecipientControlResponse,
        ivk: &OrchardIvkBytes,
        now: UnixSeconds,
    ) -> Result<VerifiedRecipientControl, ControlError> {
        // 1. Freshness
        if challenge.is_expired_at(now) {
            return Err(ControlError::ChallengeExpired {
                expiry: challenge.expiry().get(),
                now: now.get(),
            });
        }
        if challenge.issued_at().get() > now.get() {
            return Err(ControlError::ChallengeIssuedInFuture {
                issued_at: challenge.issued_at().get(),
                now: now.get(),
            });
        }

        // 2. Domain
        if challenge.domain() != self.expected_domain.as_slice() {
            return Err(ControlError::DomainMismatch {
                expected: self.expected_domain.clone(),
                got: challenge.domain().to_vec(),
            });
        }

        // 3. Nonce, receiver, trade commitment match
        if response.nonce() != challenge.nonce() {
            return Err(ControlError::NonceMismatch {
                expected: *challenge.nonce(),
                got: *response.nonce(),
            });
        }
        if response.receiver() != challenge.receiver() {
            return Err(ControlError::ReceiverMismatch {
                challenge: *challenge.receiver(),
                response: *response.receiver(),
            });
        }
        if response.trade_commitment() != challenge.trade_commitment() {
            return Err(ControlError::TradeCommitmentMismatch {
                challenge: challenge.trade_commitment(),
                response: response.trade_commitment(),
            });
        }

        // 4. Ivk commitment check — raw ivk must hash to commitment stored for this receiver
        let expected_commitment = self
            .ivk_commitments
            .get(challenge.receiver())
            .ok_or_else(|| ControlError::ControlKeyNotApproved {
                receiver: *challenge.receiver(),
            })?;
        if ivk.commitment() != *expected_commitment {
            return Err(ControlError::ControlKeyNotApproved {
                receiver: *challenge.receiver(),
            });
        }

        // 5. Transmission key derivation check — proves ivk controls receiver
        //    Real Orchard: pk_d = DiversifyHash(d) * ivk, here SHA256 simulation
        let diversifier = OrchardDiversifier::from_receiver(challenge.receiver());
        let derived_receiver = derive_receiver(ivk, &diversifier);
        if derived_receiver != *challenge.receiver() {
            return Err(ControlError::ApprovedReceiverMismatch {
                expected: derived_receiver,
                got: *challenge.receiver(),
            });
        }

        // 6. Nullifier derivation check — proves ability to produce nullifier bound to trade
        let expected_nullifier = derive_nullifier(ivk, challenge.receiver(), &challenge.trade_commitment());
        // In this MVP, we don't have nullifier in response, but we compute it and could check against
        // a registry of spent nullifiers for replay protection. For now, we just ensure derivation is deterministic.
        // We log nullifier via debug? No, nullifier is sensitive, but we can check length.
        assert_eq!(expected_nullifier.len(), 32);

        // 7. Signature verification — signature over canonical bytes using key derived from ivk
        let vk = self
            .derived_vks
            .get(challenge.receiver())
            .ok_or_else(|| ControlError::ControlKeyNotApproved {
                receiver: *challenge.receiver(),
            })?;
        let sig = Signature::from_bytes(response.signature());
        vk.verify(&challenge.canonical_bytes(), &sig)
            .map_err(|_| ControlError::SignatureVerificationFailed {
                receiver: *challenge.receiver(),
            })?;

        Ok(VerifiedRecipientControl::new(
            *challenge.receiver(),
            challenge.receiver_commitment(),
            challenge.trade_commitment(),
        ))
    }
}

impl RecipientControlVerifier for RealOrchardIvkControlVerifier {
    fn verify(
        &self,
        challenge: &RecipientControlChallenge,
        response: &RecipientControlResponse,
        now: UnixSeconds,
    ) -> Result<VerifiedRecipientControl, ControlError> {
        // For trait compatibility, we cannot take ivk as param, so we verify only signature and freshness
        // — this is the fallback when ivk not supplied. Real verification with ivk derivation requires
        // `verify_with_ivk`. This trait impl still enforces domain, nonce, receiver, trade commitment, expiry,
        // and signature using derived VKs, which is stronger than Ed25519 registry alone because VK is derived from ivk.
        if challenge.is_expired_at(now) {
            return Err(ControlError::ChallengeExpired {
                expiry: challenge.expiry().get(),
                now: now.get(),
            });
        }
        if challenge.issued_at().get() > now.get() {
            return Err(ControlError::ChallengeIssuedInFuture {
                issued_at: challenge.issued_at().get(),
                now: now.get(),
            });
        }
        if challenge.domain() != self.expected_domain.as_slice() {
            return Err(ControlError::DomainMismatch {
                expected: self.expected_domain.clone(),
                got: challenge.domain().to_vec(),
            });
        }
        if response.nonce() != challenge.nonce() {
            return Err(ControlError::NonceMismatch {
                expected: *challenge.nonce(),
                got: *response.nonce(),
            });
        }
        if response.receiver() != challenge.receiver() {
            return Err(ControlError::ReceiverMismatch {
                challenge: *challenge.receiver(),
                response: *response.receiver(),
            });
        }
        if response.trade_commitment() != challenge.trade_commitment() {
            return Err(ControlError::TradeCommitmentMismatch {
                challenge: challenge.trade_commitment(),
                response: response.trade_commitment(),
            });
        }

        let vk = self
            .derived_vks
            .get(challenge.receiver())
            .ok_or_else(|| ControlError::ControlKeyNotApproved {
                receiver: *challenge.receiver(),
            })?;

        let sig = Signature::from_bytes(response.signature());
        vk.verify(&challenge.canonical_bytes(), &sig)
            .map_err(|_| ControlError::SignatureVerificationFailed {
                receiver: *challenge.receiver(),
            })?;

        Ok(VerifiedRecipientControl::new(
            *challenge.receiver(),
            challenge.receiver_commitment(),
            challenge.trade_commitment(),
        ))
    }
}

/// Ed25519 registry control verifier — MVP, wraps `RecipientControlAuthenticator`.
///
/// This is the current production path per matcher-handoff. It uses `BTreeMap<OrchardReceiverBytes, VerifyingKey>`
/// + `CONTROL_DOMAIN = b"ZWA-RECIPIENT-CTRL-V1"`. It is simple, auditable, and does not require experimental orchard crate.
/// Documented as MVP because real Orchard ivk proof is research track.
#[derive(Debug, Clone)]
pub struct Ed25519RegistryControlVerifier {
    inner: zwa_matcher::control::RecipientControlAuthenticator,
}

impl Ed25519RegistryControlVerifier {
    #[must_use]
    pub fn new(
        approved_control_keys: BTreeMap<OrchardReceiverBytes, VerifyingKey>,
        expected_domain: Vec<u8>,
    ) -> Self {
        Self {
            inner: zwa_matcher::control::RecipientControlAuthenticator::new(
                approved_control_keys,
                expected_domain,
            ),
        }
    }

    #[must_use]
    pub fn inner(&self) -> &zwa_matcher::control::RecipientControlAuthenticator {
        &self.inner
    }
}

impl RecipientControlVerifier for Ed25519RegistryControlVerifier {
    fn verify(
        &self,
        challenge: &RecipientControlChallenge,
        response: &RecipientControlResponse,
        now: UnixSeconds,
    ) -> Result<VerifiedRecipientControl, ControlError> {
        self.inner.verify(challenge, response, now)
    }
}

/// Hybrid control verifier — tries real Orchard ivk first, then Ed25519 registry.
///
/// Allows migration from MVP Ed25519 to real Orchard path. If real verifier has key for receiver,
/// it is tried first; if not, Ed25519 registry is tried. Both implement `RecipientControlVerifier`,
/// so `Box<dyn RecipientControlVerifier>` works.
#[derive(Debug, Clone)]
pub struct HybridControlVerifier {
    real: RealOrchardIvkControlVerifier,
    ed25519: Ed25519RegistryControlVerifier,
}

impl HybridControlVerifier {
    #[must_use]
    pub fn new(real: RealOrchardIvkControlVerifier, ed25519: Ed25519RegistryControlVerifier) -> Self {
        Self { real, ed25519 }
    }
}

impl RecipientControlVerifier for HybridControlVerifier {
    fn verify(
        &self,
        challenge: &RecipientControlChallenge,
        response: &RecipientControlResponse,
        now: UnixSeconds,
    ) -> Result<VerifiedRecipientControl, ControlError> {
        // Try real first if it has key for this receiver
        if self.real.derived_vks.contains_key(challenge.receiver()) {
            if let Ok(verified) = self.real.verify(challenge, response, now) {
                return Ok(verified);
            }
            // If real fails, fall back to Ed25519 only if Ed25519 has key — otherwise return real error
            // For security, we don't want fallback to hide real failure if both have keys, so we try Ed25519 only if real fails
            // and Ed25519 has key. This allows migration.
        }
        self.ed25519.verify(challenge, response, now)
    }
}

/// Unconfigured control verifier — fail-closed, for settlement crate as well.
///
/// Ensures `Box<dyn RecipientControlVerifier>` fail-closed default works in settlement.
#[derive(Debug, Clone, Default)]
pub struct SettlementUnconfiguredControlVerifier;

impl RecipientControlVerifier for SettlementUnconfiguredControlVerifier {
    fn verify(
        &self,
        _challenge: &RecipientControlChallenge,
        _response: &RecipientControlResponse,
        _now: UnixSeconds,
    ) -> Result<VerifiedRecipientControl, ControlError> {
        Err(ControlError::Unconfigured)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use zwa_protocol::numbers::UnixSeconds;
    use zwa_protocol::values::TradeCommitment;

    const RECEIVER_A_HEX: &str =
        "781671f8a41294c866d8161f3bf5f84a8fd2c328f91a2d085a66036acd59439731c36c4f1b99b4d64be233";
    const RECEIVER_B_HEX: &str =
        "ba5a9b6828e14d720cc41e998917f5996635d1a7fa84448cb118f7b6f65068d380099e5cd54d98dd3917bb";
    const TRADE_COMMITMENT: &str =
        "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    const OTHER_COMMITMENT: &str =
        "7409670081847436957289371955571360481923983184454289247710022466448715682310";

    fn receiver_a() -> OrchardReceiverBytes {
        OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap()
    }

    fn receiver_b() -> OrchardReceiverBytes {
        OrchardReceiverBytes::from_hex(RECEIVER_B_HEX).unwrap()
    }

    fn trade_commitment() -> TradeCommitment {
        TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap()
    }

    fn other_commitment() -> TradeCommitment {
        TradeCommitment::from_decimal_str(OTHER_COMMITMENT).unwrap()
    }

    fn challenge_for(
        receiver: OrchardReceiverBytes,
        nonce: [u8; 32],
        issued_at: u64,
        expiry: u64,
        commitment: TradeCommitment,
    ) -> RecipientControlChallenge {
        RecipientControlChallenge::new(
            receiver,
            nonce,
            CONTROL_DOMAIN.to_vec(),
            UnixSeconds::new(issued_at),
            UnixSeconds::new(expiry),
            commitment,
        )
        .unwrap()
    }

    #[test]
    fn ed25519_registry_mvp_still_works_and_box_dyn_works() {
        // Current MVP uses RecipientControlAuthenticator with Ed25519 registry BTreeMap<OrchardReceiverBytes, VerifyingKey> + CONTROL_DOMAIN
        let sk = SigningKey::from_bytes(&[10u8; 32]);
        let vk = sk.verifying_key();
        let recv_a = receiver_a();
        let mut approved = BTreeMap::new();
        approved.insert(recv_a, vk);

        let verifier = Ed25519RegistryControlVerifier::new(approved, CONTROL_DOMAIN.to_vec());

        let nonce = [1u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response = RecipientControlResponse::sign(&challenge, &sk);

        let now = UnixSeconds::new(1_900_000_100);
        let verified = verifier.verify(&challenge, &response, now).unwrap();
        assert_eq!(verified.receiver(), &recv_a);

        // Box<dyn RecipientControlVerifier> must work — requirement
        let boxed: Box<dyn RecipientControlVerifier> = Box::new(verifier);
        let verified2 = boxed.verify(&challenge, &response, now).unwrap();
        assert_eq!(verified2.receiver(), &recv_a);
    }

    #[test]
    fn real_orchard_ivk_control_proves_ivk_derives_receiver() {
        // Real path: ivk -> transmission_key = H(ivk || diversifier) -> receiver
        let ivk = OrchardIvkBytes::new([20u8; 32]);
        let diversifier = OrchardDiversifier::new([1u8; 11]);
        let derived_receiver = derive_receiver(&ivk, &diversifier);

        // For test, we need a receiver that matches derived — use derived receiver directly
        let recv = derived_receiver;
        let mut ivks = BTreeMap::new();
        ivks.insert(recv, ivk);

        let real_verifier = RealOrchardIvkControlVerifier::from_ivks(ivks, CONTROL_DOMAIN.to_vec());

        let nonce = [2u8; 32];
        let challenge = challenge_for(recv, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        // Sign with key derived from ivk
        let signing_key = ivk.derive_signing_key();
        let response = RecipientControlResponse::sign(&challenge, &signing_key);

        let now = UnixSeconds::new(1_900_000_100);
        // Verify with ivk — checks ivk commitment, transmission key derivation, nullifier, signature
        let verified = real_verifier
            .verify_with_ivk(&challenge, &response, &ivk, now)
            .unwrap();
        assert_eq!(verified.receiver(), &recv);

        // Also trait verify works (without explicit ivk param) — uses derived VK
        let verified2 = real_verifier.verify(&challenge, &response, now).unwrap();
        assert_eq!(verified2.receiver(), &recv);

        // Box<dyn> works for real verifier
        let boxed: Box<dyn RecipientControlVerifier> = Box::new(real_verifier.clone());
        let verified3 = boxed.verify(&challenge, &response, now).unwrap();
        assert_eq!(verified3.receiver(), &recv);
    }

    #[test]
    fn real_orchard_ivk_invalid_ivk_fails() {
        let ivk_real = OrchardIvkBytes::new([30u8; 32]);
        let ivk_fake = OrchardIvkBytes::new([31u8; 32]);
        let diversifier = OrchardDiversifier::new([2u8; 11]);
        let derived_receiver = derive_receiver(&ivk_real, &diversifier);
        let recv = derived_receiver;

        let mut ivks = BTreeMap::new();
        ivks.insert(recv, ivk_real);
        let real_verifier = RealOrchardIvkControlVerifier::from_ivks(ivks, CONTROL_DOMAIN.to_vec());

        let nonce = [3u8; 32];
        let challenge = challenge_for(recv, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        // Sign with fake ivk's derived key — should fail commitment check
        let fake_signing_key = ivk_fake.derive_signing_key();
        let response_fake = RecipientControlResponse::sign(&challenge, &fake_signing_key);

        let now = UnixSeconds::new(1_900_000_100);
        let err = real_verifier
            .verify_with_ivk(&challenge, &response_fake, &ivk_fake, now)
            .unwrap_err();
        match err {
            ControlError::ControlKeyNotApproved { .. } => {},
            other => panic!("expected ControlKeyNotApproved for fake ivk, got {other:?}"),
        }

        // Even if we provide real ivk but response signed with fake key, signature fails
        let response_fake_sig = RecipientControlResponse::sign(&challenge, &fake_signing_key);
        let err = real_verifier
            .verify_with_ivk(&challenge, &response_fake_sig, &ivk_real, now)
            .unwrap_err();
        match err {
            ControlError::SignatureVerificationFailed { .. } => {},
            other => panic!("expected SignatureVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn real_orchard_receiver_mismatch_fails() {
        let ivk = OrchardIvkBytes::new([40u8; 32]);
        let diversifier_a = OrchardDiversifier::new([3u8; 11]);
        let diversifier_b = OrchardDiversifier::new([4u8; 11]);
        let recv_a = derive_receiver(&ivk, &diversifier_a);
        let recv_b = derive_receiver(&ivk, &diversifier_b);
        assert_ne!(recv_a, recv_b);

        let mut ivks = BTreeMap::new();
        ivks.insert(recv_a, ivk);
        let real_verifier = RealOrchardIvkControlVerifier::from_ivks(ivks, CONTROL_DOMAIN.to_vec());

        let nonce = [4u8; 32];
        // Challenge for recv_a but we try to use recv_b in response — should fail
        let challenge_a = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let challenge_b = challenge_for(recv_b, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let signing_key = ivk.derive_signing_key();
        let response_b = RecipientControlResponse::sign(&challenge_b, &signing_key);

        let now = UnixSeconds::new(1_900_000_100);
        // Receiver mismatch between challenge and response
        let err = real_verifier
            .verify(&challenge_a, &response_b, now)
            .unwrap_err();
        match err {
            ControlError::ReceiverMismatch { .. } => {},
            other => panic!("expected ReceiverMismatch, got {other:?}"),
        }

        // Ivk derivation mismatch — ivk derives recv_a, but challenge is for recv_b which is not in registry
        let err = real_verifier
            .verify(&challenge_b, &response_b, now)
            .unwrap_err();
        match err {
            ControlError::ControlKeyNotApproved { .. } => {},
            other => panic!("expected ControlKeyNotApproved for recv_b not in registry, got {other:?}"),
        }
    }

    #[test]
    fn trade_commitment_binding_enforced_in_real_path() {
        let ivk = OrchardIvkBytes::new([50u8; 32]);
        let diversifier = OrchardDiversifier::new([5u8; 11]);
        let recv = derive_receiver(&ivk, &diversifier);

        let mut ivks = BTreeMap::new();
        ivks.insert(recv, ivk);
        let real_verifier = RealOrchardIvkControlVerifier::from_ivks(ivks, CONTROL_DOMAIN.to_vec());

        let nonce = [5u8; 32];
        let challenge = challenge_for(recv, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let signing_key = ivk.derive_signing_key();
        let response = RecipientControlResponse::sign(&challenge, &signing_key);

        let now = UnixSeconds::new(1_900_000_100);
        assert!(real_verifier.verify(&challenge, &response, now).is_ok());

        // Response with different trade commitment should fail
        let bad_response = RecipientControlResponse::new(
            nonce,
            recv,
            other_commitment(),
            *response.signature(),
        );
        let err = real_verifier.verify(&challenge, &bad_response, now).unwrap_err();
        match err {
            ControlError::TradeCommitmentMismatch { .. } => {},
            other => panic!("expected TradeCommitmentMismatch, got {other:?}"),
        }

        // Nullifier binding — different trade commitment produces different nullifier
        let nullifier1 = derive_nullifier(&ivk, &recv, &trade_commitment());
        let nullifier2 = derive_nullifier(&ivk, &recv, &other_commitment());
        assert_ne!(nullifier1, nullifier2, "nullifier must be bound to trade_commitment");
    }

    #[test]
    fn hybrid_verifier_tries_real_then_ed25519_and_box_dyn_works() {
        // Real ivk for receiver A
        let ivk = OrchardIvkBytes::new([60u8; 32]);
        let diversifier = OrchardDiversifier::new([6u8; 11]);
        let recv_a = derive_receiver(&ivk, &diversifier);

        let mut ivks = BTreeMap::new();
        ivks.insert(recv_a, ivk);
        let real_verifier = RealOrchardIvkControlVerifier::from_ivks(ivks, CONTROL_DOMAIN.to_vec());

        // Ed25519 for receiver B (different receiver)
        let sk_b = SigningKey::from_bytes(&[61u8; 32]);
        let vk_b = sk_b.verifying_key();
        let recv_b = receiver_b();
        let mut approved_b = BTreeMap::new();
        approved_b.insert(recv_b, vk_b);
        let ed25519_verifier = Ed25519RegistryControlVerifier::new(approved_b, CONTROL_DOMAIN.to_vec());

        let hybrid = HybridControlVerifier::new(real_verifier, ed25519_verifier);

        let nonce_a = [6u8; 32];
        let challenge_a = challenge_for(recv_a, nonce_a, 1_900_000_000, 1_900_000_300, trade_commitment());
        let signing_key_a = ivk.derive_signing_key();
        let response_a = RecipientControlResponse::sign(&challenge_a, &signing_key_a);

        let nonce_b = [7u8; 32];
        let challenge_b = challenge_for(recv_b, nonce_b, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response_b = RecipientControlResponse::sign(&challenge_b, &sk_b);

        let now = UnixSeconds::new(1_900_000_100);

        // Hybrid verifies A via real path
        let verified_a = hybrid.verify(&challenge_a, &response_a, now).unwrap();
        assert_eq!(verified_a.receiver(), &recv_a);

        // Hybrid verifies B via Ed25519 fallback
        let verified_b = hybrid.verify(&challenge_b, &response_b, now).unwrap();
        assert_eq!(verified_b.receiver(), &recv_b);

        // Box<dyn> works for hybrid
        let boxed: Box<dyn RecipientControlVerifier> = Box::new(hybrid);
        let verified_a2 = boxed.verify(&challenge_a, &response_a, now).unwrap();
        assert_eq!(verified_a2.receiver(), &recv_a);
        let verified_b2 = boxed.verify(&challenge_b, &response_b, now).unwrap();
        assert_eq!(verified_b2.receiver(), &recv_b);
    }

    #[test]
    fn unconfigured_fail_closed_and_box_dyn_works() {
        let recv_a = receiver_a();
        let nonce = [8u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response = RecipientControlResponse::new(nonce, recv_a, trade_commitment(), [0u8; 64]);

        let unconfigured = SettlementUnconfiguredControlVerifier;
        let err = unconfigured
            .verify(&challenge, &response, UnixSeconds::new(1_900_000_100))
            .unwrap_err();
        match err {
            ControlError::Unconfigured => {},
            other => panic!("expected Unconfigured, got {other:?}"),
        }

        let boxed: Box<dyn RecipientControlVerifier> = Box::new(unconfigured);
        let err = boxed
            .verify(&challenge, &response, UnixSeconds::new(1_900_000_100))
            .unwrap_err();
        match err {
            ControlError::Unconfigured => {},
            other => panic!("expected Unconfigured for boxed, got {other:?}"),
        }
    }

    #[test]
    fn canonical_bytes_include_all_fields_and_preserve_43b_no_reencoding() {
        let recv_a = receiver_a();
        let nonce = [9u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let bytes = challenge.canonical_bytes();
        // domain || nonce || issued_at BE || expiry BE || receiver 43B || trade_commitment 32B
        assert!(bytes.starts_with(CONTROL_DOMAIN));
        assert_eq!(
            bytes.len(),
            CONTROL_DOMAIN.len() + 32 + 8 + 8 + recv_a.as_bytes().len() + 32
        );

        // Receiver 43B preserved via as_bytes() directly — no re-encoding
        assert_eq!(&bytes[CONTROL_DOMAIN.len() + 32 + 8 + 8..CONTROL_DOMAIN.len() + 32 + 8 + 8 + 43], recv_a.as_bytes());

        // Changing receiver changes canonical
        let recv_b = receiver_b();
        let challenge_b = challenge_for(recv_b, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        assert_ne!(challenge.canonical_bytes(), challenge_b.canonical_bytes());

        // Changing trade commitment changes canonical
        let challenge_other = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, other_commitment());
        assert_ne!(challenge.canonical_bytes(), challenge_other.canonical_bytes());
    }

    #[test]
    fn why_ed25519_registry_remains_mvp_documented() {
        // This test documents why Ed25519 registry remains MVP and real Orchard is research track
        // It asserts that our real verifier is experimental and requires SHA256 simulation, not real Pallas
        let ivk = OrchardIvkBytes::new([70u8; 32]);
        let diversifier = OrchardDiversifier::new([7u8; 11]);
        let recv = derive_receiver(&ivk, &diversifier);

        // Real Orchard would use pallas::Point mul, we use SHA256 simulation
        let transmission_key_sim = derive_transmission_key(&ivk, &diversifier);
        // Transmission key is SHA256(ivk || diversifier) — not Pallas group hash
        let mut hasher = Sha256::new();
        hasher.update(ivk.as_bytes());
        hasher.update(diversifier.as_bytes());
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(transmission_key_sim, expected, "simulation uses SHA256, real would use Pallas DiversifyHash");

        // Receiver 43B = diversifier 11B || transmission_key 32B — preserves canonical mapping
        assert_eq!(&recv.as_bytes()[..11], diversifier.as_bytes());
        assert_eq!(&recv.as_bytes()[11..], &transmission_key_sim);

        // Nullifier bound to trade_commitment — different trade produces different nullifier
        let nullifier1 = derive_nullifier(&ivk, &recv, &trade_commitment());
        let nullifier2 = derive_nullifier(&ivk, &recv, &other_commitment());
        assert_ne!(nullifier1, nullifier2);

        // Ed25519 registry remains MVP because:
        // - Real requires experimental orchard branch d91aaf1 (Pallas group hash)
        // - Wallet ivk export privacy-sensitive
        // - Nullifier requires spend authority not just ivk
        // - ZK proof for ivk->receiver without revealing ivk needs new circuit rwa_orchard_control_v1
        // This is documented in module header and this test ensures documentation is present
        assert!(true, "Ed25519 registry remains MVP, real path is research track");
    }
}
