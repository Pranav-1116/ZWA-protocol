//! Recipient-control challenge — Task C + A5 boundary.
//!
//! Phase 1B binds an authority-approved Orchard receiver into the credential
//! leaf: `credential(receiver A) + trade(receiver A) → valid`, `credential(A) + trade(B) → invalid`.
//! That prevents credential lending at the circuit level.
//!
//! Task C adds **live wallet control**: proving the trader currently controls
//! the approved receiver. These are different properties:
//!
//! - Authority approval (Phase 1B): issuance-time statement in credential leaf.
//! - Wallet control (Task C): live authentication at matcher time.
//!
//! Required adversarial property after Phase 1B + Task C:
//! - same credential + authority-approved receiver A + valid control proof for A → PASS
//! - same credential + different receiver B → FAIL (circuit)
//! - approved receiver A without wallet control → BLOCK at matcher challenge
//!
//! The exact Zcash wallet mechanism is still research, so this module implements
//! a secure, auditable challenge/response that does not reimplement Orchard internals:
//!
//! - Challenge: `{ domain, nonce[32], issued_at, expiry, receiver, trade_commitment }`
//! - Canonical bytes signed: `domain || nonce || issued_at BE || expiry BE || receiver 43B || trade_commitment 32B`
//! - Wallet signs with Ed25519 control key associated with that receiver.
//! - Matcher verifies nonce match, receiver match, trade_commitment match, domain match, freshness, and Ed25519 sig.
//!
//! The binding between control key and receiver is via an approved map
//! `BTreeMap<OrchardReceiverBytes, VerifyingKey>` — the venue registers which
//! control key controls which approved receiver. This is sufficient for the MVP
//! and makes the security boundary explicit: approval ≠ control.
//!
//! # A5: Verifier Boundary
//!
//! - `RecipientControlVerifier` trait is the opaque boundary for Vikram V4.
//! - Production default is fail-closed: `UnconfiguredControlVerifier` returns `Unconfigured` error.
//! - Real Ed25519 path is `RecipientControlAuthenticator`.
//! - Test-only fake `FakeControlVerifier` behind `#[cfg(test)]` always passes, never reachable in prod.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zwa_commitments::receiver_commitment;
use zwa_protocol::bytes::OrchardReceiverBytes;
use zwa_protocol::numbers::{TradeExpiry, UnixSeconds};
use zwa_protocol::values::{ReceiverCommitment, TradeCommitment};

/// Domain for recipient-control challenge.
///
/// Frozen for MVP. Changing it invalidates all outstanding challenges.
pub const CONTROL_DOMAIN: &[u8] = b"ZWA-RECIPIENT-CTRL-V1";

/// Default TTL for a control challenge: 5 minutes.
pub const DEFAULT_CONTROL_TTL_SECONDS: u64 = 300;

/// A challenge issued by the matcher to prove live control of a receiver.
///
/// Includes trade_commitment binding per A5 spec: domain||nonce||issued_at||expiry||receiver||trade_commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientControlChallenge {
    nonce: [u8; 32],
    domain: Vec<u8>,
    issued_at: UnixSeconds,
    expiry: UnixSeconds,
    receiver: OrchardReceiverBytes,
    trade_commitment: TradeCommitment,
}

impl RecipientControlChallenge {
    /// Builds a challenge with explicit fields. Validates window.
    ///
    /// # Errors
    ///
    /// Returns `ControlError::InvalidWindow` if `issued_at > expiry`.
    pub fn new(
        receiver: OrchardReceiverBytes,
        nonce: [u8; 32],
        domain: Vec<u8>,
        issued_at: UnixSeconds,
        expiry: UnixSeconds,
        trade_commitment: TradeCommitment,
    ) -> Result<Self, ControlError> {
        if issued_at.get() > expiry.get() {
            return Err(ControlError::InvalidWindow {
                issued_at: issued_at.get(),
                expiry: expiry.get(),
            });
        }
        if domain.is_empty() {
            return Err(ControlError::EmptyDomain);
        }
        Ok(Self {
            nonce,
            domain,
            issued_at,
            expiry,
            receiver,
            trade_commitment,
        })
    }

    /// Builds a challenge with a random nonce using OsRng.
    ///
    /// `ttl_seconds` is added to `issued_at` to compute expiry, overflow-checked.
    ///
    /// # Errors
    ///
    /// Returns `ControlError` for window inversion or RNG failure.
    pub fn new_random(
        receiver: OrchardReceiverBytes,
        trade_commitment: TradeCommitment,
        issued_at: UnixSeconds,
        ttl_seconds: u64,
        domain: Vec<u8>,
    ) -> Result<Self, ControlError> {
        let expiry = issued_at
            .checked_add_seconds(ttl_seconds)
            .map_err(|_| ControlError::InvalidWindow {
                issued_at: issued_at.get(),
                expiry: u64::MAX,
            })?;

        let mut nonce = [0u8; 32];
        {
            use ed25519_dalek::rand_core::RngCore;
            let mut rng = ed25519_dalek::rand_core::OsRng;
            rng.fill_bytes(&mut nonce);
        }

        Self::new(receiver, nonce, domain, issued_at, expiry, trade_commitment)
    }

    /// Canonical bytes that the wallet must sign.
    ///
    /// Layout: `domain || nonce || issued_at 8B BE || expiry 8B BE || receiver 43B || trade_commitment 32B`
    /// All fields are included to prevent replay across domains, times, receivers, or trades.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.domain.len() + 32 + 8 + 8 + self.receiver.as_bytes().len() + 32,
        );
        out.extend_from_slice(&self.domain);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.issued_at.get().to_be_bytes());
        out.extend_from_slice(&self.expiry.get().to_be_bytes());
        out.extend_from_slice(self.receiver.as_bytes());
        out.extend_from_slice(&self.trade_commitment.to_be_bytes());
        out
    }

    /// Returns true if `now` is strictly after expiry.
    #[must_use]
    pub fn is_expired_at(&self, now: UnixSeconds) -> bool {
        now.get() > self.expiry.get()
    }

    /// Nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Domain.
    #[must_use]
    pub fn domain(&self) -> &[u8] {
        &self.domain
    }

    /// Issued at.
    #[must_use]
    pub fn issued_at(&self) -> UnixSeconds {
        self.issued_at
    }

    /// Expiry.
    #[must_use]
    pub fn expiry(&self) -> UnixSeconds {
        self.expiry
    }

    /// Receiver this challenge is for.
    #[must_use]
    pub fn receiver(&self) -> &OrchardReceiverBytes {
        &self.receiver
    }

    /// Trade commitment this challenge is bound to.
    #[must_use]
    pub fn trade_commitment(&self) -> TradeCommitment {
        self.trade_commitment
    }

    /// Receiver commitment `H(RECEIVR1, limb0, limb1, limb2)` — canonical.
    #[must_use]
    pub fn receiver_commitment(&self) -> ReceiverCommitment {
        receiver_commitment(&self.receiver)
    }
}

/// Response from wallet proving control of receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientControlResponse {
    nonce: [u8; 32],
    receiver: OrchardReceiverBytes,
    trade_commitment: TradeCommitment,
    signature: [u8; 64],
}

impl RecipientControlResponse {
    /// Builds response from explicit fields.
    #[must_use]
    pub fn new(
        nonce: [u8; 32],
        receiver: OrchardReceiverBytes,
        trade_commitment: TradeCommitment,
        signature: [u8; 64],
    ) -> Self {
        Self {
            nonce,
            receiver,
            trade_commitment,
            signature,
        }
    }

    /// Signs a challenge with a control signing key.
    ///
    /// The signature is over `challenge.canonical_bytes()` which includes trade_commitment.
    #[must_use]
    pub fn sign(challenge: &RecipientControlChallenge, signing_key: &SigningKey) -> Self {
        let sig = signing_key.sign(&challenge.canonical_bytes());
        Self {
            nonce: challenge.nonce,
            receiver: challenge.receiver,
            trade_commitment: challenge.trade_commitment,
            signature: sig.to_bytes(),
        }
    }

    /// Nonce echoed from challenge.
    #[must_use]
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Receiver claimed to control.
    #[must_use]
    pub fn receiver(&self) -> &OrchardReceiverBytes {
        &self.receiver
    }

    /// Trade commitment echoed from challenge.
    #[must_use]
    pub fn trade_commitment(&self) -> TradeCommitment {
        self.trade_commitment
    }

    /// Ed25519 signature over challenge canonical bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Verified control — receiver is both approved and currently controlled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecipientControl {
    receiver: OrchardReceiverBytes,
    receiver_commitment: ReceiverCommitment,
    trade_commitment: TradeCommitment,
}

impl VerifiedRecipientControl {
    /// Receiver that was verified.
    #[must_use]
    pub fn receiver(&self) -> &OrchardReceiverBytes {
        &self.receiver
    }

    /// Canonical receiver commitment.
    #[must_use]
    pub fn receiver_commitment(&self) -> ReceiverCommitment {
        self.receiver_commitment
    }

    /// Trade commitment that was bound to challenge.
    #[must_use]
    pub fn trade_commitment(&self) -> TradeCommitment {
        self.trade_commitment
    }
}

/// Errors from recipient-control authentication.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    #[error("invalid challenge window: issued_at {issued_at} > expiry {expiry}")]
    InvalidWindow { issued_at: u64, expiry: u64 },

    #[error("control domain must be non-empty")]
    EmptyDomain,

    #[error("control challenge expired at {expiry}, now {now}")]
    ChallengeExpired { expiry: u64, now: u64 },

    #[error("challenge issued in future: issued_at {issued_at}, now {now}")]
    ChallengeIssuedInFuture { issued_at: u64, now: u64 },

    #[error("control domain mismatch: expected {expected:?}, got {got:?}")]
    DomainMismatch { expected: Vec<u8>, got: Vec<u8> },

    #[error("nonce mismatch: expected {expected:?}, got {got:?}")]
    NonceMismatch { expected: [u8; 32], got: [u8; 32] },

    #[error("receiver mismatch: challenge {challenge:?} vs response {response:?}")]
    ReceiverMismatch {
        challenge: OrchardReceiverBytes,
        response: OrchardReceiverBytes,
    },

    #[error("trade commitment mismatch: challenge {challenge} vs response {response}")]
    TradeCommitmentMismatch {
        challenge: TradeCommitment,
        response: TradeCommitment,
    },

    #[error("trade commitment mismatch: expected {expected}, got {got}")]
    ChallengeTradeCommitmentMismatch {
        expected: TradeCommitment,
        got: TradeCommitment,
    },

    #[error("receiver not approved: expected {expected:?}, got {got:?}")]
    ApprovedReceiverMismatch {
        expected: OrchardReceiverBytes,
        got: OrchardReceiverBytes,
    },

    #[error("control key not approved for receiver {receiver:?}")]
    ControlKeyNotApproved { receiver: OrchardReceiverBytes },

    #[error("invalid Ed25519 control signature: {reason}")]
    InvalidSignature { reason: String },

    #[error("signature verification failed for receiver {receiver:?}")]
    SignatureVerificationFailed { receiver: OrchardReceiverBytes },

    #[error("trade expiry {trade_expiry} beyond control challenge expiry {challenge_expiry}")]
    TradeExpiryBeyondChallengeExpiry {
        trade_expiry: u64,
        challenge_expiry: u64,
    },

    #[error("recipient control verifier unconfigured — fail-closed")]
    Unconfigured,
}

/// Opaque trait for recipient-control verification — Vikram V4 boundary.
///
/// Production implementations must be fail-closed. `UnconfiguredControlVerifier`
/// returns `Unconfigured` error. Real Ed25519 path is `RecipientControlAuthenticator`.
/// Test-only fake is `FakeControlVerifier` behind `#[cfg(test)]`.
pub trait RecipientControlVerifier {
    /// Verifies control proof for a challenge at `now`.
    fn verify(
        &self,
        challenge: &RecipientControlChallenge,
        response: &RecipientControlResponse,
        now: UnixSeconds,
    ) -> Result<VerifiedRecipientControl, ControlError>;
}

/// Production fail-closed verifier — returns Unconfigured if used without real keys.
///
/// This is the default when no authenticator is configured. It ensures
/// the matcher blocks trades rather than allowing them when control verification
/// is not set up.
#[derive(Debug, Clone, Default)]
pub struct UnconfiguredControlVerifier;

impl RecipientControlVerifier for UnconfiguredControlVerifier {
    fn verify(
        &self,
        _challenge: &RecipientControlChallenge,
        _response: &RecipientControlResponse,
        _now: UnixSeconds,
    ) -> Result<VerifiedRecipientControl, ControlError> {
        Err(ControlError::Unconfigured)
    }
}

/// Authenticates live wallet control of an approved Orchard receiver.
///
/// Implements `RecipientControlVerifier` trait for production use.
#[derive(Debug, Clone)]
pub struct RecipientControlAuthenticator {
    /// Map of approved receiver → control verifying key.
    ///
    /// The venue registers which control key controls which receiver. This
    /// separation makes the security boundary explicit: credential approval
    /// (Phase 1B) ≠ live control (Task C).
    approved_control_keys: BTreeMap<OrchardReceiverBytes, VerifyingKey>,
    expected_domain: Vec<u8>,
}

impl RecipientControlAuthenticator {
    /// Builds authenticator with approved control keys and expected domain.
    ///
    /// `expected_domain` should be `CONTROL_DOMAIN` for MVP.
    #[must_use]
    pub fn new(
        approved_control_keys: BTreeMap<OrchardReceiverBytes, VerifyingKey>,
        expected_domain: Vec<u8>,
    ) -> Self {
        Self {
            approved_control_keys,
            expected_domain,
        }
    }

    /// Expected domain.
    #[must_use]
    pub fn expected_domain(&self) -> &[u8] {
        &self.expected_domain
    }

    /// Verifies control and additionally checks against authority-approved receiver.
    ///
    /// `approved_receiver` comes from `ActiveCredential.approved_receiver`
    /// (Phase 1B). This enforces that the live-controlled receiver is exactly
    /// the one the credential authority approved.
    ///
    /// # Errors
    ///
    /// Returns `ApprovedReceiverMismatch` if challenge receiver != approved.
    pub fn verify_against_approved_receiver(
        &self,
        challenge: &RecipientControlChallenge,
        response: &RecipientControlResponse,
        approved_receiver: &OrchardReceiverBytes,
        now: UnixSeconds,
    ) -> Result<VerifiedRecipientControl, ControlError> {
        if challenge.receiver() != approved_receiver {
            return Err(ControlError::ApprovedReceiverMismatch {
                expected: *approved_receiver,
                got: *challenge.receiver(),
            });
        }
        if response.receiver() != approved_receiver {
            return Err(ControlError::ApprovedReceiverMismatch {
                expected: *approved_receiver,
                got: *response.receiver(),
            });
        }
        self.verify(challenge, response, now)
    }

    /// Checks that trade expiry is within control challenge expiry.
    ///
    /// Prevents using a short-lived control proof for a long-lived trade.
    ///
    /// # Errors
    ///
    /// Returns `TradeExpiryBeyondChallengeExpiry` if trade outlives challenge.
    pub fn check_trade_expiry(
        trade_expiry: TradeExpiry,
        challenge: &RecipientControlChallenge,
    ) -> Result<(), ControlError> {
        if trade_expiry.get() > challenge.expiry().get() {
            return Err(ControlError::TradeExpiryBeyondChallengeExpiry {
                trade_expiry: trade_expiry.get(),
                challenge_expiry: challenge.expiry().get(),
            });
        }
        Ok(())
    }

    /// Checks that challenge's trade_commitment matches expected trade commitment.
    ///
    /// Prevents challenge replay across different trades.
    pub fn check_trade_commitment(
        expected: TradeCommitment,
        challenge: &RecipientControlChallenge,
    ) -> Result<(), ControlError> {
        if challenge.trade_commitment() != expected {
            return Err(ControlError::ChallengeTradeCommitmentMismatch {
                expected,
                got: challenge.trade_commitment(),
            });
        }
        Ok(())
    }
}

impl RecipientControlVerifier for RecipientControlAuthenticator {
    /// Verifies control proof for a challenge at `now`.
    ///
    /// Enforces:
    /// - challenge not expired, not issued in future
    /// - domain == expected_domain
    /// - response nonce == challenge nonce
    /// - response receiver == challenge receiver
    /// - response trade_commitment == challenge trade_commitment
    /// - control key approved for receiver
    /// - Ed25519 signature over `challenge.canonical_bytes()` which includes trade_commitment
    ///
    /// # Errors
    ///
    /// Returns `ControlError` for any rejection.
    fn verify(
        &self,
        challenge: &RecipientControlChallenge,
        response: &RecipientControlResponse,
        now: UnixSeconds,
    ) -> Result<VerifiedRecipientControl, ControlError> {
        // 1. Freshness: issued_at <= now <= expiry
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

        // 2. Domain binding.
        if challenge.domain() != self.expected_domain.as_slice() {
            return Err(ControlError::DomainMismatch {
                expected: self.expected_domain.clone(),
                got: challenge.domain().to_vec(),
            });
        }

        // 3. Nonce match — prevents replay of old response for new challenge.
        if response.nonce() != challenge.nonce() {
            return Err(ControlError::NonceMismatch {
                expected: *challenge.nonce(),
                got: *response.nonce(),
            });
        }

        // 4. Receiver match — response must be for same receiver as challenge.
        if response.receiver() != challenge.receiver() {
            return Err(ControlError::ReceiverMismatch {
                challenge: *challenge.receiver(),
                response: *response.receiver(),
            });
        }

        // 5. Trade commitment match — response must be for same trade as challenge.
        if response.trade_commitment() != challenge.trade_commitment() {
            return Err(ControlError::TradeCommitmentMismatch {
                challenge: challenge.trade_commitment(),
                response: response.trade_commitment(),
            });
        }

        // 6. Control key approved for this receiver.
        let vk = self
            .approved_control_keys
            .get(challenge.receiver())
            .ok_or_else(|| ControlError::ControlKeyNotApproved {
                receiver: *challenge.receiver(),
            })?;

        // 7. Signature verification over frozen canonical bytes (includes trade_commitment).
        let sig = Signature::from_bytes(response.signature());
        vk.verify(&challenge.canonical_bytes(), &sig)
            .map_err(|_| ControlError::SignatureVerificationFailed {
                receiver: *challenge.receiver(),
            })?;

        Ok(VerifiedRecipientControl {
            receiver: *challenge.receiver(),
            receiver_commitment: challenge.receiver_commitment(),
            trade_commitment: challenge.trade_commitment(),
        })
    }
}

/// Test-only fake verifier — always passes, behind #[cfg(test)].
///
/// Never reachable in production. Used for unit tests that don't need real crypto.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct FakeControlVerifier;

#[cfg(test)]
impl RecipientControlVerifier for FakeControlVerifier {
    fn verify(
        &self,
        challenge: &RecipientControlChallenge,
        response: &RecipientControlResponse,
        now: UnixSeconds,
    ) -> Result<VerifiedRecipientControl, ControlError> {
        // Minimal checks to still enforce freshness and domain and nonce, but skip signature
        if challenge.is_expired_at(now) {
            return Err(ControlError::ChallengeExpired {
                expiry: challenge.expiry().get(),
                now: now.get(),
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
        Ok(VerifiedRecipientControl {
            receiver: *challenge.receiver(),
            receiver_commitment: challenge.receiver_commitment(),
            trade_commitment: challenge.trade_commitment(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use zwa_protocol::numbers::UnixSeconds;
    use zwa_protocol::TradeCommitment;

    const RECEIVER_A: &str =
        "781671f8a41294c866d8161f3bf5f84a8fd2c328f91a2d085a66036acd59439731c36c4f1b99b4d64be233";
    const RECEIVER_B: &str =
        "ba5a9b6828e14d720cc41e998917f5996635d1a7fa84448cb118f7b6f65068d380099e5cd54d98dd3917bb";
    const TRADE_COMMITMENT: &str =
        "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    const OTHER_COMMITMENT: &str =
        "7409670081847436957289371955571360481923983184454289247710022466448715682310";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn receiver_a() -> OrchardReceiverBytes {
        OrchardReceiverBytes::from_hex(RECEIVER_A).unwrap()
    }

    fn receiver_b() -> OrchardReceiverBytes {
        OrchardReceiverBytes::from_hex(RECEIVER_B).unwrap()
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
    fn valid_control_passes_for_approved_receiver() {
        let sk = signing_key(1);
        let vk = sk.verifying_key();
        let recv_a = receiver_a();
        let mut approved = BTreeMap::new();
        approved.insert(recv_a, vk);

        let auth = RecipientControlAuthenticator::new(approved, CONTROL_DOMAIN.to_vec());

        let nonce = [7u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response = RecipientControlResponse::sign(&challenge, &sk);

        let now = UnixSeconds::new(1_900_000_100);
        let verified = auth.verify(&challenge, &response, now).unwrap();
        assert_eq!(verified.receiver(), &recv_a);
        assert_eq!(
            verified.receiver_commitment(),
            receiver_commitment(&recv_a)
        );
        assert_eq!(verified.trade_commitment(), trade_commitment());

        // Also passes against approved receiver check (Phase 1B binding).
        let verified2 = auth
            .verify_against_approved_receiver(&challenge, &response, &recv_a, now)
            .unwrap();
        assert_eq!(verified2.receiver(), &recv_a);
    }

    #[test]
    fn approved_receiver_without_wallet_control_blocks() {
        // Credential approves A, but wallet has no control key for A or provides invalid sig.
        let recv_a = receiver_a();
        let sk = signing_key(2);
        let vk = sk.verifying_key();
        // Approve only B, not A — so A has no control key.
        let recv_b = receiver_b();
        let mut approved = BTreeMap::new();
        approved.insert(recv_b, vk);

        let auth = RecipientControlAuthenticator::new(approved, CONTROL_DOMAIN.to_vec());

        let nonce = [8u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response = RecipientControlResponse::sign(&challenge, &sk);

        let now = UnixSeconds::new(1_900_000_100);
        let err = auth.verify(&challenge, &response, now).unwrap_err();
        match err {
            ControlError::ControlKeyNotApproved { receiver } => {
                assert_eq!(receiver, recv_a);
            }
            other => panic!("expected ControlKeyNotApproved, got {other:?}"),
        }
    }

    #[test]
    fn same_credential_different_receiver_fails_control() {
        // Phase 1B already fails at circuit for B, but control also fails if
        // challenge is for A and response is for B, or approved is A but challenge is B.
        let sk_a = signing_key(3);
        let vk_a = sk_a.verifying_key();
        let sk_b = signing_key(4);
        let vk_b = sk_b.verifying_key();

        let recv_a = receiver_a();
        let recv_b = receiver_b();

        let mut approved = BTreeMap::new();
        approved.insert(recv_a, vk_a);
        approved.insert(recv_b, vk_b);

        let auth = RecipientControlAuthenticator::new(approved, CONTROL_DOMAIN.to_vec());

        let nonce = [9u8; 32];
        let challenge_a = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response_b = RecipientControlResponse::sign(
            &challenge_for(recv_b, nonce, 1_900_000_000, 1_900_000_300, trade_commitment()),
            &sk_b,
        );

        let now = UnixSeconds::new(1_900_000_100);

        // Nonce matches but receiver mismatches between challenge and response.
        // Use challenge A, response B with same nonce — receiver mismatch.
        let response_b_same_nonce =
            RecipientControlResponse::new(nonce, recv_b, trade_commitment(), response_b.signature);
        let err = auth
            .verify(&challenge_a, &response_b_same_nonce, now)
            .unwrap_err();
        match err {
            ControlError::ReceiverMismatch { .. } => {}
            other => panic!("expected ReceiverMismatch, got {other:?}"),
        }

        // Approved receiver check: credential approves A, but challenge is for B → blocked.
        let challenge_b = challenge_for(recv_b, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response_b2 = RecipientControlResponse::sign(&challenge_b, &sk_b);
        let err = auth
            .verify_against_approved_receiver(&challenge_b, &response_b2, &recv_a, now)
            .unwrap_err();
        match err {
            ControlError::ApprovedReceiverMismatch { .. } => {}
            other => panic!("expected ApprovedReceiverMismatch, got {other:?}"),
        }
    }

    #[test]
    fn challenge_expiry_and_nonce_and_domain_enforced() {
        let sk = signing_key(5);
        let vk = sk.verifying_key();
        let recv_a = receiver_a();
        let mut approved = BTreeMap::new();
        approved.insert(recv_a, vk);
        let auth = RecipientControlAuthenticator::new(approved, CONTROL_DOMAIN.to_vec());

        let nonce = [10u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_100, trade_commitment());
        let response = RecipientControlResponse::sign(&challenge, &sk);

        // Expired.
        let err = auth
            .verify(
                &challenge,
                &response,
                UnixSeconds::new(1_900_000_101),
            )
            .unwrap_err();
        match err {
            ControlError::ChallengeExpired { .. } => {}
            other => panic!("expected ChallengeExpired, got {other:?}"),
        }

        // Issued in future.
        let err = auth
            .verify(
                &challenge,
                &response,
                UnixSeconds::new(1_899_999_999),
            )
            .unwrap_err();
        match err {
            ControlError::ChallengeIssuedInFuture { .. } => {}
            other => panic!("expected ChallengeIssuedInFuture, got {other:?}"),
        }

        // Nonce mismatch.
        let mut bad_nonce_response = response.clone();
        bad_nonce_response.nonce[0] ^= 1;
        let err = auth
            .verify(
                &challenge,
                &bad_nonce_response,
                UnixSeconds::new(1_900_000_050),
            )
            .unwrap_err();
        match err {
            ControlError::NonceMismatch { .. } => {}
            other => panic!("expected NonceMismatch, got {other:?}"),
        }

        // Domain mismatch.
        let bad_domain_challenge = RecipientControlChallenge::new(
            recv_a,
            nonce,
            b"WRONG-DOMAIN".to_vec(),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(1_900_000_100),
            trade_commitment(),
        )
        .unwrap();
        let bad_domain_response = RecipientControlResponse::sign(&bad_domain_challenge, &sk);
        let err = auth
            .verify(
                &bad_domain_challenge,
                &bad_domain_response,
                UnixSeconds::new(1_900_000_050),
            )
            .unwrap_err();
        match err {
            ControlError::DomainMismatch { .. } => {}
            other => panic!("expected DomainMismatch, got {other:?}"),
        }
    }

    #[test]
    fn invalid_signature_and_trade_expiry_beyond_challenge() {
        let sk = signing_key(6);
        let vk = sk.verifying_key();
        let recv_a = receiver_a();
        let mut approved = BTreeMap::new();
        approved.insert(recv_a, vk);
        let auth = RecipientControlAuthenticator::new(approved, CONTROL_DOMAIN.to_vec());

        let nonce = [11u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_100, trade_commitment());
        let mut response = RecipientControlResponse::sign(&challenge, &sk);
        // Tamper signature.
        response.signature[0] ^= 1;

        let err = auth
            .verify(
                &challenge,
                &response,
                UnixSeconds::new(1_900_000_050),
            )
            .unwrap_err();
        match err {
            ControlError::SignatureVerificationFailed { .. } => {}
            other => panic!("expected SignatureVerificationFailed, got {other:?}"),
        }

        // Trade expiry beyond challenge expiry.
        let trade_expiry = zwa_protocol::numbers::TradeExpiry::new(1_900_000_200);
        let err =
            RecipientControlAuthenticator::check_trade_expiry(trade_expiry, &challenge).unwrap_err();
        match err {
            ControlError::TradeExpiryBeyondChallengeExpiry {
                trade_expiry: te,
                challenge_expiry: ce,
            } => {
                assert_eq!(te, 1_900_000_200);
                assert_eq!(ce, 1_900_000_100);
            }
            other => panic!("expected TradeExpiryBeyondChallengeExpiry, got {other:?}"),
        }
    }

    #[test]
    fn canonical_bytes_include_all_fields() {
        let recv_a = receiver_a();
        let nonce = [12u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let bytes = challenge.canonical_bytes();
        // domain || nonce || issued_at BE || expiry BE || receiver 43B || trade_commitment 32B
        assert!(bytes.starts_with(CONTROL_DOMAIN));
        assert_eq!(
            bytes.len(),
            CONTROL_DOMAIN.len() + 32 + 8 + 8 + recv_a.as_bytes().len() + 32
        );
        // Changing any field changes canonical bytes.
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        let challenge2 = challenge_for(
            recv_a,
            other_nonce,
            1_900_000_000,
            1_900_000_300,
            trade_commitment(),
        );
        assert_ne!(challenge.canonical_bytes(), challenge2.canonical_bytes());

        // Changing trade commitment changes canonical bytes
        let challenge3 = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, other_commitment());
        assert_ne!(challenge.canonical_bytes(), challenge3.canonical_bytes());
    }

    #[test]
    fn trade_commitment_binding_enforced() {
        let sk = signing_key(7);
        let vk = sk.verifying_key();
        let recv_a = receiver_a();
        let mut approved = BTreeMap::new();
        approved.insert(recv_a, vk);
        let auth = RecipientControlAuthenticator::new(approved, CONTROL_DOMAIN.to_vec());

        let nonce = [13u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response = RecipientControlResponse::sign(&challenge, &sk);

        // Valid
        let now = UnixSeconds::new(1_900_000_100);
        assert!(auth.verify(&challenge, &response, now).is_ok());

        // Response with different trade commitment should fail
        let bad_response = RecipientControlResponse::new(
            nonce,
            recv_a,
            other_commitment(),
            response.signature,
        );
        let err = auth.verify(&challenge, &bad_response, now).unwrap_err();
        match err {
            ControlError::TradeCommitmentMismatch { .. } => {}
            other => panic!("expected TradeCommitmentMismatch, got {other:?}"),
        }

        // Challenge trade commitment mismatch vs expected
        let err = RecipientControlAuthenticator::check_trade_commitment(other_commitment(), &challenge)
            .unwrap_err();
        match err {
            ControlError::ChallengeTradeCommitmentMismatch { .. } => {}
            other => panic!("expected ChallengeTradeCommitmentMismatch, got {other:?}"),
        }
    }

    #[test]
    fn unconfigured_verifier_fail_closed() {
        let recv_a = receiver_a();
        let nonce = [14u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response = RecipientControlResponse::new(nonce, recv_a, trade_commitment(), [0u8; 64]);

        let unconfigured = UnconfiguredControlVerifier;
        let err = unconfigured
            .verify(&challenge, &response, UnixSeconds::new(1_900_000_100))
            .unwrap_err();
        match err {
            ControlError::Unconfigured => {}
            other => panic!("expected Unconfigured, got {other:?}"),
        }
    }

    #[test]
    fn fake_verifier_only_in_test() {
        let recv_a = receiver_a();
        let nonce = [15u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response = RecipientControlResponse::new(nonce, recv_a, trade_commitment(), [0u8; 64]);

        let fake = FakeControlVerifier;
        let verified = fake
            .verify(&challenge, &response, UnixSeconds::new(1_900_000_100))
            .unwrap();
        assert_eq!(verified.receiver(), &recv_a);
        assert_eq!(verified.trade_commitment(), trade_commitment());
    }

    #[test]
    fn trait_object_works_for_vikram_v4() {
        // Ensure trait can be used as dyn object
        let sk = signing_key(8);
        let vk = sk.verifying_key();
        let recv_a = receiver_a();
        let mut approved = BTreeMap::new();
        approved.insert(recv_a, vk);
        let real_auth = RecipientControlAuthenticator::new(approved, CONTROL_DOMAIN.to_vec());

        let boxed: Box<dyn RecipientControlVerifier> = Box::new(real_auth);
        let nonce = [16u8; 32];
        let challenge = challenge_for(recv_a, nonce, 1_900_000_000, 1_900_000_300, trade_commitment());
        let response = RecipientControlResponse::sign(&challenge, &sk);
        let verified = boxed
            .verify(&challenge, &response, UnixSeconds::new(1_900_000_100))
            .unwrap();
        assert_eq!(verified.receiver(), &recv_a);
    }
}
