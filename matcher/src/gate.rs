//! 10-step deterministic matcher gate — Task F + A7 complete.
//!
//! Combines Tasks A-E into a single **fail-closed** allow/block decision per handbook Sec 15.
//! Cheap checks happen before expensive proof verification.
//!
//! # Exact order and why each gate exists (Sec 23 threat model)
//!
//! 1. **Parse canonical TradeIntent + TradeCommitmentV1** (already typed)
//!    Why: Prevents ticker/symbol confusion — canonical 32B AssetBase (Pallas compressed) + 43B Orchard receiver are only representations. No display metadata.
//!    Prevents: Fake RWA with convincing name.
//!
//! 2. **Verify intent/commitment correspondence → CheckedTrade (Task A, ZWA-REL-001)**
//!    Why: `ReplayStore::create(commitment, intent)` stores without recomputing. Pairing real commitment with different intent would make expiry enforcement use wrong intent.
//!    Prevents: Intent substitution (amount, fee, recipient, policy, nonce, expiry mutation), expiry bypass. Makes mismatched pair structurally impossible to reach replay/proofs.
//!    Output: `CheckedTrade` opaque witness, only constructor calls `verify_trade_commitment`.
//!
//! 3. **Authenticate issuer + credential root signatures vs approved keyset (Task B)**
//!    Why: Roots are public inputs to circuits, but authenticity is not proven inside circuits. Matcher must verify Ed25519 over frozen canonical payload `"ZWA1ROOT" | kind | version BE | valid_from BE | expires_at BE | id_len | id | root 32B`.
//!    Prevents: Forged/stale issuer root, forged credential root, wrong authority, signature malleability (Ed25519 deterministic, non-malleable 64B).
//!
//! 4. **Require current version, freshness, trade_expiry ≤ root_expiry, combined min (Task B)**
//!    Why: Version 0 invalid, only current version accepted (supersession — stale-but-signed rejected), `window.contains(now)` freshness, trade must not outlive roots.
//!    Prevents: Stale/superseded root replay, not-yet-valid root, trade expiry beyond root expiry, revocation latency abuse. Combined `trade_expiry ≤ min(issuer_expiry, credential_expiry)` ensures trade valid through earliest root.
//!    Output: `AuthenticatedIssuerRoot`, `AuthenticatedCredentialRoot` private envelope, cannot be fabricated.
//!
//! 5. **Bind the approved receiver to the trade, then verify live wallet control (F-02, Task C + A5)**
//!    Why: the raw `approved_receiver` is caller-supplied. The gate recomputes `H(RCPBIND1, subject, H(RECEIVR1, approved_receiver))` with frozen `zwa-commitments` and requires it to equal `intent.recipient_commitment`. Phase1B eligibility (step 7) binds that same recipient commitment to the credential leaf's receiver, and control is verified for exactly `approved_receiver`. So trade, credential and controlled wallet name one receiver.
//!    Prevents: proof for receiver A + control of receiver B, credential secret lent to another wallet, challenge replay across domains/times/receivers/trades, expired challenge reuse.
//!    Output: `VerifiedRecipientControl` whose receiver commitment equals the bound receiver commitment.
//!
//! 6. **Verify provenance proof vs authorizedIssuanceRoot + checked commitment (Task D + A4)**
//!    Public inputs order frozen `[root, commitment]`. Malformed proofs always reject (F-01).
//!
//! 7. **Verify eligibility Phase1B proof vs activeCredentialRoot + same commitment (Task D + A4)**
//!    Same checked commitment as step 6 (anti-splicing). VK identity pinned by hash.
//!
//! 8. **Only now write replay state (F-07): create if absent → `VERIFIED` → `SETTLEMENT_CONSTRUCTED`**
//!    Each write is a compare-and-swap on the authoritative store (F-05/F-06). A failed check in steps 1–7 leaves replay state untouched (no record, or the prior `CREATED`/`VERIFIED`). Right after step 2, a read-only precheck rejects `FAILED` (explicit `retry_after_failure` with txid acknowledgement required, then full re-verification), `CONSUMED`/`EXPIRED` (terminal) and active settlement states (replay). An expired trade (`now > expiry`; `now == expiry` is valid) moves an existing `CREATED`/`VERIFIED` record to `EXPIRED` and never creates one.
//!
//! 9. *(merged into 8)* The construction lock is the last CAS; only one concurrent caller wins.
//!
//! 10. **Return VerifiedTrade / MatcherApproval to settlement adapter (Phase 3 later)**
//!     Why: Opaque, non-serializable approval that can only be obtained via `evaluate()`. Holds checked trade, authenticated roots, verified control.
//!     Proves: All 9 gates passed. Does NOT prove: non-custodial settlement (Phase 3 independent seller/buyer auth), wallet spending-key control beyond control challenge, global compliance enforcement, production ZSA mainnet, recursive lineage.
//!
//! The matcher must not fork commitment logic, byte encodings, root serialization,
//! or replay semantics. Phase 1 remains single source of truth.

use zwa_credentials::{CredentialRootEnvelope, IssuerRootEnvelope};
use zwa_protocol::bytes::OrchardReceiverBytes;
use zwa_protocol::numbers::UnixSeconds;
use zwa_protocol::proof::{EligibilityVerifier, OpaqueProof, ProvenanceVerifier, VerificationResult};
use zwa_protocol::{SubjectCommitment, TradeCommitment, TradeIntent};

use crate::checked::CheckedTrade;
use crate::control::{ControlError, RecipientControlAuthenticator, RecipientControlChallenge, RecipientControlResponse, VerifiedRecipientControl};
use crate::replay::{PersistentReplayStore, ReplayError, ReplayPersistence};
use crate::roots::{
    check_combined_root_expiry, AuthenticatedCredentialRoot, AuthenticatedIssuerRoot,
    CredentialRootAuthenticator, IssuerRootAuthenticator, RootAuthError,
};
use crate::verifiers::{verify_trade_proofs, EligibilityVerifierBackend, ProvenanceVerifierBackend};

/// Typed rejection reasons for deterministic allow/block decision.
///
/// Every failure path is a distinct variant — no untyped strings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GateRejection {
    #[error("commitment mismatch: expected {expected}, actual {actual}")]
    CommitmentMismatch { expected: String, actual: String },

    #[error("root authentication failed: {0}")]
    RootAuth(#[from] RootAuthError),

    #[error("recipient control failed: {0}")]
    Control(#[from] ControlError),

    #[error("replay error: {0}")]
    Replay(#[from] ReplayError),

    #[error("trade expired at {expiry}, now {now}")]
    ExpiredTrade { expiry: u64, now: u64 },

    #[error("proof invalid: {0:?}")]
    ProofInvalid(VerificationResult),

    #[error("trade already consumed")]
    AlreadyConsumed,

    #[error("trade already expired")]
    AlreadyExpired,

    /// The trade is `FAILED`. The gate never retries on its own: the operator
    /// must call `PersistentReplayStore::retry_after_failure` with the exact
    /// prior txid acknowledgement, after which the trade is `CREATED` and must
    /// pass the full gate again.
    #[error("trade failed; explicit retry_after_failure (with txid acknowledgement) required")]
    RetryRequired,

    #[error("trade in illegal state for verification: {state:?}")]
    IllegalState { state: String },

    /// F-02: `H(RCPBIND1, subject, H(RECEIVR1, approved_receiver))` does not
    /// equal the trade's `recipient_commitment`, so the receiver whose control
    /// was presented is not the receiver the trade (and therefore the
    /// eligibility credential) is bound to.
    #[error("recipient binding mismatch: approved receiver is not the trade's committed recipient")]
    RecipientBindingMismatch,

    #[error("approved receiver mismatch: expected {expected:?}, got {got:?}")]
    ApprovedReceiverMismatch {
        expected: OrchardReceiverBytes,
        got: OrchardReceiverBytes,
    },
}

/// A trade that has passed the full matcher gate and is ready for settlement construction.
///
/// This is the `MatcherApproval` from spec A7 — **opaque and non-serializable**:
///
/// - Fields are private, no `Clone`, no `Serialize`, no public constructor outside `gate` module.
/// - Contains a private `_private: ()` marker so external crates cannot use struct literal syntax.
/// - `Debug` is implemented but does not expose secrets; `Display` is not implemented.
/// - Can only be obtained via `MatcherGate::evaluate()` after all 10 gates pass.
///
/// # What it proves
///
/// - Intent/commitment correspondence verified (Task A, ZWA-REL-001)
/// - Issuer root signature valid under approved key, current version, fresh, trade_expiry ≤ root_expiry (Task B)
/// - Credential root signature valid, current, fresh, trade_expiry ≤ root_expiry, combined min enforced (Task B)
/// - Live wallet control of authority-approved receiver (Task C, Phase1B + live control)
/// - Replay state allowed verification, now verified (Task E)
/// - Provenance proof valid for `authorizedIssuanceRoot` + exact `tradeCommitment` (Task D)
/// - Eligibility proof valid for `activeCredentialRoot` + same `tradeCommitment` (Task D)
/// - Settlement construction acquired (compare-and-set, only one winner)
///
/// # What it does NOT prove (per Sec 6, 24, 30)
///
/// - Not non-custodial settlement — seller/buyer independent authorization is Phase 3
/// - Not wallet spending-key control beyond Ed25519 control challenge (real Orchard ivk proof is research)
/// - Not global compliance enforcement — matcher is MVP compliance boundary, Zcash consensus does not enforce investor policy
/// - Not production ZSA mainnet — ZSA settlement is experimental QEDIT stack
/// - Not recursive lineage — optional research track
#[derive(Debug)]
pub struct VerifiedTrade {
    checked_trade: CheckedTrade,
    authenticated_issuer_root: AuthenticatedIssuerRoot,
    authenticated_credential_root: AuthenticatedCredentialRoot,
    verified_control: VerifiedRecipientControl,
    // Private marker prevents external construction and makes type opaque.
    // Also makes it !Clone and !Serialize by not deriving those traits.
    _private: (),
}

impl VerifiedTrade {
    /// Canonical checked trade that was approved.
    #[must_use]
    pub fn checked_trade(&self) -> &CheckedTrade {
        &self.checked_trade
    }

    /// Authenticated issuer root that was used.
    #[must_use]
    pub fn authenticated_issuer_root(&self) -> &AuthenticatedIssuerRoot {
        &self.authenticated_issuer_root
    }

    /// Authenticated credential root that was used.
    #[must_use]
    pub fn authenticated_credential_root(&self) -> &AuthenticatedCredentialRoot {
        &self.authenticated_credential_root
    }

    /// Verified live control of approved receiver.
    #[must_use]
    pub fn verified_control(&self) -> &VerifiedRecipientControl {
        &self.verified_control
    }

    /// Commitment that was approved — convenience getter for settlement adapter.
    #[must_use]
    pub fn commitment(&self) -> zwa_protocol::TradeCommitment {
        self.checked_trade.commitment()
    }

    /// Intent that was approved.
    #[must_use]
    pub fn intent(&self) -> zwa_protocol::TradeIntent {
        self.checked_trade.intent()
    }
}

/// Type alias for spec A7 — `MatcherApproval` is opaque non-serializable approval.
pub type MatcherApproval = VerifiedTrade;

/// Inputs for gate evaluation — bundles all data the matcher needs.
#[derive(Debug, Clone)]
pub struct GateInput {
    /// Canonical trade intent.
    pub intent: TradeIntent,
    /// Presented trade commitment.
    pub commitment: TradeCommitment,
    /// Issuer root envelope (signed).
    pub issuer_envelope: IssuerRootEnvelope,
    /// Credential root envelope (signed).
    pub credential_envelope: CredentialRootEnvelope,
    /// Raw 43-byte Orchard receiver the trader claims the authority approved.
    ///
    /// Untrusted on its own. The gate accepts it only if, together with
    /// `recipient_subject_commitment`, it re-derives the trade's
    /// `recipient_commitment` (F-02); see [`MatcherGate::evaluate`].
    pub approved_receiver: OrchardReceiverBytes,
    /// Phase 0G opening of `intent.recipient_commitment`: the credential
    /// subject commitment `H(SUBJECT1, subjectSecret)`.
    ///
    /// Needed because the frozen recipient commitment is
    /// `H(RCPBIND1, SubjectCommitment, ReceiverCommitment)`; the matcher cannot
    /// tie a raw receiver to it without this value. It is a hash of the secret,
    /// never the secret itself. Privacy note: it is stable per credential
    /// subject, so a matcher can link trades of the same subject.
    pub recipient_subject_commitment: SubjectCommitment,
    /// Control challenge issued by matcher.
    pub control_challenge: RecipientControlChallenge,
    /// Control response from wallet.
    pub control_response: RecipientControlResponse,
    /// Provenance proof (OpaqueProof).
    pub provenance_proof: OpaqueProof,
    /// Eligibility proof (OpaqueProof).
    pub eligibility_proof: OpaqueProof,
    /// Current time for freshness/expiry checks.
    pub now: UnixSeconds,
}

/// Matcher gate — deterministic allow/block decision combining A-E.
///
/// Holds all authenticators, verifiers, and persistent replay store.
///
/// # Proof verifiers
///
/// `PV` / `EV` default to the real Groth16 backends. They are type parameters
/// only so that tests can inject explicit fakes through the frozen
/// [`ProvenanceVerifier`] / [`EligibilityVerifier`] traits; no cargo feature
/// switches verification behaviour (M2 remediation F-01).
pub struct MatcherGate<
    P: ReplayPersistence,
    PV = ProvenanceVerifierBackend,
    EV = EligibilityVerifierBackend,
> {
    issuer_authenticator: IssuerRootAuthenticator,
    credential_authenticator: CredentialRootAuthenticator,
    control_authenticator: RecipientControlAuthenticator,
    provenance_verifier: PV,
    eligibility_verifier: EV,
    replay_store: PersistentReplayStore<P>,
}

impl<P: ReplayPersistence, PV, EV> std::fmt::Debug for MatcherGate<P, PV, EV> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatcherGate").finish_non_exhaustive()
    }
}

impl<P, PV, EV> MatcherGate<P, PV, EV>
where
    P: ReplayPersistence,
    PV: ProvenanceVerifier,
    EV: EligibilityVerifier,
{
    /// Builds gate with all components.
    #[must_use]
    pub fn new(
        issuer_authenticator: IssuerRootAuthenticator,
        credential_authenticator: CredentialRootAuthenticator,
        control_authenticator: RecipientControlAuthenticator,
        provenance_verifier: PV,
        eligibility_verifier: EV,
        replay_store: PersistentReplayStore<P>,
    ) -> Self {
        Self {
            issuer_authenticator,
            credential_authenticator,
            control_authenticator,
            provenance_verifier,
            eligibility_verifier,
            replay_store,
        }
    }

    /// Returns replay store reference (for inspection).
    #[must_use]
    pub fn replay_store(&self) -> &PersistentReplayStore<P> {
        &self.replay_store
    }

    /// Evaluates a trade through the full gate.
    ///
    /// Returns an opaque [`VerifiedTrade`] on ALLOW, a typed [`GateRejection`]
    /// on BLOCK. Order (M2 remediation F-07) — nothing is written to replay
    /// state until every check has passed:
    ///
    /// 1. `CheckedTrade::new` — intent/commitment correspondence.
    /// 2. Read-only replay precheck: only "no record", `CREATED` or `VERIFIED`
    ///    may proceed. `FAILED` requires an explicit
    ///    [`PersistentReplayStore::retry_after_failure`] (with txid
    ///    acknowledgement) first; `CONSUMED`/`EXPIRED` are terminal; active
    ///    settlement states are replays.
    /// 3. Trade expiry (`now > expiry` expired, `now == expiry` valid). An
    ///    existing `CREATED`/`VERIFIED` record is moved to `EXPIRED`; no record
    ///    is ever created for an expired trade.
    /// 4. Issuer + credential root authentication, currentness, freshness,
    ///    `trade_expiry <= min(root expiries)`.
    /// 5. Recipient binding (F-02) and live control of that receiver.
    /// 6. Provenance proof, then 7. eligibility proof, against the same checked
    ///    commitment and the authenticated roots.
    /// 8. Only now: create (if absent) → `VERIFIED` → `SETTLEMENT_CONSTRUCTED`,
    ///    each a compare-and-swap on the authoritative store. A lost race or a
    ///    persistence error rejects.
    ///
    /// A `VERIFIED` record found at step 2 (e.g. a crash between verify and
    /// acquire) is only locked after steps 3–7 pass again in this call.
    ///
    /// # Errors
    ///
    /// Any failed check, lifecycle rejection, CAS conflict or persistence error.
    pub fn evaluate(&self, input: GateInput) -> Result<VerifiedTrade, GateRejection> {
        use zwa_protocol::lifecycle::TradeLifecycleState as S;

        // 1. Checked trade context — fix ZWA-REL-001.
        let checked_trade = CheckedTrade::new(input.intent, input.commitment).map_err(|e| {
            match e {
                zwa_protocol::error::ProtocolError::CommitmentMismatch { expected, actual } => {
                    GateRejection::CommitmentMismatch { expected, actual }
                }
                other => GateRejection::Replay(ReplayError::Protocol(other)),
            }
        })?;
        let commitment = checked_trade.commitment();

        // 2. Read-only replay precheck (no mutation).
        let existing = self
            .replay_store
            .get(commitment)
            .map_err(GateRejection::Replay)?;
        if let Some(record) = existing {
            match record.state() {
                S::Created | S::Verified => {}
                other => return Err(state_rejection(other)),
            }
        }

        // 3. Trade expiry (frozen predicate: expired iff now > expiry).
        if checked_trade.intent().is_expired_at(input.now) {
            if existing.is_some() {
                // CREATED / VERIFIED → EXPIRED (terminal), persisted by CAS.
                self.replay_store
                    .expire(commitment, input.now)
                    .map_err(GateRejection::Replay)?;
            }
            return Err(GateRejection::ExpiredTrade {
                expiry: checked_trade.intent().expiry.get(),
                now: input.now.get(),
            });
        }

        // 4. Authenticate roots: signature, approved key, current version,
        //    freshness, trade_expiry <= root expiry, combined minimum.
        let auth_issuer = self
            .issuer_authenticator
            .authenticate(
                &input.issuer_envelope,
                input.now,
                checked_trade.intent().expiry,
            )
            .map_err(GateRejection::RootAuth)?;

        let auth_cred = self
            .credential_authenticator
            .authenticate(
                &input.credential_envelope,
                input.now,
                checked_trade.intent().expiry,
            )
            .map_err(GateRejection::RootAuth)?;

        check_combined_root_expiry(
            checked_trade.intent().expiry,
            &auth_issuer,
            &auth_cred,
        )
        .map_err(GateRejection::RootAuth)?;

        // 5a (F-02): bind the raw approved receiver to the trade.
        //
        // Chain established here, using only frozen M1 functions:
        //   (1) intent.recipient_commitment
        //         == H(RCPBIND1, subject, H(RECEIVR1, approved_receiver))   [this check]
        //   (2) the eligibility proof (Phase1B, step 7, same checked trade
        //       commitment) proves the credential leaf's receiver commitment
        //       R_c and subject S satisfy
        //         intent.recipient_commitment == H(RCPBIND1, S, R_c)
        //   (3) control is verified below for exactly `approved_receiver`
        //       (challenge.receiver == response.receiver == approved_receiver).
        // By Poseidon collision resistance, (1)+(2) give
        //   H(RECEIVR1, approved_receiver) == R_c,
        // so the receiver whose control succeeds is the credential-approved
        // receiver committed in the trade. A proof for receiver A combined
        // with control of receiver B therefore cannot pass.
        let approved_receiver_commitment =
            zwa_commitments::receiver_commitment(&input.approved_receiver);
        let derived_recipient = zwa_commitments::recipient_commitment(
            input.recipient_subject_commitment,
            approved_receiver_commitment,
        );
        if derived_recipient != checked_trade.intent().recipient_commitment {
            return Err(GateRejection::RecipientBindingMismatch);
        }

        // 5b: live wallet control of that exact receiver.
        RecipientControlAuthenticator::check_trade_expiry(
            checked_trade.intent().expiry,
            &input.control_challenge,
        )
        .map_err(GateRejection::Control)?;

        RecipientControlAuthenticator::check_trade_commitment(
            commitment,
            &input.control_challenge,
        )
        .map_err(GateRejection::Control)?;

        let verified_control = self
            .control_authenticator
            .verify_against_approved_receiver(
                &input.control_challenge,
                &input.control_response,
                &input.approved_receiver,
                input.now,
            )
            .map_err(GateRejection::Control)?;

        // Defence in depth: the verified control must be for the very receiver
        // commitment that was just bound to the trade.
        if verified_control.receiver_commitment() != approved_receiver_commitment {
            return Err(GateRejection::RecipientBindingMismatch);
        }

        // 6 + 7: provenance, then eligibility, against the same checked
        // commitment and the authenticated roots.
        verify_trade_proofs(
            &self.provenance_verifier,
            &self.eligibility_verifier,
            &checked_trade,
            &auth_issuer,
            &auth_cred,
            &input.provenance_proof,
            &input.eligibility_proof,
        )
        .map_err(GateRejection::ProofInvalid)?;

        // 8. Every check passed — only now touch replay state. Re-read: the
        //    precheck value may be stale; every write below is a CAS.
        let current = self
            .replay_store
            .get(commitment)
            .map_err(GateRejection::Replay)?;
        match current.map(|r| r.state()) {
            None => {
                self.replay_store
                    .create_checked(&checked_trade)
                    .map_err(GateRejection::Replay)?;
                self.replay_store
                    .verify(commitment, input.now)
                    .map_err(GateRejection::Replay)?;
            }
            Some(S::Created) => {
                self.replay_store
                    .verify(commitment, input.now)
                    .map_err(GateRejection::Replay)?;
            }
            Some(S::Verified) => {}
            Some(other) => return Err(state_rejection(other)),
        }

        // Compare-and-set construction lock: at most one approval per trade.
        self.replay_store
            .acquire_construction(commitment, input.now)
            .map_err(GateRejection::Replay)?;

        Ok(VerifiedTrade {
            checked_trade,
            authenticated_issuer_root: auth_issuer,
            authenticated_credential_root: auth_cred,
            verified_control,
            _private: (),
        })
    }
}

/// Maps a replay state that may not enter verification to its rejection.
fn state_rejection(state: zwa_protocol::lifecycle::TradeLifecycleState) -> GateRejection {
    use zwa_protocol::lifecycle::TradeLifecycleState as S;
    match state {
        S::Consumed => GateRejection::AlreadyConsumed,
        S::Expired => GateRejection::AlreadyExpired,
        S::Failed => GateRejection::RetryRequired,
        other => GateRejection::IllegalState {
            state: format!("{other:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{RecipientControlChallenge, RecipientControlResponse, CONTROL_DOMAIN};
    use crate::replay::{InMemoryPersistence, PersistentReplayStore};
    use crate::roots::{CredentialRootAuthenticator, IssuerRootAuthenticator};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use zwa_protocol::proof::VerificationProblem;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use zwa_credentials::{AuthorityKeyId, IssuerKeyId};
    use zwa_protocol::bytes::OrchardReceiverBytes;
    use zwa_protocol::numbers::{RootVersion, TradeExpiry, UnixSeconds};
    use zwa_protocol::proof::{EligibilityVerifier, OpaqueProof, ProvenanceVerifier};
    use zwa_protocol::{
        AssetBaseBytes, AuthorizedIssuanceRoot, ActiveCredentialRoot, MatcherFee, OpaqueSignature,
        PolicyRoot, RecipientCommitment, TradeAmount, TradeNonce, ZatoshiAmount, TradeIntent,
    };

    const ISSUANCE_ROOT: &str =
        "19309979006225485291788213177219598381134511159668519266888323889569746782051";
    const CREDENTIAL_ROOT: &str =
        "7239536478138432754387625126231950010993505962177483323536139232738771167323";
    const TRADE_COMMITMENT: &str =
        "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    const RECEIVER_A_HEX: &str =
        "781671f8a41294c866d8161f3bf5f84a8fd2c328f91a2d085a66036acd59439731c36c4f1b99b4d64be233";
    const RECEIVER_B_HEX: &str =
        "ba5a9b6828e14d720cc41e998917f5996635d1a7fa84448cb118f7b6f65068d380099e5cd54d98dd3917bb";
    /// Phase 0G `credential.subjectCommitment` = H(SUBJECT1, 77112233445566778899).
    const SUBJECT_COMMITMENT: &str =
        "8182499163832458428983635402341439692935005683808059285091898351261831993662";
    const SUBJECT_SECRET: &str = "77112233445566778899";
    /// Phase 0G `syntheticAlternativeSubjectSecret`.
    const OTHER_SUBJECT_SECRET: &str = "99887766554433221100";
    /// Phase 0G `trade.recipientCommitment` (receiver A).
    const RECIPIENT_COMMITMENT_A: &str =
        "13135279047718387126053226034283670929172341955108098732820235388025453726181";
    /// Phase 0G `tradeB.recipientCommitment` (receiver B, nonce 7002).
    const RECIPIENT_COMMITMENT_B: &str =
        "17161176809258390276335905180845953262038546658189533444510056676908192247925";
    const TRADE_B_COMMITMENT: &str =
        "4141140993944283635059564795814979270169431233615041812756992202222578526061";
    /// Real eligibility fixture public input `activeCredentialRoot`.
    const REAL_CREDENTIAL_ROOT: &str =
        "7721491042898277899686830032817687831050368809629386580479309633507500868506";

    fn subject_commitment() -> SubjectCommitment {
        SubjectCommitment::from_decimal_str(SUBJECT_COMMITMENT).unwrap()
    }

    fn control_key_b() -> SigningKey {
        signing_key(4)
    }


    // --- Explicit test-only proof verifier (F-01) ---
    //
    // Injected through the frozen verifier traits. Compiled only under
    // `cfg(test)` inside this module; no cargo feature can reach it. A "proof"
    // is valid only if its bytes were minted by `fake_proof` for exactly the
    // `(label, root, commitment)` the gate asks about, so wrong-root,
    // wrong-commitment and cross-verifier splicing all still fail. Real
    // Groth16 behaviour is covered by `verifiers::tests` and the
    // real-eligibility gate tests below.

    const PROV_LABEL: &str = "fake-provenance";
    const ELIG_LABEL: &str = "fake-eligibility";

    #[derive(Debug, Clone)]
    struct FakeVerifier {
        label: &'static str,
        calls: Arc<AtomicUsize>,
    }

    impl FakeVerifier {
        fn new(label: &'static str) -> Self {
            Self { label, calls: Arc::new(AtomicUsize::new(0)) }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn check(&self, root: String, commitment: TradeCommitment, proof: &OpaqueProof) -> VerificationResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let expected = format!("{}|{}|{}", self.label, root, commitment);
            if proof.as_bytes() == expected.as_bytes() {
                VerificationResult::Valid
            } else {
                VerificationResult::Invalid { reason: VerificationProblem::ProofRejected }
            }
        }
    }

    impl ProvenanceVerifier for FakeVerifier {
        fn verify(&self, root: AuthorizedIssuanceRoot, commitment: TradeCommitment, proof: &OpaqueProof) -> VerificationResult {
            self.check(root.to_string(), commitment, proof)
        }
    }

    impl EligibilityVerifier for FakeVerifier {
        fn verify(&self, root: ActiveCredentialRoot, commitment: TradeCommitment, proof: &OpaqueProof) -> VerificationResult {
            self.check(root.to_string(), commitment, proof)
        }
    }

    fn fake_proof(label: &str, root: &str, commitment: &str) -> OpaqueProof {
        OpaqueProof::new(format!("{label}|{root}|{commitment}").as_bytes()).unwrap()
    }

    type TestGate = MatcherGate<InMemoryPersistence, FakeVerifier, FakeVerifier>;

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

    fn build_gate() -> (
        TestGate,
        OrchardReceiverBytes,
        IssuerRootEnvelope,
        CredentialRootEnvelope,
        SigningKey,
    ) {
        build_gate_with(CREDENTIAL_ROOT, FakeVerifier::new(ELIG_LABEL))
    }

    /// Gate with real Ed25519 roots/control, fake provenance, and the given
    /// eligibility verifier bound to `credential_root`.
    fn build_gate_with<EV: EligibilityVerifier>(
        credential_root: &str,
        eligibility: EV,
    ) -> (
        MatcherGate<InMemoryPersistence, FakeVerifier, EV>,
        OrchardReceiverBytes,
        IssuerRootEnvelope,
        CredentialRootEnvelope,
        SigningKey,
    ) {
        // Issuer keys
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

        // Credential keys
        let sk_cred = signing_key(2);
        let vk_cred = sk_cred.verifying_key();
        let auth_id = AuthorityKeyId::new(b"cred-auth-1").unwrap();
        let mut approved_cred = BTreeMap::new();
        approved_cred.insert(auth_id.clone(), vk_cred);
        let cred_auth = CredentialRootAuthenticator::new(approved_cred, RootVersion::new(1));

        let cred_payload = zwa_credentials::CredentialRootPayload::new(
            ActiveCredentialRoot::from_decimal_str(credential_root).unwrap(),
            auth_id,
            RootVersion::new(1),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        ).unwrap();
        let sig2 = sk_cred.sign(&cred_payload.canonical_bytes());
        let cred_envelope = zwa_credentials::CredentialRootEnvelope::new(cred_payload, OpaqueSignature::new(&sig2.to_bytes()).unwrap());

        // Control keys — receiver A controlled by sk_control
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        // Receiver B is also a genuinely controlled wallet (key 4), so F-02
        // tests exercise an attacker who really controls B.
        let recv_b = OrchardReceiverBytes::from_hex(RECEIVER_B_HEX).unwrap();
        approved_control.insert(recv_b, control_key_b().verifying_key());
        let control_auth = crate::control::RecipientControlAuthenticator::new(approved_control, CONTROL_DOMAIN.to_vec());

        let replay = PersistentReplayStore::new(InMemoryPersistence::new(), 3).unwrap();

        let gate = MatcherGate::new(
            issuer_auth,
            cred_auth,
            control_auth,
            FakeVerifier::new(PROV_LABEL),
            eligibility,
            replay,
        );

        (gate, recv_a, issuer_envelope, cred_envelope, sk_control)
    }

    fn valid_gate_input() -> (
        GateInput,
        TestGate,
    ) {
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

        let prov_proof = fake_proof(PROV_LABEL, ISSUANCE_ROOT, TRADE_COMMITMENT);
        let elig_proof = fake_proof(ELIG_LABEL, CREDENTIAL_ROOT, TRADE_COMMITMENT);

        let input = GateInput {
            intent,
            commitment,
            issuer_envelope,
            credential_envelope: cred_envelope,
            approved_receiver: recv_a,
            recipient_subject_commitment: subject_commitment(),
            control_challenge: challenge,
            control_response: response,
            provenance_proof: prov_proof,
            eligibility_proof: elig_proof,
            now,
        };

        (input, gate)
    }

    fn control_for(
        receiver: OrchardReceiverBytes,
        commitment: TradeCommitment,
        key: &SigningKey,
    ) -> (RecipientControlChallenge, RecipientControlResponse) {
        let challenge = RecipientControlChallenge::new(
            receiver,
            [7u8; 32],
            CONTROL_DOMAIN.to_vec(),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
            commitment,
        )
        .unwrap();
        let response = RecipientControlResponse::sign(&challenge, key);
        (challenge, response)
    }

    fn real_eligibility_proof() -> OpaqueProof {
        OpaqueProof::new(include_str!("../../tests/fixtures/groth16/eligibility-proof.json").as_bytes()).unwrap()
    }

    /// Golden trade A input for a gate whose credential root is `credential_root`.
    fn input_for_trade_a(
        issuer_envelope: IssuerRootEnvelope,
        credential_envelope: CredentialRootEnvelope,
        recv_a: OrchardReceiverBytes,
        sk_control: &SigningKey,
        eligibility_proof: OpaqueProof,
    ) -> GateInput {
        let commitment = TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let (control_challenge, control_response) = control_for(recv_a, commitment, sk_control);
        GateInput {
            intent: golden_intent(),
            commitment,
            issuer_envelope,
            credential_envelope,
            approved_receiver: recv_a,
            recipient_subject_commitment: subject_commitment(),
            control_challenge,
            control_response,
            provenance_proof: fake_proof(PROV_LABEL, ISSUANCE_ROOT, TRADE_COMMITMENT),
            eligibility_proof,
            now: UnixSeconds::new(1_900_000_100),
        }
    }

    fn real_eligibility_gate() -> (
        MatcherGate<InMemoryPersistence, FakeVerifier, EligibilityVerifierBackend>,
        GateInput,
    ) {
        let (gate, recv_a, issuer_env, cred_env, sk_control) = build_gate_with(
            REAL_CREDENTIAL_ROOT,
            EligibilityVerifierBackend::from_fixture().unwrap(),
        );
        let input = input_for_trade_a(issuer_env, cred_env, recv_a, &sk_control, real_eligibility_proof());
        (gate, input)
    }

    // --- F-02: recipient substitution ---

    #[test]
    fn f02_fixture_binding_matches_frozen_commitment_functions() {
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let recv_b = OrchardReceiverBytes::from_hex(RECEIVER_B_HEX).unwrap();
        let secret = zwa_protocol::SubjectSecret::from_decimal_str(SUBJECT_SECRET).unwrap();
        assert_eq!(zwa_commitments::subject_commitment(secret), subject_commitment());
        let a = zwa_commitments::recipient_commitment(
            subject_commitment(),
            zwa_commitments::receiver_commitment(&recv_a),
        );
        let b = zwa_commitments::recipient_commitment(
            subject_commitment(),
            zwa_commitments::receiver_commitment(&recv_b),
        );
        assert_eq!(a.to_string(), RECIPIENT_COMMITMENT_A);
        assert_eq!(b.to_string(), RECIPIENT_COMMITMENT_B);
        assert_eq!(golden_intent().recipient_commitment.to_string(), RECIPIENT_COMMITMENT_A);
    }

    #[test]
    fn f02_proof_for_a_with_control_of_b_is_rejected_before_proofs() {
        let (mut input, gate) = valid_gate_input();
        let recv_b = OrchardReceiverBytes::from_hex(RECEIVER_B_HEX).unwrap();
        // Attacker genuinely controls B and presents B as "approved".
        let (challenge, response) = control_for(recv_b, input.commitment, &control_key_b());
        input.approved_receiver = recv_b;
        input.control_challenge = challenge;
        input.control_response = response;
        let commitment = input.commitment;
        let err = gate.evaluate(input).unwrap_err();
        assert!(matches!(err, GateRejection::RecipientBindingMismatch), "got {err:?}");
        assert_eq!(gate.provenance_verifier.calls(), 0);
        assert_eq!(gate.eligibility_verifier.calls(), 0);
        assert!(gate.replay_store().state(commitment).unwrap().is_none());
    }

    #[test]
    fn f02_real_eligibility_proof_receiver_a_control_a_passes() {
        let (gate, input) = real_eligibility_gate();
        let approval = gate.evaluate(input).unwrap();
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        assert_eq!(approval.verified_control().receiver(), &recv_a);
        assert_eq!(
            approval.verified_control().receiver_commitment(),
            zwa_commitments::receiver_commitment(&recv_a)
        );
    }

    #[test]
    fn f02_real_eligibility_proof_for_a_with_control_of_b_is_rejected() {
        let (gate, mut input) = real_eligibility_gate();
        let recv_b = OrchardReceiverBytes::from_hex(RECEIVER_B_HEX).unwrap();
        let (challenge, response) = control_for(recv_b, input.commitment, &control_key_b());
        input.approved_receiver = recv_b;
        input.control_challenge = challenge;
        input.control_response = response;
        let err = gate.evaluate(input).unwrap_err();
        assert!(matches!(err, GateRejection::RecipientBindingMismatch), "got {err:?}");
    }

    #[test]
    fn f02_trade_bound_to_b_with_credential_proof_for_a_is_rejected() {
        // Attacker re-commits the trade to receiver B (Phase 0G tradeB), controls
        // B and opens the binding correctly, but only holds the eligibility
        // proof generated for receiver A's trade. Phase1B (real verifier) rejects.
        let (gate, mut input) = real_eligibility_gate();
        let recv_b = OrchardReceiverBytes::from_hex(RECEIVER_B_HEX).unwrap();
        let mut intent_b = golden_intent();
        intent_b.nonce = TradeNonce::new(7002);
        intent_b.recipient_commitment = RecipientCommitment::from_decimal_str(RECIPIENT_COMMITMENT_B).unwrap();
        let commitment_b = TradeCommitment::from_decimal_str(TRADE_B_COMMITMENT).unwrap();
        let (challenge, response) = control_for(recv_b, commitment_b, &control_key_b());
        input.intent = intent_b;
        input.commitment = commitment_b;
        input.approved_receiver = recv_b;
        input.control_challenge = challenge;
        input.control_response = response;
        input.provenance_proof = fake_proof(PROV_LABEL, ISSUANCE_ROOT, TRADE_B_COMMITMENT);
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::ProofInvalid(VerificationResult::Invalid { reason }) => {
                assert_eq!(reason, VerificationProblem::ProofRejected);
            }
            other => panic!("expected real eligibility rejection, got {other:?}"),
        }
    }

    #[test]
    fn f02_wrong_raw_receiver_fails() {
        // Control still for A, but a different raw receiver is claimed approved.
        let (mut input, gate) = valid_gate_input();
        input.approved_receiver = OrchardReceiverBytes::from_hex(RECEIVER_B_HEX).unwrap();
        let err = gate.evaluate(input).unwrap_err();
        assert!(matches!(err, GateRejection::RecipientBindingMismatch), "got {err:?}");
    }

    #[test]
    fn f02_wrong_recipient_commitment_fails() {
        // (a) Trade recipient commitment swapped without re-committing: the
        //     checked-trade step rejects it.
        let (mut input, gate) = valid_gate_input();
        input.intent.recipient_commitment =
            RecipientCommitment::from_decimal_str(RECIPIENT_COMMITMENT_B).unwrap();
        let err = gate.evaluate(input).unwrap_err();
        assert!(matches!(err, GateRejection::CommitmentMismatch { .. }), "got {err:?}");

        // (b) Wrong subject opening: binding does not re-derive the commitment.
        let (mut input, gate) = valid_gate_input();
        let other = zwa_protocol::SubjectSecret::from_decimal_str(OTHER_SUBJECT_SECRET).unwrap();
        input.recipient_subject_commitment = zwa_commitments::subject_commitment(other);
        let err = gate.evaluate(input).unwrap_err();
        assert!(matches!(err, GateRejection::RecipientBindingMismatch), "got {err:?}");
    }

    // --- F-07: ordering and persisted state after rejection ---

    use zwa_protocol::lifecycle::{FailureReason, SettlementTxId, TradeLifecycleState};

    const AT_EXPIRY: UnixSeconds = UnixSeconds::new(2_000_000_000);
    const AFTER_EXPIRY: UnixSeconds = UnixSeconds::new(2_000_000_001);
    const TXID_1: SettlementTxId = SettlementTxId::new([0x11; 32]);

    fn calls(gate: &TestGate) -> (usize, usize) {
        (gate.provenance_verifier.calls(), gate.eligibility_verifier.calls())
    }

    fn state_of(gate: &TestGate, c: TradeCommitment) -> Option<TradeLifecycleState> {
        gate.replay_store().state(c).unwrap()
    }

    fn issuer_envelope(signer: &SigningKey, version: u64, from: u64, to: u64) -> IssuerRootEnvelope {
        let payload = zwa_credentials::IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap(),
            IssuerKeyId::new(b"issuer-atlas").unwrap(),
            RootVersion::new(version),
            UnixSeconds::new(from),
            UnixSeconds::new(to),
        )
        .unwrap();
        let sig = signer.sign(&payload.canonical_bytes());
        zwa_credentials::IssuerRootEnvelope::new(payload, OpaqueSignature::new(&sig.to_bytes()).unwrap())
    }

    fn credential_envelope(signer: &SigningKey, version: u64, from: u64, to: u64) -> CredentialRootEnvelope {
        let payload = zwa_credentials::CredentialRootPayload::new(
            ActiveCredentialRoot::from_decimal_str(CREDENTIAL_ROOT).unwrap(),
            AuthorityKeyId::new(b"cred-auth-1").unwrap(),
            RootVersion::new(version),
            UnixSeconds::new(from),
            UnixSeconds::new(to),
        )
        .unwrap();
        let sig = signer.sign(&payload.canonical_bytes());
        zwa_credentials::CredentialRootEnvelope::new(payload, OpaqueSignature::new(&sig.to_bytes()).unwrap())
    }

    #[test]
    fn f07_invalid_provenance_leaves_no_verified_record() {
        let (mut input, gate) = valid_gate_input();
        let c = input.commitment;
        input.provenance_proof = fake_proof(PROV_LABEL, ISSUANCE_ROOT, TRADE_B_COMMITMENT);
        let err = gate.evaluate(input).unwrap_err();
        assert!(matches!(err, GateRejection::ProofInvalid(_)), "got {err:?}");
        assert_eq!(state_of(&gate, c), None);
        assert_eq!(calls(&gate), (1, 0), "eligibility must not run after provenance fails");
    }

    #[test]
    fn f07_invalid_eligibility_leaves_no_verified_record() {
        let (mut input, gate) = valid_gate_input();
        let c = input.commitment;
        input.eligibility_proof = fake_proof(ELIG_LABEL, REAL_CREDENTIAL_ROOT, TRADE_COMMITMENT);
        let err = gate.evaluate(input).unwrap_err();
        assert!(matches!(err, GateRejection::ProofInvalid(_)), "got {err:?}");
        assert_eq!(state_of(&gate, c), None);
        assert_eq!(calls(&gate), (1, 1));
    }

    #[test]
    fn f07_failed_control_leaves_no_record_and_runs_no_proof() {
        let (mut input, gate) = valid_gate_input();
        let c = input.commitment;
        input.control_response = RecipientControlResponse::sign(&input.control_challenge, &signing_key(99));
        let err = gate.evaluate(input).unwrap_err();
        assert!(matches!(err, GateRejection::Control(_)), "got {err:?}");
        assert_eq!(state_of(&gate, c), None);
        assert_eq!(calls(&gate), (0, 0));
    }

    #[test]
    fn f07_root_failures_leave_no_record_and_run_no_later_check() {
        let now = 1_900_000_100;
        type Mutation = Box<dyn Fn(&mut GateInput)>;
        let cases: Vec<(&str, Mutation)> = vec![
            ("wrong issuer signer", Box::new(move |i: &mut GateInput| {
                i.issuer_envelope = issuer_envelope(&signing_key(77), 1, 1_900_000_000, 2_100_000_000);
            })),
            ("wrong credential signer", Box::new(move |i: &mut GateInput| {
                i.credential_envelope = credential_envelope(&signing_key(78), 1, 1_900_000_000, 2_100_000_000);
            })),
            ("expired issuer root", Box::new(move |i: &mut GateInput| {
                i.issuer_envelope = issuer_envelope(&signing_key(1), 1, 1_800_000_000, now - 1);
            })),
            ("not-yet-valid issuer root", Box::new(move |i: &mut GateInput| {
                i.issuer_envelope = issuer_envelope(&signing_key(1), 1, now + 1, 2_100_000_000);
            })),
            ("expired credential root", Box::new(move |i: &mut GateInput| {
                i.credential_envelope = credential_envelope(&signing_key(2), 1, 1_800_000_000, now - 1);
            })),
            ("not-yet-valid credential root", Box::new(move |i: &mut GateInput| {
                i.credential_envelope = credential_envelope(&signing_key(2), 1, now + 1, 2_100_000_000);
            })),
            ("stale (superseded) issuer version", Box::new(move |i: &mut GateInput| {
                i.issuer_envelope = issuer_envelope(&signing_key(1), 2, 1_900_000_000, 2_100_000_000);
            })),
            ("stale (superseded) credential version", Box::new(move |i: &mut GateInput| {
                i.credential_envelope = credential_envelope(&signing_key(2), 2, 1_900_000_000, 2_100_000_000);
            })),
            ("root expires before trade", Box::new(move |i: &mut GateInput| {
                i.issuer_envelope = issuer_envelope(&signing_key(1), 1, 1_900_000_000, 1_999_999_999);
            })),
        ];
        for (name, mutate) in cases {
            let (mut input, gate) = valid_gate_input();
            let c = input.commitment;
            mutate(&mut input);
            let err = gate.evaluate(input).unwrap_err();
            assert!(matches!(err, GateRejection::RootAuth(_)), "{name}: got {err:?}");
            assert_eq!(state_of(&gate, c), None, "{name}");
            assert_eq!(calls(&gate), (0, 0), "{name}");
        }
    }

    #[test]
    fn f07_now_equal_expiry_is_valid() {
        let (mut input, gate) = valid_gate_input();
        let c = input.commitment;
        input.now = AT_EXPIRY;
        gate.evaluate(input).unwrap();
        assert_eq!(state_of(&gate, c), Some(TradeLifecycleState::SettlementConstructed));
    }

    #[test]
    fn f07_expired_trade_without_record_creates_nothing() {
        let (mut input, gate) = valid_gate_input();
        let c = input.commitment;
        input.now = AFTER_EXPIRY;
        let err = gate.evaluate(input).unwrap_err();
        assert!(matches!(err, GateRejection::ExpiredTrade { .. }), "got {err:?}");
        assert_eq!(state_of(&gate, c), None);
        assert_eq!(calls(&gate), (0, 0));
    }

    #[test]
    fn f07_expired_trade_with_created_record_is_persisted_expired() {
        let (input, gate) = valid_gate_input();
        let c = input.commitment;
        gate.evaluate(input).unwrap();
        gate.replay_store().fail(c, FailureReason::ConstructionFailed).unwrap();
        gate.replay_store().retry_after_failure(c, None, UnixSeconds::new(1_900_000_200)).unwrap();
        assert_eq!(state_of(&gate, c), Some(TradeLifecycleState::Created));

        let (mut late, _) = valid_gate_input();
        late.now = AFTER_EXPIRY;
        let before = calls(&gate);
        let err = gate.evaluate(late).unwrap_err();
        assert!(matches!(err, GateRejection::ExpiredTrade { .. }), "got {err:?}");
        assert_eq!(state_of(&gate, c), Some(TradeLifecycleState::Expired));
        assert_eq!(calls(&gate), before);

        // Terminal: even a fully valid, timely request is refused.
        let (again, _) = valid_gate_input();
        assert!(matches!(gate.evaluate(again).unwrap_err(), GateRejection::AlreadyExpired));
    }

    #[test]
    fn f07_failed_requires_explicit_retry_then_full_reverification() {
        let (input, gate) = valid_gate_input();
        let c = input.commitment;
        let now = input.now;
        gate.evaluate(input).unwrap();
        gate.replay_store().submit(c, TXID_1, now).unwrap();
        gate.replay_store().fail(c, FailureReason::SubmissionFailed).unwrap();
        let after_first = calls(&gate);
        assert_eq!(after_first, (1, 1));

        // The gate never retries by itself (old code auto-acknowledged the txid).
        let (again, _) = valid_gate_input();
        assert!(matches!(gate.evaluate(again).unwrap_err(), GateRejection::RetryRequired));
        assert_eq!(state_of(&gate, c), Some(TradeLifecycleState::Failed));
        assert_eq!(calls(&gate), after_first);

        // Explicit retry needs the exact prior txid.
        assert!(gate.replay_store().retry_after_failure(c, None, now).is_err());
        let rec = gate.replay_store().retry_after_failure(c, Some(TXID_1), now).unwrap();
        assert_eq!(rec.state(), TradeLifecycleState::Created);
        assert_eq!(rec.retry_count(), 1);

        // CREATED after retry: a failing proof must not produce VERIFIED.
        let (mut bad, _) = valid_gate_input();
        bad.eligibility_proof = fake_proof(ELIG_LABEL, CREDENTIAL_ROOT, TRADE_B_COMMITMENT);
        assert!(matches!(gate.evaluate(bad).unwrap_err(), GateRejection::ProofInvalid(_)));
        assert_eq!(state_of(&gate, c), Some(TradeLifecycleState::Created));

        // Full re-verification: both proofs run again, then construction.
        let (good, _) = valid_gate_input();
        gate.evaluate(good).unwrap();
        assert_eq!(state_of(&gate, c), Some(TradeLifecycleState::SettlementConstructed));
        assert_eq!(calls(&gate), (after_first.0 + 2, after_first.1 + 2));
        let rec = gate.replay_store().get(c).unwrap().unwrap();
        assert_eq!(rec.retry_count(), 1);
        assert_eq!(rec.prior_txid(), None);
    }

    #[test]
    fn f07_verified_record_is_reverified_before_construction() {
        // Simulates a crash between VERIFIED and acquire.
        let (input, gate) = valid_gate_input();
        let c = input.commitment;
        let checked = CheckedTrade::new(input.intent, c).unwrap();
        gate.replay_store().create_checked(&checked).unwrap();
        gate.replay_store().verify(c, input.now).unwrap();

        let (mut bad, _) = valid_gate_input();
        bad.provenance_proof = fake_proof(PROV_LABEL, ISSUANCE_ROOT, TRADE_B_COMMITMENT);
        assert!(matches!(gate.evaluate(bad).unwrap_err(), GateRejection::ProofInvalid(_)));
        assert_eq!(state_of(&gate, c), Some(TradeLifecycleState::Verified));

        gate.evaluate(input).unwrap();
        assert_eq!(state_of(&gate, c), Some(TradeLifecycleState::SettlementConstructed));
    }

    #[test]
    fn f07_replay_attempt_rejected_before_any_proof_runs() {
        let (input, gate) = valid_gate_input();
        let c = input.commitment;
        gate.evaluate(input).unwrap();
        let before = calls(&gate);
        let (again, _) = valid_gate_input();
        assert!(matches!(gate.evaluate(again).unwrap_err(), GateRejection::IllegalState { .. }));
        assert_eq!(calls(&gate), before);
        assert_eq!(state_of(&gate, c), Some(TradeLifecycleState::SettlementConstructed));
    }

    #[test]
    fn f07_concurrent_identical_requests_yield_exactly_one_approval() {
        let (_, gate) = valid_gate_input();
        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let gate = &gate;
                    scope.spawn(move || {
                        let (input, _) = valid_gate_input();
                        gate.evaluate(input)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1, "{results:?}");
    }

    #[test]
    fn gate_allows_valid_private_trade() {
        let (input, gate) = valid_gate_input();
        let verified = gate.evaluate(input).unwrap();
        assert_eq!(verified.checked_trade().commitment().to_string(), TRADE_COMMITMENT);
        assert_eq!(verified.authenticated_issuer_root().root().to_string(), ISSUANCE_ROOT);
        assert_eq!(verified.authenticated_credential_root().root().to_string(), CREDENTIAL_ROOT);
        // Opaque approval — can get commitment/intent via getters, but cannot Clone or serialize
        assert_eq!(verified.commitment().to_string(), TRADE_COMMITMENT);
    }

    #[test]
    fn verified_trade_is_opaque_non_clone() {
        // VerifiedTrade / MatcherApproval must be opaque non-serializable
        // - No Clone (compile-time)
        // - Private _private field prevents external construction
        // - Only obtainable via MatcherGate::evaluate()
        let (input, gate) = valid_gate_input();
        let verified = gate.evaluate(input).unwrap();
        // Can access via getters
        let _commitment = verified.commitment();
        let _intent = verified.intent();
        let _checked = verified.checked_trade();
        let _issuer = verified.authenticated_issuer_root();
        let _cred = verified.authenticated_credential_root();
        let _control = verified.verified_control();
        // Cannot clone — this would fail to compile if uncommented:
        // let _cloned = verified.clone();
        // Cannot construct via struct literal — _private is private
        // let _fake = VerifiedTrade { checked_trade: ..., _private: () }; // fails outside module
        // Debug is allowed, but Display is not implemented
        let debug_str = format!("{:?}", verified);
        assert!(debug_str.contains("VerifiedTrade"));
    }

    #[test]
    fn identical_request_twice_does_not_create_two_approvals() {
        // Spec A7: Identical request twice does not create two approvals
        let (input, gate) = valid_gate_input();
        let commitment = input.commitment;
        // First request → ALLOW, state SETTLEMENT_CONSTRUCTED
        let first = gate.evaluate(input.clone()).unwrap();
        assert_eq!(first.commitment().to_string(), TRADE_COMMITMENT);
        assert_eq!(
            gate.replay_store().state(commitment).unwrap(),
            Some(zwa_protocol::lifecycle::TradeLifecycleState::SettlementConstructed)
        );

        // Second identical request → BLOCK, not second approval
        // Must be IllegalState (already constructed) or AlreadyConsumed/AlreadyExpired
        let (input2, _) = valid_gate_input();
        let err = gate.evaluate(input2).unwrap_err();
        match err {
            GateRejection::IllegalState { .. } => {}
            GateRejection::AlreadyConsumed => {}
            other => panic!("identical request twice must not create second approval, got {other:?}"),
        }

        // Still only one record, still SETTLEMENT_CONSTRUCTED
        assert_eq!(
            gate.replay_store().state(commitment).unwrap(),
            Some(zwa_protocol::lifecycle::TradeLifecycleState::SettlementConstructed)
        );
    }

    #[test]
    fn no_later_verifier_runs_after_early_failure() {
        // Spec A7: No later verifier runs after early failure (cheap checks before expensive proofs)
        // We test that early failures (commitment mismatch, root auth) leave replay store empty,
        // proving proof verifiers and construction were never reached.

        // Early failure 1: Commitment mismatch (Step 2) — cheapest gate
        let (mut input, gate) = valid_gate_input();
        let commitment = input.commitment;
        assert!(gate.replay_store().state(commitment).unwrap().is_none(), "precondition empty");
        input.intent.offered_amount = TradeAmount::new(9999);
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::CommitmentMismatch { .. } => {}
            other => panic!("expected CommitmentMismatch, got {other:?}"),
        }
        // Replay store must still be empty — no create, no verify, no proof verification, no construction
        assert!(
            gate.replay_store().state(commitment).unwrap().is_none(),
            "early commitment mismatch must not create replay record, must not run later verifiers"
        );

        // Early failure 2: Root auth failure (Step 3) — before control, replay, proofs
        let (mut input2, gate2) = valid_gate_input();
        let commitment2 = input2.commitment;
        assert!(gate2.replay_store().state(commitment2).unwrap().is_none());
        // Tamper issuer envelope to have wrong version → VersionNotCurrent
        let sk_issuer = signing_key(1);
        let issuer_payload_bad = zwa_credentials::IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap(),
            IssuerKeyId::new(b"issuer-atlas").unwrap(),
            RootVersion::new(99),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        )
        .unwrap();
        let sig = sk_issuer.sign(&issuer_payload_bad.canonical_bytes());
        let envelope_bad = zwa_credentials::IssuerRootEnvelope::new(
            issuer_payload_bad,
            OpaqueSignature::new(&sig.to_bytes()).unwrap(),
        );
        input2.issuer_envelope = envelope_bad;
        let err = gate2.evaluate(input2).unwrap_err();
        match err {
            GateRejection::RootAuth(_) => {}
            other => panic!("expected RootAuth, got {other:?}"),
        }
        assert!(
            gate2.replay_store().state(commitment2).unwrap().is_none(),
            "root auth failure must not create replay record, must not run control/proof verifiers"
        );

        // Early failure 3: Control failure (Step 5) — before replay and proofs
        let (mut input3, gate3) = valid_gate_input();
        let commitment3 = input3.commitment;
        let sk_other = signing_key(99);
        input3.control_response = RecipientControlResponse::sign(&input3.control_challenge, &sk_other);
        let err = gate3.evaluate(input3).unwrap_err();
        match err {
            GateRejection::Control(_) => {}
            other => panic!("expected Control failure, got {other:?}"),
        }
        assert!(
            gate3.replay_store().state(commitment3).unwrap().is_none(),
            "control failure must not create replay record, must not run proof verifiers"
        );
    }

    #[test]
    fn gate_blocks_unauthorized_asset_commitment_mismatch() {
        // Authorized asset with convincing name but wrong AssetBase → commitment mismatch
        let (mut input, gate) = valid_gate_input();
        input.intent.offered_amount = TradeAmount::new(999); // mutate committed field
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::CommitmentMismatch { .. } => {}
            other => panic!("expected CommitmentMismatch, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_wrong_investor_class_via_eligibility_proof() {
        // Valid asset, wrong investor class → eligibility proof has wrong public inputs
        let (mut input, gate) = valid_gate_input();
        // Make eligibility proof for different commitment (simulating wrong class proof)
        let bad_proof = fake_proof(ELIG_LABEL, CREDENTIAL_ROOT, "7409670081847436957289371955571360481923983184454289247710022466448715682310");
        input.eligibility_proof = bad_proof;
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::ProofInvalid(_) => {}
            other => panic!("expected ProofInvalid, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_valid_credential_but_receiver_not_approved() {
        // Credential approves A, but trade tries to settle to B → control challenge for B vs approved A
        let (mut input, gate) = valid_gate_input();
        let recv_b = OrchardReceiverBytes::from_hex(RECEIVER_B_HEX).unwrap();
        // Challenge for B, but approved is A
        let commitment_b = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
        let challenge_b = RecipientControlChallenge::new(
            recv_b,
            [8u8; 32],
            CONTROL_DOMAIN.to_vec(),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
            commitment_b,
        ).unwrap();
        let sk_b = signing_key(9);
        let response_b = RecipientControlResponse::sign(&challenge_b, &sk_b);
        input.control_challenge = challenge_b;
        input.control_response = response_b;
        // approved_receiver still A, so mismatch
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::Control(ControlError::ApprovedReceiverMismatch { .. }) => {}
            other => panic!("expected ApprovedReceiverMismatch, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_approved_receiver_without_wallet_control() {
        // Approved A, but no control key for A (or invalid sig)
        let (mut input, gate) = valid_gate_input();
        // Use different signing key not in approved_control_keys
        let sk_other = signing_key(99);
        let response_bad = RecipientControlResponse::sign(&input.control_challenge, &sk_other);
        input.control_response = response_bad;
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::Control(ControlError::SignatureVerificationFailed { .. }) => {}
            other => panic!("expected SignatureVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_expired_trade_and_stale_root() {
        let (mut input, gate) = valid_gate_input();
        // Expired trade
        input.now = UnixSeconds::new(2_000_000_001);
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::ExpiredTrade { .. } => {}
            other => panic!("expected ExpiredTrade, got {other:?}"),
        }

        // Stale root tested in Task B, but gate also blocks via RootAuth
        let (mut input2, gate2) = valid_gate_input();
        // Make issuer envelope version 2 while authenticator expects 1? Actually build_gate expects 1, so version 2 is stale? No, current is 1, version 2 != current → VersionNotCurrent
        // We need to build a new envelope with version 2
        let sk_issuer = signing_key(1);
        let issuer_payload_v2 = zwa_credentials::IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap(),
            IssuerKeyId::new(b"issuer-atlas").unwrap(),
            RootVersion::new(2),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        ).unwrap();
        let sig = sk_issuer.sign(&issuer_payload_v2.canonical_bytes());
        let envelope_v2 = zwa_credentials::IssuerRootEnvelope::new(issuer_payload_v2, OpaqueSignature::new(&sig.to_bytes()).unwrap());
        input2.issuer_envelope = envelope_v2;
        let err = gate2.evaluate(input2).unwrap_err();
        match err {
            GateRejection::RootAuth(RootAuthError::VersionNotCurrent { .. }) => {}
            other => panic!("expected VersionNotCurrent, got {other:?}"),
        }
    }

    #[test]
    fn gate_blocks_proof_splicing_from_different_trades() {
        // Proof A from trade A, proof B from trade B with different commitment → must fail
        let (mut input, gate) = valid_gate_input();
        let spliced_elig = fake_proof(ELIG_LABEL, CREDENTIAL_ROOT, "4141140993944283635059564795814979270169431233615041812756992202222578526061");
        input.eligibility_proof = spliced_elig;
        let err = gate.evaluate(input).unwrap_err();
        match err {
            GateRejection::ProofInvalid(_) => {}
            other => panic!("expected ProofInvalid for splicing, got {other:?}"),
        }
    }

    #[test]
    fn gate_acquires_construction_only_after_all_gates_pass() {
        let (input, gate) = valid_gate_input();
        let commitment = input.commitment;
        // Before evaluate, no record
        assert!(gate.replay_store().state(commitment).unwrap().is_none());

        let _verified = gate.evaluate(input).unwrap();

        // After evaluate, state must be SETTLEMENT_CONSTRUCTED (acquired)
        assert_eq!(
            gate.replay_store().state(commitment).unwrap(),
            Some(zwa_protocol::lifecycle::TradeLifecycleState::SettlementConstructed)
        );

        // Second evaluate must fail — already in SETTLEMENT_CONSTRUCTED, not allowed to re-verify
        let (input2, _) = valid_gate_input();
        // Need new gate with same replay store that already has SETTLEMENT_CONSTRUCTED
        // For this test, we reuse same gate which already has that state
        let err = gate.evaluate(input2).unwrap_err();
        match err {
            GateRejection::IllegalState { .. } => {}
            other => panic!("expected IllegalState for double construction, got {other:?}"),
        }
    }

    #[test]
    fn a8_integration_real_signatures_real_control_persistent_replay_injected_fake_proofs() {
        use crate::replay::{JsonFilePersistence, PersistentReplayStore};
        use std::fs;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("zwa-a8-e2e-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);
        let commitment = zwa_protocol::TradeCommitment::from_decimal_str(TRADE_COMMITMENT).unwrap();
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
        let issuer_envelope = zwa_credentials::IssuerRootEnvelope::new(
            issuer_payload,
            OpaqueSignature::new(&sig.to_bytes()).unwrap(),
        );
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
        let cred_envelope = zwa_credentials::CredentialRootEnvelope::new(
            cred_payload,
            OpaqueSignature::new(&sig2.to_bytes()).unwrap(),
        );
        let sk_control = signing_key(3);
        let vk_control = sk_control.verifying_key();
        let recv_a = OrchardReceiverBytes::from_hex(RECEIVER_A_HEX).unwrap();
        let mut approved_control = BTreeMap::new();
        approved_control.insert(recv_a, vk_control);
        let control_auth = crate::control::RecipientControlAuthenticator::new(approved_control, CONTROL_DOMAIN.to_vec());
        let persistence = JsonFilePersistence::new(&path).unwrap();
        let replay = PersistentReplayStore::new(persistence, 3).unwrap();
        let gate = MatcherGate::new(
            issuer_auth,
            cred_auth,
            control_auth,
            FakeVerifier::new(PROV_LABEL),
            FakeVerifier::new(ELIG_LABEL),
            replay,
        );
        let now = UnixSeconds::new(1_900_000_100);
        let challenge = RecipientControlChallenge::new(
            recv_a,
            [7u8; 32],
            CONTROL_DOMAIN.to_vec(),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
            commitment,
        ).unwrap();
        let response = RecipientControlResponse::sign(&challenge, &sk_control);
        let prov_proof = fake_proof(PROV_LABEL, ISSUANCE_ROOT, TRADE_COMMITMENT);
        let elig_proof = fake_proof(ELIG_LABEL, CREDENTIAL_ROOT, TRADE_COMMITMENT);
        let input = GateInput {
            intent: golden_intent(),
            commitment,
            issuer_envelope,
            credential_envelope: cred_envelope,
            approved_receiver: recv_a,
            recipient_subject_commitment: subject_commitment(),
            control_challenge: challenge,
            control_response: response,
            provenance_proof: prov_proof,
            eligibility_proof: elig_proof,
            now,
        };
        let approval = gate.evaluate(input).unwrap();
        assert_eq!(approval.commitment().to_string(), TRADE_COMMITMENT);
        assert!(path.exists());
        let data = fs::read_to_string(&path).unwrap();
        assert!(data.contains("schema_version"));
        drop(gate);
        let persistence2 = JsonFilePersistence::new(&path).unwrap();
        assert_eq!(persistence2.load_all().unwrap().len(), 1);
        assert_eq!(
            persistence2.load(commitment).unwrap().unwrap().state(),
            zwa_protocol::lifecycle::TradeLifecycleState::SettlementConstructed,
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a8_integration_real_groth16_proofs_individually_verify() {
        use crate::verifiers::{EligibilityVerifierBackend, ProvenanceVerifierBackend};
        let prov_backend = ProvenanceVerifierBackend::from_fixture().unwrap();
        let prov_root = AuthorizedIssuanceRoot::from_decimal_str(
            "8857867840332676380575934803462643968319857770249975039236308904195120230546",
        ).unwrap();
        let prov_commitment = zwa_protocol::TradeCommitment::from_decimal_str(
            "7409670081847436957289371955571360481923983184454289247710022466448715682310",
        ).unwrap();
        let prov_proof_bytes = include_str!("../../tests/fixtures/groth16/provenance-proof.json");
        let prov_proof = OpaqueProof::new(prov_proof_bytes.as_bytes()).unwrap();
        let prov_result = prov_backend.verify(prov_root, prov_commitment, &prov_proof);
        assert_eq!(prov_result, VerificationResult::Valid);
        let elig_backend = EligibilityVerifierBackend::from_fixture().unwrap();
        let elig_root = ActiveCredentialRoot::from_decimal_str(
            "7721491042898277899686830032817687831050368809629386580479309633507500868506",
        ).unwrap();
        let elig_commitment = zwa_protocol::TradeCommitment::from_decimal_str(
            "10187400613857124614980227259922066295752635539032972479692659299555113110306",
        ).unwrap();
        let elig_proof_bytes = include_str!("../../tests/fixtures/groth16/eligibility-proof.json");
        let elig_proof = OpaqueProof::new(elig_proof_bytes.as_bytes()).unwrap();
        let elig_result = elig_backend.verify(elig_root, elig_commitment, &elig_proof);
        assert_eq!(elig_result, VerificationResult::Valid);
        assert_eq!(
            prov_backend.vk_hash(),
            "4831d3eef9575ef7daf318eb8767e1a39ef1e26da20339ddda137b1e246f1350"
        );
        assert_eq!(
            elig_backend.vk_hash(),
            "879d427a16f334edc163e78614c94dfe00c3ae3cb657c3ef4d7d82c39e4f5e75"
        );
    }
}
