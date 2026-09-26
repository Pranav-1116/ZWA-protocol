//! Persistent replay coordination — M2 remediation F-05 / F-06.
//!
//! Frozen `zwa_protocol::ReplayStore` is the canonical, in-memory definition of
//! the replay lifecycle. Its `TradeRecord` has private fields and no restore
//! constructor, so a persisted record can never be turned back into a frozen
//! `TradeRecord` without re-running historical transitions with invented inputs
//! (the defect found in audit: hardcoded timestamps, fake txids, collapsed
//! failure reasons, lost retry counts).
//!
//! This module therefore persists an M2-owned [`ReplayRecord`] that carries every
//! field of the frozen record **directly** — commitment, intent, state, failure
//! reason, prior txid, retry count — plus a monotonically increasing `version`
//! used for compare-and-swap. Nothing is replayed on load.
//!
//! # Lifecycle semantics are not redesigned
//!
//! [`apply`] is a line-by-line mirror of the frozen `ReplayStore` transition
//! methods (`verify`, `acquire_construction`, `submit`, `confirm`, `consume`,
//! `fail`, `expire`, `retry_after_failure`), including the frozen behaviour that
//! an expiry-gated transition on an expired trade *moves the record to
//! `EXPIRED`* and then rejects. The differential test
//! `tests::apply_matches_frozen_replay_store_exhaustively` drives the frozen
//! store and [`apply`] through every reachable operation sequence up to a fixed
//! depth and requires identical results, errors, and resulting records.
//!
//! # Atomicity and durability
//!
//! - The persistence backend is the **only** state. [`PersistentReplayStore`]
//!   keeps no in-memory copy, so memory can never run ahead of durable state.
//! - Every transition is: fallible `load` → pure [`apply`] →
//!   [`ReplayPersistence::compare_and_swap`] conditioned on the loaded record's
//!   state and version. If the write fails or loses the race, the caller gets an
//!   error and the stored record is unchanged.
//! - Loads are fallible and fail closed: I/O errors, unknown schema versions,
//!   unknown enum tags, malformed hex/decimal, or a stored commitment that does
//!   not recompute from the stored intent are errors, never "absent".
//! - [`SqlitePersistence`] (feature `sqlite`) performs the CAS inside an
//!   `IMMEDIATE` transaction with `WHERE version = ? AND state = ?`; it is safe
//!   for multiple store instances / processes sharing one database file.
//! - [`JsonFilePersistence`] re-reads the file on every operation, writes via
//!   fsynced temp file + rename (+ directory fsync on Unix), and serializes
//!   writers **within one instance** only. It is a single-writer demo backend;
//!   use SQLite when more than one instance or process can write.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use zwa_protocol::error::ProtocolError;
use zwa_protocol::lifecycle::{
    FailureReason, LifecycleEvent, SettlementTxId, TradeLifecycleState,
};
use zwa_protocol::numbers::{
    TradeAmount, TradeExpiry, TradeNonce, UnixSeconds, ZatoshiAmount,
};
use zwa_protocol::{
    AssetBaseBytes, MatcherFee, PolicyRoot, RecipientCommitment, TradeCommitment, TradeIntent,
};

use crate::checked::CheckedTrade;

/// Current schema version for persisted records.
///
/// Version 1 files/tables (which stored records that were rebuilt by replaying
/// transitions) are rejected without migration.
pub const PERSISTENCE_SCHEMA_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the persistence layer. Every variant means "fail closed".
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PersistenceError {
    #[error("io error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),

    #[error("unknown schema version {got}, expected {expected} — rejecting without migration")]
    UnknownSchemaVersion { got: u32, expected: u32 },

    #[error("corrupted record: {0}")]
    CorruptedRecord(String),

    /// Compare-and-swap lost: the stored record is not the expected one (a
    /// concurrent writer advanced it, or it already exists on insert).
    #[error("compare-and-swap conflict for commitment {commitment}")]
    Conflict { commitment: String },

    /// Backend is not available in this build/configuration.
    #[error("persistence backend not configured: {0}")]
    NotConfigured(String),
}

/// Errors from the persistent replay store — protocol or persistence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("persistence error: {0}")]
    Persistence(#[from] PersistenceError),
}

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

/// Authoritative persisted replay record (M2-owned).
///
/// Carries every field of the frozen `zwa_protocol::TradeRecord` plus a CAS
/// `version`. Fields are private; records are produced only by
/// [`PersistentReplayStore`] transitions or by strict decoding of persisted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayRecord {
    commitment: TradeCommitment,
    intent: TradeIntent,
    state: TradeLifecycleState,
    failure_reason: Option<FailureReason>,
    prior_txid: Option<SettlementTxId>,
    retry_count: u32,
    version: u64,
}

impl ReplayRecord {
    /// Fresh `CREATED` record at version 1, only from a checked trade.
    fn created(checked: &CheckedTrade) -> Self {
        Self {
            commitment: checked.commitment(),
            intent: checked.intent(),
            state: TradeLifecycleState::Created,
            failure_reason: None,
            prior_txid: None,
            retry_count: 0,
            version: 1,
        }
    }

    /// Trade commitment this record is keyed by.
    #[must_use]
    pub const fn commitment(&self) -> TradeCommitment {
        self.commitment
    }

    /// Canonical intent stored at `CREATED`.
    #[must_use]
    pub const fn intent(&self) -> TradeIntent {
        self.intent
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> TradeLifecycleState {
        self.state
    }

    /// Reason for the current or last `FAILED` state, if any.
    #[must_use]
    pub const fn failure_reason(&self) -> Option<FailureReason> {
        self.failure_reason
    }

    /// Txid of the last submission, if one was recorded.
    #[must_use]
    pub const fn prior_txid(&self) -> Option<SettlementTxId> {
        self.prior_txid
    }

    /// Number of successful controlled retries already consumed.
    #[must_use]
    pub const fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Compare-and-swap version; incremented by every committed transition.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
}

// ---------------------------------------------------------------------------
// Transition function (mirror of frozen ReplayStore)
// ---------------------------------------------------------------------------

/// A lifecycle operation, one per frozen `ReplayStore` transition method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Verify(UnixSeconds),
    AcquireConstruction(UnixSeconds),
    Submit(SettlementTxId, UnixSeconds),
    Confirm,
    Consume,
    Fail(FailureReason),
    Expire(UnixSeconds),
    Retry(Option<SettlementTxId>, UnixSeconds),
}

/// Result of applying an [`Op`] to a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    /// Transition succeeded; persist `0` and return it.
    Commit(ReplayRecord),
    /// Frozen semantics mutate the record (to `EXPIRED`) *and* reject: persist
    /// `0`, then return the error.
    CommitThenReject(ReplayRecord, ProtocolError),
    /// Rejected without mutation.
    Reject(ProtocolError),
}

fn reject(from: TradeLifecycleState, attempted: LifecycleEvent) -> ProtocolError {
    if from.is_consumed() {
        ProtocolError::AlreadyConsumed
    } else {
        ProtocolError::InvalidStateTransition { from, attempted }
    }
}

/// Mirrors frozen `expire_if_elapsed`: returns the `EXPIRED` record and error
/// when `now` is strictly after the committed expiry.
fn expire_if_elapsed(record: &ReplayRecord, now: UnixSeconds) -> Option<Step> {
    if record.intent.is_expired_at(now) {
        let mut expired = *record;
        expired.state = TradeLifecycleState::Expired;
        return Some(Step::CommitThenReject(
            bump(expired, record.version),
            ProtocolError::ExpiredTrade {
                expiry: record.intent.expiry.get(),
                now: now.get(),
            },
        ));
    }
    None
}

fn bump(mut next: ReplayRecord, from_version: u64) -> ReplayRecord {
    // A record admits a bounded number of transitions (the retry budget bounds
    // the only cycle), so this can never saturate in practice.
    next.version = from_version.saturating_add(1);
    next
}

/// Pure lifecycle transition with the exact semantics of frozen `ReplayStore`.
pub(crate) fn apply(record: &ReplayRecord, op: Op, max_retries: u32) -> Step {
    use TradeLifecycleState as S;

    // Frozen: every transition starts with `deny_consumed`.
    if record.state.is_consumed() {
        return Step::Reject(ProtocolError::AlreadyConsumed);
    }
    let mut next = *record;
    match op {
        Op::Verify(now) => {
            if record.state != S::Created {
                return Step::Reject(reject(record.state, LifecycleEvent::Verify));
            }
            if let Some(step) = expire_if_elapsed(record, now) {
                return step;
            }
            next.state = S::Verified;
            next.failure_reason = None;
        }
        Op::AcquireConstruction(now) => {
            if record.state != S::Verified {
                return Step::Reject(reject(record.state, LifecycleEvent::AcquireConstruction));
            }
            if let Some(step) = expire_if_elapsed(record, now) {
                return step;
            }
            next.state = S::SettlementConstructed;
        }
        Op::Submit(txid, now) => {
            if record.state != S::SettlementConstructed {
                return Step::Reject(reject(record.state, LifecycleEvent::Submit));
            }
            if let Some(step) = expire_if_elapsed(record, now) {
                return step;
            }
            next.state = S::Submitted;
            next.prior_txid = Some(txid);
        }
        Op::Confirm => {
            if record.state != S::Submitted {
                return Step::Reject(reject(record.state, LifecycleEvent::Confirm));
            }
            next.state = S::Confirmed;
        }
        Op::Consume => {
            if record.state != S::Confirmed {
                return Step::Reject(reject(record.state, LifecycleEvent::Consume));
            }
            next.state = S::Consumed;
        }
        Op::Fail(reason) => {
            if !matches!(
                record.state,
                S::Created | S::Verified | S::SettlementConstructed | S::Submitted
            ) {
                return Step::Reject(reject(record.state, LifecycleEvent::Fail));
            }
            if record.state != S::Submitted {
                next.prior_txid = None;
            }
            next.state = S::Failed;
            next.failure_reason = Some(reason);
        }
        Op::Expire(now) => {
            if !matches!(
                record.state,
                S::Created | S::Verified | S::SettlementConstructed | S::Failed
            ) {
                return Step::Reject(reject(record.state, LifecycleEvent::Expire));
            }
            if !record.intent.is_expired_at(now) {
                return Step::Reject(reject(record.state, LifecycleEvent::Expire));
            }
            next.state = S::Expired;
        }
        Op::Retry(acknowledged_txid, now) => {
            if record.state != S::Failed {
                return Step::Reject(reject(record.state, LifecycleEvent::Retry));
            }
            if let Some(step) = expire_if_elapsed(record, now) {
                return step;
            }
            if record.retry_count >= max_retries {
                return Step::Reject(ProtocolError::RetryBudgetExhausted {
                    attempts: record.retry_count,
                    max: max_retries,
                });
            }
            if record.prior_txid != acknowledged_txid {
                return Step::Reject(ProtocolError::UnreconciledPriorSubmission);
            }
            next.state = S::Created;
            next.failure_reason = None;
            next.prior_txid = None;
            next.retry_count = record.retry_count.saturating_add(1);
        }
    }
    Step::Commit(bump(next, record.version))
}

// ---------------------------------------------------------------------------
// Persistence trait
// ---------------------------------------------------------------------------

/// Pluggable, authoritative replay persistence.
///
/// Implementations must be linearizable per commitment and must only return
/// `Ok` from [`compare_and_swap`](Self::compare_and_swap) once the write is
/// durable for that backend.
pub trait ReplayPersistence: Send + Sync {
    /// Loads the record for `commitment`.
    ///
    /// `Ok(None)` means "definitely absent". Any read, decode, or integrity
    /// failure must be `Err` (fail closed), never `Ok(None)`.
    fn load(&self, commitment: TradeCommitment) -> Result<Option<ReplayRecord>, PersistenceError>;

    /// Loads and validates every record (startup integrity check).
    fn load_all(&self) -> Result<Vec<ReplayRecord>, PersistenceError>;

    /// Atomic conditional write.
    ///
    /// - `expected == None`: insert `new` only if no record exists for
    ///   `new.commitment()`.
    /// - `expected == Some(e)`: replace only if the stored record currently has
    ///   `e.state()` **and** `e.version()`.
    ///
    /// On mismatch returns [`PersistenceError::Conflict`] and leaves storage
    /// unchanged.
    fn compare_and_swap(
        &self,
        expected: Option<&ReplayRecord>,
        new: &ReplayRecord,
    ) -> Result<(), PersistenceError>;
}

/// Shared backends: several stores (e.g. worker threads) may share one
/// persistence instance; CAS in the backend arbitrates between them.
impl<T: ReplayPersistence + ?Sized> ReplayPersistence for std::sync::Arc<T> {
    fn load(&self, commitment: TradeCommitment) -> Result<Option<ReplayRecord>, PersistenceError> {
        (**self).load(commitment)
    }

    fn load_all(&self) -> Result<Vec<ReplayRecord>, PersistenceError> {
        (**self).load_all()
    }

    fn compare_and_swap(
        &self,
        expected: Option<&ReplayRecord>,
        new: &ReplayRecord,
    ) -> Result<(), PersistenceError> {
        (**self).compare_and_swap(expected, new)
    }
}

fn conflict(commitment: TradeCommitment) -> PersistenceError {
    PersistenceError::Conflict {
        commitment: commitment.to_string(),
    }
}

/// Shared CAS precondition over a map snapshot.
fn check_expected(
    current: Option<&ReplayRecord>,
    expected: Option<&ReplayRecord>,
    new: &ReplayRecord,
) -> Result<(), PersistenceError> {
    match (current, expected) {
        (None, None) => Ok(()),
        (Some(cur), Some(exp)) if cur.state == exp.state && cur.version == exp.version => Ok(()),
        _ => Err(conflict(new.commitment)),
    }
}

// ---------------------------------------------------------------------------
// In-memory backend
// ---------------------------------------------------------------------------

/// In-memory persistence — `BTreeMap` behind `Mutex`, for tests and demos.
///
/// Not durable across process restart. `Clone` takes an independent snapshot.
#[derive(Debug, Default)]
pub struct InMemoryPersistence {
    inner: Mutex<BTreeMap<TradeCommitment, ReplayRecord>>,
}

impl Clone for InMemoryPersistence {
    fn clone(&self) -> Self {
        // A poisoned lock cannot hide a half-applied write (every write is a
        // single map insert), so the snapshot is taken from the inner data.
        let data = self
            .inner
            .lock()
            .map_or_else(|e| e.into_inner().clone(), |g| g.clone());
        Self {
            inner: Mutex::new(data),
        }
    }
}

impl InMemoryPersistence {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn guard(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<TradeCommitment, ReplayRecord>>, PersistenceError>
    {
        self.inner
            .lock()
            .map_err(|_| PersistenceError::Io("in-memory persistence lock poisoned".to_string()))
    }
}

impl ReplayPersistence for InMemoryPersistence {
    fn load(&self, commitment: TradeCommitment) -> Result<Option<ReplayRecord>, PersistenceError> {
        Ok(self.guard()?.get(&commitment).copied())
    }

    fn load_all(&self) -> Result<Vec<ReplayRecord>, PersistenceError> {
        Ok(self.guard()?.values().copied().collect())
    }

    fn compare_and_swap(
        &self,
        expected: Option<&ReplayRecord>,
        new: &ReplayRecord,
    ) -> Result<(), PersistenceError> {
        let mut guard = self.guard()?;
        check_expected(guard.get(&new.commitment), expected, new)?;
        guard.insert(new.commitment, *new);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Strict codec (shared by JSON file and SQLite backends)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedIntent {
    offered_asset_hex: String,
    offered_amount: u64,
    requested_asset_hex: String,
    requested_amount: u64,
    recipient_commitment_decimal: String,
    policy_root_decimal: String,
    matcher_fee_amount: u64,
    matcher_fee_recipient_commitment_decimal: String,
    nonce: u64,
    expiry: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRecord {
    commitment_decimal: String,
    intent: PersistedIntent,
    state: String,
    failure_reason: Option<String>,
    prior_txid_hex: Option<String>,
    retry_count: u32,
    version: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedFile {
    schema_version: u32,
    records: Vec<PersistedRecord>,
}

fn state_tag(state: TradeLifecycleState) -> &'static str {
    match state {
        TradeLifecycleState::Created => "CREATED",
        TradeLifecycleState::Verified => "VERIFIED",
        TradeLifecycleState::SettlementConstructed => "SETTLEMENT_CONSTRUCTED",
        TradeLifecycleState::Submitted => "SUBMITTED",
        TradeLifecycleState::Confirmed => "CONFIRMED",
        TradeLifecycleState::Consumed => "CONSUMED",
        TradeLifecycleState::Expired => "EXPIRED",
        TradeLifecycleState::Failed => "FAILED",
    }
}

fn parse_state(tag: &str) -> Result<TradeLifecycleState, PersistenceError> {
    Ok(match tag {
        "CREATED" => TradeLifecycleState::Created,
        "VERIFIED" => TradeLifecycleState::Verified,
        "SETTLEMENT_CONSTRUCTED" => TradeLifecycleState::SettlementConstructed,
        "SUBMITTED" => TradeLifecycleState::Submitted,
        "CONFIRMED" => TradeLifecycleState::Confirmed,
        "CONSUMED" => TradeLifecycleState::Consumed,
        "EXPIRED" => TradeLifecycleState::Expired,
        "FAILED" => TradeLifecycleState::Failed,
        other => {
            return Err(PersistenceError::CorruptedRecord(format!(
                "unknown state tag {other:?}"
            )))
        }
    })
}

fn failure_tag(reason: FailureReason) -> &'static str {
    match reason {
        FailureReason::VerificationRejected => "VERIFICATION_REJECTED",
        FailureReason::ConstructionFailed => "CONSTRUCTION_FAILED",
        FailureReason::SubmissionFailed => "SUBMISSION_FAILED",
        FailureReason::ConfirmationFailed => "CONFIRMATION_FAILED",
    }
}

fn parse_failure(tag: &str) -> Result<FailureReason, PersistenceError> {
    Ok(match tag {
        "VERIFICATION_REJECTED" => FailureReason::VerificationRejected,
        "CONSTRUCTION_FAILED" => FailureReason::ConstructionFailed,
        "SUBMISSION_FAILED" => FailureReason::SubmissionFailed,
        "CONFIRMATION_FAILED" => FailureReason::ConfirmationFailed,
        other => {
            return Err(PersistenceError::CorruptedRecord(format!(
                "unknown failure reason tag {other:?}"
            )))
        }
    })
}

fn parse_txid(text: &str) -> Result<SettlementTxId, PersistenceError> {
    let bytes = hex::decode(text)
        .map_err(|e| PersistenceError::CorruptedRecord(format!("prior_txid hex: {e}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        PersistenceError::CorruptedRecord("prior_txid must be exactly 32 bytes".to_string())
    })?;
    if hex::encode(arr) != text {
        return Err(PersistenceError::CorruptedRecord(
            "prior_txid must be lowercase canonical hex".to_string(),
        ));
    }
    Ok(SettlementTxId::new(arr))
}

fn encode_intent(intent: &TradeIntent) -> PersistedIntent {
    PersistedIntent {
        offered_asset_hex: intent.offered_asset.to_hex(),
        offered_amount: intent.offered_amount.get(),
        requested_asset_hex: intent.requested_asset.to_hex(),
        requested_amount: intent.requested_amount.get(),
        recipient_commitment_decimal: intent.recipient_commitment.to_string(),
        policy_root_decimal: intent.policy_root.to_string(),
        matcher_fee_amount: intent.matcher_fee.amount.get(),
        matcher_fee_recipient_commitment_decimal: intent.matcher_fee.recipient_commitment.to_string(),
        nonce: intent.nonce.get(),
        expiry: intent.expiry.get(),
    }
}

fn decode_intent(p: &PersistedIntent) -> Result<TradeIntent, PersistenceError> {
    let bad = |field: &str, e: &dyn std::fmt::Display| {
        PersistenceError::CorruptedRecord(format!("{field}: {e}"))
    };
    Ok(TradeIntent {
        offered_asset: AssetBaseBytes::from_hex(&p.offered_asset_hex)
            .map_err(|e| bad("offered_asset", &e))?,
        offered_amount: TradeAmount::new(p.offered_amount),
        requested_asset: AssetBaseBytes::from_hex(&p.requested_asset_hex)
            .map_err(|e| bad("requested_asset", &e))?,
        requested_amount: TradeAmount::new(p.requested_amount),
        recipient_commitment: RecipientCommitment::from_decimal_str(&p.recipient_commitment_decimal)
            .map_err(|e| bad("recipient_commitment", &e))?,
        policy_root: PolicyRoot::from_decimal_str(&p.policy_root_decimal)
            .map_err(|e| bad("policy_root", &e))?,
        matcher_fee: MatcherFee::new(
            ZatoshiAmount::new(p.matcher_fee_amount),
            RecipientCommitment::from_decimal_str(&p.matcher_fee_recipient_commitment_decimal)
                .map_err(|e| bad("matcher_fee_recipient_commitment", &e))?,
        ),
        nonce: TradeNonce::new(p.nonce),
        expiry: TradeExpiry::new(p.expiry),
    })
}

fn encode_record(r: &ReplayRecord) -> PersistedRecord {
    PersistedRecord {
        commitment_decimal: r.commitment.to_string(),
        intent: encode_intent(&r.intent),
        state: state_tag(r.state).to_string(),
        failure_reason: r.failure_reason.map(|f| failure_tag(f).to_string()),
        prior_txid_hex: r.prior_txid.map(|t| hex::encode(t.as_bytes())),
        retry_count: r.retry_count,
        version: r.version,
    }
}

fn decode_record(p: &PersistedRecord) -> Result<ReplayRecord, PersistenceError> {
    let commitment = TradeCommitment::from_decimal_str(&p.commitment_decimal)
        .map_err(|e| PersistenceError::CorruptedRecord(format!("commitment: {e}")))?;
    let intent = decode_intent(&p.intent)?;
    // Integrity: the stored commitment must recompute from the stored intent
    // with the frozen TradeCommitmentV1 (same check as CheckedTrade::new).
    let checked = CheckedTrade::new(intent, commitment).map_err(|e| {
        PersistenceError::CorruptedRecord(format!("stored commitment does not match intent: {e}"))
    })?;
    if p.version == 0 {
        return Err(PersistenceError::CorruptedRecord(
            "version must be >= 1".to_string(),
        ));
    }
    Ok(ReplayRecord {
        commitment: checked.commitment(),
        intent: checked.intent(),
        state: parse_state(&p.state)?,
        failure_reason: p.failure_reason.as_deref().map(parse_failure).transpose()?,
        prior_txid: p.prior_txid_hex.as_deref().map(parse_txid).transpose()?,
        retry_count: p.retry_count,
        version: p.version,
    })
}

// ---------------------------------------------------------------------------
// JSON file backend
// ---------------------------------------------------------------------------

/// File-backed JSON persistence — survives restart; single-writer.
///
/// Format: `{"schema_version":2,"records":[...]}`. Missing file = empty store.
/// An empty, corrupted, legacy (bare array / schema 1) or unknown-version file
/// is an error; the file is never overwritten or migrated in that case.
///
/// Every operation re-reads the file, so sequential use from several instances
/// sees each other's writes, but concurrent writers from different instances or
/// processes are **not** serialized. Use [`SqlitePersistence`] for that.
#[derive(Debug)]
pub struct JsonFilePersistence {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl JsonFilePersistence {
    /// Opens persistence at `path`, validating any existing file.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable, corrupted, legacy, or unknown-version
    /// files, or any record that fails strict decoding.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, PersistenceError> {
        let this = Self {
            path: path.as_ref().to_path_buf(),
            write_lock: Mutex::new(()),
        };
        this.read_map()?;
        Ok(this)
    }

    /// Path of the file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn tmp_path(&self) -> PathBuf {
        self.path.with_extension("tmp")
    }

    fn read_map(&self) -> Result<BTreeMap<TradeCommitment, ReplayRecord>, PersistenceError> {
        let data = match fs::read_to_string(&self.path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => {
                return Err(PersistenceError::Io(format!(
                    "read {}: {e}",
                    self.path.display()
                )))
            }
        };
        // Check the version before strict decoding so that legacy/unknown
        // versions report UnknownSchemaVersion rather than a field error.
        let value: serde_json::Value = serde_json::from_str(&data).map_err(|e| {
            PersistenceError::Deserialization(format!(
                "corrupted persistence file {}: {e}",
                self.path.display()
            ))
        })?;
        let version = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                PersistenceError::Deserialization(format!(
                    "{}: missing schema_version (legacy or foreign format)",
                    self.path.display()
                ))
            })?;
        if version != u64::from(PERSISTENCE_SCHEMA_VERSION) {
            return Err(PersistenceError::UnknownSchemaVersion {
                got: u32::try_from(version).unwrap_or(u32::MAX),
                expected: PERSISTENCE_SCHEMA_VERSION,
            });
        }
        let file: PersistedFile = serde_json::from_value(value)
            .map_err(|e| PersistenceError::Deserialization(format!("{}: {e}", self.path.display())))?;
        let mut map = BTreeMap::new();
        for p in &file.records {
            let rec = decode_record(p)?;
            if map.insert(rec.commitment, rec).is_some() {
                return Err(PersistenceError::CorruptedRecord(format!(
                    "duplicate record for commitment {}",
                    rec.commitment
                )));
            }
        }
        Ok(map)
    }

    fn write_map(
        &self,
        map: &BTreeMap<TradeCommitment, ReplayRecord>,
    ) -> Result<(), PersistenceError> {
        let file = PersistedFile {
            schema_version: PERSISTENCE_SCHEMA_VERSION,
            records: map.values().map(encode_record).collect(),
        };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|e| PersistenceError::Serialization(format!("{e}")))?;
        let tmp = self.tmp_path();
        let io = |what: &str, e: std::io::Error| PersistenceError::Io(format!("{what}: {e}"));
        {
            let mut f = fs::File::create(&tmp).map_err(|e| io("create tmp", e))?;
            f.write_all(&json).map_err(|e| io("write tmp", e))?;
            f.sync_all().map_err(|e| io("fsync tmp", e))?;
        }
        fs::rename(&tmp, &self.path).map_err(|e| io("rename tmp", e))?;
        #[cfg(unix)]
        {
            let dir = match self.path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            fs::File::open(dir)
                .and_then(|d| d.sync_all())
                .map_err(|e| io("fsync dir", e))?;
        }
        Ok(())
    }
}

impl ReplayPersistence for JsonFilePersistence {
    fn load(&self, commitment: TradeCommitment) -> Result<Option<ReplayRecord>, PersistenceError> {
        Ok(self.read_map()?.get(&commitment).copied())
    }

    fn load_all(&self) -> Result<Vec<ReplayRecord>, PersistenceError> {
        Ok(self.read_map()?.into_values().collect())
    }

    fn compare_and_swap(
        &self,
        expected: Option<&ReplayRecord>,
        new: &ReplayRecord,
    ) -> Result<(), PersistenceError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| PersistenceError::Io("json persistence lock poisoned".to_string()))?;
        let mut map = self.read_map()?;
        check_expected(map.get(&new.commitment), expected, new)?;
        map.insert(new.commitment, *new);
        self.write_map(&map)
    }
}

// ---------------------------------------------------------------------------
// SQLite backend
// ---------------------------------------------------------------------------

/// SQLite persistence (feature `sqlite`) — multi-instance safe CAS.
///
/// ```sql
/// CREATE TABLE IF NOT EXISTS replay_records_v2 (
///   commitment     TEXT PRIMARY KEY NOT NULL,
///   version        INTEGER NOT NULL,
///   state          TEXT NOT NULL,
///   data           TEXT NOT NULL,   -- strict JSON of the full record
///   schema_version INTEGER NOT NULL
/// )
/// ```
///
/// Writes run in a `BEGIN IMMEDIATE` transaction; updates are
/// `UPDATE … WHERE commitment = ? AND version = ? AND state = ?` and succeed
/// only if exactly one row changed. `synchronous = FULL`. A legacy v1 `replay`
/// table is rejected without migration.
#[cfg(feature = "sqlite")]
#[derive(Debug)]
pub struct SqlitePersistence {
    path: PathBuf,
    conn: Mutex<rusqlite::Connection>,
}

#[cfg(feature = "sqlite")]
fn sql_err(what: &str, e: rusqlite::Error) -> PersistenceError {
    PersistenceError::Io(format!("sqlite {what}: {e}"))
}

#[cfg(feature = "sqlite")]
impl SqlitePersistence {
    /// Opens or creates the database at `path` and validates every row.
    ///
    /// # Errors
    ///
    /// SQLite errors, a legacy v1 table, or any row failing strict decoding.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, PersistenceError> {
        let path = path.as_ref().to_path_buf();
        let conn = rusqlite::Connection::open(&path).map_err(|e| sql_err("open", e))?;
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(|e| sql_err("busy_timeout", e))?;
        conn.execute_batch(
            "PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS replay_records_v2 (
                 commitment     TEXT PRIMARY KEY NOT NULL,
                 version        INTEGER NOT NULL,
                 state          TEXT NOT NULL,
                 data           TEXT NOT NULL,
                 schema_version INTEGER NOT NULL
             );",
        )
        .map_err(|e| sql_err("init", e))?;
        let legacy: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'replay'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| sql_err("legacy check", e))?;
        if legacy != 0 {
            return Err(PersistenceError::UnknownSchemaVersion {
                got: 1,
                expected: PERSISTENCE_SCHEMA_VERSION,
            });
        }
        let this = Self {
            path,
            conn: Mutex::new(conn),
        };
        this.load_all()?;
        Ok(this)
    }

    /// Path of the database file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, PersistenceError> {
        self.conn
            .lock()
            .map_err(|_| PersistenceError::Io("sqlite connection lock poisoned".to_string()))
    }

    fn decode_row(
        key: &str,
        version: i64,
        state: &str,
        data: &str,
        schema_version: i64,
    ) -> Result<ReplayRecord, PersistenceError> {
        if schema_version != i64::from(PERSISTENCE_SCHEMA_VERSION) {
            return Err(PersistenceError::UnknownSchemaVersion {
                got: u32::try_from(schema_version).unwrap_or(u32::MAX),
                expected: PERSISTENCE_SCHEMA_VERSION,
            });
        }
        let p: PersistedRecord = serde_json::from_str(data)
            .map_err(|e| PersistenceError::Deserialization(format!("row {key}: {e}")))?;
        let rec = decode_record(&p)?;
        let consistent = rec.commitment.to_string() == key
            && i64::try_from(rec.version).ok() == Some(version)
            && state_tag(rec.state) == state;
        if !consistent {
            return Err(PersistenceError::CorruptedRecord(format!(
                "row {key}: key/version/state columns disagree with record data"
            )));
        }
        Ok(rec)
    }
}

#[cfg(feature = "sqlite")]
impl ReplayPersistence for SqlitePersistence {
    fn load(&self, commitment: TradeCommitment) -> Result<Option<ReplayRecord>, PersistenceError> {
        use rusqlite::OptionalExtension;
        let key = commitment.to_string();
        let conn = self.conn()?;
        let row: Option<(i64, String, String, i64)> = conn
            .query_row(
                "SELECT version, state, data, schema_version FROM replay_records_v2 WHERE commitment = ?1",
                rusqlite::params![key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|e| sql_err("load", e))?;
        row.map(|(version, state, data, sv)| Self::decode_row(&key, version, &state, &data, sv))
            .transpose()
    }

    fn load_all(&self) -> Result<Vec<ReplayRecord>, PersistenceError> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT commitment, version, state, data, schema_version FROM replay_records_v2 ORDER BY commitment",
            )
            .map_err(|e| sql_err("prepare", e))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| sql_err("query", e))?;
        let mut out = Vec::new();
        for row in rows {
            let (key, version, state, data, sv) = row.map_err(|e| sql_err("row", e))?;
            out.push(Self::decode_row(&key, version, &state, &data, sv)?);
        }
        Ok(out)
    }

    fn compare_and_swap(
        &self,
        expected: Option<&ReplayRecord>,
        new: &ReplayRecord,
    ) -> Result<(), PersistenceError> {
        let key = new.commitment.to_string();
        let data = serde_json::to_string(&encode_record(new))
            .map_err(|e| PersistenceError::Serialization(format!("{e}")))?;
        let to_i64 = |v: u64| {
            i64::try_from(v).map_err(|_| PersistenceError::Serialization("version overflow".to_string()))
        };
        let new_version = to_i64(new.version)?;
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| sql_err("begin", e))?;
        let changed = match expected {
            None => tx
                .execute(
                    "INSERT OR IGNORE INTO replay_records_v2 (commitment, version, state, data, schema_version)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![key, new_version, state_tag(new.state), data, PERSISTENCE_SCHEMA_VERSION],
                )
                .map_err(|e| sql_err("insert", e))?,
            Some(exp) => tx
                .execute(
                    "UPDATE replay_records_v2
                     SET version = ?1, state = ?2, data = ?3, schema_version = ?4
                     WHERE commitment = ?5 AND version = ?6 AND state = ?7",
                    rusqlite::params![
                        new_version,
                        state_tag(new.state),
                        data,
                        PERSISTENCE_SCHEMA_VERSION,
                        key,
                        to_i64(exp.version)?,
                        state_tag(exp.state)
                    ],
                )
                .map_err(|e| sql_err("update", e))?,
        };
        if changed != 1 {
            // Dropping `tx` rolls back.
            return Err(conflict(new.commitment));
        }
        tx.commit().map_err(|e| sql_err("commit", e))
    }
}

// ---------------------------------------------------------------------------
// RocksDB placeholder
// ---------------------------------------------------------------------------

/// RocksDB persistence placeholder — every operation fails closed.
#[derive(Debug, Default)]
pub struct RocksDbPersistence;

impl RocksDbPersistence {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn unavailable() -> PersistenceError {
        PersistenceError::NotConfigured(
            "RocksDB persistence is not implemented; use SqlitePersistence".to_string(),
        )
    }
}

impl ReplayPersistence for RocksDbPersistence {
    fn load(&self, _commitment: TradeCommitment) -> Result<Option<ReplayRecord>, PersistenceError> {
        Err(Self::unavailable())
    }

    fn load_all(&self) -> Result<Vec<ReplayRecord>, PersistenceError> {
        Err(Self::unavailable())
    }

    fn compare_and_swap(
        &self,
        _expected: Option<&ReplayRecord>,
        _new: &ReplayRecord,
    ) -> Result<(), PersistenceError> {
        Err(Self::unavailable())
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Persistent replay store: frozen lifecycle semantics over an authoritative,
/// CAS-capable backend.
///
/// Holds no lifecycle state of its own. The commitment-keyed `create_checked`,
/// `verify` and `acquire_construction` are crate-private and used only by
/// [`crate::gate::MatcherGate`] after every gate check has passed (F-07).
/// Other crates can create, verify or lock a trade only by presenting the
/// resulting `MatcherApproval` (`create_from_approval`, `verify_approved`,
/// `acquire_construction_approved`).
#[derive(Debug)]
pub struct PersistentReplayStore<P: ReplayPersistence> {
    persistence: P,
    max_retries: u32,
}

impl<P: ReplayPersistence> PersistentReplayStore<P> {
    /// Builds a store over `persistence`, validating every stored record.
    ///
    /// # Errors
    ///
    /// Any persistence error (fail closed: a store is never built over data
    /// that cannot be fully decoded).
    pub fn new(persistence: P, max_retries: u32) -> Result<Self, ReplayError> {
        persistence.load_all()?;
        Ok(Self {
            persistence,
            max_retries,
        })
    }

    /// Builds a store over `persistence` **without** the startup scan.
    ///
    /// Still fail closed: every operation loads through the backend and a
    /// corrupted, legacy or unreadable record is an error on access (the JSON
    /// backend re-validates the whole file on every operation). Use [`new`](Self::new)
    /// when corruption of unrelated records should also stop startup.
    #[must_use]
    pub fn lazy(persistence: P, max_retries: u32) -> Self {
        Self {
            persistence,
            max_retries,
        }
    }

    /// Returns the persistence backend.
    #[must_use]
    pub fn persistence(&self) -> &P {
        &self.persistence
    }

    /// Configured retry bound.
    #[must_use]
    pub const fn max_retries(&self) -> u32 {
        self.max_retries
    }

    fn load_existing(&self, commitment: TradeCommitment) -> Result<ReplayRecord, ReplayError> {
        self.persistence
            .load(commitment)?
            .ok_or(ReplayError::Protocol(ProtocolError::UnknownTrade))
    }

    fn transition(&self, commitment: TradeCommitment, op: Op) -> Result<ReplayRecord, ReplayError> {
        let current = self.load_existing(commitment)?;
        match apply(&current, op, self.max_retries) {
            Step::Commit(next) => {
                self.persistence.compare_and_swap(Some(&current), &next)?;
                Ok(next)
            }
            Step::CommitThenReject(next, err) => {
                self.persistence.compare_and_swap(Some(&current), &next)?;
                Err(ReplayError::Protocol(err))
            }
            Step::Reject(err) => Err(ReplayError::Protocol(err)),
        }
    }

    /// Inserts a `CREATED` record from a checked trade (gate only).
    pub(crate) fn create_checked(&self, checked: &CheckedTrade) -> Result<ReplayRecord, ReplayError> {
        if let Some(existing) = self.persistence.load(checked.commitment())? {
            return Err(ReplayError::Protocol(reject(existing.state, LifecycleEvent::Create)));
        }
        let record = ReplayRecord::created(checked);
        self.persistence.compare_and_swap(None, &record)?;
        Ok(record)
    }

    /// `CREATED → VERIFIED` (gate only, after every check passed).
    pub(crate) fn verify(
        &self,
        commitment: TradeCommitment,
        now: UnixSeconds,
    ) -> Result<ReplayRecord, ReplayError> {
        self.transition(commitment, Op::Verify(now))
    }

    /// `VERIFIED → SETTLEMENT_CONSTRUCTED` compare-and-set lock (gate only).
    pub(crate) fn acquire_construction(
        &self,
        commitment: TradeCommitment,
        now: UnixSeconds,
    ) -> Result<ReplayRecord, ReplayError> {
        self.transition(commitment, Op::AcquireConstruction(now))
    }

    // --- Approval-gated API for downstream replay stores (settlement side) ---
    //
    // A `MatcherApproval` can only be produced by `MatcherGate::evaluate` after
    // every gate check passed for exactly `approval.commitment()`, so holding
    // one is the authorization to create / verify / lock that trade in another
    // replay store. There is no way to reach `VERIFIED` or
    // `SETTLEMENT_CONSTRUCTED` through the public API without an approval.

    /// Inserts a `CREATED` record for an approved trade.
    ///
    /// # Errors
    ///
    /// Duplicate / terminal record (frozen lifecycle error), persistence errors,
    /// CAS conflict.
    pub fn create_from_approval(
        &self,
        approval: &crate::gate::MatcherApproval,
    ) -> Result<ReplayRecord, ReplayError> {
        self.create_checked(approval.checked_trade())
    }

    /// `CREATED → VERIFIED` for an approved trade (expiry-gated).
    ///
    /// # Errors
    ///
    /// Frozen lifecycle errors, persistence errors, CAS conflict.
    pub fn verify_approved(
        &self,
        approval: &crate::gate::MatcherApproval,
        now: UnixSeconds,
    ) -> Result<ReplayRecord, ReplayError> {
        self.verify(approval.commitment(), now)
    }

    /// `VERIFIED → SETTLEMENT_CONSTRUCTED` for an approved trade — CAS lock,
    /// exactly one winner (expiry-gated).
    ///
    /// # Errors
    ///
    /// Frozen lifecycle errors, persistence errors, CAS conflict.
    pub fn acquire_construction_approved(
        &self,
        approval: &crate::gate::MatcherApproval,
        now: UnixSeconds,
    ) -> Result<ReplayRecord, ReplayError> {
        self.acquire_construction(approval.commitment(), now)
    }

    /// `SETTLEMENT_CONSTRUCTED → SUBMITTED`, recording `txid`.
    ///
    /// # Errors
    ///
    /// Frozen lifecycle errors, or persistence errors / CAS conflict.
    pub fn submit(
        &self,
        commitment: TradeCommitment,
        txid: SettlementTxId,
        now: UnixSeconds,
    ) -> Result<ReplayRecord, ReplayError> {
        self.transition(commitment, Op::Submit(txid, now))
    }

    /// `SUBMITTED → CONFIRMED`.
    ///
    /// # Errors
    ///
    /// Frozen lifecycle errors, or persistence errors / CAS conflict.
    pub fn confirm(&self, commitment: TradeCommitment) -> Result<ReplayRecord, ReplayError> {
        self.transition(commitment, Op::Confirm)
    }

    /// `CONFIRMED → CONSUMED` — terminal success.
    ///
    /// # Errors
    ///
    /// Frozen lifecycle errors, or persistence errors / CAS conflict.
    pub fn consume(&self, commitment: TradeCommitment) -> Result<ReplayRecord, ReplayError> {
        self.transition(commitment, Op::Consume)
    }

    /// Records failure from `CREATED`, `VERIFIED`, `SETTLEMENT_CONSTRUCTED`, `SUBMITTED`.
    ///
    /// # Errors
    ///
    /// Frozen lifecycle errors, or persistence errors / CAS conflict.
    pub fn fail(
        &self,
        commitment: TradeCommitment,
        reason: FailureReason,
    ) -> Result<ReplayRecord, ReplayError> {
        self.transition(commitment, Op::Fail(reason))
    }

    /// Terminal expiry from `CREATED`, `VERIFIED`, `SETTLEMENT_CONSTRUCTED`,
    /// `FAILED` when `now` is strictly after the committed expiry.
    ///
    /// # Errors
    ///
    /// Frozen lifecycle errors, or persistence errors / CAS conflict.
    pub fn expire(
        &self,
        commitment: TradeCommitment,
        now: UnixSeconds,
    ) -> Result<ReplayRecord, ReplayError> {
        self.transition(commitment, Op::Expire(now))
    }

    /// Controlled `FAILED → CREATED` retry. The trade must then pass the full
    /// gate again before it can become `VERIFIED`.
    ///
    /// # Errors
    ///
    /// Frozen lifecycle errors (expired, budget exhausted, unreconciled txid),
    /// or persistence errors / CAS conflict.
    pub fn retry_after_failure(
        &self,
        commitment: TradeCommitment,
        acknowledged_txid: Option<SettlementTxId>,
        now: UnixSeconds,
    ) -> Result<ReplayRecord, ReplayError> {
        self.transition(commitment, Op::Retry(acknowledged_txid, now))
    }

    /// Current state, read from the authoritative backend.
    ///
    /// # Errors
    ///
    /// Persistence errors (fail closed; never reported as "absent").
    pub fn state(&self, commitment: TradeCommitment) -> Result<Option<TradeLifecycleState>, ReplayError> {
        Ok(self.persistence.load(commitment)?.map(|r| r.state))
    }

    /// Full record, read from the authoritative backend.
    ///
    /// # Errors
    ///
    /// Persistence errors (fail closed; never reported as "absent").
    pub fn get(&self, commitment: TradeCommitment) -> Result<Option<ReplayRecord>, ReplayError> {
        Ok(self.persistence.load(commitment)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use zwa_protocol::{ReplayStore, TradeRecord};

    const PHASE_0G_GOLDEN: &str =
        "10187400613857124614980227259922066295752635539032972479692659299555113110306";
    /// Phase 0G `tradeB` (nonce 7002, receiver B binding).
    const PHASE_0G_TRADE_B: &str =
        "4141140993944283635059564795814979270169431233615041812756992202222578526061";
    const RECIPIENT_COMMITMENT_B: &str =
        "17161176809258390276335905180845953262038546658189533444510056676908192247925";

    const EXPIRY: u64 = 2_000_000_000;
    const BEFORE: UnixSeconds = UnixSeconds::new(EXPIRY - 100);
    const AT: UnixSeconds = UnixSeconds::new(EXPIRY);
    const AFTER: UnixSeconds = UnixSeconds::new(EXPIRY + 1);
    const T1: SettlementTxId = SettlementTxId::new([0x11; 32]);
    const T2: SettlementTxId = SettlementTxId::new([0x22; 32]);

    fn golden_intent() -> TradeIntent {
        TradeIntent {
            offered_asset: AssetBaseBytes::from_hex(
                "4889ad11564115f3655f7e434bffb23074d42aafd58cfecae32a5b5eafaf5301",
            )
            .unwrap(),
            offered_amount: TradeAmount::new(10),
            requested_asset: AssetBaseBytes::from_hex(
                "a7ac13ded8b51e7a59c400097b70fe6d5d855b30ad19b1897de1fd74721a9339",
            )
            .unwrap(),
            requested_amount: TradeAmount::new(6),
            recipient_commitment: RecipientCommitment::from_decimal_str(
                "13135279047718387126053226034283670929172341955108098732820235388025453726181",
            )
            .unwrap(),
            policy_root: PolicyRoot::from_decimal_str(
                "1514393595722546217125953798550283818470332284949639873172624869558831825935",
            )
            .unwrap(),
            matcher_fee: MatcherFee::new(
                ZatoshiAmount::new(5),
                RecipientCommitment::from_decimal_str(
                    "1800273984094439421343257609634901689467303577600258601269976617936586404380",
                )
                .unwrap(),
            ),
            nonce: TradeNonce::new(7001),
            expiry: TradeExpiry::new(EXPIRY),
        }
    }

    fn checked_trade() -> CheckedTrade {
        CheckedTrade::new(
            golden_intent(),
            TradeCommitment::from_decimal_str(PHASE_0G_GOLDEN).unwrap(),
        )
        .unwrap()
    }

    fn checked_trade_b() -> CheckedTrade {
        let mut intent = golden_intent();
        intent.nonce = TradeNonce::new(7002);
        intent.recipient_commitment =
            RecipientCommitment::from_decimal_str(RECIPIENT_COMMITMENT_B).unwrap();
        CheckedTrade::new(intent, TradeCommitment::from_decimal_str(PHASE_0G_TRADE_B).unwrap())
            .unwrap()
    }

    fn temp_path(tag: &str, ext: &str) -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "zwa-m2-{tag}-{}-{n}.{ext}",
            std::process::id()
        ));
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(p.with_extension("tmp"));
        p
    }

    fn mem_store() -> PersistentReplayStore<InMemoryPersistence> {
        PersistentReplayStore::new(InMemoryPersistence::new(), 3).unwrap()
    }

    fn is_conflict(e: &ReplayError) -> bool {
        matches!(e, ReplayError::Persistence(PersistenceError::Conflict { .. }))
    }

    /// Drives a store through a history that exercises every persisted field:
    /// trade A ends SUBMITTED with txid T2 after one retry that acknowledged T1;
    /// trade B ends EXPIRED while retaining failure reason ConstructionFailed.
    fn build_rich_history<P: ReplayPersistence>(store: &PersistentReplayStore<P>) -> (ReplayRecord, ReplayRecord) {
        let a = checked_trade();
        let c = a.commitment();
        store.create_checked(&a).unwrap();
        store.verify(c, BEFORE).unwrap();
        store.acquire_construction(c, BEFORE).unwrap();
        store.submit(c, T1, BEFORE).unwrap();
        let failed = store.fail(c, FailureReason::SubmissionFailed).unwrap();
        assert_eq!(failed.prior_txid(), Some(T1));
        assert_eq!(failed.failure_reason(), Some(FailureReason::SubmissionFailed));
        store.retry_after_failure(c, Some(T1), BEFORE).unwrap();
        store.verify(c, BEFORE).unwrap();
        store.acquire_construction(c, BEFORE).unwrap();
        let rec_a = store.submit(c, T2, AT).unwrap();
        assert_eq!(rec_a.state(), TradeLifecycleState::Submitted);
        assert_eq!(rec_a.prior_txid(), Some(T2));
        assert_eq!(rec_a.retry_count(), 1);

        let b = checked_trade_b();
        let cb = b.commitment();
        store.create_checked(&b).unwrap();
        store.verify(cb, BEFORE).unwrap();
        store.fail(cb, FailureReason::ConstructionFailed).unwrap();
        let rec_b = store.expire(cb, AFTER).unwrap();
        assert_eq!(rec_b.state(), TradeLifecycleState::Expired);
        assert_eq!(rec_b.failure_reason(), Some(FailureReason::ConstructionFailed));
        (rec_a, rec_b)
    }

    // --- Test-only persistence wrappers ---

    /// Fails every CAS while `fail` is set (persistence failure injection).
    #[derive(Debug)]
    struct FailingCas<P> {
        inner: P,
        fail: AtomicBool,
    }

    impl<P: ReplayPersistence> ReplayPersistence for FailingCas<P> {
        fn load(&self, c: TradeCommitment) -> Result<Option<ReplayRecord>, PersistenceError> {
            self.inner.load(c)
        }
        fn load_all(&self) -> Result<Vec<ReplayRecord>, PersistenceError> {
            self.inner.load_all()
        }
        fn compare_and_swap(&self, e: Option<&ReplayRecord>, n: &ReplayRecord) -> Result<(), PersistenceError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(PersistenceError::Io("injected write failure".to_string()));
            }
            self.inner.compare_and_swap(e, n)
        }
    }

    /// Holds every CAS at a barrier so that all racing stores have already
    /// loaded the same version before any of them writes.
    #[derive(Debug)]
    struct BarrierCas<P> {
        inner: P,
        barrier: Arc<Barrier>,
    }

    impl<P: ReplayPersistence> ReplayPersistence for BarrierCas<P> {
        fn load(&self, c: TradeCommitment) -> Result<Option<ReplayRecord>, PersistenceError> {
            self.inner.load(c)
        }
        fn load_all(&self) -> Result<Vec<ReplayRecord>, PersistenceError> {
            self.inner.load_all()
        }
        fn compare_and_swap(&self, e: Option<&ReplayRecord>, n: &ReplayRecord) -> Result<(), PersistenceError> {
            self.barrier.wait();
            self.inner.compare_and_swap(e, n)
        }
    }

    /// Races `acquire_construction` from two stores over backends `pa` / `pb`
    /// (which must share storage) on a VERIFIED record; exactly one must win.
    fn race_acquire<P: ReplayPersistence>(pa: P, pb: P, c: TradeCommitment, verified_version: u64) {
        let barrier = Arc::new(Barrier::new(2));
        let sa = PersistentReplayStore::new(BarrierCas { inner: pa, barrier: Arc::clone(&barrier) }, 3).unwrap();
        let sb = PersistentReplayStore::new(BarrierCas { inner: pb, barrier }, 3).unwrap();
        let (ra, rb) = std::thread::scope(|scope| {
            let ha = scope.spawn(|| sa.acquire_construction(c, BEFORE));
            let hb = scope.spawn(|| sb.acquire_construction(c, BEFORE));
            (ha.join().unwrap(), hb.join().unwrap())
        });
        let (winner, loser) = match (ra, rb) {
            (Ok(w), Err(l)) | (Err(l), Ok(w)) => (w, l),
            (a, b) => panic!("exactly one acquire must win, got {a:?} / {b:?}"),
        };
        assert!(is_conflict(&loser), "loser must be a CAS conflict, got {loser:?}");
        assert_eq!(winner.state(), TradeLifecycleState::SettlementConstructed);
        assert_eq!(winner.version(), verified_version + 1);
        let stored = sa.get(c).unwrap().unwrap();
        assert_eq!(stored, winner);
    }

    // --- Differential equivalence with frozen ReplayStore ---

    fn same(frozen: &TradeRecord, m2: &ReplayRecord) -> bool {
        frozen.commitment() == m2.commitment()
            && frozen.intent() == m2.intent()
            && frozen.state() == m2.state()
            && frozen.failure_reason() == m2.failure_reason()
            && frozen.prior_txid() == m2.prior_txid()
            && frozen.retry_count() == m2.retry_count()
    }

    fn call_frozen(store: &mut ReplayStore, c: TradeCommitment, op: Op) -> Result<TradeRecord, ProtocolError> {
        match op {
            Op::Verify(now) => store.verify(c, now),
            Op::AcquireConstruction(now) => store.acquire_construction(c, now),
            Op::Submit(txid, now) => store.submit(c, txid, now),
            Op::Confirm => store.confirm(c),
            Op::Consume => store.consume(c),
            Op::Fail(reason) => store.fail(c, reason),
            Op::Expire(now) => store.expire(c, now),
            Op::Retry(ack, now) => store.retry_after_failure(c, ack, now),
        }
    }

    fn explore(
        frozen: &ReplayStore,
        m2: &ReplayRecord,
        depth: usize,
        ops: &[Op],
        max: u32,
        visited: &mut usize,
        states_seen: &mut std::collections::BTreeSet<&'static str>,
    ) {
        states_seen.insert(state_tag(m2.state()));
        if depth == 0 {
            return;
        }
        let c = m2.commitment();
        for &op in ops {
            *visited += 1;
            let mut f = frozen.clone();
            let fres = call_frozen(&mut f, c, op);
            let f_after = *f.get(c).unwrap();
            match (fres, apply(m2, op, max)) {
                (Ok(fr), Step::Commit(next)) => {
                    assert!(same(&fr, &next), "{op:?} from {m2:?}: frozen {fr:?} vs m2 {next:?}");
                    assert!(same(&f_after, &next));
                    assert_eq!(next.version(), m2.version() + 1);
                    explore(&f, &next, depth - 1, ops, max, visited, states_seen);
                }
                (Err(fe), Step::CommitThenReject(next, me)) => {
                    assert_eq!(fe, me, "{op:?} from {m2:?}");
                    assert!(same(&f_after, &next), "{op:?}: frozen mutated to {f_after:?}, m2 {next:?}");
                    assert_eq!(next.version(), m2.version() + 1);
                    explore(&f, &next, depth - 1, ops, max, visited, states_seen);
                }
                (Err(fe), Step::Reject(me)) => {
                    assert_eq!(fe, me, "{op:?} from {m2:?}");
                    assert!(same(&f_after, m2), "{op:?}: frozen mutated on reject to {f_after:?}");
                }
                (f, m) => panic!("{op:?} from {m2:?}: frozen {f:?} vs m2 {m:?}"),
            }
        }
    }

    #[test]
    fn apply_matches_frozen_replay_store_exhaustively() {
        let ops = [
            Op::Verify(AT),
            Op::Verify(AFTER),
            Op::AcquireConstruction(AT),
            Op::AcquireConstruction(AFTER),
            Op::Submit(T1, AT),
            Op::Submit(T1, AFTER),
            Op::Confirm,
            Op::Consume,
            Op::Fail(FailureReason::VerificationRejected),
            Op::Fail(FailureReason::SubmissionFailed),
            Op::Expire(AT),
            Op::Expire(AFTER),
            Op::Retry(None, AT),
            Op::Retry(Some(T1), AT),
            Op::Retry(Some(T2), AT),
            Op::Retry(None, AFTER),
        ];
        let max_retries = 1;
        let checked = checked_trade();
        let mut frozen = ReplayStore::with_max_retries(max_retries);
        let created = frozen.create(checked.commitment(), checked.intent()).unwrap();
        let m2 = ReplayRecord::created(&checked);
        assert!(same(&created, &m2));
        let mut visited = 0;
        let mut states = std::collections::BTreeSet::new();
        explore(&frozen, &m2, 7, &ops, max_retries, &mut visited, &mut states);
        assert!(visited > 1_000, "explored {visited}");
        assert_eq!(states.len(), 8, "every lifecycle state must be reached: {states:?}");
    }

    // --- Store behaviour ---

    #[test]
    fn create_only_via_checked_trade_and_duplicates_rejected() {
        let store = mem_store();
        let checked = checked_trade();
        let rec = store.create_checked(&checked).unwrap();
        assert_eq!(rec.state(), TradeLifecycleState::Created);
        assert_eq!(rec.version(), 1);
        let err = store.create_checked(&checked).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::Protocol(ProtocolError::InvalidStateTransition {
                from: TradeLifecycleState::Created,
                attempted: LifecycleEvent::Create
            })
        ));
    }

    #[test]
    fn now_equal_expiry_is_valid_and_now_after_expiry_expires_persistently() {
        let store = mem_store();
        let c = checked_trade().commitment();
        store.create_checked(&checked_trade()).unwrap();
        assert_eq!(store.verify(c, AT).unwrap().state(), TradeLifecycleState::Verified);
        assert_eq!(
            store.acquire_construction(c, AT).unwrap().state(),
            TradeLifecycleState::SettlementConstructed
        );

        let store = mem_store();
        store.create_checked(&checked_trade()).unwrap();
        let err = store.verify(c, AFTER).unwrap_err();
        assert!(matches!(err, ReplayError::Protocol(ProtocolError::ExpiredTrade { .. })));
        assert_eq!(store.state(c).unwrap(), Some(TradeLifecycleState::Expired));
        // Terminal.
        assert!(store.fail(c, FailureReason::VerificationRejected).is_err());
        assert!(store.retry_after_failure(c, None, BEFORE).is_err());
    }

    #[test]
    fn consumed_is_terminal() {
        let store = mem_store();
        let c = checked_trade().commitment();
        store.create_checked(&checked_trade()).unwrap();
        store.verify(c, BEFORE).unwrap();
        store.acquire_construction(c, BEFORE).unwrap();
        store.submit(c, T1, BEFORE).unwrap();
        store.confirm(c).unwrap();
        store.consume(c).unwrap();
        for err in [
            store.fail(c, FailureReason::ConfirmationFailed).unwrap_err(),
            store.expire(c, AFTER).unwrap_err(),
            store.verify(c, BEFORE).unwrap_err(),
            store.create_checked(&checked_trade()).unwrap_err(),
        ] {
            assert!(matches!(err, ReplayError::Protocol(ProtocolError::AlreadyConsumed)), "{err:?}");
        }
    }

    #[test]
    fn retry_requires_exact_txid_ack_and_returns_to_created() {
        let store = mem_store();
        let c = checked_trade().commitment();
        store.create_checked(&checked_trade()).unwrap();
        store.verify(c, BEFORE).unwrap();
        store.acquire_construction(c, BEFORE).unwrap();
        store.submit(c, T1, BEFORE).unwrap();
        store.fail(c, FailureReason::SubmissionFailed).unwrap();
        for bad in [None, Some(T2)] {
            let err = store.retry_after_failure(c, bad, BEFORE).unwrap_err();
            assert!(matches!(err, ReplayError::Protocol(ProtocolError::UnreconciledPriorSubmission)));
        }
        let rec = store.retry_after_failure(c, Some(T1), BEFORE).unwrap();
        assert_eq!(rec.state(), TradeLifecycleState::Created);
        assert_eq!(rec.retry_count(), 1);
        assert_eq!(rec.prior_txid(), None);
        // CREATED: construction impossible until a fresh verification.
        assert!(store.acquire_construction(c, BEFORE).is_err());
    }

    #[test]
    fn stale_cas_is_rejected_by_every_backend() {
        fn check<P: ReplayPersistence>(store: PersistentReplayStore<P>) {
            let checked = checked_trade();
            let c = checked.commitment();
            let created = store.create_checked(&checked).unwrap();
            // Duplicate insert via raw CAS.
            assert!(matches!(
                store.persistence().compare_and_swap(None, &created),
                Err(PersistenceError::Conflict { .. })
            ));
            let verified = store.verify(c, BEFORE).unwrap();
            // Writer that still believes the record is `created`.
            let Step::Commit(stale_next) = apply(&created, Op::Fail(FailureReason::VerificationRejected), 3) else {
                panic!("fail from CREATED must commit");
            };
            assert!(matches!(
                store.persistence().compare_and_swap(Some(&created), &stale_next),
                Err(PersistenceError::Conflict { .. })
            ));
            assert_eq!(store.get(c).unwrap(), Some(verified));
        }
        check(mem_store());
        let path = temp_path("stale-cas", "json");
        check(PersistentReplayStore::new(JsonFilePersistence::new(&path).unwrap(), 3).unwrap());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn persistence_failure_does_not_advance_state() {
        let store = PersistentReplayStore::new(
            FailingCas { inner: InMemoryPersistence::new(), fail: AtomicBool::new(false) },
            3,
        )
        .unwrap();
        let checked = checked_trade();
        let c = checked.commitment();

        // Failed create leaves no record.
        store.persistence().fail.store(true, Ordering::SeqCst);
        assert!(matches!(store.create_checked(&checked), Err(ReplayError::Persistence(_))));
        assert_eq!(store.get(c).unwrap(), None);

        store.persistence().fail.store(false, Ordering::SeqCst);
        store.create_checked(&checked).unwrap();
        let verified = store.verify(c, BEFORE).unwrap();

        // Failed acquire leaves VERIFIED at the same version.
        store.persistence().fail.store(true, Ordering::SeqCst);
        assert!(matches!(store.acquire_construction(c, BEFORE), Err(ReplayError::Persistence(_))));
        assert_eq!(store.get(c).unwrap(), Some(verified));

        // Expiry transition that cannot be persisted surfaces the persistence
        // error (not ExpiredTrade) and leaves the record untouched.
        assert!(matches!(store.acquire_construction(c, AFTER), Err(ReplayError::Persistence(_))));
        assert_eq!(store.get(c).unwrap(), Some(verified));

        store.persistence().fail.store(false, Ordering::SeqCst);
        assert_eq!(
            store.acquire_construction(c, BEFORE).unwrap().state(),
            TradeLifecycleState::SettlementConstructed
        );
    }

    #[test]
    fn concurrent_cas_loser_fails_in_memory_shared_backend() {
        let shared = Arc::new(InMemoryPersistence::new());
        let setup = PersistentReplayStore::new(Arc::clone(&shared), 3).unwrap();
        let c = checked_trade().commitment();
        setup.create_checked(&checked_trade()).unwrap();
        let v = setup.verify(c, BEFORE).unwrap().version();
        race_acquire(Arc::clone(&shared), Arc::clone(&shared), c, v);
    }

    #[test]
    fn json_restart_round_trips_every_field_exactly() {
        let path = temp_path("json-restart", "json");
        let (a, b) = {
            let store = PersistentReplayStore::new(JsonFilePersistence::new(&path).unwrap(), 3).unwrap();
            build_rich_history(&store)
        };
        assert!(!path.with_extension("tmp").exists(), "temp file must not survive a write");
        let store = PersistentReplayStore::new(JsonFilePersistence::new(&path).unwrap(), 3).unwrap();
        assert_eq!(store.get(a.commitment()).unwrap(), Some(a));
        assert_eq!(store.get(b.commitment()).unwrap(), Some(b));
        // The reloaded record is live: it continues from the exact state.
        assert_eq!(store.confirm(a.commitment()).unwrap().prior_txid(), Some(T2));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn json_sequential_instances_see_each_others_writes() {
        let path = temp_path("json-two", "json");
        let s1 = PersistentReplayStore::new(JsonFilePersistence::new(&path).unwrap(), 3).unwrap();
        let s2 = PersistentReplayStore::new(JsonFilePersistence::new(&path).unwrap(), 3).unwrap();
        let c = checked_trade().commitment();
        s1.create_checked(&checked_trade()).unwrap();
        assert!(s2.create_checked(&checked_trade()).is_err());
        s2.verify(c, BEFORE).unwrap();
        assert_eq!(s1.state(c).unwrap(), Some(TradeLifecycleState::Verified));
        let _ = fs::remove_file(&path);
    }

    fn rewrite_json(path: &Path, f: impl FnOnce(&mut serde_json::Value)) {
        let mut v: serde_json::Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        f(&mut v);
        fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
    }

    #[test]
    fn json_load_failures_fail_closed() {
        let path = temp_path("json-bad", "json");
        let store = PersistentReplayStore::new(JsonFilePersistence::new(&path).unwrap(), 3).unwrap();
        let c = checked_trade().commitment();
        store.create_checked(&checked_trade()).unwrap();
        let good = fs::read_to_string(&path).unwrap();

        // Corruption after open: reads error, never "absent".
        fs::write(&path, b"{ not json").unwrap();
        assert!(store.state(c).is_err());
        assert!(store.get(c).is_err());
        assert!(store.verify(c, BEFORE).is_err());
        assert!(JsonFilePersistence::new(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"{ not json", "no destructive rewrite");

        type Mutation = Box<dyn Fn(&mut serde_json::Value)>;
        let cases: Vec<(&str, Mutation)> = vec![
            ("unknown state", Box::new(|v: &mut serde_json::Value| v["records"][0]["state"] = "APPROVED".into())),
            ("unknown failure", Box::new(|v: &mut serde_json::Value| v["records"][0]["failure_reason"] = "OOPS".into())),
            ("bad txid", Box::new(|v: &mut serde_json::Value| v["records"][0]["prior_txid_hex"] = "abcd".into())),
            ("tampered commitment", Box::new(|v: &mut serde_json::Value| v["records"][0]["commitment_decimal"] = PHASE_0G_TRADE_B.into())),
            ("tampered intent", Box::new(|v: &mut serde_json::Value| v["records"][0]["intent"]["offered_amount"] = 11.into())),
            ("unknown field", Box::new(|v: &mut serde_json::Value| v["records"][0]["extra"] = 1.into())),
            ("zero version", Box::new(|v: &mut serde_json::Value| v["records"][0]["version"] = 0.into())),
            ("duplicate", Box::new(|v: &mut serde_json::Value| {
                let r = v["records"][0].clone();
                v["records"].as_array_mut().unwrap().push(r);
            })),
        ];
        for (name, mutate) in cases {
            fs::write(&path, &good).unwrap();
            rewrite_json(&path, |v| mutate(v));
            assert!(JsonFilePersistence::new(&path).is_err(), "{name} must fail to open");
            assert!(store.get(c).is_err(), "{name} must fail to load");
        }

        // Legacy / foreign formats.
        fs::write(&path, &good).unwrap();
        rewrite_json(&path, |v| v["schema_version"] = 1.into());
        assert!(matches!(
            JsonFilePersistence::new(&path),
            Err(PersistenceError::UnknownSchemaVersion { got: 1, .. })
        ));
        fs::write(&path, b"[]").unwrap();
        assert!(JsonFilePersistence::new(&path).is_err(), "legacy bare array rejected");
        fs::write(&path, b"").unwrap();
        assert!(JsonFilePersistence::new(&path).is_err(), "empty file rejected");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rocksdb_placeholder_fails_closed() {
        assert!(matches!(
            PersistentReplayStore::new(RocksDbPersistence::new(), 3),
            Err(ReplayError::Persistence(PersistenceError::NotConfigured(_)))
        ));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_restart_round_trips_every_field_exactly() {
        let path = temp_path("sqlite-restart", "db");
        let (a, b) = {
            let store = PersistentReplayStore::new(SqlitePersistence::new(&path).unwrap(), 3).unwrap();
            build_rich_history(&store)
        };
        let store = PersistentReplayStore::new(SqlitePersistence::new(&path).unwrap(), 3).unwrap();
        assert_eq!(store.get(a.commitment()).unwrap(), Some(a));
        assert_eq!(store.get(b.commitment()).unwrap(), Some(b));
        let all = store.persistence().load_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(store.confirm(a.commitment()).unwrap().prior_txid(), Some(T2));
        let _ = fs::remove_file(&path);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_two_instances_same_db_concurrent_cas_loser_fails() {
        let path = temp_path("sqlite-race", "db");
        let setup = PersistentReplayStore::new(SqlitePersistence::new(&path).unwrap(), 3).unwrap();
        let c = checked_trade().commitment();
        setup.create_checked(&checked_trade()).unwrap();
        let v = setup.verify(c, BEFORE).unwrap().version();
        // Two independent connections to the same database file.
        race_acquire(
            SqlitePersistence::new(&path).unwrap(),
            SqlitePersistence::new(&path).unwrap(),
            c,
            v,
        );
        let _ = fs::remove_file(&path);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_stale_cas_and_corruption_fail_closed() {
        let path = temp_path("sqlite-bad", "db");
        let store = PersistentReplayStore::new(SqlitePersistence::new(&path).unwrap(), 3).unwrap();
        let checked = checked_trade();
        let c = checked.commitment();
        let created = store.create_checked(&checked).unwrap();
        let verified = store.verify(c, BEFORE).unwrap();
        let Step::Commit(stale_next) = apply(&created, Op::Fail(FailureReason::VerificationRejected), 3) else {
            panic!("fail from CREATED must commit");
        };
        assert!(matches!(
            store.persistence().compare_and_swap(Some(&created), &stale_next),
            Err(PersistenceError::Conflict { .. })
        ));
        assert_eq!(store.get(c).unwrap(), Some(verified));

        // Column/data disagreement is corruption, not "absent".
        let raw = rusqlite::Connection::open(&path).unwrap();
        raw.execute("UPDATE replay_records_v2 SET state = 'CONSUMED'", []).unwrap();
        assert!(store.get(c).is_err());
        assert!(SqlitePersistence::new(&path).is_err());
        raw.execute("UPDATE replay_records_v2 SET state = 'VERIFIED', schema_version = 1", []).unwrap();
        assert!(matches!(
            store.persistence().load(c),
            Err(PersistenceError::UnknownSchemaVersion { got: 1, .. })
        ));
        drop(raw);
        let _ = fs::remove_file(&path);

        // Legacy v1 table is rejected without migration.
        let legacy = temp_path("sqlite-legacy", "db");
        let raw = rusqlite::Connection::open(&legacy).unwrap();
        raw.execute_batch("CREATE TABLE replay (commitment TEXT PRIMARY KEY, data TEXT NOT NULL, schema_version INTEGER NOT NULL);").unwrap();
        drop(raw);
        assert!(matches!(
            SqlitePersistence::new(&legacy),
            Err(PersistenceError::UnknownSchemaVersion { got: 1, .. })
        ));
        let _ = fs::remove_file(&legacy);
    }
}
