//! Matcher gate for ZWA Protocol — Phase 2.
//!
//! This crate is the **only** place where the Phase 1 frozen types are composed
//! into an allow/block decision. It imports `zwa-protocol`, `zwa-commitments`,
//! and `zwa-credentials` and must never reimplement their encodings, domains,
//! or Poseidon staging.
//!
//! # Task A — Checked Trade Context (Fix ZWA-REL-001)
//!
//! Final Phase 1 audit finding `ZWA-REL-001 Low`: `ReplayStore::create(commitment, intent)`
//! stores a commitment and `TradeIntent` without recomputing whether they
//! correspond. A caller could pair a real commitment with a different intent,
//! making expiry enforcement use the wrong intent.
//!
//! Phase 2 must make `verify_trade_commitment(intent, commitment)` mandatory
//! before replay creation, preferably through a matcher-level checked trade
//! witness that respects crate dependency direction.
//!
//! `CheckedTrade` is that witness. It can only be constructed after successful
//! `verify_trade_commitment`. All matcher code must obtain a `CheckedTrade`
//! first, then use it to create replay records.
//!
//! # Task B — Root Authentication (Ed25519 over frozen canonical payload)
//!
//! `IssuerRootAuthenticator` and `CredentialRootAuthenticator` verify
//! `OpaqueSignature` against `canonical_bytes()` with Ed25519. They enforce:
//! - version >= 1, version == current_version (supersession)
//! - `window.contains(now)` (freshness)
//! - `trade_expiry <= root_expires_at` and combined `trade_expiry <= min(issuer, credential)`
//! - approved key lookup via `IssuerKeyId` / `AuthorityKeyId`
//!
//! Canonical payload layout (frozen): `"ZWA1ROOT" 8B | kind 1B | version 8B BE | valid_from 8B BE | expires_at 8B BE | id_len 1B | id | root 32B`
//!
//! # Compliance boundary
//!
//! Matcher is the MVP compliance boundary. Zcash consensus does not enforce
//! investor policy. ZSA settlement is experimental. This crate enforces the
//! frozen `TradeCommitmentV1` binding.

#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod checked;
pub mod control;
pub mod gate;
pub mod replay;
pub mod roots;
pub mod verifiers;

pub use checked::CheckedTrade;
pub use control::{
    RecipientControlAuthenticator, RecipientControlChallenge, RecipientControlResponse,
    RecipientControlVerifier, UnconfiguredControlVerifier, VerifiedRecipientControl,
    CONTROL_DOMAIN, DEFAULT_CONTROL_TTL_SECONDS, ControlError,
};
#[cfg(test)]
pub use control::FakeControlVerifier;
pub use gate::{GateInput, GateRejection, MatcherApproval, MatcherGate, VerifiedTrade};
pub use replay::{
    InMemoryPersistence, JsonFilePersistence, PersistentReplayStore, ReplayPersistence,
    RocksDbPersistence, PersistenceError, ReplayError, PERSISTENCE_SCHEMA_VERSION,
};
#[cfg(feature = "sqlite")]
pub use replay::SqlitePersistence;
pub use roots::{
    check_combined_root_expiry, AuthenticatedCredentialRoot, AuthenticatedIssuerRoot,
    CredentialRootAuthenticator, IssuerRootAuthenticator, RootAuthError,
};
pub use verifiers::{EligibilityVerifierBackend, MatcherProofGate, ProvenanceVerifierBackend};
#[cfg(test)]
pub use verifiers::make_test_proof_json;

// Re-export frozen crates for matcher consumers so they don't need direct deps.
pub use zwa_commitments;
pub use zwa_credentials;
pub use zwa_protocol;
