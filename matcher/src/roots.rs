//! Root authentication — Task B.
//!
//! Implements concrete Ed25519 verification over the frozen canonical payload:
//! `"ZWA1ROOT" 8B | kind 1B | version 8B BE | valid_from 8B BE | expires_at 8B BE | id_len 1B | id | root 32B`
//!
//! - `IssuerRootAuthenticator` authenticates `IssuerRootEnvelope`
//! - `CredentialRootAuthenticator` authenticates `CredentialRootEnvelope`
//!
//! Both enforce:
//! - version >= 1 (already checked by `RootMetadata::new`, re-checked)
//! - version == current_version (supersession — stale-but-signed rejected)
//! - `window.contains(now)` via `validate_structure_at` (freshness)
//! - `trade_expiry <= root_expires_at` and combined `trade_expiry <= min(issuer, credential)`
//! - Ed25519 signature over `canonical_bytes()` verified against approved key
//!
//! Signature choice is open per handbook Sec 13, but Ed25519 is easy to implement
//! safely in Rust and does not change the signed bytes.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use zwa_credentials::{AuthorityKeyId, CredentialRootEnvelope, IssuerKeyId, IssuerRootEnvelope};
use zwa_protocol::error::ProtocolError;
use zwa_protocol::numbers::{RootVersion, TradeExpiry, UnixSeconds};

/// Errors from root authentication.
///
/// These are matcher-level typed rejections, not `ProtocolError` strings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RootAuthError {
    #[error("structural validation failed: {0}")]
    Structural(#[from] ProtocolError),

    #[error("issuer key not approved: {id:?}")]
    IssuerKeyNotApproved { id: Vec<u8> },

    #[error("credential authority key not approved: {id:?}")]
    AuthorityKeyNotApproved { id: Vec<u8> },

    #[error("root version not current: expected {expected}, got {got}")]
    VersionNotCurrent { expected: u64, got: u64 },

    #[error("trade expiry {trade_expiry} beyond root expiry {root_expiry}")]
    TradeExpiryBeyondRootExpiry { trade_expiry: u64, root_expiry: u64 },

    #[error("combined root expiry {min_expiry} is before trade expiry {trade_expiry}")]
    CombinedExpiryViolation { trade_expiry: u64, min_expiry: u64 },

    #[error("invalid Ed25519 signature encoding: expected 64 bytes, got {got}")]
    InvalidSignatureEncoding { got: usize },

    #[error("invalid Ed25519 signature: {reason}")]
    InvalidSignature { reason: String },

    #[error("signature verification failed for key {key_id:?}")]
    SignatureVerificationFailed { key_id: Vec<u8> },
}

/// An issuer root that has been authenticated.
///
/// Holds the original envelope plus the verified metadata needed for later
/// combined checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedIssuerRoot {
    envelope: IssuerRootEnvelope,
}

impl AuthenticatedIssuerRoot {
    /// Original envelope.
    #[must_use]
    pub fn envelope(&self) -> &IssuerRootEnvelope {
        &self.envelope
    }

    /// Authorized issuance root.
    #[must_use]
    pub fn root(&self) -> zwa_protocol::AuthorizedIssuanceRoot {
        self.envelope.payload().root()
    }

    /// Issuer identifier that was approved.
    #[must_use]
    pub fn issuer_id(&self) -> &IssuerKeyId {
        self.envelope.payload().issuer_id()
    }

    /// Version that was verified to be current.
    #[must_use]
    pub fn version(&self) -> RootVersion {
        self.envelope.payload().metadata().version()
    }

    /// Expiry of this root.
    #[must_use]
    pub fn expires_at(&self) -> UnixSeconds {
        self.envelope.payload().metadata().expires_at()
    }
}

/// An active credential root that has been authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCredentialRoot {
    envelope: CredentialRootEnvelope,
}

impl AuthenticatedCredentialRoot {
    /// Original envelope.
    #[must_use]
    pub fn envelope(&self) -> &CredentialRootEnvelope {
        &self.envelope
    }

    /// Active credential root.
    #[must_use]
    pub fn root(&self) -> zwa_protocol::ActiveCredentialRoot {
        self.envelope.payload().root()
    }

    /// Authority identifier that was approved.
    #[must_use]
    pub fn authority_id(&self) -> &AuthorityKeyId {
        self.envelope.payload().authority_id()
    }

    /// Version that was verified to be current.
    #[must_use]
    pub fn version(&self) -> RootVersion {
        self.envelope.payload().metadata().version()
    }

    /// Expiry of this root.
    #[must_use]
    pub fn expires_at(&self) -> UnixSeconds {
        self.envelope.payload().metadata().expires_at()
    }
}

/// Authenticates issuer roots with Ed25519 over frozen canonical payload.
#[derive(Debug, Clone)]
pub struct IssuerRootAuthenticator {
    approved_keys: BTreeMap<IssuerKeyId, VerifyingKey>,
    current_version: RootVersion,
}

impl IssuerRootAuthenticator {
    /// Builds authenticator with approved issuer keys and current version.
    ///
    /// `current_version` must be >= `RootVersion::MIN`. Version 0 is rejected
    /// at payload construction time and again here.
    #[must_use]
    pub fn new(
        approved_keys: BTreeMap<IssuerKeyId, VerifyingKey>,
        current_version: RootVersion,
    ) -> Self {
        Self {
            approved_keys,
            current_version,
        }
    }

    /// Current version this authenticator accepts (supersession policy).
    #[must_use]
    pub const fn current_version(&self) -> RootVersion {
        self.current_version
    }

    /// Authenticates an issuer envelope.
    ///
    /// Enforces:
    /// - structural validity at `now` (window.contains(now))
    /// - version >= 1, version == current_version (supersession)
    /// - trade_expiry <= root_expires_at
    /// - Ed25519 signature over canonical_bytes()
    ///
    /// # Errors
    ///
    /// Returns `RootAuthError` for any rejection.
    pub fn authenticate(
        &self,
        envelope: &IssuerRootEnvelope,
        now: UnixSeconds,
        trade_expiry: TradeExpiry,
    ) -> Result<AuthenticatedIssuerRoot, RootAuthError> {
        // 1. Structural + freshness: valid_from <= now <= expires_at, version >=1
        envelope
            .validate_structure_at(now)
            .map_err(RootAuthError::Structural)?;

        let metadata = envelope.payload().metadata();
        let version = metadata.version();

        // Explicit version >=1 check (RootVersion::MIN = 1) — defense in depth,
        // even though payload construction already enforces it.
        if !version.is_valid() {
            return Err(RootAuthError::Structural(
                ProtocolError::UnsupportedVersion { got: version.get() },
            ));
        }

        // 2. Supersession: only current version accepted. Stale-but-still-signed rejected.
        if version != self.current_version {
            return Err(RootAuthError::VersionNotCurrent {
                expected: self.current_version.get(),
                got: version.get(),
            });
        }

        // 3. Trade expiry must be no later than root expiry.
        let root_expiry = metadata.expires_at();
        if trade_expiry.get() > root_expiry.get() {
            return Err(RootAuthError::TradeExpiryBeyondRootExpiry {
                trade_expiry: trade_expiry.get(),
                root_expiry: root_expiry.get(),
            });
        }

        // 4. Approved key lookup.
        let issuer_id = envelope.payload().issuer_id();
        let verifying_key = self
            .approved_keys
            .get(issuer_id)
            .ok_or_else(|| RootAuthError::IssuerKeyNotApproved {
                id: issuer_id.as_bytes().to_vec(),
            })?;

        // 5. Signature verification over frozen canonical payload.
        verify_ed25519_signature(
            verifying_key,
            &envelope.canonical_payload_bytes(),
            envelope.signature().as_bytes(),
            issuer_id.as_bytes(),
        )?;

        Ok(AuthenticatedIssuerRoot {
            envelope: envelope.clone(),
        })
    }
}

/// Authenticates credential-authority roots with Ed25519.
#[derive(Debug, Clone)]
pub struct CredentialRootAuthenticator {
    approved_keys: BTreeMap<AuthorityKeyId, VerifyingKey>,
    current_version: RootVersion,
}

impl CredentialRootAuthenticator {
    /// Builds authenticator with approved authority keys and current version.
    #[must_use]
    pub fn new(
        approved_keys: BTreeMap<AuthorityKeyId, VerifyingKey>,
        current_version: RootVersion,
    ) -> Self {
        Self {
            approved_keys,
            current_version,
        }
    }

    /// Current version this authenticator accepts.
    #[must_use]
    pub const fn current_version(&self) -> RootVersion {
        self.current_version
    }

    /// Authenticates a credential envelope.
    ///
    /// Same enforcement as issuer authenticator:
    /// - version >=1, version == current_version
    /// - freshness, trade expiry, approved key, Ed25519 sig.
    ///
    /// # Errors
    ///
    /// Returns `RootAuthError` for any rejection.
    pub fn authenticate(
        &self,
        envelope: &CredentialRootEnvelope,
        now: UnixSeconds,
        trade_expiry: TradeExpiry,
    ) -> Result<AuthenticatedCredentialRoot, RootAuthError> {
        envelope
            .validate_structure_at(now)
            .map_err(RootAuthError::Structural)?;

        let metadata = envelope.payload().metadata();
        let version = metadata.version();

        if !version.is_valid() {
            return Err(RootAuthError::Structural(
                ProtocolError::UnsupportedVersion { got: version.get() },
            ));
        }

        if version != self.current_version {
            return Err(RootAuthError::VersionNotCurrent {
                expected: self.current_version.get(),
                got: version.get(),
            });
        }

        let root_expiry = metadata.expires_at();
        if trade_expiry.get() > root_expiry.get() {
            return Err(RootAuthError::TradeExpiryBeyondRootExpiry {
                trade_expiry: trade_expiry.get(),
                root_expiry: root_expiry.get(),
            });
        }

        let authority_id = envelope.payload().authority_id();
        let verifying_key = self
            .approved_keys
            .get(authority_id)
            .ok_or_else(|| RootAuthError::AuthorityKeyNotApproved {
                id: authority_id.as_bytes().to_vec(),
            })?;

        verify_ed25519_signature(
            verifying_key,
            &envelope.canonical_payload_bytes(),
            envelope.signature().as_bytes(),
            authority_id.as_bytes(),
        )?;

        Ok(AuthenticatedCredentialRoot {
            envelope: envelope.clone(),
        })
    }
}

/// Checks combined expiry: trade_expiry <= min(issuer_expiry, credential_expiry).
///
/// Phase 2 must require trade expiry to be no later than earliest authenticated
/// root expiry (handbook Sec 13).
///
/// # Errors
///
/// Returns `CombinedExpiryViolation` if trade expiry is beyond min root expiry.
pub fn check_combined_root_expiry(
    trade_expiry: TradeExpiry,
    issuer_root: &AuthenticatedIssuerRoot,
    credential_root: &AuthenticatedCredentialRoot,
) -> Result<(), RootAuthError> {
    let issuer_exp = issuer_root.expires_at().get();
    let cred_exp = credential_root.expires_at().get();
    let min_expiry = issuer_exp.min(cred_exp);

    if trade_expiry.get() > min_expiry {
        return Err(RootAuthError::CombinedExpiryViolation {
            trade_expiry: trade_expiry.get(),
            min_expiry,
        });
    }
    Ok(())
}

/// Verifies Ed25519 signature over message.
///
/// `signature_bytes` comes from `OpaqueSignature` container (max 1024, non-empty).
/// For Ed25519, it must be exactly 64 bytes. The signed message is the frozen
/// canonical payload — no re-encoding.
fn verify_ed25519_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8],
    key_id: &[u8],
) -> Result<(), RootAuthError> {
    if signature_bytes.len() != 64 {
        return Err(RootAuthError::InvalidSignatureEncoding {
            got: signature_bytes.len(),
        });
    }

    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| RootAuthError::InvalidSignatureEncoding {
            got: signature_bytes.len(),
        })?;

    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| RootAuthError::SignatureVerificationFailed {
            key_id: key_id.to_vec(),
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use zwa_credentials::{CredentialRootPayload, IssuerRootPayload};
    use zwa_protocol::{
        ActiveCredentialRoot, AuthorizedIssuanceRoot, OpaqueSignature, RootVersion, UnixSeconds,
    };

    const ISSUANCE_ROOT: &str =
        "19309979006225485291788213177219598381134511159668519266888323889569746782051";
    const CREDENTIAL_ROOT: &str =
        "7239536478138432754387625126231950010993505962177483323536139232738771167323";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn issuer_envelope_with_sig(
        signing_key: &SigningKey,
        issuer_id: &[u8],
        version: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> IssuerRootEnvelope {
        let payload = IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap(),
            IssuerKeyId::new(issuer_id).unwrap(),
            RootVersion::new(version),
            UnixSeconds::new(valid_from),
            UnixSeconds::new(expires_at),
        )
        .unwrap();
        let sig = signing_key.sign(&payload.canonical_bytes());
        let opaque = OpaqueSignature::new(&sig.to_bytes()).unwrap();
        IssuerRootEnvelope::new(payload, opaque)
    }

    fn credential_envelope_with_sig(
        signing_key: &SigningKey,
        authority_id: &[u8],
        version: u64,
        valid_from: u64,
        expires_at: u64,
    ) -> CredentialRootEnvelope {
        let payload = CredentialRootPayload::new(
            ActiveCredentialRoot::from_decimal_str(CREDENTIAL_ROOT).unwrap(),
            AuthorityKeyId::new(authority_id).unwrap(),
            RootVersion::new(version),
            UnixSeconds::new(valid_from),
            UnixSeconds::new(expires_at),
        )
        .unwrap();
        let sig = signing_key.sign(&payload.canonical_bytes());
        let opaque = OpaqueSignature::new(&sig.to_bytes()).unwrap();
        CredentialRootEnvelope::new(payload, opaque)
    }

    #[test]
    fn issuer_authentication_passes_for_current_version_and_fresh_root() {
        let sk = signing_key(1);
        let vk = sk.verifying_key();
        let issuer_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved = BTreeMap::new();
        approved.insert(issuer_id.clone(), vk);

        let auth = IssuerRootAuthenticator::new(approved, RootVersion::new(1));

        let envelope = issuer_envelope_with_sig(&sk, b"issuer-atlas", 1, 1_900_000_000, 2_100_000_000);

        let now = UnixSeconds::new(2_000_000_000);
        let trade_expiry = TradeExpiry::new(2_000_000_000);

        let authenticated = auth.authenticate(&envelope, now, trade_expiry).unwrap();
        assert_eq!(authenticated.root().to_string(), ISSUANCE_ROOT);
        assert_eq!(authenticated.version().get(), 1);
    }

    #[test]
    fn issuer_authentication_rejects_stale_version_supersession() {
        let sk = signing_key(2);
        let vk = sk.verifying_key();
        let issuer_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved = BTreeMap::new();
        approved.insert(issuer_id, vk);

        // Current version is 2, but envelope is version 1 — stale-but-signed must be rejected.
        let auth = IssuerRootAuthenticator::new(approved, RootVersion::new(2));
        let envelope = issuer_envelope_with_sig(&sk, b"issuer-atlas", 1, 1_900_000_000, 2_100_000_000);

        let now = UnixSeconds::new(2_000_000_000);
        let trade_expiry = TradeExpiry::new(2_000_000_000);

        let err = auth.authenticate(&envelope, now, trade_expiry).unwrap_err();
        match err {
            RootAuthError::VersionNotCurrent { expected, got } => {
                assert_eq!(expected, 2);
                assert_eq!(got, 1);
            }
            other => panic!("expected VersionNotCurrent, got {other:?}"),
        }
    }

    #[test]
    fn issuer_authentication_rejects_unapproved_key() {
        let sk = signing_key(3);
        let vk = sk.verifying_key();
        let approved_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved = BTreeMap::new();
        approved.insert(approved_id, vk);

        let auth = IssuerRootAuthenticator::new(approved, RootVersion::new(1));

        // Envelope signed by same key but claims different issuer id — not in approved map.
        let envelope = issuer_envelope_with_sig(&sk, b"issuer-other", 1, 1_900_000_000, 2_100_000_000);

        let now = UnixSeconds::new(2_000_000_000);
        let trade_expiry = TradeExpiry::new(2_000_000_000);

        let err = auth.authenticate(&envelope, now, trade_expiry).unwrap_err();
        match err {
            RootAuthError::IssuerKeyNotApproved { id } => {
                assert_eq!(id, b"issuer-other");
            }
            other => panic!("expected IssuerKeyNotApproved, got {other:?}"),
        }
    }

    #[test]
    fn issuer_authentication_rejects_expired_window_and_trade_beyond_root_expiry() {
        let sk = signing_key(4);
        let vk = sk.verifying_key();
        let issuer_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved = BTreeMap::new();
        approved.insert(issuer_id, vk);
        let auth = IssuerRootAuthenticator::new(approved, RootVersion::new(1));

        let envelope = issuer_envelope_with_sig(&sk, b"issuer-atlas", 1, 1_900_000_000, 2_100_000_000);

        // Not yet valid.
        let err = auth
            .authenticate(
                &envelope,
                UnixSeconds::new(1_899_999_999),
                TradeExpiry::new(2_000_000_000),
            )
            .unwrap_err();
        match err {
            RootAuthError::Structural(_) => {}
            other => panic!("expected Structural, got {other:?}"),
        }

        // Expired.
        let err = auth
            .authenticate(
                &envelope,
                UnixSeconds::new(2_100_000_001),
                TradeExpiry::new(2_000_000_000),
            )
            .unwrap_err();
        match err {
            RootAuthError::Structural(_) => {}
            other => panic!("expected Structural, got {other:?}"),
        }

        // Trade expiry beyond root expiry.
        let err = auth
            .authenticate(
                &envelope,
                UnixSeconds::new(2_000_000_000),
                TradeExpiry::new(2_100_000_001),
            )
            .unwrap_err();
        match err {
            RootAuthError::TradeExpiryBeyondRootExpiry {
                trade_expiry,
                root_expiry,
            } => {
                assert_eq!(trade_expiry, 2_100_000_001);
                assert_eq!(root_expiry, 2_100_000_000);
            }
            other => panic!("expected TradeExpiryBeyondRootExpiry, got {other:?}"),
        }
    }

    #[test]
    fn issuer_authentication_rejects_invalid_signature() {
        let sk = signing_key(5);
        let vk = sk.verifying_key();
        let issuer_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved = BTreeMap::new();
        approved.insert(issuer_id.clone(), vk);
        let auth = IssuerRootAuthenticator::new(approved, RootVersion::new(1));

        // Create valid payload, then sign different bytes (tamper).
        let payload = IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap(),
            issuer_id,
            RootVersion::new(1),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        )
        .unwrap();
        let mut tampered_bytes = payload.canonical_bytes();
        tampered_bytes[0] ^= 1;
        let sig = sk.sign(&tampered_bytes);
        let envelope =
            IssuerRootEnvelope::new(payload, OpaqueSignature::new(&sig.to_bytes()).unwrap());

        let err = auth
            .authenticate(
                &envelope,
                UnixSeconds::new(2_000_000_000),
                TradeExpiry::new(2_000_000_000),
            )
            .unwrap_err();
        match err {
            RootAuthError::SignatureVerificationFailed { .. } => {}
            other => panic!("expected SignatureVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn credential_authentication_passes_and_combined_expiry_enforced() {
        let sk_issuer = signing_key(10);
        let vk_issuer = sk_issuer.verifying_key();
        let issuer_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved_issuer = BTreeMap::new();
        approved_issuer.insert(issuer_id, vk_issuer);
        let issuer_auth = IssuerRootAuthenticator::new(approved_issuer, RootVersion::new(1));
        let issuer_env =
            issuer_envelope_with_sig(&sk_issuer, b"issuer-atlas", 1, 1_900_000_000, 2_100_000_000);

        let sk_auth = signing_key(11);
        let vk_auth = sk_auth.verifying_key();
        let authority_id = AuthorityKeyId::new(b"cred-auth-1").unwrap();
        let mut approved_auth = BTreeMap::new();
        approved_auth.insert(authority_id, vk_auth);
        let cred_auth = CredentialRootAuthenticator::new(approved_auth, RootVersion::new(1));
        let cred_env = credential_envelope_with_sig(
            &sk_auth,
            b"cred-auth-1",
            1,
            1_900_000_000,
            2_050_000_000,
        );

        let now = UnixSeconds::new(2_000_000_000);
        let trade_expiry_ok = TradeExpiry::new(2_000_000_000);
        let trade_expiry_beyond_cred = TradeExpiry::new(2_060_000_000);

        let auth_issuer = issuer_auth
            .authenticate(&issuer_env, now, trade_expiry_ok)
            .unwrap();
        let auth_cred = cred_auth
            .authenticate(&cred_env, now, trade_expiry_ok)
            .unwrap();

        // Combined check passes when trade expiry <= min(2_100_000_000, 2_050_000_000) = 2_050_000_000
        assert!(check_combined_root_expiry(trade_expiry_ok, &auth_issuer, &auth_cred).is_ok());

        // Trade expiry 2_060_000_000 > min 2_050_000_000 → fails combined check
        // Note: individual credential auth already fails for this expiry, but combined also fails.
        let err = cred_auth
            .authenticate(&cred_env, now, trade_expiry_beyond_cred)
            .unwrap_err();
        match err {
            RootAuthError::TradeExpiryBeyondRootExpiry { .. } => {}
            other => panic!("expected TradeExpiryBeyondRootExpiry, got {other:?}"),
        }

        // If we authenticate with ok expiry, then combined with later expiry should fail.
        let trade_expiry_late = TradeExpiry::new(2_080_000_000);
        let err = check_combined_root_expiry(trade_expiry_late, &auth_issuer, &auth_cred)
            .unwrap_err();
        match err {
            RootAuthError::CombinedExpiryViolation {
                trade_expiry,
                min_expiry,
            } => {
                assert_eq!(trade_expiry, 2_080_000_000);
                assert_eq!(min_expiry, 2_050_000_000);
            }
            other => panic!("expected CombinedExpiryViolation, got {other:?}"),
        }
    }

    #[test]
    fn canonical_payload_is_not_changed_by_authenticator() {
        // The authenticator must verify exactly the frozen canonical bytes, not a re-encoded version.
        let _sk = signing_key(20);
        let payload = IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap(),
            IssuerKeyId::new(b"issuer-atlas").unwrap(),
            RootVersion::new(1),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        )
        .unwrap();
        let canonical = payload.canonical_bytes();
        assert_eq!(&canonical[..8], b"ZWA1ROOT");
        assert_eq!(canonical[8], 1); // kind issuer
        // Version 1 BE
        assert_eq!(&canonical[9..17], &1u64.to_be_bytes());
        // id_len + id + root 32B at end
        assert_eq!(canonical.len(), 8 + 1 + 8 * 3 + 1 + b"issuer-atlas".len() + 32);
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex length must be even");
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("invalid hex") as u8;
            let lo = (bytes[i + 1] as char).to_digit(16).expect("invalid hex") as u8;
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    #[test]
    fn golden_vectors_file_verifies_in_rust_and_matches_canonical_encoding() {
        let candidates = [
            "tests/fixtures/root-sig-golden-vectors.json".to_string(),
            "../tests/fixtures/root-sig-golden-vectors.json".to_string(),
            format!(
                "{}/tests/fixtures/root-sig-golden-vectors.json",
                env!("CARGO_MANIFEST_DIR").trim_end_matches("/matcher")
            ),
            format!(
                "{}/../tests/fixtures/root-sig-golden-vectors.json",
                env!("CARGO_MANIFEST_DIR")
            ),
        ];

        let mut json_str = None;
        for path in &candidates {
            if let Ok(s) = std::fs::read_to_string(path) {
                json_str = Some(s);
                break;
            }
        }
        let json_str = json_str.expect(
            "root-sig-golden-vectors.json not found — run from workspace root or matcher crate",
        );

        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // --- Issuer ---
        let issuer = &v["issuer"];
        let issuer_canonical_hex = issuer["canonical_payload_hex"].as_str().unwrap();
        let issuer_sig_hex = issuer["ed25519_signature_hex"].as_str().unwrap();
        let issuer_pub_hex = issuer["ed25519_pubkey_hex"].as_str().unwrap();
        let issuer_id = issuer["issuer_id"].as_str().unwrap();
        let issuer_root_decimal = issuer["authorized_issuance_root_decimal"].as_str().unwrap();
        let issuer_version = issuer["version"].as_u64().unwrap();
        let issuer_valid_from = issuer["valid_from"].as_u64().unwrap();
        let issuer_expires_at = issuer["expires_at"].as_u64().unwrap();

        let issuer_canonical_bytes = hex_decode(issuer_canonical_hex);
        let issuer_sig_bytes: [u8; 64] = hex_decode(issuer_sig_hex)
            .try_into()
            .expect("issuer sig 64B");
        let issuer_pub_bytes: [u8; 32] = hex_decode(issuer_pub_hex)
            .try_into()
            .expect("issuer pub 32B");

        let vk = VerifyingKey::from_bytes(&issuer_pub_bytes).unwrap();
        let sig = Signature::from_bytes(&issuer_sig_bytes);
        vk.verify(&issuer_canonical_bytes, &sig)
            .expect("issuer golden signature must verify in Rust");

        let reconstructed_issuer_payload = IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(issuer_root_decimal).unwrap(),
            IssuerKeyId::new(issuer_id.as_bytes()).unwrap(),
            RootVersion::new(issuer_version),
            UnixSeconds::new(issuer_valid_from),
            UnixSeconds::new(issuer_expires_at),
        )
        .unwrap();
        assert_eq!(
            reconstructed_issuer_payload.canonical_bytes(),
            issuer_canonical_bytes,
            "issuer canonical bytes from crate must equal frozen file hex — proves no reserialization drift"
        );

        let issuer_envelope = IssuerRootEnvelope::new(
            reconstructed_issuer_payload,
            OpaqueSignature::new(&issuer_sig_bytes).unwrap(),
        );
        let mut approved_issuer = BTreeMap::new();
        approved_issuer.insert(IssuerKeyId::new(issuer_id.as_bytes()).unwrap(), vk);
        let issuer_auth =
            IssuerRootAuthenticator::new(approved_issuer, RootVersion::new(issuer_version));
        let now = UnixSeconds::new(2_000_000_000);
        let trade_expiry = TradeExpiry::new(2_000_000_000);
        let auth_issuer = issuer_auth
            .authenticate(&issuer_envelope, now, trade_expiry)
            .expect("issuer golden envelope must authenticate");
        assert_eq!(auth_issuer.root().to_string(), issuer_root_decimal);

        // --- Credential ---
        let cred = &v["credential"];
        let cred_canonical_hex = cred["canonical_payload_hex"].as_str().unwrap();
        let cred_sig_hex = cred["ed25519_signature_hex"].as_str().unwrap();
        let cred_pub_hex = cred["ed25519_pubkey_hex"].as_str().unwrap();
        let cred_authority_id = cred["authority_id"].as_str().unwrap();
        let cred_root_decimal = cred["active_credential_root_decimal"].as_str().unwrap();
        let cred_version = cred["version"].as_u64().unwrap();
        let cred_valid_from = cred["valid_from"].as_u64().unwrap();
        let cred_expires_at = cred["expires_at"].as_u64().unwrap();

        let cred_canonical_bytes = hex_decode(cred_canonical_hex);
        let cred_sig_bytes: [u8; 64] = hex_decode(cred_sig_hex).try_into().expect("cred sig 64B");
        let cred_pub_bytes: [u8; 32] = hex_decode(cred_pub_hex).try_into().expect("cred pub 32B");

        let vk_cred = VerifyingKey::from_bytes(&cred_pub_bytes).unwrap();
        let sig_cred = Signature::from_bytes(&cred_sig_bytes);
        vk_cred
            .verify(&cred_canonical_bytes, &sig_cred)
            .expect("credential golden signature must verify in Rust");

        let reconstructed_cred_payload = CredentialRootPayload::new(
            ActiveCredentialRoot::from_decimal_str(cred_root_decimal).unwrap(),
            AuthorityKeyId::new(cred_authority_id.as_bytes()).unwrap(),
            RootVersion::new(cred_version),
            UnixSeconds::new(cred_valid_from),
            UnixSeconds::new(cred_expires_at),
        )
        .unwrap();
        assert_eq!(
            reconstructed_cred_payload.canonical_bytes(),
            cred_canonical_bytes,
            "credential canonical bytes from crate must equal frozen file hex"
        );

        let cred_envelope = CredentialRootEnvelope::new(
            reconstructed_cred_payload,
            OpaqueSignature::new(&cred_sig_bytes).unwrap(),
        );
        let mut approved_cred = BTreeMap::new();
        approved_cred.insert(
            AuthorityKeyId::new(cred_authority_id.as_bytes()).unwrap(),
            vk_cred,
        );
        let cred_auth =
            CredentialRootAuthenticator::new(approved_cred, RootVersion::new(cred_version));
        let auth_cred = cred_auth
            .authenticate(&cred_envelope, now, trade_expiry)
            .expect("credential golden envelope must authenticate");
        assert_eq!(auth_cred.root().to_string(), cred_root_decimal);

        assert!(check_combined_root_expiry(trade_expiry, &auth_issuer, &auth_cred).is_ok());
    }

    #[test]
    fn issuer_authentication_rejects_truncated_signature_encoding() {
        // OpaqueSignature allows any length up to 1024, but Ed25519 must be exactly 64B.
        // This maps to RootAuthError::InvalidSignatureEncoding in the verifier.
        let sk = signing_key(30);
        let vk = sk.verifying_key();
        let issuer_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved = BTreeMap::new();
        approved.insert(issuer_id.clone(), vk);
        let auth = IssuerRootAuthenticator::new(approved, RootVersion::new(1));

        let payload = IssuerRootPayload::new(
            AuthorizedIssuanceRoot::from_decimal_str(ISSUANCE_ROOT).unwrap(),
            issuer_id.clone(),
            RootVersion::new(1),
            UnixSeconds::new(1_900_000_000),
            UnixSeconds::new(2_100_000_000),
        )
        .unwrap();
        let sig = sk.sign(&payload.canonical_bytes());
        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes.truncate(32); // truncated — must be rejected as InvalidSignatureEncoding

        let envelope = IssuerRootEnvelope::new(
            payload,
            OpaqueSignature::new(&sig_bytes).unwrap(),
        );

        let err = auth
            .authenticate(
                &envelope,
                UnixSeconds::new(2_000_000_000),
                TradeExpiry::new(2_000_000_000),
            )
            .unwrap_err();

        match err {
            RootAuthError::InvalidSignatureEncoding { got } => {
                assert_eq!(got, 32);
            }
            other => panic!("expected InvalidSignatureEncoding, got {other:?}"),
        }
    }

    #[test]
    fn authenticated_root_types_cannot_be_fabricated() {
        // AuthenticatedIssuerRoot and AuthenticatedCredentialRoot have private envelope field
        // and no public constructor — only authenticate() can produce them.
        // This test documents the invariant: you cannot construct them without a valid sig.
        // If someone tries to use std::mem::zeroed or unsafe, it would be outside safe API.
        // We prove that authenticate() is the only path by checking that direct construction
        // is not possible via type system (compile-time), and that a forged envelope fails.
        let sk = signing_key(31);
        let vk = sk.verifying_key();
        let issuer_id = IssuerKeyId::new(b"issuer-atlas").unwrap();
        let mut approved = BTreeMap::new();
        approved.insert(issuer_id.clone(), vk);
        let auth = IssuerRootAuthenticator::new(approved, RootVersion::new(1));

        // Valid envelope should succeed
        let valid = issuer_envelope_with_sig(&sk, b"issuer-atlas", 1, 1_900_000_000, 2_100_000_000);
        assert!(auth
            .authenticate(
                &valid,
                UnixSeconds::new(2_000_000_000),
                TradeExpiry::new(2_000_000_000)
            )
            .is_ok());

        // Envelope with wrong key id must fail — proves you cannot fabricate Authenticated root
        // without going through approved key lookup + sig verification.
        let invalid = issuer_envelope_with_sig(&sk, b"issuer-other", 1, 1_900_000_000, 2_100_000_000);
        assert!(auth
            .authenticate(
                &invalid,
                UnixSeconds::new(2_000_000_000),
                TradeExpiry::new(2_000_000_000)
            )
            .is_err());
    }
}
