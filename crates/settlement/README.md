# zwa-settlement — Milestone 3 (RFQ → ApprovedSettlement)

Owner: Vikram. Status: **pending re-audit** after the M3 remediation.

```text
RfqRequest ─exact─▶ TradeIntent ─▶ TradeCommitmentV1 (frozen M1)
                                    │
                   M2 MatcherGate::evaluate ─▶ MatcherApproval
                                    │
   seller + buyer PartyKeyAttestation ── PartyAttestationTrustRoot
     (signed by a configured credential authority / issuer)
   seller + buyer PartyAuthorization (each signed locally with the attested key)
                                    │
              SettlementAuthorizer::approve ─▶ ApprovedSettlement ─▶ M4
```

**Claim.** M3 verifies credential-authority-attested party consent for the exact
M2-approved trade. M3 does not hold spending authority. M4 requires each
party's wallet to authorize its own Zcash spend.

M3 stops at `ApprovedSettlement`. This crate **does not** construct, prove, sign,
submit or confirm any Zcash/ZSA transaction, and no API accepts a private,
spending, wallet, seed or Orchard key. The earlier M4 prototype is archived and
not compiled: see [`archive/m4-prototype/`](../../archive/m4-prototype/README.md).

## RFQ (`rfq.rs`)

`RfqRequest` has exactly the nine `TradeIntent` fields. The mapping is 1:1 in
both directions, and `ensure_matches` compares every field (exhaustive
destructuring). There is no raw-receiver override: the settlement receiver is
the one whose control M2 verified and bound to `recipient_commitment` (F-02).

## Party-key attestation (`attestation.rs`, ADR 0006)

Owner decision **B + C**: in M3 a credential authority or issuer attests the
seller and buyer authorization public keys; in M4 each party's wallet signs its
own spend.

- **Trust root:** `PartyAttestationTrustRoot`, configured by the operator with
  the Ed25519 public keys of the approved authorities, each restricted to the
  roles it may attest. Empty by default, which fails closed.
- **Signed message:** `"ZWA1PARTYKEYATTEST" | 0x01 | role (1 seller / 2 buyer) |
  authority_id_len | authority_id (1..=64) | party_id_len | party_id (1..=64) |
  party_key (32) | valid_from u64 BE | expires_at u64 BE`.
- **Verification order:** role, known authority, authority allowed for the role,
  window (inclusive), party key well formed (not small order), then
  `verify_strict`. Only a verified `AttestedPartyIdentity` supplies an expected
  key.
- **Rejected in `approve`:** missing, forged, unknown-authority, wrong-role,
  role-not-allowed, not-yet-valid and expired attestations; the same party id
  or the same key in both roles.
- **Not claimed:** an attestation is not custody and not spend authority. There
  is no per-attestation revocation list; before `expires_at` an attestation is
  revoked only by rebuilding the trust root without its authority.

## Party consent (`party_auth.rs`)

- **Trust anchor (F-03):** the expected seller and buyer keys come only from
  the two verified attestations, never from the consent object and never from
  a registry the coordinator fills on its own. The earlier
  `PartyIdentitySource` / `RegisteredPartyKeys` interface is removed (M3-F1).
- **No keys on the server (F-04):** the server issues a
  `PartyAuthorizationRequest`. The party signs `signing_bytes()` locally with
  Ed25519 and returns `PartyAuthorization { request, claimed_signer, signature }`.
- **Signed bytes (95):** `"ZWA1PARTYAUTH" | 0x01 | role (1 seller / 2 buyer) |
  TradeCommitmentV1 (32 BE) | nonce (32) | issued_at u64 BE | expires_at u64 BE`.
- **Verification:** role, trade, request echo, window (`now > expires_at`
  fails), signer == expected key, then `verify_strict`.
- **Replay:** a signature only verifies against its exact issued request (role,
  trade, 32-byte random nonce, window). Re-verifying the same request is
  idempotent. Single use comes from the single M2 `MatcherApproval`, which
  `approve` consumes by value; M3 keeps no replay state (F-09).

## ApprovedSettlement (`approved.rs`)

The only producer is `SettlementAuthorizer::approve(MatcherApproval, &RfqRequest,
seller, buyer, now)`, where the authorizer is built from a
`PartyAttestationTrustRoot` and each `PartySubmission` carries the party's
attestation, the issued request and the returned consent. It requires a
self-consistent M2 approval, terms equal to the approved intent, an unexpired
trade, verified seller and buyer attestations, and consents signed by the
attested keys. All fields are private, and the type is not `Clone`, not
`Default` and not deserializable (checked by compile-fail doctests in
`lib.rs`). It carries the commitment, the intent snapshot, the M2-verified
receiver, both attested identities, both consent evidences, `approved_at`, and
a domain-separated `handoff_digest` (`ZWA1APPROVEDSETTLEMENT`, v2, which covers
the attestations, their signatures and the authority keys). `verify_integrity()`
re-checks everything at the M4 boundary; whether the recorded authorities are
still trusted is for M4's own trust root to decide. It contains no secrets,
witnesses, private keys, RFQ internals or matcher state.

## Owner gates (not resolved by M3)

- **Groth16 verification keys:** `tests/fixtures/groth16/provenance-vkey.json`
  (sha256 `4831d3ee…1350`) and `eligibility-vkey.json` (sha256 `879d427a…5e75`)
  were exported in `ef7fc73` from the `dummyProd` circuit variant. M3 does not
  change them. Production provenance needs re-issuance or explicit approval by
  the M1 owner.
- **M4:** wallet spend authorization and Zcash/ZSA settlement are not
  implemented here and are not started.
