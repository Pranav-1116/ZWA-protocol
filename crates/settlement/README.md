# zwa-settlement — Milestone 3 (RFQ → ApprovedSettlement)

Owner: Vikram. Status: **pending re-audit** after the M3 remediation.

```text
RfqRequest ─exact─▶ TradeIntent ─▶ TradeCommitmentV1 (frozen M1)
                                    │
                   M2 MatcherGate::evaluate ─▶ MatcherApproval
                                    │
   seller + buyer PartyAuthorization (each signed locally by that party)
   expected keys ◀── PartyIdentitySource (independent; fails closed by default)
                                    │
              SettlementAuthorizer::approve ─▶ ApprovedSettlement ─▶ M4
```

M3 stops at `ApprovedSettlement`. This crate **does not** construct, prove, sign,
submit or confirm any Zcash/ZSA transaction, and no API accepts a private,
spending, wallet, seed or Orchard key. The earlier M4 prototype is archived and
not compiled: see [`archive/m4-prototype/`](../../archive/m4-prototype/README.md).

## RFQ (`rfq.rs`)

`RfqRequest` has exactly the nine `TradeIntent` fields. The mapping is 1:1 in
both directions, and `ensure_matches` compares every field (exhaustive
destructuring). There is no raw-receiver override: the settlement receiver is
the one whose control M2 verified and bound to `recipient_commitment` (F-02).

## Party authorization (`party_auth.rs`)

- **Trust anchor (F-03):** the expected seller and buyer keys come only from a
  `PartyIdentitySource`, never from the authorization. The shipped sources are
  `UnconfiguredPartyIdentitySource` (always fails closed) and
  `RegisteredPartyKeys` (an explicit registry that must be populated from an
  authenticated channel; conflicting re-registration is rejected). The
  product's actual source (authenticated client session, wallet identity,
  external key registration) is an integration decision.
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
seller, buyer, now)`. It requires a self-consistent M2 approval, terms equal to
the approved intent, an unexpired trade, and valid seller and buyer
authorizations from the independently expected keys. All fields are private,
and the type is not `Clone` and not serializable. It carries the commitment,
the intent snapshot (assets, amounts, recipient commitment, policy root, fee
amount and recipient commitment, nonce, expiry), the M2-verified receiver, both
authorization evidences, `approved_at`, and a domain-separated
`handoff_digest` (`ZWA1APPROVEDSETTLEMENT`, v1). `verify_integrity()` re-checks
everything at the M4 boundary. It contains no secrets, witnesses, private keys,
RFQ internals or matcher state.
