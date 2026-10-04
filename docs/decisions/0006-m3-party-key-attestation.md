# ADR 0006: M3 party keys — authority attestation (B + C)

- **Status:** Implemented on `fix/m3-remediation`; pending M3 review
- **Decision:** In M3, a configured credential authority or issuer attests the
  seller and buyer authorization public keys. In M4, each party's wallet
  authorizes its own Zcash spend.
- **Owner decision:** B + C (M3 remediation, finding M3-F1)

## Claim

M3 verifies credential-authority-attested party consent for the exact
M2-approved trade. M3 does not hold spending authority. M4 requires each
party's wallet to authorize its own Zcash spend.

## Context

The reviewed M3 candidate (`0f033df`) took the expected seller and buyer keys
from a `PartyIdentitySource`, whose only usable implementation was a registry
the coordinator filled itself. A matcher could register two keys it controls
and consent on behalf of both parties (M3-F1, HOLD).

## Decision

- `PartyKeyAttestation` binds `(authority id, role, party id, party key,
  valid_from, expires_at)` under the domain `ZWA1PARTYKEYATTEST` v1 and is
  signed with Ed25519 by the authority.
- `PartyAttestationTrustRoot` holds the operator-approved authority public
  keys and the roles each may attest. It is empty by default (fail closed).
- `SettlementAuthorizer::approve` verifies the seller attestation for the
  seller role and the buyer attestation for the buyer role, rejects the same
  party or key in both roles, builds the expected keys only from the attested
  keys, and then verifies each party's consent (`ZWA1PARTYAUTH`) for the exact
  M2-approved trade.
- `ApprovedSettlement` records both attested identities. Handoff digest v2
  covers them.

## Consequences

- A matcher without an authority signing key cannot introduce party keys.
- Authority attestations and trade consents use separate domains and keys.
- No private key, Orchard spend key or subject secret enters M3.
- Revocation before `expires_at` requires rebuilding the trust root; short
  attestation windows are recommended.
- How authorities issue attestations to parties is outside M3.
- Wallet spend authorization is M4 work and is not claimed here.
