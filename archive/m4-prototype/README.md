# ARCHIVED M4 PROTOTYPE — NOT BUILT, NOT PRODUCTION

This directory holds code that the M3 (RFQ / client contract) work had
implemented even though it belongs to **M4 — Zcash Settlement Adapter** (owner:
repository owner). M3 remediation (audit findings F-04, F-09, F-12 and §8)
removes it from the M3 production path. It is kept here, unchanged except
where noted below, so the M4 owner can inspect it. Git history is preserved
(`git log --follow <file>`).

**Nothing here is compiled.** Neither directory is a workspace member, and
there is no `Cargo.toml` (the manifests are kept as `Cargo.toml.archived`).
None of it is production functionality, and none of it may be presented as
such.

| Archived file | What it was | Why it is not M3 production |
| --- | --- | --- |
| `settlement/src/lib.rs` | `SettlementAdapter`, `SettlementDraft`, the old `SellerAuthorization` / `BuyerAuthorization`, **`MockSettlementAdapter`** (SHA-256-derived **fake txid**), `RealZsaAdapterPlaceholder` | Construction and submission are M4. The authorization objects carried their own verifying key (F-03) and were signed from a server-side `SigningKey` (F-04). |
| `settlement/src/zsa.rs` | Experimental ZSA builder, mock ZSA adapter | M4 construction |
| `settlement/src/execution.rs` | `SettlementExecutor`: construct, sign both parties, submit, confirm, consume | M4 execution; it received both parties' private keys (F-04) |
| `settlement/src/production.rs` | "Production" settlement coordinator built on the mock adapter | Mock behind a production name (§8) |
| `settlement/src/integration.rs` | `process_rfq_and_settle(…, seller_sk, buyer_sk)` | Received both private keys (F-04); it also held a raw-receiver override |
| `settlement/src/replay.rs` | `SettlementReplayCoordinator`, a second replay store | Duplicated the M2 lifecycle (F-09) |
| `settlement/src/non_custodial.rs` | Server-held `SellerSigningKey` / `BuyerSigningKey` | F-04 |
| `settlement/src/control.rs` | Simulated "Orchard ivk" recipient control (SHA-256 + Ed25519) | Simulation named as "real" (F-12). Recipient control is M2's job. |
| `settlement/src/audit.rs` | Self-declared "SAFE / 0 Critical" audit strings | Unverifiable claims |
| `settlement/PRODUCTION.md`, `V0_INVENTORY.md` | Docs for the above | Describe archived code |
| `zcash-adapter/` | `MockZcashAdapter` and the QEDIT placeholder, built on `zsa.rs` | M4. At `b017962` `crates/zcash-adapter` was a reserved README owned by the repository owner; that placeholder is restored. |

Changes applied while archiving (source level only):

- **F-11:** `OrchardIvkBytes` no longer derives `Debug` or `Copy`. It has a
  redacted manual `Debug` and is zeroized on drop.
- **F-12:** simulated "Real Orchard" types were renamed to
  `SimulatedOrchardIvkControlVerifier` / `SimulatedOrchardControlProof`, and
  `control.rs` carries a banner stating it is a simulation.

The M3 output that M4 should consume is `zwa_settlement::ApprovedSettlement`.
See `crates/settlement/README.md`.
