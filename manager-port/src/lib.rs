//! # `manager.compact` ported to the MinoCrab eDSL
//!
//! (Comments throughout this crate cite project numbers — `00012`, `00018`, `00020` — and finding
//! IDs — `F-00012-07`, `F-00020-01` — from the research log that produced the port. They are
//! provenance markers, not files in this repository; see the README.)
//!
//! One module per ported circuit family. Every circuit here is a **faithful** port under
//! spec FR-003: same typed argument/output schema, same disclosures, same guard set and order,
//! FAB-compatible public-input encoding, **no statement change**. MinoCrab's own
//! instruction-selection optimizations are allowed and are precisely what the comparison
//! measures; statement-changing optimizations (Poseidon for keccak, Borsh for FAB, restructured
//! preimages) belong exclusively to the isolated aggressive arm (FR-009, plan Phase 6) and must
//! never appear in this crate.
//!
//! The baseline this is compared against is **our own** compactc artifact for the same contract
//! commit — compiled by `scripts/compile-baseline.sh` into `generated/baseline/manager/zkir/` —
//! not minocrab's own corpus (Q3 bar A).

use minocrab::v3::Compiled3;

pub mod coins;
pub mod custody;
pub mod deposits;
pub mod eip712;
pub mod execute;
pub mod envelope;
pub mod guards;
pub mod hello;
pub mod ledger;
pub mod payload;
pub mod queries;
pub mod words;

/// Every circuit this crate can emit, as `(zkir-file-stem, builder)`.
///
/// The emitter binary walks this list; the differential suite indexes it by name. Adding a
/// ported circuit means adding one line here, mirroring
/// `minocrab-contracts/tests/support::circuits()`.
pub fn circuits() -> Vec<(&'static str, fn() -> Compiled3)> {
    vec![
        ("hello_positive_amount", hello::positive_amount as fn() -> Compiled3),
        // Phase 2 probe. The name is the compactc circuit name, so the emitted
        // `<name>.zkir` sits next to the baseline artifact of the same name.
        ("isRegistered", queries::is_registered as fn() -> Compiled3),
        // Phase 3 — the headline circuit.
        ("execute", execute::execute as fn() -> Compiled3),
        // Phase 4 — the rest of the nine-ZKIR provable surface.
        ("poolHasColour", queries::pool_has_colour as fn() -> Compiled3),
        ("poolValue", queries::pool_value as fn() -> Compiled3),
        (
            "shieldedAccountBalance",
            queries::shielded_account_balance as fn() -> Compiled3,
        ),
        (
            "unshieldedAccountBalance",
            queries::unshielded_account_balance as fn() -> Compiled3,
        ),
        ("accountRecord", queries::account_record as fn() -> Compiled3),
        (
            "depositUnshielded",
            deposits::deposit_unshielded as fn() -> Compiled3,
        ),
        (
            "depositShielded",
            deposits::deposit_shielded as fn() -> Compiled3,
        ),
    ]
}
