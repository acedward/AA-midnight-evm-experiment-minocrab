//! # `manager.compact` ported to the MinoCrab eDSL
//!
//! (Comments throughout this crate cite project numbers — `00012`, `00018`, `00020` — and finding
//! IDs — `F-00012-07`, `F-00020-01` — from the research log that produced the port. They are
//! provenance markers, not files in this repository; see the README.)
//!
//! Every circuit here is a **faithful** port under spec FR-003: same typed argument/output schema,
//! same disclosures, same guard set and order, FAB-compatible public-input encoding, **no statement
//! change**. MinoCrab's own instruction-selection optimizations are allowed and are precisely what
//! the comparison measures; statement-changing optimizations (Poseidon for keccak, Borsh for FAB,
//! restructured preimages) belong exclusively to the isolated aggressive arm (FR-009, plan
//! Phase 6) and must never appear in this crate.
//!
//! The baseline this is compared against is **our own** compactc artifact for the same contract
//! commit — compiled by `scripts/compile-baseline.sh` into `generated/baseline/manager/zkir/` —
//! not minocrab's own corpus (Q3 bar A).
//!
//! ## One Rust module per Compact module
//!
//! The contract this transcribes is a **preset plus nine modules**
//! (product `main` @ `41de69d`), and the modules below carry the same names, so a reader moving
//! between the two repositories can open the file with the same name and find the same circuits.
//!
//! | Compact | here | key-emitting circuits |
//! |---|---|---|
//! | `contracts/manager.compact` (the preset) | [`execute`] | `execute` |
//! | `contracts/modules/AccountRegistry.compact` | [`account_registry`] | `isRegistered`, `accountRecord` |
//! | `contracts/modules/ShieldedCustody.compact` | [`shielded_custody`] | `shieldedAccountBalance`, `poolValue`, `poolHasColour` |
//! | `contracts/modules/UnshieldedCustody.compact` | [`unshielded_custody`] | `unshieldedAccountBalance` |
//! | `contracts/modules/Custody.compact` | [`custody`] | `depositShielded`, `depositUnshielded` |
//! | `contracts/modules/ActionEnvelope.compact` | [`action_envelope`] | — (`ExecutePayload` and the envelope asserts) |
//! | `contracts/modules/Eip712.compact` | [`eip712`] | — (pure; frozen bytes) |
//! | `contracts/modules/ByteCodec.compact` | [`byte_codec`] | — (pure; where the row win is) |
//! | `contracts/modules/ZswapPrimitives.compact` | [`zswap_primitives`] | — (pure; recipes over the kernel) |
//! | `contracts/modules/SemanticCommitment.compact` | **no counterpart** | — |
//!
//! `SemanticCommitment` is not ported: it is pure, emits no key, and is not among the nine provable
//! circuits, so there is nothing for the differential suite to compare. Two modules here have no
//! Compact twin either, and say so in their own headers: [`ledger`] (the slot table, which in
//! Compact is spread across the four files that own state), [`checks`] (predicates Compact
//! expresses as syntax) and [`disclosures`] (one type per `disclose(…)` label, which Compact
//! expresses as the argument's name). [`hello`] is a bring-up scaffold, not a port.
//!
//! The mapping is **not** one-to-one on every function: where a Compact internal only ever runs
//! inside `custodyDispatch`, it is inlined there rather than given a Rust function of its own,
//! because the emitted op stream is what has to match and inlining is what compactc does. Each
//! module header says which of its twin's circuits it holds and which it does not.

use minocrab::v3::Compiled3;

pub mod account_registry;
pub mod action_envelope;
pub mod byte_codec;
pub mod checks;
pub mod custody;
pub mod disclosures;
pub mod eip712;
pub mod execute;
pub mod hello;
pub mod ledger;
pub mod shielded_custody;
pub mod unshielded_custody;
pub mod zswap_primitives;

/// Every circuit this crate can emit, as `(zkir-file-stem, builder)`.
///
/// The emitter binary walks this list; the differential suite indexes it by name. Adding a
/// ported circuit means adding one line here, mirroring
/// `minocrab-contracts/tests/support::circuits()`.
///
/// **The names and their ORDER are part of the artifact identity** — `emit-zkir` writes the files
/// in this order and `scripts/check-port-artifacts.sh` compares them by name — so a refactor that
/// moves a builder between modules changes the path on the right and nothing on the left.
pub fn circuits() -> Vec<(&'static str, fn() -> Compiled3)> {
    vec![
        (
            "hello_positive_amount",
            hello::positive_amount as fn() -> Compiled3,
        ),
        // Phase 2 probe. The name is the compactc circuit name, so the emitted
        // `<name>.zkir` sits next to the baseline artifact of the same name.
        (
            "isRegistered",
            account_registry::is_registered as fn() -> Compiled3,
        ),
        // Phase 3 — the headline circuit.
        ("execute", execute::execute as fn() -> Compiled3),
        // Phase 4 — the rest of the nine-ZKIR provable surface.
        (
            "poolHasColour",
            shielded_custody::pool_has_colour as fn() -> Compiled3,
        ),
        (
            "poolValue",
            shielded_custody::pool_value as fn() -> Compiled3,
        ),
        (
            "shieldedAccountBalance",
            shielded_custody::shielded_account_balance as fn() -> Compiled3,
        ),
        (
            "unshieldedAccountBalance",
            unshielded_custody::unshielded_account_balance as fn() -> Compiled3,
        ),
        (
            "accountRecord",
            account_registry::account_record as fn() -> Compiled3,
        ),
        (
            "depositUnshielded",
            custody::deposit_unshielded as fn() -> Compiled3,
        ),
        (
            "depositShielded",
            custody::deposit_shielded as fn() -> Compiled3,
        ),
    ]
}
