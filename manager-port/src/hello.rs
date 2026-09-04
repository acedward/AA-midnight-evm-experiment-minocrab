//! The Phase 0.4 scaffold circuit.
//!
//! **No Compact twin** — it is not a port of anything, and it is not one of the nine provable
//! circuits. It stays because `scripts/check-port-artifacts.sh` gates its emitted ZKIR like the
//! rest, which makes it a free canary on the eDSL itself.
//!
//! Not a port of anything — its only job is to prove that this workspace builds against the
//! pinned minocrab crates by path, emits ZKIR, and that the emitted ZKIR is accepted by the
//! project's `zkir-v3 mock-compile` oracle (task 0.5). It mirrors the smallest real guard in
//! `manager.compact`'s deposit path: a positive-amount assertion on a `Uint<64>`.

use minocrab::v3::{Circuit3, Compiled3};
use minocrab_std::v3::Uint;

/// `assert(amount > 0)` over one constrained `Uint<64>` argument.
///
/// The width of the comparison comes from the argument's type, never from a number written at
/// the call site — the eDSL's rule, and the same rule compactc follows.
pub fn positive_amount() -> Compiled3 {
    let mut c = Circuit3::new();
    let w = c.arg("amount");
    let amount = Uint::<64>::from_field_checked(&mut c, w);
    c.assert(amount.gt(0u64).message("Amount must be positive"));
    c.finish(true)
}
