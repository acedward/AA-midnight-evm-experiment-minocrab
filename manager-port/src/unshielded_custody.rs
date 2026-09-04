//! `contracts/modules/UnshieldedCustody.compact` — the unshielded custody family.
//!
//! **Compact twin**: `contracts/modules/UnshieldedCustody.compact`, which owns the ledger field
//! `unshieldedBalances` and every write to it.
//!
//! **Circuits ported here** (1 of the nine key-emitting circuits):
//! [`unshielded_account_balance`]. The module's `_familyTag`, `_balanceAt` and `_give` are here;
//! `_credit` and `_writeCell` only ever run inside `custodyDispatch` and are inlined in
//! [`crate::custody::custody_dispatch`].
//!
//! `unshieldedKey(acct, colour)` is [`crate::custody::family_key`] with
//! [`unshielded_family_tag`] — the twin of the shielded module's, deliberately symmetric, as in
//! Compact.
//!
//! [`send_unshielded`] is the stdlib recipe `_give` calls, transcribed here rather than imported;
//! its doc comment carries the reason (finding F-00012-07).

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_std::v3::{
    circuit, kernel, CoinColor, ContractAddress, Disclose, Discloses, Uint, B32,
};

use crate::custody::family_key;
use crate::disclosures::{Colour, Owner};
use crate::ledger::MANAGER;

/// `_familyTag()` — `pad(32, "aa:manager:unshielded:v1")` (`contracts/modules/UnshieldedCustody.compact:63-65`),
/// the unshielded family's half of the pair above.
pub fn unshielded_family_tag(c: &mut Circuit3) -> B32<Public> {
    B32::pad(c, "aa:manager:unshielded:v1")
}

/// `unshieldedBalances.member(k) ? unshieldedBalances.lookup(k) : 0` (`contracts/modules/UnshieldedCustody.compact:90-92`).
pub fn unshielded_balance_at(c: &mut Circuit3, k: &B32<Public>) -> Uint<128, Public> {
    let present = MANAGER.unshielded_balances.member(c, k);
    c.when_value(present.field(), |c| {
        MANAGER.unshielded_balances.lookup(c, k)
    })
    .otherwise(|c| Uint::<128, Public>::constant(c, 0))
    .into_inner()
}

/// `unshieldedBalanceOf(acct, colour)` (`contracts/modules/UnshieldedCustody.compact:73-76`) — the OTHER family, and a
/// different constant tag, so the two answer independently for a byte-identical `colour`.
///
/// Top-level only, for the same reason as [`crate::shielded_custody::shielded_balance_of`].
pub fn unshielded_balance_of(
    c: &mut Circuit3,
    acct: &B32<Public>,
    colour: &B32<Public>,
) -> Uint<128, Public> {
    let tag = unshielded_family_tag(c);
    let k = family_key(c, acct, colour, &tag);
    let present = MANAGER.unshielded_balances.member(c, &k);
    MANAGER
        .unshielded_balances
        .lookup_guarded(c, present.field(), &k)
        .or_default()
}

/// The stdlib's `sendUnshielded(color, amount, recipient)` (`standard-library.compact:113-120`),
/// transcribed because minocrab's own copy is unusable inside a branch — **finding F-00012-07**.
///
/// ```text
/// kernel.incUnshieldedOutputs(left<Bytes<32>, Bytes<32>>(color), amount);
/// kernel.claimUnshieldedCoinSpend(left<Bytes<32>, Bytes<32>>(color), recipient, amount);
/// if (recipient.is_left && recipient.left.bytes == kernel.self().bytes) {
///   kernel.incUnshieldedInputs(left<Bytes<32>, Bytes<32>>(color), amount);
/// }
/// ```
///
/// `minocrab-std`'s `kernel::send_unshielded` reads `kernel.self()` through `kernel_self_guarded`,
/// which mints the read's `public_input` gates against the **raw** `is_left` wire while the op
/// itself is emitted under `ambient && is_left`. Called inside a `c.when` scope — which is where
/// `custodyDispatch` calls it from — the gates are therefore guarded more weakly than the op, and
/// the run consumes a public-transcript output the ledger never produced. Written here as a scope
/// instead, so the guard on the gates and the guard on the op are the same wire.
pub fn send_unshielded(
    c: &mut Circuit3,
    color: B32<Public>,
    amount: minocrab_std::v3::Uint<128, Public>,
    recipient: &kernel::UnshieldedRecipient<Public>,
) {
    let token = kernel::unshielded(c, CoinColor(color));
    kernel::inc_unshielded_outputs(c, &token, amount);
    kernel::claim_unshielded_coin_spend(c, &token, recipient, amount);

    // `recipient.is_left && recipient.left.bytes == kernel.self().bytes` — the AUTO-RECEIVE guard.
    // The `kernel.self()` read is guarded by `is_left` alone in Compact (a recipient that is a user
    // address never needs the contract's own address), and by `ambient && is_left` here, which is
    // the same wire compactc guards both the gates and the op with.
    let is_left = recipient.is_left.field();
    let zero = c.constant(0u64);
    let me = c
        .when_value(is_left, |c| kernel::self_address(c).address())
        .otherwise(|_c| ContractAddress(B32 { hi: zero, lo: zero }))
        .into_inner();
    let left = recipient.left.bytes();
    let mine = {
        let me = me.bytes();
        let eq_hi = c.test_eq(left.hi, me.hi);
        let eq_lo = c.test_eq(left.lo, me.lo);
        // compactc lowers `&&` on Booleans as a `cond_select`, not a `mul`.
        let both = c.cond_select(eq_hi, eq_lo, 0u64);
        c.cond_select(is_left, both, 0u64)
    };
    kernel::inc_unshielded_inputs_under(c, mine, &token, amount);
}

/// `export circuit unshieldedAccountBalance(owner, colour): Uint<128>` (`contracts/modules/UnshieldedCustody.compact:84-86`)
#[circuit(output = "balance")]
pub fn unshielded_account_balance(
    c: &mut Circuit3,
    owner: B32<Private>,
    colour: B32<Private>,
) -> Discloses<(Owner, Colour), Uint<128, Public>> {
    let owner = owner.disclose_as::<Owner>(c);
    let colour = colour.disclose_as::<Colour>(c);
    Discloses::of(unshielded_balance_of(c, &owner, &colour))
}
