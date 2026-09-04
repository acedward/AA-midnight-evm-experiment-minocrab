//! The contract's disclosure vocabulary — one type per `disclose(…)` label. **NO Compact twin.**
//!
//! In Compact a disclosure is `disclose(owner)` and the label is simply the argument's name, so no
//! declaration exists to port. minocrab makes the label a TYPE, so that a circuit's declared
//! disclosures (`Discloses<(Owner, Colour)>`) can be checked against the ones its body actually
//! makes — the generated `the_declared_disclosures_are_the_ones_the_circuit_makes` test in every
//! disclosing circuit. That check is why these are worth having; it is also why they are declared
//! ONCE, here, instead of per module: two modules each declaring their own `Colour = "colour"`
//! would be two distinct Rust types with one string between them, and the first divergence would
//! be silent.
//!
//! Labels are metadata — no instruction, no row — exactly as in Compact, so naming them costs
//! nothing in the emitted circuit.

use minocrab_std::v3::label;

label! {
    /// `disclose(owner)` — the account id a reader is asking about. Disclosed because a
    /// `Set.member` or `Map.lookup` read puts the key in the public transcript; that is the same
    /// disclosure compactc's `disclose(owner)` makes, and naming it here is what the generated
    /// set-equality test enforces.
    pub Owner = "owner";
    /// `disclose(colour)` — the colour whose cell or pool is being read or credited.
    pub Colour = "colour";
    /// `disclose(account)` — `accountRecord`'s subject.
    pub Account = "account";
    /// `disclose(coin)` — the deposited coin. It lands in ledger state (the pool), so it is a
    /// public fact of the transfer.
    pub Coin = "coin";
    /// `disclose(account)` — the credited account id, in the deposit circuits.
    pub CreditAccount = "account";
    /// `disclose(amount)` — the unshielded amount being credited.
    pub Amount = "amount";
}
