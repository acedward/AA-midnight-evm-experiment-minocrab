//! The contract's read-only browser-facing queries. Since the module split they live with the
//! state they read: `contracts/modules/AccountRegistry.compact:116-159` (`myAccount`,
//! `isRegistered`, `accountRecord`), `contracts/modules/ShieldedCustody.compact:116-129`
//! (`shieldedAccountBalance`, `poolValue`, `poolHasColour`) and
//! `contracts/modules/UnshieldedCustody.compact:84-86` (`unshieldedAccountBalance`).
//!
//! Phase 2 ported [`is_registered`], the smallest provable circuit in the contract (k=8 / 129 rows
//! under compactc). Phase 4 adds the other five readers: [`pool_has_colour`], [`pool_value`],
//! [`shielded_account_balance`], [`unshielded_account_balance`] and [`account_record`].
//!
//! ## What these five have in common, and why that matters to the comparison
//!
//! Every one of them is a disclosure, one or two ledger reads, and a return. The Phase-2 construct
//! survey measured the byte-chain opcodes (`div_mod_power_of_two` / `reconstitute_field` /
//! their `cond_select`s) at **0.0%** of these circuits' instructions — the entire minocrab
//! opportunity on this contract sits in `execute`. `isRegistered`'s Δ=0 was the first confirmation;
//! these are the rest of the falsification surface.
//!
//! ## The one structural trap: Compact's early `return` is a GUARD
//!
//! [`account_record`] is a chain of `if (…) { return …; }` blocks. A circuit has no control flow, so
//! compactc compiles every block and each one's reads and asserts are emitted under its own
//! condition AND the negation of every earlier one — the same lowering `envelope.rs` documents for
//! `assertActionEnvelope`. [`Circuit3::when_value`](minocrab::v3::Circuit3::when_value) is that
//! lowering: it pushes an ambient guard the enclosed ledger operations and asserts pick up, and
//! selects the value at the end.
//!
//! ## The short-circuit trap, again
//!
//! `!evmOwners.member(acct) && !evmNonces.member(acct)` does NOT read `evmNonces` unless the left
//! operand held: the compactc artifact guards that second `member` by `t.5 && !t.7`
//! (`accountRecord.zkir:38`). A minocrab `Check::and` is an inert descriptor and would not guard
//! the read — the read already happened at the call site — so each short-circuited read is written
//! as a scope. Same for `evmOwners.member(acct) && evmNonces.member(acct)` in the EVM arm.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_std::v3::{
    circuit, is_true, label, not, Bool, Bytes, CircuitOut, Disclose, Discloses, Select, Uint, B32,
};

use crate::coins::{family_key, shielded_family_tag, unshielded_family_tag, POOLS_READ};
use crate::ledger::MANAGER;

label! {
    /// `disclose(owner)` — the account id the caller is asking about. Disclosed because a
    /// `Set.member` read puts the key in the public transcript; that is the same disclosure
    /// compactc's `disclose(owner)` makes, and naming it here is what the generated
    /// set-equality test enforces.
    Owner = "owner";
    /// `disclose(colour)` — the colour whose cell or pool is being read.
    Colour = "colour";
    /// `disclose(account)` — `accountRecord`'s subject.
    Account = "account";
}

/// `export circuit isRegistered(owner: Bytes<32>): Boolean` (`contracts/modules/AccountRegistry.compact:121-123`)
///
/// A faithful port: one disclosure, one `Set.member` read against field 1, the Boolean returned
/// as the circuit's declared output. No guard, no witness, no arithmetic — which is exactly why
/// it is the feasibility probe.
#[circuit(output = "registered")]
pub fn is_registered(c: &mut Circuit3, owner: B32<Private>) -> Discloses<(Owner,), Bool<Public>> {
    let owner = owner.disclose_as::<Owner>(c);
    Discloses::of(MANAGER.accounts.member(c, &owner))
}

/// `export circuit poolHasColour(colour: Bytes<32>): Boolean` (`contracts/modules/ShieldedCustody.compact:127-129`)
///
/// [`is_registered`] against ledger field **0** (`pools`) instead of field 1 (`accounts`) — the
/// same four instructions, the same shape. It is in the table as its own row because the baseline
/// measures it as its own ZKIR (k=8 / 129 rows), not because it is a different construction.
#[circuit(output = "hasColour")]
pub fn pool_has_colour(
    c: &mut Circuit3,
    colour: B32<Private>,
) -> Discloses<(Colour,), Bool<Public>> {
    let colour = colour.disclose_as::<Colour>(c);
    Discloses::of(MANAGER.pools.member(c, &colour))
}

/// `export circuit poolValue(colour: Bytes<32>): Uint<128>` (`contracts/modules/ShieldedCustody.compact:121-124`)
///
/// ```compact
/// const col = disclose(colour);
/// return pools.member(col) ? pools.lookup(col).value : 0;
/// ```
///
/// The `lookup` reads a `QualifiedShieldedCoinInfo` — six limbs — through [`POOLS_READ`], the
/// second view of field 0 that finding **F-00012-05** made necessary (minocrab gives a coin-valued
/// map `insert_coin`/`member`/`remove` but not `lookup`). Only `.value` is selected, which is what
/// the compactc artifact does too: one `cond_select` over the fifth limb (`poolValue.zkir:30`).
#[circuit(output = "value")]
pub fn pool_value(
    c: &mut Circuit3,
    colour: B32<Private>,
) -> Discloses<(Colour,), Uint<128, Public>> {
    let col = colour.disclose_as::<Colour>(c);
    let present = MANAGER.pools.member(c, &col);
    let pooled = POOLS_READ.lookup_guarded(c, present.field(), &col);
    Discloses::of(Uint::from_field_unchecked(pooled.or_default().value))
}

/// `shieldedBalanceOf(acct, colour)` (`contracts/modules/ShieldedCustody.compact:105-108`) —
/// `shieldedBalances.member(k) ? shieldedBalances.lookup(k) : 0`, where `k = shieldedKey(acct, colour)`.
///
/// **A MISSING CELL READS AS 0** (FR-204/FR-206) — and that is not re-implemented here, it is the
/// guarded read's own semantics. A guarded-off `public_input` gate yields the type's default and
/// consumes no transcript (upstream's VM, `ir_vm.rs:348-366`), so `Guarded::or_default()` — which
/// emits **nothing** — *is* the `: 0` arm. compactc still emits a `cond_select` over the same two
/// values; both answer 0 on the missing-cell path, and the equivalence gate compares the resulting
/// PI vectors and circuit outputs rather than taking that on trust.
///
/// **TOP-LEVEL ONLY.** `lookup_guarded` mints the read's gates under `guard` and emits its op under
/// `ambient && guard`; where there is no ambient scope those are the same wire, which is compactc's
/// shape exactly. Inside a `c.when` scope they are NOT (finding **F-00012-07**), and the scope form
/// is required instead — which is why `custody.rs` keeps its own `shielded_balance_at` for the
/// `execute` call sites. Every caller of this function is a top-level circuit body.
pub fn shielded_balance_of(
    c: &mut Circuit3,
    acct: &B32<Public>,
    colour: &B32<Public>,
) -> Uint<128, Public> {
    let tag = shielded_family_tag(c);
    let k = family_key(c, acct, colour, &tag);
    let present = MANAGER.shielded_balances.member(c, &k);
    MANAGER
        .shielded_balances
        .lookup_guarded(c, present.field(), &k)
        .or_default()
}

/// `unshieldedBalanceOf(acct, colour)` (`contracts/modules/UnshieldedCustody.compact:73-76`) — the OTHER family, and a
/// different constant tag, so the two answer independently for a byte-identical `colour`.
///
/// Top-level only, for the same reason as [`shielded_balance_of`].
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

/// `export circuit shieldedAccountBalance(owner, colour): Uint<128>` (`contracts/modules/ShieldedCustody.compact:116-118`)
#[circuit(output = "balance")]
pub fn shielded_account_balance(
    c: &mut Circuit3,
    owner: B32<Private>,
    colour: B32<Private>,
) -> Discloses<(Owner, Colour), Uint<128, Public>> {
    let owner = owner.disclose_as::<Owner>(c);
    let colour = colour.disclose_as::<Colour>(c);
    Discloses::of(shielded_balance_of(c, &owner, &colour))
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

// ---- accountRecord ------------------------------------------------------------------------------

/// `export struct AccountRecord` (`contracts/modules/AccountRegistry.compact:57-62`) — the only STRUCT RETURN in the
/// contract's provable surface.
///
/// **Hand-written [`CircuitOut`] and [`Select`], because minocrab has no derive for either.** The
/// field order below IS the output slot order, which the compactc artifact pins:
/// `accountRecord.zkir` declares four `Scalar<BLS12-381>` outputs and ends with
/// `output [%t.2, %t.25, %t.26, %t.27]` — registered, mode, owner, nextNonce. Reordering the
/// fields changes the public schema, which the differential's schema-identity clause catches.
#[derive(Clone, Copy)]
pub struct AccountRecordOut {
    pub registered: Bool<Public>,
    pub mode: Uint<8, Public>,
    pub owner: Bytes<20, Public>,
    pub next_nonce: Uint<64, Public>,
}

impl AccountRecordOut {
    /// `AccountRecord{ registered: false, mode: 0, owner: default<Bytes<20>>, nextNonce: 0 }` —
    /// the all-zero inactive record an unknown account returns.
    fn zero(c: &mut Circuit3) -> Self {
        let z = c.constant(0u64);
        AccountRecordOut {
            registered: Bool::from_field_unchecked(z),
            mode: Uint::from_field_unchecked(z),
            owner: Bytes::from_field_unchecked(z),
            next_nonce: Uint::from_field_unchecked(z),
        }
    }
}

impl CircuitOut for AccountRecordOut {
    const SLOTS: usize = 4;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.registered.field(), &format!("{label} registered"));
        c.output(self.mode.field(), &format!("{label} mode"));
        c.output(self.owner.field(), &format!("{label} owner"));
        c.output(self.next_nonce.field(), &format!("{label} nextNonce"));
    }
}

impl Select<Public> for AccountRecordOut {
    fn select(
        c: &mut Circuit3,
        bit: Wire3<FieldT, Public>,
        taken: Self,
        fallback: Self,
    ) -> Self {
        AccountRecordOut {
            registered: Select::select(c, bit, taken.registered, fallback.registered),
            mode: Select::select(c, bit, taken.mode, fallback.mode),
            owner: Select::select(c, bit, taken.owner, fallback.owner),
            next_nonce: Select::select(c, bit, taken.next_nonce, fallback.next_nonce),
        }
    }
}

/// `export circuit accountRecord(account: Bytes<32>): AccountRecord` (`contracts/modules/AccountRegistry.compact:131-159`)
///
/// ```compact
/// const acct = disclose(account);
/// if (!accounts.member(acct)) { return AccountRecord{false, 0, default, 0}; }
/// const mode = accountModes.lookup(acct);
/// if (mode == 0) {
///   assert(!evmOwners.member(acct) && !evmNonces.member(acct), "native record carries EVM state");
///   return AccountRecord{true, 0, default, 0};
/// }
/// assert(mode == 1, "unknown account authorization mode");
/// assert(evmOwners.member(acct) && evmNonces.member(acct), "EVM record is incomplete");
/// return AccountRecord{true, 1, evmOwners.lookup(acct), evmNonces.lookup(acct)};
/// ```
///
/// Eight ledger reads in the compactc artifact, under five distinct guards, in this order —
/// which is what `pi_skips` equality forces the port to reproduce:
///
/// | # | read | guard |
/// |---:|---|---|
/// | 1 | `accounts.member` (field 1) | ambient |
/// | 2 | `accountModes.lookup` (field 4) | `registered` |
/// | 3 | `evmOwners.member` (field 5) | `registered && mode == 0` |
/// | 4 | `evmNonces.member` (field 6) | `… && !hasOwner` (short-circuit) |
/// | 5 | `evmOwners.member` (field 5) | `registered && mode != 0` — a SECOND read |
/// | 6 | `evmNonces.member` (field 6) | `… && hasOwner` (short-circuit) |
/// | 7 | `evmOwners.lookup` (field 5) | `registered && mode != 0` |
/// | 8 | `evmNonces.lookup` (field 6) | `registered && mode != 0` |
///
/// Reads 3 and 5 are the SAME `evmOwners.member(acct)` written twice in the source, once per
/// branch. Compactc compiles both, under different guards; hoisting it to one read would drop an
/// `Impact` and fail `pi_skips` — the `contracts/modules/AccountRegistry.compact:178` precedent from Phase 3.
#[circuit(output = "record")]
pub fn account_record(
    c: &mut Circuit3,
    account: B32<Private>,
) -> Discloses<(Account,), AccountRecordOut> {
    let acct = account.disclose_as::<Account>(c);

    // `if (!accounts.member(acct)) { return <zero record>; }` — the early return is the guard for
    // everything below it.
    let registered = MANAGER.accounts.member(c, &acct);
    let record = c
        .when_value(registered.field(), |c| {
            let mode = MANAGER.account_modes.lookup(c, &acct);
            let is_native = mode.eq(0u64).into_wire(c);

            c.when_value(is_native, |c| {
                // `assert(!evmOwners.member(acct) && !evmNonces.member(acct), …)` — the second
                // read is SHORT-CIRCUITED behind the first, so it is a scope, not a `Check::and`.
                let has_owner = MANAGER.evm_owners.member(c, &acct);
                let no_owner = c.not(has_owner.field());
                let has_nonce = c
                    .when_value(no_owner, |c| MANAGER.evm_nonces.member(c, &acct).field())
                    .otherwise(|c| c.constant(0u64))
                    .into_inner();
                c.assert(
                    not(is_true(has_owner))
                        .and(not(is_true(Bool::from_field_unchecked(has_nonce))))
                        .message("native record carries EVM state"),
                );
                let one = c.constant(1u64);
                let zero = c.constant(0u64);
                AccountRecordOut {
                    registered: Bool::from_field_unchecked(one),
                    mode: Uint::from_field_unchecked(zero),
                    owner: Bytes::from_field_unchecked(zero),
                    next_nonce: Uint::from_field_unchecked(zero),
                }
            })
            .otherwise(|c| {
                c.assert(mode.eq(1u64).message("unknown account authorization mode"));
                // `assert(evmOwners.member(acct) && evmNonces.member(acct), …)` — short-circuited
                // the other way round: the nonce read happens only where the owner read held.
                let has_owner = MANAGER.evm_owners.member(c, &acct);
                let has_nonce = c
                    .when_value(has_owner.field(), |c| {
                        MANAGER.evm_nonces.member(c, &acct).field()
                    })
                    .otherwise(|c| c.constant(0u64))
                    .into_inner();
                c.assert(
                    is_true(has_owner)
                        .and(is_true(Bool::from_field_unchecked(has_nonce)))
                        .message("EVM record is incomplete"),
                );
                let owner = MANAGER.evm_owners.lookup(c, &acct);
                let next_nonce = MANAGER.evm_nonces.lookup(c, &acct);
                let one = c.constant(1u64);
                AccountRecordOut {
                    registered: Bool::from_field_unchecked(one),
                    mode: Uint::from_field_unchecked(one),
                    owner,
                    next_nonce,
                }
            })
            .into_inner()
        })
        .otherwise(AccountRecordOut::zero)
        .into_inner();

    Discloses::of(record)
}
