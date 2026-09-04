//! `contracts/modules/ShieldedCustody.compact` — the shielded custody family.
//!
//! **Compact twin**: `contracts/modules/ShieldedCustody.compact`, which owns the ledger fields
//! `pools` and `shieldedBalances` and every write to them.
//!
//! **Circuits ported here** (3 of the nine key-emitting circuits):
//! [`shielded_account_balance`], [`pool_value`], [`pool_has_colour`]. The module's internals
//! `_familyTag`, `_balanceAt`, `_credit`, `_writeCell`, `_pooled`, `_sendNamed`, `_releaseOpen` and
//! `_claimWant` are here too where they exist as separate functions; the four that only ever run
//! inside `custodyDispatch` are inlined in [`crate::custody::custody_dispatch`], exactly as the
//! op stream requires, and are documented there.
//!
//! `shieldedKey(acct, colour)` is [`crate::custody::family_key`] with [`shielded_family_tag`]:
//! the hash body is identical in both families and in the composer's `debitKey`, so the port has
//! one helper where Compact has three call sites.
//!
//! ## The one ledger-typing workaround, and why it is sound
//!
//! `pools` is a `Map<Bytes<32>, QualifiedShieldedCoinInfo>`. minocrab gives that map
//! `insert_coin`, `member` and `remove`, but **not `lookup`**: `LedgerRepr` — the trait a value type
//! needs to be read back out of a map — is implemented for the leaf types and for `Either`/`Maybe`,
//! not for `QualifiedShieldedCoinInfo3`, and the orphan rule forbids adding it from here.
//!
//! The fix is a second *view* of the same field: [`PooledCoin`] is a local struct with the identical
//! FAB shape, [`PooledCoin`] implements `LedgerRepr` (a foreign trait on a LOCAL type — allowed),
//! and [`POOLS_READ`] is `LedgerMap::at(ledger::slot::POOLS)` over it. Same field index, same key
//! type, same atoms, so the emitted `dup 0; idx [POOLS]; idx {key}; popeq` is byte-identical to
//! what a native `lookup` would emit; the only thing that changed is which Rust type names the
//! popeq's limbs. The atoms are taken from `QualifiedShieldedCoinInfo3`'s own `CircuitAbi` impl
//! rather than re-listed, so the two views cannot drift.
//!
//! The index is TAKEN FROM the ledger block, never written here. It used to be the literal `0`,
//! and the product's module split moved `pools` to slot 4 — a second handle carrying its own copy
//! of a slot number is exactly how a reorder silently retargets half a circuit, so this one now
//! derives it. `the_read_view_is_the_same_field_as_the_write_view` pins the two together.
//!
//! ## The `member ? lookup : 0` idiom
//!
//! [`shielded_balance_at`] is `member(k) ? lookup(k) : 0`. compactc lowers that to a `member` under
//! the ambient guard and a `lookup` under `ambient && member`, whose `public_input` gates yield the
//! type default when the guard is off — which is exactly what a `when_value` scope emits here. See
//! finding F-00012-07 in [`crate::custody`]'s docs for why this is a SCOPE and not
//! `lookup_guarded`.
//!
//! ## What the readers have in common, and why that matters to the comparison
//!
//! Every read-only circuit in this contract is a disclosure, one or two ledger reads, and a return.
//! The Phase-2 construct survey measured the byte-chain opcodes (`div_mod_power_of_two` /
//! `reconstitute_field` / their `cond_select`s) at **0.0%** of these circuits' instructions — the
//! entire minocrab opportunity on this contract sits in `execute`. `isRegistered`'s Δ=0 was the
//! first confirmation; the other readers are the rest of the falsification surface.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{AlignmentAtom, Private, Public};
use minocrab_std::v3::{
    circuit, Bool, CircuitAbi, CoinColor, CoinNonce, Disclose, Discloses, LedgerMap, LedgerRepr,
    QualifiedShieldedCoinInfo3, ShieldedCoinInfo3, Uint, B32,
};

use crate::custody::family_key;
use crate::disclosures::{Colour, Owner};
use crate::ledger::MANAGER;
use crate::zswap_primitives::self_recipient;

/// `_familyTag()` — `pad(32, "aa:manager:shielded:v1")` (`contracts/modules/ShieldedCustody.compact:95-97`).
///
/// It was `shieldedFamilyTag` while the contract was one file; the split gave each family module
/// the same private name, and `Custody.compact` disambiguates them with a renaming import.
pub fn shielded_family_tag(c: &mut Circuit3) -> B32<Public> {
    B32::pad(c, "aa:manager:shielded:v1")
}

/// `QualifiedShieldedCoinInfo` as a LOCAL type, so it can carry `LedgerRepr` (see the module docs).
///
/// Field order is Compact's declaration order and therefore the FAB slot order:
/// `nonce: Bytes<32>` (2 limbs), `color: Bytes<32>` (2), `value: Uint<128>` (1),
/// `mt_index: Uint<64>` (1) — six limbs under four atoms, which is exactly the
/// `popeq(<32+32+16+8>[…6 limbs])` the compactc artifact emits for `pools.lookup`
/// (`evidence/00012/raw/00012-p3.4-execute-impact-ops.txt`, op 133).
#[derive(Clone, Copy)]
pub struct PooledCoin {
    pub nonce: B32<Public>,
    pub color: B32<Public>,
    pub value: Wire3<FieldT, Public>,
    pub mt_index: Wire3<FieldT, Public>,
}

impl PooledCoin {
    /// The same value as minocrab's own coin type, so the kernel gadgets can take it.
    pub fn as_qualified(&self) -> QualifiedShieldedCoinInfo3<Public> {
        QualifiedShieldedCoinInfo3 {
            nonce: CoinNonce(self.nonce),
            color: CoinColor(self.color),
            value: self.value,
            mt_index: self.mt_index,
        }
    }

    /// `dropMerkleIndex(coin)` — the stdlib's private `downcastQualifiedCoin`
    /// (`contracts/modules/ZswapPrimitives.compact:79-81`). Zero instructions.
    pub fn downcast(&self) -> ShieldedCoinInfo3<Public> {
        ShieldedCoinInfo3 {
            nonce: CoinNonce(self.nonce),
            color: CoinColor(self.color),
            value: self.value,
        }
    }
}

impl LedgerRepr for PooledCoin {
    fn atoms() -> Vec<AlignmentAtom> {
        // Taken from minocrab's own coin type rather than re-listed, so the two views of `pools`
        // cannot drift apart.
        <QualifiedShieldedCoinInfo3<Public> as CircuitAbi>::atoms()
    }

    fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.push(self.nonce.hi);
        limbs.push(self.nonce.lo);
        limbs.push(self.color.hi);
        limbs.push(self.color.lo);
        limbs.push(self.value);
        limbs.push(self.mt_index);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        debug_assert_eq!(limbs.len(), 6, "a pooled coin reads back six limbs");
        PooledCoin {
            nonce: B32 {
                hi: limbs[0],
                lo: limbs[1],
            },
            color: B32 {
                hi: limbs[2],
                lo: limbs[3],
            },
            value: limbs[4],
            mt_index: limbs[5],
        }
    }
}

/// The READ view of the `pools` ledger field. Same field, same key type, different Rust value type
/// — see the module docs. Writes still go through [`MANAGER.pools`](crate::ledger::Manager::pools),
/// whose `insert_coin` is the one method that needs minocrab's own coin type.
///
/// The slot comes from [`crate::ledger::slot::POOLS`], so this view and the write view are the
/// same field by construction rather than by two matching literals.
pub const POOLS_READ: LedgerMap<B32<Public>, PooledCoin> =
    LedgerMap::at(crate::ledger::slot::POOLS);

/// The read view and the write view name the SAME ledger field.
///
/// They are two handles over one slot, so a hard-coded index in either would be a silent
/// retarget of every pooled-coin read. This is the check that made the `41de69d` re-target's
/// `pools` move (slot 0 → 4) impossible to miss: before the slot was derived, the read view still
/// pointed at slot 0 — which by then held `accounts` — and the differential suite caught it as
/// `idx [0x00]` where compactc emits `idx [0x04]`.
#[test]
fn the_read_view_is_the_same_field_as_the_write_view() {
    assert_eq!(
        POOLS_READ.index(),
        crate::ledger::MANAGER.pools.index(),
        "the pooled-coin READ view is not the ledger's `pools` field"
    );
    assert_eq!(POOLS_READ.index(), crate::ledger::slot::POOLS);
}

/// `shieldedBalances.member(k) ? shieldedBalances.lookup(k) : 0` (`contracts/modules/ShieldedCustody.compact:133-135`).
pub fn shielded_balance_at(c: &mut Circuit3, k: &B32<Public>) -> Uint<128, Public> {
    let present = MANAGER.shielded_balances.member(c, k);
    // A SCOPE, not `lookup_guarded(c, present, …)`: see F-00012-07 in the module docs. The
    // scope's guard is `ambient && present`, which is what compactc puts on BOTH the read's gates
    // and its op.
    c.when_value(present.field(), |c| MANAGER.shielded_balances.lookup(c, k))
        .otherwise(|c| Uint::<128, Public>::constant(c, 0))
        .into_inner()
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

/// `repoolOrRemove(col, change)` (`contracts/modules/ShieldedCustody.compact:144-151`) — write back what is left of colour
/// `col`'s pool after a debit, or drop the colour entirely.
///
/// ```text
/// if (change.is_some) { pools.insertCoin(col, change.value, right(kernel.self())); }
/// else                { pools.remove(col); }
/// ```
///
/// Both arms are compiled, each under its own guard, exactly as Compact does — and the op stream
/// confirms the ORDER: the `insertCoin` arm first, the `remove` arm second (ops 175-188).
pub fn repool_or_remove(
    c: &mut Circuit3,
    is_some: Wire3<FieldT, Public>,
    col: &B32<Public>,
    change: &ShieldedCoinInfo3<Public>,
) {
    c.when(is_some, |c| {
        let recipient = self_recipient(c);
        MANAGER.pools.insert_coin(c, col, change, &recipient);
    })
    .otherwise(|c| {
        MANAGER.pools.remove(c, col);
    });
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

/// `export circuit poolValue(colour: Bytes<32>): Uint<128>` (`contracts/modules/ShieldedCustody.compact:121-124`)
///
/// ```compact
/// const col = disclose(colour);
/// return pools.member(col) ? pools.lookup(col).value : 0;
/// ```
///
/// The `lookup` reads a `QualifiedShieldedCoinInfo` — six limbs — through [`POOLS_READ`], the
/// second view of `pools` that finding **F-00012-05** made necessary (minocrab gives a coin-valued
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

/// `export circuit poolHasColour(colour: Bytes<32>): Boolean` (`contracts/modules/ShieldedCustody.compact:127-129`)
///
/// [`crate::account_registry::is_registered`] against the `pools` field instead of `accounts` — the
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
