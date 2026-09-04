//! Phase 4 — the two credit paths: `depositShielded` and `depositUnshielded`
//! (the preset's public wrappers `contracts/manager.compact:288-290` and `:299-301`, over the
//! composer's `contracts/modules/Custody.compact:100-111` and `:120-134`).
//!
//! These are the only circuits besides `execute` that WRITE ledger state and touch the zswap /
//! unshielded kernel, so they are the only Phase-4 rows whose scenarios need the transcript model
//! Phase 3 built. Everything they need already exists: `receiveShielded` and the family-key hash in
//! [`crate::coins`], `receive_unshielded` and `merge_coin_immediate` directly from
//! `minocrab-std/src/v3/kernel.rs`, `LedgerMap::insert_coin` for the pool write.
//!
//! ## THE TRAP THESE TWO CARRY: compactc inlines, so a doubled call is a doubled hash
//!
//! Both circuits end with
//!
//! ```compact
//! xBalances.insert(xKey(acct, col), (xBalanceOf(acct, col) + amt) as Uint<128>);
//! ```
//!
//! and `xBalanceOf` computes `xKey(acct, col)` *again* internally. compactc inlines the call, so
//! the artifact carries **two identical `persistent_hash` instructions** over the same three words
//! — the outer key first (it is the insert's first argument, evaluated first), the inner one second
//! (`depositUnshielded.zkir:44` and `:46`; `depositShielded.zkir:150` and `:152`). Hoisting it to
//! one hash would be a statement-preserving optimization **compactc did not take**, so it is not
//! this port's to take either (FR-003: faithful, same structure); the same precedent as
//! `contracts/modules/AccountRegistry.compact:178`'s double `accountModes.lookup` in `execute`. It costs rows on both sides
//! equally, which is precisely why leaving it in keeps the comparison honest.
//!
//! ## `receiveShielded` is a recipe, not a primitive
//!
//! The pinned Compact standard library defines it as `right(kernel.self())` → `createZswapOutput`
//! (a Void witness native that emits nothing) → `kernel.claimZswapCoinReceive(coinCommitment(...))`.
//! [`crate::coins::receive_shielded`] is that transcription, and the artifact confirms the shape:
//! one `kernel.self()` context read, one `persistent_hash` under `midnight:zswap-cc[v1]`, one
//! effects claim, with nothing between them (`depositShielded.zkir:32-44`).

use minocrab::v3::{Circuit3, Compiled3};
use minocrab::{Private, Public};
use minocrab_std::v3::{
    circuit, is_true, kernel, label, CircuitArg, CoinColor, CoinNonce, Discloses, Disclose,
    ShieldedCoinInfo3, Uint, B32,
};

use crate::coins::{family_key, receive_shielded, self_recipient, shielded_family_tag, POOLS_READ};
use crate::ledger::MANAGER;
use crate::queries::{shielded_balance_of, unshielded_balance_of};

label! {
    /// `disclose(coin)` — the deposited coin. It lands in ledger state (the pool), so it is a
    /// public fact of the transfer.
    Coin = "coin";
    /// `disclose(account)` — the credited account id.
    CreditAccount = "account";
    /// `disclose(colour)` — the unshielded colour being credited.
    Colour = "colour";
    /// `disclose(amount)` — the unshielded amount being credited.
    Amount = "amount";
}

/// `struct ShieldedCoinInfo` as `depositShielded`'s first argument.
///
/// **Not `ShieldedCoinInfo3` itself:** minocrab has no `CircuitArg` impl for it (the trait is
/// implemented for the leaves, `[T; N]`, `Maybe` and `Either`, not for the coin structs), and
/// `#[circuit]` can only declare arguments through that trait. A local mirror with
/// `#[derive(CircuitArg)]` gives the identical slot layout — nonce (2), color (2), value (1) — which
/// the artifact pins as `%coin.0..4` with `constrain_bits` 8/248/8/248/**128**
/// (`depositShielded.zkir:16-20`). The same expressiveness gap as F-00012-06, and the same cost:
/// zero rows, zero statement change, only the spelling.
#[derive(CircuitArg)]
pub struct DepositCoin<V: minocrab_std::v3::Vis3> {
    pub nonce: B32<V>,
    pub color: B32<V>,
    pub value: Uint<128, V>,
}

impl DepositCoin<Public> {
    /// The same value as minocrab's own coin type, so the kernel gadgets can take it.
    fn as_coin(&self) -> ShieldedCoinInfo3<Public> {
        ShieldedCoinInfo3 {
            nonce: CoinNonce(self.nonce),
            color: CoinColor(self.color),
            value: self.value.field(),
        }
    }
}

/// `export circuit depositShielded(coin: ShieldedCoinInfo, account: Bytes<32>): []`
/// (`contracts/modules/Custody.compact:100-111`)
///
/// ```compact
/// const c = disclose(coin);
/// const acct = disclose(account);
/// assert(c.value > 0, "deposit must be positive");
/// assert(accounts.member(acct), "credit account is not registered");
/// receiveShielded(c);
/// if (pools.member(c.color)) {
///   pools.insertCoin(c.color, mergeCoinImmediate(pools.lookup(c.color), c), right(kernel.self()));
/// } else {
///   pools.insertCoin(c.color, c, right(kernel.self()));
/// }
/// shieldedBalances.insert(shieldedKey(acct, c.color), (shieldedBalanceOf(acct, c.color) + c.value) as Uint<128>);
/// ```
///
/// Every guard precedes every write, so a refusal creates nothing (FR-202) — preserved literally.
#[circuit]
pub fn deposit_shielded(
    c: &mut Circuit3,
    coin: DepositCoin<Private>,
    account: B32<Private>,
) -> Discloses<(Coin, CreditAccount)> {
    let coin = DepositCoin::<Public> {
        nonce: coin.nonce.disclose_as::<Coin>(c),
        color: coin.color.disclose_as::<Coin>(c),
        value: Uint::from_field_unchecked(coin.value.field().disclose_as::<Coin>(c)),
    };
    let acct = account.disclose_as::<CreditAccount>(c);

    c.assert(coin.value.gt(0u64).message("deposit must be positive"));
    let registered = MANAGER.accounts.member(c, &acct);
    c.assert(is_true(registered).message("credit account is not registered"));

    // Must precede insertCoin: this is what allocates the Merkle-tree index.
    let info = coin.as_coin();
    receive_shielded(c, &info);

    // `if (pools.member(c.color)) { merge } else { first credit }` — both arms are compiled, each
    // under its own guard, exactly as Compact does.
    let pooled = MANAGER.pools.member(c, &coin.color);
    c.when(pooled.field(), |c| {
        // A SCOPE, so the `lookup`'s gates and its op carry the same wire (F-00012-07).
        let existing = POOLS_READ.lookup(c, &coin.color);
        let merged = kernel::merge_coin_immediate(c, &existing.as_qualified(), &info);
        let recipient = self_recipient(c);
        MANAGER.pools.insert_coin(c, &coin.color, &merged, &recipient);
    })
    .otherwise(|c| {
        // FIRST CREDIT of this colour — the pool is created lazily, right here.
        let recipient = self_recipient(c);
        MANAGER.pools.insert_coin(c, &coin.color, &info, &recipient);
    });

    // The doubled key hash — see the module docs. The insert's key argument is evaluated first.
    let tag = shielded_family_tag(c);
    let key = family_key(c, &acct, &coin.color, &tag);
    let credited = {
        let held = shielded_balance_of(c, &acct, &coin.color);
        let sum = c.add(held.field(), coin.value.field());
        let w = Uint::<128, Public>::from_field_unchecked(sum);
        w.constrain_input(c);
        Uint::<128, Public>::from_field_unchecked(c.copy(sum))
    };
    MANAGER.shielded_balances.insert(c, &key, &credited);

    Discloses::of(())
}

/// `export circuit depositUnshielded(colour: Bytes<32>, amount: Uint<128>, account: Bytes<32>): []`
/// (`contracts/modules/Custody.compact:120-134`)
///
/// ```compact
/// const col = disclose(colour); const amt = disclose(amount); const acct = disclose(account);
/// assert(amt > 0, "deposit must be positive");
/// assert(accounts.member(acct), "credit account is not registered");
/// receiveUnshielded(col, amt);
/// unshieldedBalances.insert(unshieldedKey(acct, col), (unshieldedBalanceOf(acct, col) + amt) as Uint<128>);
/// ```
///
/// The tightest circuit in the contract: 7,918 of 8,192 rows at k=13, 3.3% headroom.
#[circuit]
pub fn deposit_unshielded(
    c: &mut Circuit3,
    colour: B32<Private>,
    amount: Uint<128, Private>,
    account: B32<Private>,
) -> Discloses<(Colour, Amount, CreditAccount)> {
    let col = colour.disclose_as::<Colour>(c);
    let amt = Uint::<128, Public>::from_field_unchecked(amount.field().disclose_as::<Amount>(c));
    let acct = account.disclose_as::<CreditAccount>(c);

    c.assert(amt.gt(0u64).message("deposit must be positive"));
    let registered = MANAGER.accounts.member(c, &acct);
    c.assert(is_true(registered).message("credit account is not registered"));

    kernel::receive_unshielded(c, CoinColor(col), amt);

    let tag = crate::coins::unshielded_family_tag(c);
    let key = family_key(c, &acct, &col, &tag);
    let credited = {
        let held = unshielded_balance_of(c, &acct, &col);
        let sum = c.add(held.field(), amt.field());
        let w = Uint::<128, Public>::from_field_unchecked(sum);
        w.constrain_input(c);
        Uint::<128, Public>::from_field_unchecked(c.copy(sum))
    };
    MANAGER.unshielded_balances.insert(c, &key, &credited);

    Discloses::of(())
}

/// Silence the unused-import lint when the macro expansion does not need `Compiled3` by name.
const _: fn() -> Compiled3 = deposit_shielded;
