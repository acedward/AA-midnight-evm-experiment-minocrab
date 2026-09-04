//! Phase 3.4 — `custodyDispatch` (`contracts/modules/Custody.compact:213-353`), the o2 custody mux: one debit leg,
//! one credit leg, muxed arguments, for all five custody selectors (2..6).
//!
//! **Compact twin**: `contracts/modules/Custody.compact`, THE COMPOSER — the only file that calls
//! both custody families, the contract's only debit path, and the owner of no ledger field at all.
//!
//! **Circuits ported here** (2 of the nine key-emitting circuits): [`deposit_shielded`] and
//! [`deposit_unshielded`], which in Compact are the preset's public wrappers
//! (`contracts/manager.compact:288-301`) over this module's `_depositShielded` / `_depositUnshielded`
//! (`contracts/modules/Custody.compact:100-134`). The wrapper and the internal are one function
//! here because the wrapper is a single call: splitting them would add a Rust function and change
//! no emitted byte.
//!
//! [`family_key`] is the hash body shared by `ShieldedCustody`'s `shieldedKey`,
//! `UnshieldedCustody`'s `unshieldedKey` and this module's own `debitKey` / `creditKey`
//! (`contracts/modules/Custody.compact:250-251`) — three Compact call sites, one helper here.
//!
//! The family internals `_credit`, `_writeCell`, `_pooled`, `_sendNamed`, `_releaseOpen`,
//! `_claimWant` and `_give` are **inlined** into [`custody_dispatch`] rather than given Rust
//! functions of their own: each runs at exactly one point in the mux, under a guard the dispatch
//! owns, and the emitted op stream is what has to match. Their Compact homes are cited at the
//! point of use.
//!
//! ## THE TRAP THE TWO DEPOSITS CARRY: compactc inlines, so a doubled call is a doubled hash
//!
//! Both deposit circuits end with
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
//! `contracts/modules/AccountRegistry.compact:178`'s double `accountModes.lookup` in `execute`. It
//! costs rows on both sides equally, which is precisely why leaving it in keeps the comparison
//! honest.
//!
//! They are also the only circuits besides `execute` that WRITE ledger state and touch the zswap /
//! unshielded kernel, so they are the only non-`execute` rows whose scenarios need the transcript
//! model Phase 3 built. Everything they need already exists: `receiveShielded` and the family-key
//! hash below, `receive_unshielded` and `merge_coin_immediate` directly from
//! `minocrab-std/src/v3/kernel.rs`, `LedgerMap::insert_coin` for the pool write.
//!
//! ## What this port is required to preserve, and how it does it
//!
//! **FR-204 GUARD ORDER IS INTENDED BEHAVIOUR** (00010 third follow-up), so it is preserved
//! literally: the assert sequence below is the same topological superset the contract documents —
//! swap sanity, then transfer destination checks, then the per-(account, colour) guard, then the
//! pool guard, then the swap credit target — and every guard still precedes every write. The
//! Compact source's block structure is reproduced 1:1 with [`Circuit3::when`], which is Compact's
//! `if`: it pushes an ambient guard that every enclosed ledger operation and every enclosed
//! `assert` picks up, lowered as `cond_select(outer, inner, 0)` — compactc's own `&&` lowering.
//!
//! **The refusal set and every assert MESSAGE are unchanged.**
//!
//! ## Two Compact lowerings this module has to reproduce deliberately
//!
//! 1. **`&&` and `||` SHORT-CIRCUIT over ledger reads.** `assert(!isTransfer ||
//!    accounts.member(p.toAccount), …)` does not read the set unless `isTransfer` holds — the
//!    compactc artifact guards that `member` by `isTransfer` (op 102-106 of
//!    `evidence/00012/raw/00012-p3.4-execute-impact-ops.txt`). A `Check::or` in minocrab is an inert
//!    descriptor and would NOT guard the read, because the read already happened at the call site.
//!    So every short-circuited ledger read here is written as an explicitly guarded read.
//! 2. **A constant branch tag FOLDS.** `repoolOrRemove(col, none<ShieldedCoinInfo>())` has
//!    `is_some = false` at compile time, so Compact emits only the `remove` arm — the artifact has
//!    no `insertCoin` there (ops 198-201). minocrab would emit an always-off Impact instead, which
//!    changes `pi_skips` and therefore fails the equivalence gate. Both constant-tag call sites are
//!    written in their folded form, with this note as the reason.
//!
//! ## The `member ? lookup : 0` idiom
//!
//! The two families' `_balanceAt` (named `shieldedBalanceAt` / `unshieldedBalanceAt` before the
//! module split) are `member(k) ? lookup(k) : 0`. compactc lowers that
//! to a `member` under the ambient guard and a `lookup` under `ambient && member`, whose
//! `public_input` gates yield the type default when the guard is off. That is exactly
//! `LedgerMap::lookup_guarded`, and the resulting zero means "the guard was off", which here is the
//! same thing as "the key was absent" — the FR-204 missing-cell-reads-0 rule, preserved by
//! construction rather than re-implemented.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Private, Public};
use minocrab_std::v3::{
    circuit, is_true, kernel, not, Bool, CircuitArg, CoinColor, CoinNonce, CoinRecipient,
    ContractAddress, Disclose, Discloses, Either, ShieldedCoinInfo3, Uint, UserAddress,
    ZswapCoinPublicKey, B32,
};

use crate::action_envelope::Selectors;
use crate::checks::b32_eq;
use crate::disclosures::{Amount, Coin, Colour, CreditAccount};
use crate::ledger::MANAGER;
use crate::shielded_custody::{
    shielded_balance_at, shielded_balance_of, shielded_family_tag, POOLS_READ,
};
use crate::unshielded_custody::{
    unshielded_balance_at, unshielded_balance_of, unshielded_family_tag,
};
use crate::zswap_primitives::{contract_recipient, evolve_nonce, receive_shielded, self_recipient};

/// `a || b` on Booleans, as compactc lowers it: `cond_select(a, 1, b)`.
fn or(
    c: &mut Circuit3,
    a: Wire3<FieldT, Public>,
    b: Wire3<FieldT, Public>,
) -> Wire3<FieldT, Public> {
    c.cond_select(a, 1u64, b)
}

/// `(w) as Uint<128>` on a value just computed: the range constraint, then the `Copy` the cast
/// names its result with — compactc's shape for a cast (`minocrab-std/src/v3/kernel.rs:619`).
fn as_uint128(c: &mut Circuit3, w: Wire3<FieldT, Public>) -> Uint<128, Public> {
    Uint::<128, Public>::from_field_unchecked(w).constrain_input(c);
    Uint::from_field_unchecked(c.copy(w))
}

/// The muxed selector algebra of `contracts/modules/Custody.compact:219-236`.
struct Mux {
    is_withdraw_shielded: Wire3<FieldT, Public>,
    is_withdraw_unshielded: Wire3<FieldT, Public>,
    is_swap: Wire3<FieldT, Public>,
    is_transfer: Wire3<FieldT, Public>,
    debit_shielded: Wire3<FieldT, Public>,
    credit_shielded: Wire3<FieldT, Public>,
    has_credit: Wire3<FieldT, Public>,
    needs_pool: Wire3<FieldT, Public>,
}

impl Mux {
    fn of(c: &mut Circuit3, s: &Selectors) -> Self {
        let is_transfer = or(c, s.s4, s.s5);
        let debit_shielded = {
            let a = or(c, s.s2, s.s4);
            or(c, a, s.s6)
        };
        let credit_shielded = or(c, s.s4, s.s6);
        let has_credit = or(c, is_transfer, s.s6);
        let needs_pool = or(c, s.s2, s.s6);
        Mux {
            is_withdraw_shielded: s.s2,
            is_withdraw_unshielded: s.s3,
            is_swap: s.s6,
            is_transfer,
            debit_shielded,
            credit_shielded,
            has_credit,
            needs_pool,
        }
    }
}

/// `custodyDispatch(p, account, toRegistered, creditRegistered)` — the whole custody dispatch for
/// selectors 2..6, with one copy of every expensive operation
/// (`contracts/modules/Custody.compact:213-353`).
///
/// The caller wraps this in `c.when(!isRegistration, …)`, which is where `execute` calls it from
/// (`contracts/manager.compact:378-380`); every operation below therefore inherits that ambient guard.
///
/// ## THE REGISTRY-TO-CUSTODY SEAM (product `41de69d`)
///
/// `to_registered` and `credit_registered` are `accounts.member(p.toAccount)` and
/// `accounts.member(p.creditAccount)`, **read by the caller and passed in**. Before the product's
/// module split this circuit read the set itself, each read short-circuited by the guard of the
/// assert that consumed it (`isTransfer`, `isSwap`). `Custody.compact` holds no registry state and
/// a Compact module never resolves caller identity, so the split hoisted both reads into
/// `manager.compact`'s `execute`, where they are evaluated as ARGUMENTS — unconditionally under the
/// ambient `!isRegistration` — and asserted here, at the original positions, with the original
/// messages.
///
/// That is a real change to the read schedule, not a rename: the two `member` ops move earlier in
/// the transcript and lose their inner guards. It is also the whole of the compactc-side
/// `382,781 → 382,780` delta the product recorded for `execute`. The port follows it because the
/// port transcribes the contract; the differential suite is what proves the two streams still
/// agree instruction for instruction.
pub fn custody_dispatch(
    c: &mut Circuit3,
    p: &crate::action_envelope::ExecutePayload<Public>,
    s: &Selectors,
    account: &B32<Public>,
    to_registered: Bool<Public>,
    credit_registered: Bool<Public>,
) {
    c.region("custody dispatch", |c| {
        let m = Mux::of(c, s);

        let col = p.primary_color;
        let val = p.primary_amount;
        let credit_acct = B32::cond_select(c, m.is_swap, &p.credit_account, &p.to_account);
        let credit_colour = B32::cond_select(c, m.is_swap, &p.want_color, &col);

        // --- 0. swap parameter sanity -----------------------------------------------------------
        // `!isSwap || X` on pure arithmetic: no ledger read to short-circuit, so the plain
        // disjunction is faithful.
        let not_swap = not(is_true(Bool::from_field_unchecked(m.is_swap)));
        c.assert(
            not_swap
                .or(val.gt(0u64))
                .message("swap must give a positive amount"),
        );
        let not_swap = not(is_true(Bool::from_field_unchecked(m.is_swap)));
        c.assert(
            not_swap
                .or(p.want_amount.gt(0u64))
                .message("swap must want a positive amount"),
        );
        let not_swap = not(is_true(Bool::from_field_unchecked(m.is_swap)));
        let same_colour = b32_eq(c, &col, &p.want_color);
        c.assert(
            not_swap
                .or(not(same_colour))
                .message("swap legs must be different colours"),
        );

        // --- 1. internal-transfer destination checks (selectors 4/5), in their product order -----
        // THE SEAM: `toRegistered` arrives as an argument (`Custody.compact:244`), so there is no
        // read to short-circuit here any more. `Check::or` over an already-computed Boolean is
        // exactly what compactc emits for `!isTransfer || toRegistered`.
        let not_transfer = not(is_true(Bool::from_field_unchecked(m.is_transfer)));
        c.assert(
            not_transfer
                .or(is_true(to_registered))
                .message("destination account is not registered"),
        );
        let not_transfer = not(is_true(Bool::from_field_unchecked(m.is_transfer)));
        let same_account = b32_eq(c, account, &p.to_account);
        c.assert(
            not_transfer
                .or(not(same_account))
                .message("internal transfer to the same account"),
        );
        let not_transfer = not(is_true(Bool::from_field_unchecked(m.is_transfer)));
        c.assert(
            not_transfer
                .or(val.gt(0u64))
                .message("internal transfer must be positive"),
        );

        // --- 2. THE PER-(ACCOUNT, COLOUR) GUARD, before any pool guard, missing cell reads 0 -----
        let shielded_tag = shielded_family_tag(c);
        let unshielded_tag = unshielded_family_tag(c);
        let debit_tag = B32::cond_select(c, m.debit_shielded, &shielded_tag, &unshielded_tag);
        let debit_key = family_key(c, account, &col, &debit_tag);
        let debit_balance = c
            .when_value(m.debit_shielded, |c| shielded_balance_at(c, &debit_key))
            .otherwise(|c| unshielded_balance_at(c, &debit_key));
        c.assert(
            debit_balance
                .ge(val)
                .message("account colour balance too low"),
        );

        // --- 3. only now, the pool guard and the shielded give leg (selectors 2 and 6) -----------
        c.when(m.needs_pool, |c| {
            let pooled_present = MANAGER.pools.member(c, &col);
            c.assert(is_true(pooled_present).message("no pooled coin for this colour"));
            let pooled = POOLS_READ.lookup(c, &col);
            let pooled_value = Uint::<128, Public>::from_field_unchecked(pooled.value);
            c.assert(
                pooled_value
                    .ge(val)
                    .message("pooled colour balance too low"),
            );

            // PR#9 / project 00013 — THE POOL-UNDERFLOW FIX (`contracts/modules/Custody.compact:279`).
            //
            //     const safeGive = (pooled.value >= val ? val : 0) as Uint<128>;
            //
            // A circuit compiles every branch, and Compact guards only a branch's *effects* and
            // *asserts*, never its arithmetic. For selectors 3/4/5 `needsPool` is false, so
            // `pools.lookup(col)` is a guarded-off read handing back the type default 0 while the
            // envelope has already required `primaryAmount > 0` — and `pooled.value - val` is then
            // a NEGATIVE field element fed unguarded to a `Uint<128>`, which no witness satisfies
            // (00012 F-00012-08). The clamp gives the guarded-off case a 0 that stays in range.
            //
            // The condition is `pooled.value >= val`, NOT the block's own `needsPool` guard: 00013
            // measured that compactc FOLDS a mux conditioned on the block guard (fix shapes B and C
            // were refuted that way), so the clamp has to be conditioned on the comparison itself.
            // BOTH consumers take `safe_give` — the `sendShielded` amount and `changeValue`.
            let give_ok = pooled_value.ge(val).into_wire(c);
            let zero_amount = c.constant(0u64);
            let safe_give = Uint::<128, Public>::from_field_unchecked(c.cond_select(
                give_ok,
                val.field(),
                zero_amount,
            ));

            // --- 4. the swap credit target, at its product position: after the pool guard --------
            // THE SEAM again: `creditRegistered` was read by the caller
            // (`Custody.compact:282`), so only the assert is left here.
            let not_swap = not(is_true(Bool::from_field_unchecked(m.is_swap)));
            c.assert(
                not_swap
                    .or(is_true(credit_registered))
                    .message("credit account is not registered"),
            );

            let kind_is_zero = p.recipient_kind.eq(0u64).into_wire(c);
            let kind_nonzero = c.not(kind_is_zero);
            let named = or(c, m.is_withdraw_shielded, kind_nonzero);
            c.when(named, |c| {
                // ONE `sendShielded`, shared by the withdrawal and the named-swap shape.
                let kind0 = p.recipient_kind.eq(0u64).into_wire(c);
                let kind1 = p.recipient_kind.eq(1u64).into_wire(c);
                let use_left = c.cond_select(m.is_withdraw_shielded, kind0, kind1);
                let zero = c.constant(0u64);
                let zero_b32 = B32 { hi: zero, lo: zero };
                let rcpt = CoinRecipient {
                    is_left: use_left,
                    left: ZswapCoinPublicKey(B32::cond_select(
                        c,
                        use_left,
                        &p.recipient,
                        &zero_b32,
                    )),
                    right: ContractAddress(B32::cond_select(c, use_left, &zero_b32, &p.recipient)),
                };
                // PR#9: the give amount is the CLAMPED one.
                let result = kernel::send_shielded(c, &pooled.as_qualified(), &rcpt, safe_give);
                crate::shielded_custody::repool_or_remove(
                    c,
                    result.change.is_some.field(),
                    &col,
                    &result.change.value,
                );
            })
            .otherwise(|c| {
                // The FR-308 v2(a) OPEN shape: the pooled coin is consumed as a zswap input and its
                // nullifier claimed, but the only output created is the change back to this
                // contract. `createZswapInput`/`createZswapOutput` are Void witnesses — nothing.
                let self_addr = kernel::self_address(c);
                let nul = minocrab_std::v3::coin_nullifier_contract(
                    c,
                    &pooled.downcast(),
                    &self_addr.bytes(),
                );
                kernel::claim_zswap_nullifier(c, &nul);

                // PR#9: `const changeValue = (pooled.value - safeGive) as Uint<128>;` — the SECOND
                // consumer of the clamp, and the one the underflow actually fired through.
                let change_value = Uint::<128, Public>::from_field_unchecked(pooled.value)
                    .sub_with(c, safe_give, "result of subtraction would be negative");
                let spent_it_all = c.test_eq(change_value.field(), 0u64);
                c.when(spent_it_all, |c| {
                    // `repoolOrRemove(col, none<ShieldedCoinInfo>())` FOLDED: a constant-false tag
                    // means Compact emits only this arm (see the module docs).
                    MANAGER.pools.remove(c, &col);
                })
                .otherwise(|c| {
                    let change_coin = minocrab_std::v3::ShieldedCoinInfo3 {
                        nonce: CoinNonce(evolve_nonce(c, 2, &pooled.nonce)),
                        color: CoinColor(col),
                        value: change_value.field(),
                    };
                    let self_recipient = contract_recipient(c, self_addr.address());
                    let cm = minocrab_std::v3::coin_commitment(c, &change_coin, &self_recipient);
                    kernel::claim_zswap_coin_spend(c, &cm);
                    kernel::claim_zswap_coin_receive(c, &cm);
                    // `repoolOrRemove(col, some(changeCoin))` FOLDED to its `insertCoin` arm.
                    let recipient = self_recipient_fresh(c);
                    MANAGER.pools.insert_coin(c, &col, &change_coin, &recipient);
                });
            });
        });

        // --- the unshielded give leg (selector 3) ------------------------------------------------
        c.when(m.is_withdraw_unshielded, |c| {
            let enough = kernel::unshielded_balance_gte(c, CoinColor(col), val);
            c.assert(is_true(enough).message("contract unshielded balance too low"));
            // PR#10 / project 00016 — THE RECIPIENT-TAG FIX (`contracts/modules/Custody.compact:313-315`):
            //
            //     sendUnshielded(col, val, p.recipientKind == 0
            //       ? right<ContractAddress, UserAddress>(UserAddress{ bytes: p.recipient })
            //       : left <ContractAddress, UserAddress>(ContractAddress{ bytes: p.recipient }));
            //
            // `sendUnshielded`'s `Either<ContractAddress, UserAddress>` is the MIRROR of the
            // shielded `Either<ZswapCoinPublicKey, ContractAddress>` used a few lines above: LEFT
            // is the contract arm here. So `recipientKind == 0` ("user") is the RIGHT arm, and
            // `is_left` is `recipientKind != 0`.
            //
            // The two arms are also muxed against the type default, because that is what
            // `left<A,B>(v)` / `right<A,B>(v)` mean — `Either{is_left: true, left: v,
            // right: default<B>}` and `Either{is_left: false, left: default<A>, right: v}` — and
            // an `Either` in an effects slot carries the tag AND BOTH arms
            // (`minocrab-std/src/v3/entry.rs:571`). The compactc artifact confirms it: the
            // `claimUnshieldedCoinSpend` push at `execute` Impact op 258 carries FOUR DISTINCT
            // recipient limbs (`push(cell<1+32+32+1+32+32>[…, %t, %recipient.a, %recipient.b,
            // %recipient.c, %recipient.d])`), not the same pair twice. See finding F-00020-01.
            let kind0 = p.recipient_kind.eq(0u64).into_wire(c);
            let kind_nonzero = c.not(kind0);
            let zero = c.constant(0u64);
            let zero_b32 = B32 { hi: zero, lo: zero };
            let recipient: kernel::UnshieldedRecipient<Public> = Either {
                is_left: Bool::from_field_unchecked(kind_nonzero),
                left: ContractAddress(B32::cond_select(c, kind_nonzero, &p.recipient, &zero_b32)),
                right: UserAddress(B32::cond_select(c, kind_nonzero, &zero_b32, &p.recipient)),
            };
            crate::unshielded_custody::send_unshielded(c, col, val, &recipient);
        });

        // --- ONE debit write, into the muxed family ----------------------------------------------
        let new_debit = debit_balance.sub_with(c, val, "result of subtraction would be negative");
        c.when(m.debit_shielded, |c| {
            MANAGER.shielded_balances.insert(c, &debit_key, &new_debit);
        })
        .otherwise(|c| {
            MANAGER
                .unshielded_balances
                .insert(c, &debit_key, &new_debit);
        });

        // --- the swap WANT leg: claim `wantCoin` into custody ------------------------------------
        c.when(m.is_swap, |c| {
            let want_coin = minocrab_std::v3::ShieldedCoinInfo3 {
                nonce: CoinNonce(p.want_nonce),
                color: CoinColor(p.want_color),
                value: p.want_amount.field(),
            };
            receive_shielded(c, &want_coin);
            let have = MANAGER.pools.member(c, &p.want_color);
            c.when(have.field(), |c| {
                let a = POOLS_READ.lookup(c, &p.want_color);
                let merged = kernel::merge_coin_immediate(c, &a.as_qualified(), &want_coin);
                let recipient = self_recipient_fresh(c);
                MANAGER
                    .pools
                    .insert_coin(c, &p.want_color, &merged, &recipient);
            })
            .otherwise(|c| {
                let recipient = self_recipient_fresh(c);
                MANAGER
                    .pools
                    .insert_coin(c, &p.want_color, &want_coin, &recipient);
            });
        });

        // --- ONE credit write (selectors 4, 5, 6) -------------------------------------------------
        c.when(m.has_credit, |c| {
            let credit_tag = B32::cond_select(c, m.credit_shielded, &shielded_tag, &unshielded_tag);
            let credit_key = family_key(c, &credit_acct, &credit_colour, &credit_tag);
            let credit_value = Uint::<128, Public>::from_field_unchecked(c.cond_select(
                m.is_swap,
                p.want_amount.field(),
                val.field(),
            ));
            c.when(m.credit_shielded, |c| {
                let now = shielded_balance_at(c, &credit_key);
                let sum = c.add(now.field(), credit_value.field());
                let next = as_uint128(c, sum);
                MANAGER.shielded_balances.insert(c, &credit_key, &next);
            })
            .otherwise(|c| {
                let now = unshielded_balance_at(c, &credit_key);
                let sum = c.add(now.field(), credit_value.field());
                let next = as_uint128(c, sum);
                MANAGER.unshielded_balances.insert(c, &credit_key, &next);
            });
        });
    })
}

/// `right<ZswapCoinPublicKey, ContractAddress>(kernel.self())` with its OWN read — the shape
/// `pools.insertCoin(…, right(kernel.self()))` writes at every call site.
fn self_recipient_fresh(c: &mut Circuit3) -> CoinRecipient<Public> {
    self_recipient(c)
}

/// The alignment of `Vector<3, Bytes<32>>` — what `shieldedKey`/`unshieldedKey` and
/// `custodyDispatch`'s muxed `debitKey`/`creditKey` all hash under.
fn three_words() -> Alignment {
    Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
    ])
}

/// `persistentHash<Vector<3, Bytes<32>>>([acct, colour, tag])` — the body of `shieldedKey`,
/// `unshieldedKey` and the mux's one key derivation
/// (`contracts/modules/ShieldedCustody.compact:99-101`,
/// `contracts/modules/UnshieldedCustody.compact:67-69`, `contracts/modules/Custody.compact:250-251`).
pub fn family_key(
    c: &mut Circuit3,
    acct: &B32<Public>,
    colour: &B32<Public>,
    tag: &B32<Public>,
) -> B32<Public> {
    let digest = c.persistent_hash(
        three_words(),
        &[
            acct.hi.erase(),
            acct.lo.erase(),
            colour.hi.erase(),
            colour.lo.erase(),
            tag.hi.erase(),
            tag.lo.erase(),
        ],
    );
    B32::from_typed(c, digest)
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
        MANAGER
            .pools
            .insert_coin(c, &coin.color, &merged, &recipient);
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

    let tag = crate::unshielded_custody::unshielded_family_tag(c);
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
