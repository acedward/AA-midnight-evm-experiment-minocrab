//! Phase 3.4 — `custodyDispatch` (`manager.compact:1001-1135`), the o2 custody mux: one debit leg,
//! one credit leg, muxed arguments, for all five custody selectors (2..6).
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
//! `shieldedBalanceAt`/`unshieldedBalanceAt` are `member(k) ? lookup(k) : 0`. compactc lowers that
//! to a `member` under the ambient guard and a `lookup` under `ambient && member`, whose
//! `public_input` gates yield the type default when the guard is off. That is exactly
//! `LedgerMap::lookup_guarded`, and the resulting zero means "the guard was off", which here is the
//! same thing as "the key was absent" — the FR-204 missing-cell-reads-0 rule, preserved by
//! construction rather than re-implemented.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::Public;
use minocrab_std::v3::{
    is_true, kernel, not, Bool, CoinRecipient, ContractAddress, Either, Uint, UserAddress, B32,
};

use crate::coins::{
    contract_recipient, evolve_nonce, family_key, receive_shielded, self_recipient,
    shielded_family_tag, unshielded_family_tag, POOLS_READ,
};
use crate::envelope::Selectors;
use crate::guards::b32_eq;
use crate::ledger::MANAGER;

/// `a || b` on Booleans, as compactc lowers it: `cond_select(a, 1, b)`.
fn or(c: &mut Circuit3, a: Wire3<FieldT, Public>, b: Wire3<FieldT, Public>) -> Wire3<FieldT, Public> {
    c.cond_select(a, 1u64, b)
}

/// `(w) as Uint<128>` on a value just computed: the range constraint, then the `Copy` the cast
/// names its result with — compactc's shape for a cast (`minocrab-std/src/v3/kernel.rs:619`).
fn as_uint128(c: &mut Circuit3, w: Wire3<FieldT, Public>) -> Uint<128, Public> {
    Uint::<128, Public>::from_field_unchecked(w).constrain_input(c);
    Uint::from_field_unchecked(c.copy(w))
}

/// `shieldedBalances.member(k) ? shieldedBalances.lookup(k) : 0` (`manager.compact:953-955`).
fn shielded_balance_at(c: &mut Circuit3, k: &B32<Public>) -> Uint<128, Public> {
    let present = MANAGER.shielded_balances.member(c, k);
    // A SCOPE, not `lookup_guarded(c, present, …)`: see F-00012-07 in the module docs. The
    // scope's guard is `ambient && present`, which is what compactc puts on BOTH the read's gates
    // and its op.
    c.when_value(present.field(), |c| MANAGER.shielded_balances.lookup(c, k))
        .otherwise(|c| Uint::<128, Public>::constant(c, 0))
        .into_inner()
}

/// `unshieldedBalances.member(k) ? unshieldedBalances.lookup(k) : 0` (`manager.compact:957-959`).
fn unshielded_balance_at(c: &mut Circuit3, k: &B32<Public>) -> Uint<128, Public> {
    let present = MANAGER.unshielded_balances.member(c, k);
    c.when_value(present.field(), |c| MANAGER.unshielded_balances.lookup(c, k))
        .otherwise(|c| Uint::<128, Public>::constant(c, 0))
        .into_inner()
}

/// The muxed selector algebra of `manager.compact:1003-1020`.
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

/// `custodyDispatch(p, account)` — the whole custody dispatch for selectors 2..6, with one copy of
/// every expensive operation.
///
/// The caller wraps this in `c.when(!isRegistration, …)`, which is where `execute` calls it from
/// (`manager.compact:1352-1355`); every operation below therefore inherits that ambient guard.
pub fn custody_dispatch(
    c: &mut Circuit3,
    p: &crate::payload::ExecutePayload<Public>,
    s: &Selectors,
    account: &B32<Public>,
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
        // SHORT-CIRCUIT: the `accounts.member` read only happens under `isTransfer`.
        let dest_registered = c
            .when_value(m.is_transfer, |c| MANAGER.accounts.member(c, &p.to_account))
            .otherwise(|c| Bool::constant(c, false))
            .into_inner();
        let not_transfer = not(is_true(Bool::from_field_unchecked(m.is_transfer)));
        c.assert(
            not_transfer
                .or(is_true(dest_registered))
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

            // PR#9 / project 00013 — THE POOL-UNDERFLOW FIX (`manager.compact:1064`).
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
            // SHORT-CIRCUIT again: the read is guarded by `isSwap`.
            let credit_registered = c
                .when_value(m.is_swap, |c| MANAGER.accounts.member(c, &p.credit_account))
                .otherwise(|c| Bool::constant(c, false))
                .into_inner();
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
                    left: B32::cond_select(c, use_left, &p.recipient, &zero_b32),
                    right: B32::cond_select(c, use_left, &zero_b32, &p.recipient),
                };
                // PR#9: the give amount is the CLAMPED one.
                let result = kernel::send_shielded(c, &pooled.as_qualified(), &rcpt, safe_give);
                crate::coins::repool_or_remove(
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
                        nonce: evolve_nonce(c, 2, &pooled.nonce),
                        color: col,
                        value: change_value.field(),
                    };
                    let self_recipient = contract_recipient(c, self_addr);
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
            let enough = kernel::unshielded_balance_gte(c, col, val);
            c.assert(is_true(enough).message("contract unshielded balance too low"));
            // PR#10 / project 00016 — THE RECIPIENT-TAG FIX (`manager.compact:1097-1099`):
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
            crate::coins::send_unshielded(c, col, val, &recipient);
        });

        // --- ONE debit write, into the muxed family ----------------------------------------------
        let new_debit = debit_balance.sub_with(c, val, "result of subtraction would be negative");
        c.when(m.debit_shielded, |c| {
            MANAGER
                .shielded_balances
                .insert(c, &debit_key, &new_debit);
        })
        .otherwise(|c| {
            MANAGER
                .unshielded_balances
                .insert(c, &debit_key, &new_debit);
        });

        // --- the swap WANT leg: claim `wantCoin` into custody ------------------------------------
        c.when(m.is_swap, |c| {
            let want_coin = minocrab_std::v3::ShieldedCoinInfo3 {
                nonce: p.want_nonce,
                color: p.want_color,
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
        });    })
}

/// `right<ZswapCoinPublicKey, ContractAddress>(kernel.self())` with its OWN read — the shape
/// `pools.insertCoin(…, right(kernel.self()))` writes at every call site.
fn self_recipient_fresh(c: &mut Circuit3) -> CoinRecipient<Public> {
    self_recipient(c)
}
