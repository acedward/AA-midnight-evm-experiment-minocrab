//! Phase 3.3 — `assertActionEnvelope` (`contracts/modules/ActionEnvelope.compact:80-158`) and the account-selection
//! guards (`contracts/modules/AccountRegistry.compact:171-207`).
//!
//! **Compact twin**: `contracts/modules/ActionEnvelope.compact`, which holds `ExecutePayload` and
//! `assertActionEnvelope` — every canonical-zero rule for every selector, in one place.
//! **Circuits ported here: none** — the module emits no key; its work shows up inside `execute`.
//! [`ExecutePayload`] is the argument struct of `execute`, `evmStructHashFor`, `evmDigestFor`,
//! `gatewayAccount` and `custodyDispatch` alike, which is why five Compact files import this one.
//!
//! [`Selectors`] has no Compact counterpart: Compact recomputes `p.selector == N` at each use and
//! the compiler folds the repeats, while minocrab needs the wires named once. It emits the same
//! comparisons in the same order.
//!
//! `authenticatedActionAccount` and `gatewayAccount` used to live here, when this file was
//! `envelope.rs`; they are `AccountRegistry`'s and now live in [`crate::account_registry`].
//!
//! ## How Compact's early `return`s become guards
//!
//! The Compact source is a chain of `if (selector == N) { …asserts…; return; }` blocks. A circuit
//! has no control flow — every branch is compiled — so an early `return` means "the asserts below
//! me only bind when my condition did NOT hold". Each block's asserts are therefore emitted under
//! the conjunction of its own condition and the negation of every earlier block's:
//!
//! | Compact block | guard here |
//! |---|---|
//! | `selector == 0` | `s0` |
//! | `selector == 1` | `s1` |
//! | the common action asserts | `is_action = !s0 && !s1` |
//! | `selector == 2 \|\| 3` | `is_action && is_withdraw` |
//! | `selector == 4 \|\| 5` | `is_action && is_transfer` |
//! | the trailing swap block | `is_action && !is_withdraw && !is_transfer` |
//!
//! That reproduces the refusal set exactly: a payload is refused by this circuit iff it is refused
//! by the Compact one, with the same message.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::Public;
use minocrab_std::v3::{not, Bytes, Check, CircuitArg, Uint, B32};

use crate::checks::{b32_eq, b32_is_nonzero, b32_is_zero};

/// A boolean wire, as the AND of two boolean wires.
fn and(
    c: &mut Circuit3,
    a: Wire3<FieldT, Public>,
    b: Wire3<FieldT, Public>,
) -> Wire3<FieldT, Public> {
    c.mul(a, b)
}

/// `selector == n` as a wire.
fn sel_is(c: &mut Circuit3, p: &ExecutePayload<Public>, n: u64) -> Wire3<FieldT, Public> {
    let k = Uint::<8, Public>::constant(c, n);
    p.selector.eq(k).into_wire(c)
}

/// The selector predicates `assertActionEnvelope` and `custodyDispatch` share.
pub struct Selectors {
    pub s0: Wire3<FieldT, Public>,
    pub s1: Wire3<FieldT, Public>,
    pub s2: Wire3<FieldT, Public>,
    pub s3: Wire3<FieldT, Public>,
    pub s4: Wire3<FieldT, Public>,
    pub s5: Wire3<FieldT, Public>,
    pub s6: Wire3<FieldT, Public>,
    /// `!s0 && !s1` — the payload is one of the five custody actions.
    pub is_action: Wire3<FieldT, Public>,
    /// `s2 || s3`
    pub is_withdraw: Wire3<FieldT, Public>,
    /// `s4 || s5`
    pub is_transfer: Wire3<FieldT, Public>,
}

impl Selectors {
    pub fn of(c: &mut Circuit3, p: &ExecutePayload<Public>) -> Self {
        let s0 = sel_is(c, p, 0);
        let s1 = sel_is(c, p, 1);
        let s2 = sel_is(c, p, 2);
        let s3 = sel_is(c, p, 3);
        let s4 = sel_is(c, p, 4);
        let s5 = sel_is(c, p, 5);
        let s6 = sel_is(c, p, 6);
        // The selectors are mutually exclusive, so `||` over them is `+` — one add instead of the
        // three instructions a general `or` would cost. `assert(selector <= 6)` (below) plus
        // exclusivity is what makes the sum a boolean.
        let is_withdraw = c.add(s2, s3);
        let is_transfer = c.add(s4, s5);
        let not_s0 = c.not(s0);
        let not_s1 = c.not(s1);
        let is_action = and(c, not_s0, not_s1);
        Selectors {
            s0,
            s1,
            s2,
            s3,
            s4,
            s5,
            s6,
            is_action,
            is_withdraw,
            is_transfer,
        }
    }
}

/// `assert(cond, msg)` under a guard wire.
fn guarded(
    c: &mut Circuit3,
    guard: Wire3<FieldT, Public>,
    check: Check<Public>,
    msg: &'static str,
) {
    c.assert(check.message(msg).when(guard));
}

/// `p.owner == default<Bytes<20>>`.
fn owner_is_zero(p: &ExecutePayload<Public>) -> Check<Public> {
    p.owner.eq(0u64)
}

/// `assertActionEnvelope(p)` — the whole envelope, in source order.
pub fn assert_action_envelope(c: &mut Circuit3, p: &ExecutePayload<Public>, s: &Selectors) {
    c.region("envelope", |c| {
        c.assert(p.selector.le(6u64).message("unknown execute selector"));
        c.assert(p.auth_mode.le(1u64).message("unknown authorization mode"));

        // ---- selector 0: native registration -------------------------------------------------
        let g = s.s0;
        guarded(
            c,
            g,
            p.auth_mode.eq(0u64),
            "native registration requires native authorization",
        );
        let acct_zero = b32_is_zero(c, &p.account);
        guarded(c, g, acct_zero, "native registration account is derived");
        let salt_zero = b32_is_zero(c, &p.account_salt);
        guarded(
            c,
            g,
            owner_is_zero(p).and(salt_zero),
            "native registration EVM fields must be inactive",
        );
        guarded(
            c,
            g,
            p.nonce.eq(0u64).and(p.valid_until.eq(0u64)),
            "native registration replay fields must be inactive",
        );
        let color_zero = b32_is_zero(c, &p.primary_color);
        guarded(
            c,
            g,
            color_zero.and(p.primary_amount.eq(0u64)),
            "native registration action fields must be inactive",
        );
        let rcpt_zero = b32_is_zero(c, &p.recipient);
        guarded(
            c,
            g,
            p.recipient_kind.eq(0u64).and(rcpt_zero),
            "native registration recipient must be inactive",
        );
        let to_zero = b32_is_zero(c, &p.to_account);
        let wn_zero = b32_is_zero(c, &p.want_nonce);
        guarded(
            c,
            g,
            to_zero.and(wn_zero),
            "native registration targets must be inactive",
        );
        let wc_zero = b32_is_zero(c, &p.want_color);
        let ca_zero = b32_is_zero(c, &p.credit_account);
        guarded(
            c,
            g,
            wc_zero.and(p.want_amount.eq(0u64)).and(ca_zero),
            "native registration swap fields must be inactive",
        );

        // ---- selector 1: EVM registration -----------------------------------------------------
        let g = s.s1;
        guarded(
            c,
            g,
            p.auth_mode.eq(1u64),
            "EVM registration requires EVM authorization",
        );
        let acct_nz = b32_is_nonzero(c, &p.account);
        guarded(c, g, acct_nz, "EVM registration account must be supplied");
        guarded(
            c,
            g,
            not(owner_is_zero(p)),
            "EVM registration owner must be nonzero",
        );
        let salt_nz = b32_is_nonzero(c, &p.account_salt);
        guarded(c, g, salt_nz, "EVM registration salt must be nonzero");
        guarded(
            c,
            g,
            p.nonce.eq(0u64).and(p.valid_until.gt(0u64)),
            "EVM registration replay fields are noncanonical",
        );
        let color_zero = b32_is_zero(c, &p.primary_color);
        guarded(
            c,
            g,
            color_zero.and(p.primary_amount.eq(0u64)),
            "EVM registration action fields must be inactive",
        );
        let rcpt_zero = b32_is_zero(c, &p.recipient);
        guarded(
            c,
            g,
            p.recipient_kind.eq(0u64).and(rcpt_zero),
            "EVM registration recipient must be inactive",
        );
        let to_zero = b32_is_zero(c, &p.to_account);
        let wn_zero = b32_is_zero(c, &p.want_nonce);
        guarded(
            c,
            g,
            to_zero.and(wn_zero),
            "EVM registration targets must be inactive",
        );
        let wc_zero = b32_is_zero(c, &p.want_color);
        let ca_zero = b32_is_zero(c, &p.credit_account);
        guarded(
            c,
            g,
            wc_zero.and(p.want_amount.eq(0u64)).and(ca_zero),
            "EVM registration swap fields must be inactive",
        );

        // ---- the common action asserts (selectors 2..6) ---------------------------------------
        let g = s.is_action;
        let acct_nz = b32_is_nonzero(c, &p.account);
        guarded(c, g, acct_nz, "action account must be supplied");
        let salt_zero = b32_is_zero(c, &p.account_salt);
        guarded(c, g, salt_zero, "action account salt must be inactive");

        // `if (p.authMode == 0) { … } else { … }` — both arms, each under its own conjunction.
        let native_mode = p.auth_mode.eq(0u64).into_wire(c);
        let evm_mode = c.not(native_mode);
        let g_native = and(c, g, native_mode);
        guarded(
            c,
            g_native,
            owner_is_zero(p),
            "native action owner must be inactive",
        );
        guarded(
            c,
            g_native,
            p.nonce.eq(0u64).and(p.valid_until.eq(0u64)),
            "native action replay fields must be inactive",
        );
        let g_evm = and(c, g, evm_mode);
        guarded(
            c,
            g_evm,
            not(owner_is_zero(p)),
            "EVM action owner must be nonzero",
        );
        guarded(
            c,
            g_evm,
            p.valid_until.gt(0u64),
            "EVM action deadline must be nonzero",
        );

        // ---- selectors 2/3: withdraw ----------------------------------------------------------
        let g = and(c, s.is_action, s.is_withdraw);
        guarded(
            c,
            g,
            p.primary_amount.gt(0u64),
            "withdraw amount must be positive",
        );
        guarded(
            c,
            g,
            p.recipient_kind.le(1u64),
            "withdraw recipient kind is invalid",
        );
        // PR#10 / project 00016 — the envelope refuses the contract-recipient payout shapes.
        // Source order matters: this sits immediately after the `<= 1` bound and before the
        // nonzero check (`manager.compact`, selector 2||3 block).
        guarded(
            c,
            g,
            p.recipient_kind.eq(0u64),
            "withdraw to a contract recipient is not supported",
        );
        let rcpt_nz = b32_is_nonzero(c, &p.recipient);
        guarded(c, g, rcpt_nz, "withdraw recipient must be nonzero");
        let to_zero = b32_is_zero(c, &p.to_account);
        guarded(c, g, to_zero, "withdraw transfer target must be inactive");
        let wn_zero = b32_is_zero(c, &p.want_nonce);
        let wc_zero = b32_is_zero(c, &p.want_color);
        guarded(
            c,
            g,
            wn_zero.and(wc_zero),
            "withdraw swap fields must be inactive",
        );
        let ca_zero = b32_is_zero(c, &p.credit_account);
        guarded(
            c,
            g,
            p.want_amount.eq(0u64).and(ca_zero),
            "withdraw swap target must be inactive",
        );

        // ---- selectors 4/5: internal transfer --------------------------------------------------
        let g = and(c, s.is_action, s.is_transfer);
        guarded(
            c,
            g,
            p.primary_amount.gt(0u64),
            "internal transfer must be positive",
        );
        let rcpt_zero = b32_is_zero(c, &p.recipient);
        guarded(
            c,
            g,
            p.recipient_kind.eq(0u64).and(rcpt_zero),
            "internal transfer recipient must be inactive",
        );
        let to_nz = b32_is_nonzero(c, &p.to_account);
        guarded(c, g, to_nz, "internal transfer target must be supplied");
        let wn_zero = b32_is_zero(c, &p.want_nonce);
        let wc_zero = b32_is_zero(c, &p.want_color);
        guarded(
            c,
            g,
            wn_zero.and(wc_zero),
            "internal transfer swap fields must be inactive",
        );
        let ca_zero = b32_is_zero(c, &p.credit_account);
        guarded(
            c,
            g,
            p.want_amount.eq(0u64).and(ca_zero),
            "internal transfer swap target must be inactive",
        );

        // ---- the trailing block: selector 6, open swap ------------------------------------------
        let not_wd = c.not(s.is_withdraw);
        let not_tr = c.not(s.is_transfer);
        let rest = and(c, not_wd, not_tr);
        let g = and(c, s.is_action, rest);
        guarded(c, g, p.selector.eq(6u64), "unknown execute selector");
        guarded(
            c,
            g,
            p.primary_amount.gt(0u64),
            "swap must give a positive amount",
        );
        guarded(
            c,
            g,
            p.recipient_kind.le(2u64),
            "swap recipient kind is invalid",
        );
        // PR#10 / project 00016 — a swap taker may be a user (1) or open (0), never a contract (2).
        guarded(
            c,
            g,
            p.recipient_kind.le(1u64),
            "swap to a contract taker is not supported",
        );

        // `if (recipientKind == 0) { recipient must be zero } else { must be nonzero }`
        let kind0 = p.recipient_kind.eq(0u64).into_wire(c);
        let kind_nz = c.not(kind0);
        let g_k0 = and(c, g, kind0);
        let rcpt_zero = b32_is_zero(c, &p.recipient);
        guarded(c, g_k0, rcpt_zero, "open swap recipient must be zero");
        let g_kn = and(c, g, kind_nz);
        let rcpt_nz = b32_is_nonzero(c, &p.recipient);
        guarded(c, g_kn, rcpt_nz, "named swap recipient must be nonzero");

        let to_zero = b32_is_zero(c, &p.to_account);
        guarded(c, g, to_zero, "swap transfer target must be inactive");
        guarded(
            c,
            g,
            p.want_amount.gt(0u64),
            "swap must want a positive amount",
        );
        let colours_eq = b32_eq(c, &p.primary_color, &p.want_color);
        guarded(c, g, not(colours_eq), "swap legs must be different colours");
        let ca_nz = b32_is_nonzero(c, &p.credit_account);
        guarded(c, g, ca_nz, "swap credit account must be supplied");
    })
}

/// `struct ExecutePayload` — the muxed action envelope every `execute` call carries.
#[derive(CircuitArg)]
pub struct ExecutePayload<V: minocrab_std::v3::Vis3> {
    /// 0 = native registration, 1..6 = the EIP-712 signed actions.
    pub selector: Uint<8, V>,
    /// 0 = native witness authorization, 1 = EVM EOA.
    pub auth_mode: Uint<8, V>,
    pub account: B32<V>,
    pub owner: Bytes<20, V>,
    pub account_salt: B32<V>,
    pub nonce: Uint<64, V>,
    pub valid_until: Uint<64, V>,
    pub primary_color: B32<V>,
    pub primary_amount: Uint<128, V>,
    pub recipient_kind: Uint<8, V>,
    pub recipient: B32<V>,
    pub to_account: B32<V>,
    pub want_nonce: B32<V>,
    pub want_color: B32<V>,
    pub want_amount: Uint<128, V>,
    pub credit_account: B32<V>,
}
