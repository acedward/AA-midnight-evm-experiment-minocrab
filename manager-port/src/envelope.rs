//! Phase 3.3 — `assertActionEnvelope` (`contracts/modules/ActionEnvelope.compact:80-158`) and the account-selection
//! guards (`contracts/modules/AccountRegistry.compact:171-207`).
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
use minocrab_std::v3::{is_true, not, Bool, Check, Uint, B32};

use crate::guards::{b32_eq, b32_is_nonzero, b32_is_zero};
use crate::ledger::MANAGER;
use crate::payload::ExecutePayload;

/// A boolean wire, as the AND of two boolean wires.
fn and(c: &mut Circuit3, a: Wire3<FieldT, Public>, b: Wire3<FieldT, Public>) -> Wire3<FieldT, Public> {
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
        Selectors { s0, s1, s2, s3, s4, s5, s6, is_action, is_withdraw, is_transfer }
    }
}

/// `assert(cond, msg)` under a guard wire.
fn guarded(c: &mut Circuit3, guard: Wire3<FieldT, Public>, check: Check<Public>, msg: &'static str) {
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
        guarded(c, g, p.auth_mode.eq(0u64), "native registration requires native authorization");
        let acct_zero = b32_is_zero(c, &p.account);
        guarded(c, g, acct_zero, "native registration account is derived");
        let salt_zero = b32_is_zero(c, &p.account_salt);
        guarded(c, g, owner_is_zero(p).and(salt_zero), "native registration EVM fields must be inactive");
        guarded(c, g, p.nonce.eq(0u64).and(p.valid_until.eq(0u64)), "native registration replay fields must be inactive");
        let color_zero = b32_is_zero(c, &p.primary_color);
        guarded(c, g, color_zero.and(p.primary_amount.eq(0u64)), "native registration action fields must be inactive");
        let rcpt_zero = b32_is_zero(c, &p.recipient);
        guarded(c, g, p.recipient_kind.eq(0u64).and(rcpt_zero), "native registration recipient must be inactive");
        let to_zero = b32_is_zero(c, &p.to_account);
        let wn_zero = b32_is_zero(c, &p.want_nonce);
        guarded(c, g, to_zero.and(wn_zero), "native registration targets must be inactive");
        let wc_zero = b32_is_zero(c, &p.want_color);
        let ca_zero = b32_is_zero(c, &p.credit_account);
        guarded(c, g, wc_zero.and(p.want_amount.eq(0u64)).and(ca_zero), "native registration swap fields must be inactive");

        // ---- selector 1: EVM registration -----------------------------------------------------
        let g = s.s1;
        guarded(c, g, p.auth_mode.eq(1u64), "EVM registration requires EVM authorization");
        let acct_nz = b32_is_nonzero(c, &p.account);
        guarded(c, g, acct_nz, "EVM registration account must be supplied");
        guarded(c, g, not(owner_is_zero(p)), "EVM registration owner must be nonzero");
        let salt_nz = b32_is_nonzero(c, &p.account_salt);
        guarded(c, g, salt_nz, "EVM registration salt must be nonzero");
        guarded(c, g, p.nonce.eq(0u64).and(p.valid_until.gt(0u64)), "EVM registration replay fields are noncanonical");
        let color_zero = b32_is_zero(c, &p.primary_color);
        guarded(c, g, color_zero.and(p.primary_amount.eq(0u64)), "EVM registration action fields must be inactive");
        let rcpt_zero = b32_is_zero(c, &p.recipient);
        guarded(c, g, p.recipient_kind.eq(0u64).and(rcpt_zero), "EVM registration recipient must be inactive");
        let to_zero = b32_is_zero(c, &p.to_account);
        let wn_zero = b32_is_zero(c, &p.want_nonce);
        guarded(c, g, to_zero.and(wn_zero), "EVM registration targets must be inactive");
        let wc_zero = b32_is_zero(c, &p.want_color);
        let ca_zero = b32_is_zero(c, &p.credit_account);
        guarded(c, g, wc_zero.and(p.want_amount.eq(0u64)).and(ca_zero), "EVM registration swap fields must be inactive");

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
        guarded(c, g_native, owner_is_zero(p), "native action owner must be inactive");
        guarded(c, g_native, p.nonce.eq(0u64).and(p.valid_until.eq(0u64)), "native action replay fields must be inactive");
        let g_evm = and(c, g, evm_mode);
        guarded(c, g_evm, not(owner_is_zero(p)), "EVM action owner must be nonzero");
        guarded(c, g_evm, p.valid_until.gt(0u64), "EVM action deadline must be nonzero");

        // ---- selectors 2/3: withdraw ----------------------------------------------------------
        let g = and(c, s.is_action, s.is_withdraw);
        guarded(c, g, p.primary_amount.gt(0u64), "withdraw amount must be positive");
        guarded(c, g, p.recipient_kind.le(1u64), "withdraw recipient kind is invalid");
        // PR#10 / project 00016 — the envelope refuses the contract-recipient payout shapes.
        // Source order matters: this sits immediately after the `<= 1` bound and before the
        // nonzero check (`manager.compact`, selector 2||3 block).
        guarded(c, g, p.recipient_kind.eq(0u64), "withdraw to a contract recipient is not supported");
        let rcpt_nz = b32_is_nonzero(c, &p.recipient);
        guarded(c, g, rcpt_nz, "withdraw recipient must be nonzero");
        let to_zero = b32_is_zero(c, &p.to_account);
        guarded(c, g, to_zero, "withdraw transfer target must be inactive");
        let wn_zero = b32_is_zero(c, &p.want_nonce);
        let wc_zero = b32_is_zero(c, &p.want_color);
        guarded(c, g, wn_zero.and(wc_zero), "withdraw swap fields must be inactive");
        let ca_zero = b32_is_zero(c, &p.credit_account);
        guarded(c, g, p.want_amount.eq(0u64).and(ca_zero), "withdraw swap target must be inactive");

        // ---- selectors 4/5: internal transfer --------------------------------------------------
        let g = and(c, s.is_action, s.is_transfer);
        guarded(c, g, p.primary_amount.gt(0u64), "internal transfer must be positive");
        let rcpt_zero = b32_is_zero(c, &p.recipient);
        guarded(c, g, p.recipient_kind.eq(0u64).and(rcpt_zero), "internal transfer recipient must be inactive");
        let to_nz = b32_is_nonzero(c, &p.to_account);
        guarded(c, g, to_nz, "internal transfer target must be supplied");
        let wn_zero = b32_is_zero(c, &p.want_nonce);
        let wc_zero = b32_is_zero(c, &p.want_color);
        guarded(c, g, wn_zero.and(wc_zero), "internal transfer swap fields must be inactive");
        let ca_zero = b32_is_zero(c, &p.credit_account);
        guarded(c, g, p.want_amount.eq(0u64).and(ca_zero), "internal transfer swap target must be inactive");

        // ---- the trailing block: selector 6, open swap ------------------------------------------
        let not_wd = c.not(s.is_withdraw);
        let not_tr = c.not(s.is_transfer);
        let rest = and(c, not_wd, not_tr);
        let g = and(c, s.is_action, rest);
        guarded(c, g, p.selector.eq(6u64), "unknown execute selector");
        guarded(c, g, p.primary_amount.gt(0u64), "swap must give a positive amount");
        guarded(c, g, p.recipient_kind.le(2u64), "swap recipient kind is invalid");
        // PR#10 / project 00016 — a swap taker may be a user (1) or open (0), never a contract (2).
        guarded(c, g, p.recipient_kind.le(1u64), "swap to a contract taker is not supported");

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
        guarded(c, g, p.want_amount.gt(0u64), "swap must want a positive amount");
        let colours_eq = b32_eq(c, &p.primary_color, &p.want_color);
        guarded(c, g, not(colours_eq), "swap legs must be different colours");
        let ca_nz = b32_is_nonzero(c, &p.credit_account);
        guarded(c, g, ca_nz, "swap credit account must be supplied");
    })
}

/// `authenticatedActionAccount(p, nativeAccount)` (`contracts/modules/AccountRegistry.compact:171-191`).
///
/// Both arms are compiled; each arm's asserts bind only under its own mode, and the returned
/// account is the `cond_select` of the two. Source order preserved within each arm.
///
/// **Compact's `&&` SHORT-CIRCUITS over ledger reads**, and both arms rely on it:
/// `!evmOwners.member(acct) && !evmNonces.member(acct)` reads `evmNonces` only where the left
/// operand held, and `evmOwners.member(p.account) && evmNonces.member(p.account)` likewise. The
/// compactc artifact guards each second read by the first read's outcome (ops 30-34 and 54-58 of
/// `evidence/00012/raw/00012-p3.4-execute-impact-ops.txt`), so the port does too — a `Check::and`
/// would not, because by the time it runs the read has already been emitted.
///
/// The caller runs this inside `c.when(is_action, …)`; the two mode arms open their own scopes.
///
/// EFFECTS ONLY. Compact's `return acct` / `return p.account` is
/// `cond_select(native_mode, nativeAccount, p.account)`, which is pure compute and is therefore
/// **not** guarded in the artifact — the caller ([`gateway_account`]) computes it outside the
/// scope. Returning it from inside a `when_value` would cost two extra selects compactc does not
/// pay.
pub fn authenticated_action_account_effects(
    c: &mut Circuit3,
    p: &ExecutePayload<Public>,
    native_account: &B32<Public>,
    native_mode: Wire3<FieldT, Public>,
) {
    c.region("auth: action account", |c| {
        c.when(native_mode, |c| {
            // ---- native arm ------------------------------------------------------------------
            crate::guards::authenticated_native_account(c, native_account);

            let same = b32_eq(c, native_account, &p.account);
            c.assert(same.message("native witness does not match supplied account transcript"));
            // A SECOND `accountModes.lookup(acct)` — `contracts/modules/AccountRegistry.compact:178` re-reads the cell rather
            // than reusing `authenticatedNativeAccount`'s, and compactc inlines the call, so the
            // artifact carries two identical lookups (ops 17-20 and 21-24). Reusing the first
            // value here would drop an Impact instruction and fail `pi_skips` equality.
            let mode = MANAGER.account_modes.lookup(c, native_account);
            c.assert(
                mode.eq(p.auth_mode)
                    .message("authorization mode does not match account record"),
            );
            let has_owner = MANAGER.evm_owners.member(c, native_account);
            let no_owner = c.not(has_owner.field());
            // A SCOPE, not `member_under(c, no_owner, …)`: see the module docs on F-00012-07 —
            // `_under` mints the read's gates against the AMBIENT guard while emitting the op under
            // `ambient && guard`, so the two diverge and the run consumes a transcript output the
            // reference never produced.
            let has_nonce = c
                .when_value(no_owner, |c| MANAGER.evm_nonces.member(c, native_account))
                .otherwise(|c| Bool::constant(c, false))
                .into_inner();
            c.assert(
                not(is_true(has_owner))
                    .and(not(is_true(has_nonce)))
                    .message("native account carries EVM state"),
            );
        })
        .otherwise(|c| {
            // ---- EVM arm ---------------------------------------------------------------------
            c.assert(
                p.auth_mode
                    .eq(1u64)
                    .message("unknown account authorization mode"),
            );
            let member = MANAGER.accounts.member(c, &p.account);
            c.assert(is_true(member).message("gateway account is not registered"));
            let has_mode = MANAGER.account_modes.member(c, &p.account);
            c.assert(is_true(has_mode).message("registered account has no authorization mode"));
            let mode = MANAGER.account_modes.lookup(c, &p.account);
            c.assert(
                mode.eq(1u64)
                    .message("authorization mode does not match account record"),
            );
            let has_owner = MANAGER.evm_owners.member(c, &p.account);
            let has_nonce = c
                .when_value(has_owner.field(), |c| MANAGER.evm_nonces.member(c, &p.account))
                .otherwise(|c| Bool::constant(c, false))
                .into_inner();
            c.assert(
                is_true(has_owner)
                    .and(is_true(has_nonce))
                    .message("EVM account record is incomplete"),
            );
            let stored_owner = MANAGER.evm_owners.lookup(c, &p.account);
            c.assert(
                p.owner
                    .eq(stored_owner)
                    .message("signed owner does not match stored owner"),
            );
            let stored_nonce = MANAGER.evm_nonces.lookup(c, &p.account);
            c.assert(p.nonce.eq(stored_nonce).message("EVM nonce mismatch"));
        });
    })
}

/// `gatewayAccount(p, nativeAccount, evmRegistrationAccount)` (`contracts/modules/AccountRegistry.compact:195-207`).
///
/// Selector 0 → the native commitment, selector 1 → the derived EVM registration id, otherwise the
/// authenticated action account. The action arm's ledger reads run under `is_action`, which is the
/// `!s0 && !s1` fall-through of Compact's two early `return`s.
pub fn gateway_account(
    c: &mut Circuit3,
    s: &Selectors,
    p: &ExecutePayload<Public>,
    native_account: &B32<Public>,
    evm_registration_account: &B32<Public>,
) -> B32<Public> {
    let native_mode = p.auth_mode.eq(0u64).into_wire(c);
    c.when(s.is_action, |c| {
        authenticated_action_account_effects(c, p, native_account, native_mode)
    });
    let action_account = B32::cond_select(c, native_mode, native_account, &p.account);
    // s0 ? native : (s1 ? evmRegistration : action)
    let inner = B32::cond_select(c, s.s1, evm_registration_account, &action_account);
    B32::cond_select(c, s.s0, native_account, &inner)
}

/// `Bool` helper kept local so callers do not need the import.
pub fn as_bool<V: minocrab_std::v3::Vis3>(w: Wire3<FieldT, V>) -> Bool<V> {
    Bool::from_field_unchecked(w)
}
