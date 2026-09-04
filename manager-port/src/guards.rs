//! Phase 3.3 — the envelope asserts, the deadline, the account identity and the registration
//! guards (`contracts/modules/AccountRegistry.compact:85-109`,
//! `contracts/modules/ActionEnvelope.compact:80-158`,
//! `contracts/modules/AccountRegistry.compact:171-207`).
//!
//! **Guard ORDER and the refusal set are the product's behaviour** (FR-204), so this module keeps
//! both: every assert appears in the same relative order as the Compact source and carries the
//! same message text. Messages are metadata in minocrab (no instruction, no row), exactly as in
//! Compact, so preserving them is free and makes a failed proof diagnosable.
//!
//! ## Guarding convention (changed in the 3.4-3.6 pass)
//!
//! These helpers no longer take a `guard` parameter. Compact's `if` is
//! [`Circuit3::when`](minocrab::v3::Circuit3::when), which pushes an AMBIENT guard that every
//! enclosed ledger operation and every enclosed `assert` picks up, lowered as
//! `cond_select(outer, inner, 0)` — compactc's own `&&`. Passing an explicit guard *inside* such a
//! scope would conjoin it with the ambient one a second time and emit an extra instruction per
//! call, so the call sites open a scope and the helpers stay plain. That also makes Compact's
//! nesting and this port's nesting the same shape, which is what a reader checks.
//!
//! ## The `Bytes<32>` comparison trap
//!
//! `B32` is deliberately **not** a `CheckOperand` in minocrab, and Compact does not offer `<` on
//! `Bytes<32>` either. Equality still has to be written, and it must be written **limbwise** —
//! `hi` is byte 31 and `lo` is bytes 0..30 little-endian, so a lexicographic reading of the pair
//! would be wrong. Only equality is needed here, and equality is limbwise-safe.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab_std::v3::{is_true, Bool, Check, Uint, Vis3, B32};

use crate::ledger::MANAGER;

/// `a == b` for a `Bytes<32>` pair: both limbs equal.
pub fn b32_eq<V: Vis3>(c: &mut Circuit3, a: &B32<V>, b: &B32<V>) -> Check<V> {
    let hi = Bool::from_field_unchecked(c.test_eq(a.hi, b.hi));
    let lo = Bool::from_field_unchecked(c.test_eq(a.lo, b.lo));
    is_true(hi).and(is_true(lo))
}

/// `a == default<Bytes<32>>` — the all-zero 32-byte string.
pub fn b32_is_zero<V: Vis3>(c: &mut Circuit3, a: &B32<V>) -> Check<V> {
    let zero = V::from_public(c.constant(0u64));
    let z = B32 { hi: zero, lo: zero };
    b32_eq(c, a, &z)
}

/// `a != default<Bytes<32>>`.
pub fn b32_is_nonzero<V: Vis3>(c: &mut Circuit3, a: &B32<V>) -> Check<V> {
    minocrab_std::v3::not(b32_is_zero(c, a))
}

/// A boolean wire as a `Check`.
pub fn wire_is_true<V: Vis3>(w: Wire3<FieldT, V>) -> Check<V> {
    is_true(Bool::from_field_unchecked(w))
}

/// `ownerCommitment(sk)` (`contracts/modules/AccountRegistry.compact:85-87`) —
/// `persistentCommit<Bytes<21>>("aa:manager:owner:v1.0", disclose(sk))`.
///
/// **`persistentCommit` has no v3 spelling in minocrab** (it is v2-only, `minocrab-std/src/hash.rs:43`),
/// so it is transcribed here from the v2 body, which is itself compactc's lowering: a
/// `persistentHash` whose preimage is **rand-then-value** with the alignment `bytes 32` consed onto
/// the value's atoms. Here `rand` is the 32-byte secret and `value` is the 21-byte domain string,
/// so the preimage is `sk ‖ "aa:manager:owner:v1.0"` under alignment `[bytes 32, bytes 21]`.
///
/// This is the highest-blast-radius helper in the port: it defines account identity, so every
/// native authorization path and every ledger key derives from it. It is not checked by a
/// standalone fixture — there is no frozen vector for it — but it is checked by construction: the
/// account id it produces flows into `gatewayAccount`, into the ledger keys, and therefore into
/// `execute`'s public transcript, where the Phase-3.6 PI-vector differential compares it against
/// the compactc artifact element for element.
pub fn owner_commitment<V: Vis3>(c: &mut Circuit3, sk: &B32<V>) -> B32<V> {
    c.region("owner commitment", |c| {
        const DOMAIN: &[u8] = b"aa:manager:owner:v1.0";
        const _: () = assert!(DOMAIN.len() == 21, "the domain literal is a Bytes<21>");
        let tag = {
            let mut le = [0u8; 21];
            le.copy_from_slice(DOMAIN);
            V::from_public(
                c.constant(minocrab::Fr::from_le_bytes(&le).expect("21 bytes fit the field")),
            )
        };
        let alignment = minocrab::Alignment(vec![
            minocrab::AlignmentSegment::Atom(minocrab::AlignmentAtom::Bytes { length: 32 }),
            minocrab::AlignmentSegment::Atom(minocrab::AlignmentAtom::Bytes { length: 21 }),
        ]);
        let inputs = vec![sk.hi.erase(), sk.lo.erase(), tag.erase()];
        let digest = c.persistent_hash(alignment, &inputs);
        B32::from_typed(c, digest)
    })
}

/// `authenticatedNativeAccount(acct)` (`contracts/modules/AccountRegistry.compact:92-97`) — THE single authorization choke
/// point for every native debiting action. Three asserts, in source order.
///
/// Runs under whatever ambient guard the caller's `c.when` scope established.
pub fn authenticated_native_account(
    c: &mut Circuit3,
    acct: &B32<minocrab::Public>,
) -> Uint<8, minocrab::Public> {
    let member = MANAGER.accounts.member(c, acct);
    c.assert(is_true(member).message("caller's owner witness matches no registered account"));

    let has_mode = MANAGER.account_modes.member(c, acct);
    c.assert(is_true(has_mode).message("registered account has no authorization mode"));

    let mode = MANAGER.account_modes.lookup(c, acct);
    c.assert(
        mode.eq(0u64)
            .message("EVM account cannot enter native authorization"),
    );
    mode
}

/// `registerAccount(acct, mode)` (`contracts/modules/AccountRegistry.compact:103-109`) — the shared collision gateway.
/// Three asserts then two inserts, in source order. Runs under the caller's ambient guard.
pub fn register_account(
    c: &mut Circuit3,
    acct: &B32<minocrab::Public>,
    mode: Uint<8, minocrab::Public>,
) {
    let nonzero = b32_is_nonzero(c, acct);
    c.assert(nonzero.message("account id must be nonzero"));

    let already = MANAGER.accounts.member(c, acct);
    c.assert(minocrab_std::v3::not(is_true(already)).message("account already registered"));

    let mode_collision = MANAGER.account_modes.member(c, acct);
    c.assert(minocrab_std::v3::not(is_true(mode_collision)).message("account mode collision"));

    MANAGER.accounts.insert(c, acct);
    MANAGER.account_modes.insert(c, acct, &mode);
}

/// `assertLiveDeadline(validUntil)` (`contracts/manager.compact:310-327`). `execute` calls it inside
/// `if (isEvmAuthorized)`, so the caller opens that scope and this body inherits it.
///
/// Three asserts in source order: the horizon is representable, the deadline is not further out
/// than 3600 seconds, and it has not passed.
pub fn assert_live_deadline(c: &mut Circuit3, valid_until: Uint<64, minocrab::Public>) {
    c.assert(
        valid_until
            .gt(3600u64)
            .message("EVM authorization deadline cannot satisfy the horizon"),
    );

    // `(validUntil - 3600) as Uint<64>` — Compact inserts an underflow guard before every `-`,
    // and `sub_with` emits exactly that guard, in the same order, at the same width. The assert
    // above already establishes the precondition, so the emitted guard is the same redundant-but-
    // present check compactc emits.
    let horizon = Uint::<64, minocrab::Public>::constant(c, 3600);
    let earliest = valid_until.sub_with(c, horizon, "result of subtraction would be negative");

    let gte = minocrab_std::v3::kernel::block_time_gte(c, earliest);
    c.assert(is_true(gte).message("EVM authorization deadline exceeds 3600-second horizon"));

    let lt = minocrab_std::v3::kernel::block_time_lt(c, valid_until);
    c.assert(is_true(lt).message("EVM authorization has expired"));
}
