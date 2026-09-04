//! Shared predicates over `Bytes<32>` and Boolean wires. **NO Compact twin.**
//!
//! Every other module in this crate names a `contracts/…compact` file it transcribes. This one does
//! not: Compact has `==` on `Bytes<32>` as a language primitive and needs no helper, while minocrab
//! deliberately does **not** make `B32` a `CheckOperand`. So these four exist to say in Rust what
//! Compact says in syntax, and they are kept together rather than scattered so that a reader
//! looking for the port of a contract circuit never finds one here.
//!
//! ## The `Bytes<32>` comparison trap
//!
//! Equality must be written **limbwise** — `hi` is byte 31 and `lo` is bytes 0..30 little-endian,
//! so a lexicographic reading of the pair would be wrong. Only equality is needed here, and
//! equality is limbwise-safe. (`bytes32LexicographicLt`, which is not, lives in
//! `contracts/modules/ByteCodec.compact` and is used only by `SemanticCommitment`, which this crate
//! does not port.)

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab_std::v3::{is_true, Bool, Check, Vis3, B32};

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

/// `Bool` helper kept local so callers do not need the import.
pub fn as_bool<V: minocrab_std::v3::Vis3>(w: Wire3<FieldT, V>) -> Bool<V> {
    Bool::from_field_unchecked(w)
}
