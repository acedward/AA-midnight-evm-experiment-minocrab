//! Phase 3.1 — leaf helpers: constants and the big-endian EVM word encoders.
//!
//! These are the bottom of the `execute` port. They are also **where the row win is**: the
//! compactc artifact spends 3,140 of `execute`'s 5,780 instructions on `div_mod_power_of_two` /
//! `reconstitute_field` chains (54.3%), which is what the per-byte `Bytes[...]` permutations in
//! `contracts/modules/ByteCodec.compact:30-87` lower to. ZKIR has a native `ReverseBytes`, so each of these encoders
//! becomes one instruction instead of a chain.
//!
//! **Faithfulness (FR-003).** Same bytes out, no statement change. The contract's own comment
//! (`contracts/modules/ByteCodec.compact:52-62`) proves the byte equality it relies on: `v as Bytes<N>` is
//! little-endian, so a value's LE bytes reversed inside a 32-byte string *are* its big-endian
//! 32-byte rendering. That is exactly what `reverse_bytes` computes, so the port takes the same
//! bytes by a cheaper route — the definition of an allowed instruction-selection win.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Fr, Public};
use minocrab_std::v3::{pow2_const, Vis3, B32};

/// A `Bytes<32>` compile-time constant from its 32 bytes, in the contract's display order
/// (`value[0]` first). Mirrors `B32::pad`'s limbing: `hi` is byte 31, `lo` is bytes 0..30 LE.
pub fn b32_const(c: &mut Circuit3, bytes: &[u8; 32]) -> B32<Public> {
    B32 {
        hi: c.constant(Fr::from(u64::from(bytes[31]))),
        lo: c.constant(Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit the field")),
    }
}

/// `reverseBytes32(value)` — ZKIR's native byte reversal.
///
/// One instruction (~150 rows) where compactc's `Bytes[value[31], value[30], …]` lowers to a
/// per-byte explode/rebuild chain (~4,600 rows). Same permutation, same bytes.
pub fn reverse_bytes32<V: Vis3>(c: &mut Circuit3, b: &B32<V>) -> B32<V> {
    let typed = b.to_typed(c);
    let rev = c.reverse_bytes(typed);
    B32::from_typed(c, rev)
}

/// The 32-byte **big-endian** rendering of an integer that fits in 248 bits.
///
/// This is `uint64Word` / `uint128Word` / `uint8Word` (`contracts/modules/ByteCodec.compact:63-81`) — all three are
/// the same operation at different widths, because each places the value's LE bytes reversed at
/// the tail of an otherwise-zero 32-byte string:
///
/// - `uint64Word(v)`  = 24 zero bytes then `b[7]…b[0]`   (v's 8 LE bytes reversed)
/// - `uint128Word(v)` = 16 zero bytes then `b[15]…b[0]`
/// - `uint8Word(v)`   = 31 zero bytes then `b[0]`
///
/// Put the value in `lo` (so its LE bytes sit at string positions 0..) with `hi = 0`, and reverse
/// the 32-byte string: the bytes land, reversed, at the tail. The zero prefix is free because it
/// is the rest of an all-zero string.
///
/// **The width is not a parameter and does not need to be.** The three Compact circuits differ
/// only in how many leading bytes they hard-code as zero, and a value below `2^(8n)` already has
/// zeros above byte `n`. One helper is therefore faithful to all three — and the caller's argument
/// type is what guarantees the bound (`Uint<64>` *is* `assert_bits(w, 64)`).
pub fn numeric_word<V: Vis3>(c: &mut Circuit3, value: Wire3<FieldT, V>) -> B32<V> {
    let zero = V::from_public(c.constant(0u64));
    let padded = B32 { hi: zero, lo: value };
    reverse_bytes32(c, &padded)
}

/// `addressWord(value: Bytes<20>)` — 12 zero bytes then the 20 address bytes in display order
/// (`contracts/modules/ByteCodec.compact:85-87`).
///
/// A `Bytes<20>` is a single 160-bit limb whose bytes are already in display order at string
/// positions 0..19. The word wants them at 12..31, i.e. shifted up by 12 bytes — but a limb only
/// holds 31 bytes, so the top byte (position 31) must move to `hi`. Split the limb at bit 152
/// (= 19 bytes): the high byte becomes `hi`, and the low 19 bytes shift up by 12 into `lo`.
pub fn address_word<V: Vis3>(c: &mut Circuit3, addr: Wire3<FieldT, V>) -> B32<V> {
    let (hi, low152) = c.div_mod_power_of_two(addr, 152);
    let shift96 = V::from_public(pow2_const(c, 12));
    let lo = c.mul(low152, shift96);
    B32 { hi, lo }
}
