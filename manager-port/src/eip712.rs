//! Phase 3.2 — the AUTH-EIP712-AA-V3-V1 chain: `evmAccountIdFor`, `evmDomainSeparatorFor`,
//! `evmStructHashFor`, `evmDigestFor` (`contracts/modules/Eip712.compact:55-207`).
//!
//! **Compact twin**: `contracts/modules/Eip712.compact`, which holds the ten frozen EIP-712 hex
//! constants and the whole digest chain. **Circuits ported here: none** — every circuit in that
//! module is `pure` and emits no key; they are exported as free oracles and are called from
//! `execute`.
//!
//! **These bytes are FROZEN.** They are what a MetaMask signature commits to, so a single wrong
//! byte silently invalidates every signature the deployed contract would accept. The gate is
//! therefore not "the differential passes" but byte-equality against the 00010 keyless suite's
//! frozen fixtures (`harness/src/auth/fixtures/v1.json`), which carry `manual.domainSeparator`,
//! `manual.structHash` and `manual.digest` for every case. See `tests/eip712_fixtures.rs`.
//!
//! ## The one design decision worth stating
//!
//! compactc builds each keccak preimage by `slice<N>([...], 0) as Bytes<N>` — a single `Bytes<N>`
//! FAB atom assembled from a byte vector, which is where the explode/rebuild chains come from.
//! This port hashes the **same byte string** as a *sequence of atoms* (`[bytes(32), bytes(32), …]`),
//! feeding the `B32` limbs straight in with no repacking. The digest is unchanged because a FAB
//! byte-string atom serializes to exactly its bytes, so a concatenation of atoms and one wide atom
//! present the same octet string to keccak — and minocrab's own ported contracts hash multi-atom
//! preimages against compactc artifacts on exactly this basis
//! (`minocrab-contracts/src/signet.rs:708`).
//!
//! That claim is **not taken on faith**: it is what the frozen-fixture suite checks, on 60 cases
//! across all six action types. If it were wrong, every digest would differ.

use minocrab::v3::AnyWire3;
use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Public};
use minocrab_std::v3::{pow2_const, Vis3, B32};

use crate::action_envelope::ExecutePayload;
use crate::byte_codec::{address_word, b32_const, numeric_word};

/// One `Bytes<n>` alignment segment.
fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

/// An alignment of `count` 32-byte atoms.
fn words(count: usize) -> Alignment {
    Alignment((0..count).map(|_| atom(32)).collect())
}

// ---- the frozen constants (`contracts/modules/Eip712.compact:55-123`) -----------------------------------------
//
// Byte-for-byte from the contract. Each is a keccak type hash or a hashed domain field, computed
// off-circuit once and frozen; the contract hard-codes them and so does this port.

/// `accountTag()` — the `evmAccountIdFor` domain separator.
pub const ACCOUNT_TAG: [u8; 32] = [
    0x55, 0xbc, 0x94, 0x0f, 0x83, 0x53, 0x37, 0xf1, 0x22, 0x4c, 0x18, 0x11, 0x10, 0xb2, 0xb7, 0x7f,
    0x57, 0xed, 0x69, 0x4c, 0xae, 0x0c, 0x4b, 0xf8, 0xff, 0x6b, 0xb3, 0xe0, 0x3b, 0xe6, 0xa9, 0x88,
];

/// `domainType()` — `keccak256("EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)")`.
pub const DOMAIN_TYPE: [u8; 32] = [
    0x36, 0xc2, 0x5d, 0xe3, 0xe5, 0x41, 0xd5, 0xd9, 0x70, 0xf6, 0x6e, 0x42, 0x10, 0xd7, 0x28, 0x72,
    0x12, 0x20, 0xff, 0xf5, 0xc0, 0x77, 0xcc, 0x6c, 0xd0, 0x08, 0xb3, 0xa0, 0xc6, 0x2a, 0xda, 0xb7,
];

/// `domainName()` — `keccak256("AA v3 EVM Manager")`.
pub const DOMAIN_NAME: [u8; 32] = [
    0xb2, 0xa1, 0x61, 0xc1, 0xe1, 0xfe, 0x09, 0xf6, 0x31, 0x58, 0x5b, 0x3b, 0xda, 0x0e, 0x4a, 0x22,
    0xf3, 0x17, 0xd7, 0xc6, 0x63, 0xc5, 0x82, 0xa0, 0x7c, 0x1d, 0x68, 0x3e, 0x61, 0xfd, 0xcd, 0xb1,
];

/// `domainVersion()` — `keccak256("1")`.
pub const DOMAIN_VERSION: [u8; 32] = [
    0xc8, 0x9e, 0xfd, 0xaa, 0x54, 0xc0, 0xf2, 0x0c, 0x7a, 0xdf, 0x61, 0x28, 0x82, 0xdf, 0x09, 0x50,
    0xf5, 0xa9, 0x51, 0x63, 0x7e, 0x03, 0x07, 0xcd, 0xcb, 0x4c, 0x67, 0x2f, 0x29, 0x8b, 0x8b, 0xc6,
];

/// `registerType()` — selector 1.
pub const REGISTER_TYPE: [u8; 32] = [
    0xe6, 0xac, 0xe6, 0xc7, 0x0a, 0x9d, 0x92, 0xef, 0x85, 0x1c, 0x2e, 0x2a, 0x67, 0xb2, 0x30, 0x90,
    0x17, 0xb0, 0x51, 0xd3, 0x9e, 0x05, 0x54, 0xc7, 0x46, 0x27, 0x4a, 0x17, 0x69, 0x59, 0xac, 0x4f,
];

/// `withdrawShieldedType()` — selector 2.
pub const WITHDRAW_SHIELDED_TYPE: [u8; 32] = [
    0x71, 0x7e, 0x1e, 0x74, 0x12, 0x98, 0x52, 0xbd, 0x43, 0x67, 0x44, 0xa5, 0xa1, 0x10, 0x8f, 0x0d,
    0xb9, 0x02, 0x92, 0x70, 0x31, 0xf5, 0xe7, 0x79, 0x96, 0x18, 0xec, 0x12, 0x93, 0x66, 0xd6, 0x1e,
];

/// `withdrawUnshieldedType()` — selector 3.
pub const WITHDRAW_UNSHIELDED_TYPE: [u8; 32] = [
    0xb6, 0x01, 0x29, 0xea, 0x6c, 0xa4, 0xc1, 0xb5, 0x1d, 0x86, 0x60, 0x77, 0xd1, 0x1c, 0xdb, 0x02,
    0x30, 0xe6, 0x06, 0x58, 0x76, 0xa5, 0x42, 0x06, 0xfe, 0xce, 0x04, 0x41, 0x3e, 0xda, 0xba, 0x9d,
];

/// `transferShieldedType()` — selector 4.
pub const TRANSFER_SHIELDED_TYPE: [u8; 32] = [
    0x06, 0xbe, 0xb8, 0x3e, 0xc8, 0xde, 0xd3, 0xa8, 0x08, 0x0b, 0xfa, 0xb5, 0x91, 0xd8, 0x9a, 0x1b,
    0x86, 0xed, 0x9e, 0x3f, 0x8d, 0xf6, 0xc1, 0x0e, 0xd3, 0x67, 0x74, 0x16, 0xd0, 0xa5, 0x60, 0x64,
];

/// `transferUnshieldedType()` — selector 5.
pub const TRANSFER_UNSHIELDED_TYPE: [u8; 32] = [
    0x46, 0xe9, 0x6f, 0x44, 0x96, 0xc1, 0x82, 0xe9, 0x83, 0x95, 0xb6, 0x89, 0x70, 0x1a, 0x94, 0x5c,
    0xbd, 0xb4, 0x75, 0x43, 0x57, 0x42, 0x42, 0xcc, 0x17, 0xf9, 0xb6, 0x44, 0x8c, 0x04, 0x9a, 0x07,
];

/// `openSwapType()` — selector 6.
pub const OPEN_SWAP_TYPE: [u8; 32] = [
    0xf7, 0x87, 0xd7, 0xf9, 0x63, 0xe8, 0x9e, 0xfc, 0xda, 0x8e, 0x6a, 0x54, 0x6b, 0xaf, 0xff, 0x33,
    0x38, 0x8c, 0xbd, 0xf4, 0x4b, 0x81, 0xf6, 0xf5, 0x95, 0x0c, 0x4b, 0xd3, 0xb0, 0x66, 0x58, 0x48,
];

// ---- the chain --------------------------------------------------------------------------------

/// Push a `B32`'s two limbs onto a limb vector, erased to `AnyWire3`.
fn push_b32<V: Vis3>(limbs: &mut Vec<AnyWire3<V>>, b: &B32<V>) {
    limbs.push(b.hi.erase());
    limbs.push(b.lo.erase());
}

/// Lift a public `B32` constant into the caller's visibility. Zero instructions — it is the
/// same two wires, retyped.
fn b32_from_public<V: Vis3>(b: B32<Public>) -> B32<V> {
    B32 {
        hi: V::from_public(b.hi),
        lo: V::from_public(b.lo),
    }
}

/// `evmAccountIdFor(manager, owner, salt)` (`contracts/modules/Eip712.compact:139-144`).
///
/// `keccak256(accountTag ‖ manager ‖ addressWord(owner) ‖ salt)` — four 32-byte words.
pub fn evm_account_id_for<V: Vis3>(
    c: &mut Circuit3,
    manager: &B32<V>,
    owner: Wire3<FieldT, V>,
    salt: &B32<V>,
) -> B32<V> {
    c.region("eip712: accountId", |c| {
        let tag = b32_const(c, &ACCOUNT_TAG);
        let owner_word = address_word(c, owner);
        let mut limbs = Vec::with_capacity(8);
        push_b32(&mut limbs, &b32_from_public::<V>(tag));
        push_b32(&mut limbs, manager);
        push_b32(&mut limbs, &owner_word);
        push_b32(&mut limbs, salt);
        let d = c.keccak256(words(4), &limbs);
        B32::from_typed(c, d)
    })
}

/// `evmDomainSeparatorFor(manager, domain)` (`contracts/modules/Eip712.compact:148-154`).
///
/// The manager's 32 bytes are first hashed and truncated to a 20-byte EVM **alias**
/// (`slice<20>(keccak256(manager), 12)` — the low 20 bytes of the digest, EVM address convention),
/// then the separator is `keccak256(domainType ‖ domainName ‖ domainVersion ‖ addressWord(alias)
/// ‖ domain)` — five 32-byte words.
pub fn evm_domain_separator_for<V: Vis3>(
    c: &mut Circuit3,
    manager: &B32<V>,
    domain: &B32<V>,
) -> B32<V> {
    c.region("eip712: domain separator", |c| {
        let alias_word = manager_alias_word(c, manager);
        let dtype = b32_const(c, &DOMAIN_TYPE);
        let dname = b32_const(c, &DOMAIN_NAME);
        let dver = b32_const(c, &DOMAIN_VERSION);
        let mut limbs = Vec::with_capacity(10);
        push_b32(&mut limbs, &b32_from_public::<V>(dtype));
        push_b32(&mut limbs, &b32_from_public::<V>(dname));
        push_b32(&mut limbs, &b32_from_public::<V>(dver));
        push_b32(&mut limbs, &alias_word);
        push_b32(&mut limbs, domain);
        let d = c.keccak256(words(5), &limbs);
        B32::from_typed(c, d)
    })
}

/// `addressWord(slice<20>(keccak256<Bytes<32>>(manager), 12))` — the manager's EVM alias, already
/// left-padded back into a 32-byte word.
///
/// `slice<20>(digest, 12)` takes digest bytes 12..31, and `addressWord` then puts those same bytes
/// back at word positions 12..31 with 12 zero bytes in front. The composition is therefore exactly
/// "zero the digest's leading 12 bytes", which is one mask, not a slice-then-shift pair: keep the
/// digest's `hi` limb (byte 31) and clear bytes 0..11 of `lo` by taking `lo mod 2^248` above the
/// 12-byte boundary — i.e. drop the low 12 bytes and shift back up.
fn manager_alias_word<V: Vis3>(c: &mut Circuit3, manager: &B32<V>) -> B32<V> {
    let digest = {
        let mut limbs = Vec::with_capacity(2);
        push_b32(&mut limbs, manager);
        let d = c.keccak256(words(1), &limbs);
        B32::from_typed(c, d)
    };
    // `lo` holds digest bytes 0..30 (LE). Dropping its low 12 bytes and shifting back up by 12
    // clears positions 0..11 and leaves 12..30 in place; `hi` (byte 31) is untouched.
    let (high, _low96) = c.div_mod_power_of_two(digest.lo, 96);
    let shift96 = V::from_public(pow2_const(c, 12));
    let lo = c.mul(high, shift96);
    B32 { hi: digest.hi, lo }
}

/// `eip712Digest(domainSeparator, structHash)` (`contracts/modules/Eip712.compact:194-197`).
///
/// `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)` — a 2-byte prefix atom then two
/// 32-byte words, 66 bytes total.
pub fn eip712_digest<V: Vis3>(
    c: &mut Circuit3,
    domain_separator: &B32<V>,
    struct_hash: &B32<V>,
) -> B32<V> {
    c.region("eip712: digest", |c| {
        // The `\x19\x01` prefix is a 2-byte constant atom: 0x1901 big-endian, which as a
        // little-endian field limb is 0x0119.
        let prefix = V::from_public(c.constant(0x0119u64));
        let alignment = Alignment(vec![atom(2), atom(32), atom(32)]);
        let mut limbs = vec![prefix.erase()];
        push_b32(&mut limbs, domain_separator);
        push_b32(&mut limbs, struct_hash);
        let d = c.keccak256(alignment, &limbs);
        B32::from_typed(c, d)
    })
}

/// The per-selector struct-hash preimages of `evmStructHashFor` (`contracts/modules/Eip712.compact:158-192`).
///
/// Returned as `(alignment_word_count, limbs)` so the caller can hash them; each is a sequence of
/// 32-byte words, matching the Compact source's `Bytes<192>` / `Bytes<320>` / `Bytes<288>` /
/// `Bytes<448>` preimages (6 / 10 / 9 / 14 words respectively).
pub struct StructHashPreimage<V: Vis3> {
    pub word_count: usize,
    pub limbs: Vec<AnyWire3<V>>,
}

/// Selector 1 — `RegisterEvmAccount`, `Bytes<192>` = 6 words:
/// `registerType ‖ manager ‖ account ‖ addressWord(owner) ‖ accountSalt ‖ uint64Word(validUntil)`.
pub fn struct_hash_preimage_register<V: Vis3>(
    c: &mut Circuit3,
    manager: &B32<V>,
    p: &ExecutePayload<V>,
) -> StructHashPreimage<V> {
    let t = b32_const(c, &REGISTER_TYPE);
    let owner_word = address_word(c, p.owner.field());
    let valid_until = numeric_word(c, p.valid_until.field());
    let mut limbs = Vec::with_capacity(12);
    push_b32(&mut limbs, &b32_from_public::<V>(t));
    push_b32(&mut limbs, manager);
    push_b32(&mut limbs, &p.account);
    push_b32(&mut limbs, &owner_word);
    push_b32(&mut limbs, &p.account_salt);
    push_b32(&mut limbs, &valid_until);
    StructHashPreimage {
        word_count: 6,
        limbs,
    }
}

/// Selectors 2 and 3 — `WithdrawShielded` / `WithdrawUnshielded`, `Bytes<320>` = 10 words:
/// `typeHash ‖ manager ‖ account ‖ addressWord(owner) ‖ uint64Word(nonce) ‖ uint64Word(validUntil)
/// ‖ primaryColor ‖ uint128Word(primaryAmount) ‖ uint8Word(recipientKind) ‖ recipient`.
///
/// `type_hash` is the caller's mux over selector 2 vs 3, so the choice stays where the guard order
/// can be preserved.
pub fn struct_hash_preimage_withdraw<V: Vis3>(
    c: &mut Circuit3,
    type_hash: &B32<V>,
    manager: &B32<V>,
    p: &ExecutePayload<V>,
) -> StructHashPreimage<V> {
    let owner_word = address_word(c, p.owner.field());
    let nonce = numeric_word(c, p.nonce.field());
    let valid_until = numeric_word(c, p.valid_until.field());
    let amount = numeric_word(c, p.primary_amount.field());
    let kind = numeric_word(c, p.recipient_kind.field());
    let mut limbs = Vec::with_capacity(20);
    push_b32(&mut limbs, type_hash);
    push_b32(&mut limbs, manager);
    push_b32(&mut limbs, &p.account);
    push_b32(&mut limbs, &owner_word);
    push_b32(&mut limbs, &nonce);
    push_b32(&mut limbs, &valid_until);
    push_b32(&mut limbs, &p.primary_color);
    push_b32(&mut limbs, &amount);
    push_b32(&mut limbs, &kind);
    push_b32(&mut limbs, &p.recipient);
    StructHashPreimage {
        word_count: 10,
        limbs,
    }
}

/// Selectors 4 and 5 — `TransferInternalShielded` / `TransferInternalUnshielded`, `Bytes<288>` =
/// 9 words: `typeHash ‖ manager ‖ account ‖ addressWord(owner) ‖ uint64Word(nonce)
/// ‖ uint64Word(validUntil) ‖ toAccount ‖ primaryColor ‖ uint128Word(primaryAmount)`.
pub fn struct_hash_preimage_transfer<V: Vis3>(
    c: &mut Circuit3,
    type_hash: &B32<V>,
    manager: &B32<V>,
    p: &ExecutePayload<V>,
) -> StructHashPreimage<V> {
    let owner_word = address_word(c, p.owner.field());
    let nonce = numeric_word(c, p.nonce.field());
    let valid_until = numeric_word(c, p.valid_until.field());
    let amount = numeric_word(c, p.primary_amount.field());
    let mut limbs = Vec::with_capacity(18);
    push_b32(&mut limbs, type_hash);
    push_b32(&mut limbs, manager);
    push_b32(&mut limbs, &p.account);
    push_b32(&mut limbs, &owner_word);
    push_b32(&mut limbs, &nonce);
    push_b32(&mut limbs, &valid_until);
    push_b32(&mut limbs, &p.to_account);
    push_b32(&mut limbs, &p.primary_color);
    push_b32(&mut limbs, &amount);
    StructHashPreimage {
        word_count: 9,
        limbs,
    }
}

/// Selector 6 — `OpenSwapShielded`, `Bytes<448>` = 14 words:
/// `openSwapType ‖ manager ‖ account ‖ addressWord(owner) ‖ uint64Word(nonce)
/// ‖ uint64Word(validUntil) ‖ primaryColor ‖ uint128Word(primaryAmount)
/// ‖ uint8Word(recipientKind) ‖ recipient ‖ wantNonce ‖ wantColor ‖ uint128Word(wantAmount)
/// ‖ creditAccount`.
pub fn struct_hash_preimage_open_swap<V: Vis3>(
    c: &mut Circuit3,
    manager: &B32<V>,
    p: &ExecutePayload<V>,
) -> StructHashPreimage<V> {
    let t = b32_const(c, &OPEN_SWAP_TYPE);
    let owner_word = address_word(c, p.owner.field());
    let nonce = numeric_word(c, p.nonce.field());
    let valid_until = numeric_word(c, p.valid_until.field());
    let amount = numeric_word(c, p.primary_amount.field());
    let kind = numeric_word(c, p.recipient_kind.field());
    let want_amount = numeric_word(c, p.want_amount.field());
    let mut limbs = Vec::with_capacity(28);
    push_b32(&mut limbs, &b32_from_public::<V>(t));
    push_b32(&mut limbs, manager);
    push_b32(&mut limbs, &p.account);
    push_b32(&mut limbs, &owner_word);
    push_b32(&mut limbs, &nonce);
    push_b32(&mut limbs, &valid_until);
    push_b32(&mut limbs, &p.primary_color);
    push_b32(&mut limbs, &amount);
    push_b32(&mut limbs, &kind);
    push_b32(&mut limbs, &p.recipient);
    push_b32(&mut limbs, &p.want_nonce);
    push_b32(&mut limbs, &p.want_color);
    push_b32(&mut limbs, &want_amount);
    push_b32(&mut limbs, &p.credit_account);
    StructHashPreimage {
        word_count: 14,
        limbs,
    }
}

/// Hash a prepared struct-hash preimage.
pub fn hash_struct_preimage<V: Vis3>(c: &mut Circuit3, pre: StructHashPreimage<V>) -> B32<V> {
    let d = c.keccak256(words(pre.word_count), &pre.limbs);
    B32::from_typed(c, d)
}

/// `evmDigestFor(manager, domain, payload)` (`contracts/modules/Eip712.compact:201-207`) —
/// `eip712Digest(evmDomainSeparatorFor(manager, domain), evmStructHashFor(manager, payload))`.
pub fn evm_digest_for(
    c: &mut Circuit3,
    manager: &B32<Public>,
    domain: &B32<Public>,
    p: &ExecutePayload<Public>,
) -> B32<Public> {
    let sep = evm_domain_separator_for(c, manager, domain);
    let sh = evm_struct_hash_for(c, manager, p);
    eip712_digest(c, &sep, &sh)
}

/// `evmStructHashFor(manager, payload)` (`contracts/modules/Eip712.compact:158-192`).
///
/// A chain of `if (…) { return keccak(…); }` blocks: a circuit compiles every arm, so all four
/// preimages are hashed and the answer is selected. The trailing
/// `assert(p.selector == 6, "EIP-712 selector must be 1..6")` binds under the fall-through
/// condition — which, combined with the caller's `selector != 0` guard, is exactly "selector is 6".
pub fn evm_struct_hash_for(
    c: &mut Circuit3,
    manager: &B32<Public>,
    p: &ExecutePayload<Public>,
) -> B32<Public> {
    c.region("eip712: struct hash", |c| {
        let s1 = p.selector.eq(1u64).into_wire(c);
        let s2 = p.selector.eq(2u64).into_wire(c);
        let s3 = p.selector.eq(3u64).into_wire(c);
        let s4 = p.selector.eq(4u64).into_wire(c);
        let s5 = p.selector.eq(5u64).into_wire(c);
        let is_withdraw = c.cond_select(s2, 1u64, s3);
        let is_transfer = c.cond_select(s4, 1u64, s5);

        let register = {
            let pre = struct_hash_preimage_register(c, manager, p);
            hash_struct_preimage(c, pre)
        };
        let withdraw = {
            let a = b32_const(c, &WITHDRAW_SHIELDED_TYPE);
            let b = b32_const(c, &WITHDRAW_UNSHIELDED_TYPE);
            let t = B32::cond_select(c, s2, &a, &b);
            let pre = struct_hash_preimage_withdraw(c, &t, manager, p);
            hash_struct_preimage(c, pre)
        };
        let transfer = {
            let a = b32_const(c, &TRANSFER_SHIELDED_TYPE);
            let b = b32_const(c, &TRANSFER_UNSHIELDED_TYPE);
            let t = B32::cond_select(c, s4, &a, &b);
            let pre = struct_hash_preimage_transfer(c, &t, manager, p);
            hash_struct_preimage(c, pre)
        };
        let swap = {
            let pre = struct_hash_preimage_open_swap(c, manager, p);
            hash_struct_preimage(c, pre)
        };

        // The fall-through assert: `!s1 && !(s2||s3) && !(s4||s5)` must mean selector 6.
        let not_s1 = c.not(s1);
        let not_wd = c.not(is_withdraw);
        let not_tr = c.not(is_transfer);
        let rest = c.cond_select(not_s1, not_wd, 0u64);
        let rest = c.cond_select(rest, not_tr, 0u64);
        c.when(rest, |c| {
            c.assert(p.selector.eq(6u64).message("EIP-712 selector must be 1..6"));
        });

        // s1 ? register : (isWithdraw ? withdraw : (isTransfer ? transfer : swap))
        let inner = B32::cond_select(c, is_transfer, &transfer, &swap);
        let inner = B32::cond_select(c, is_withdraw, &withdraw, &inner);
        B32::cond_select(c, s1, &register, &inner)
    })
}
