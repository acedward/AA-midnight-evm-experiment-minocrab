//! Phase 3.5 — the zswap-facing half of the port: the family-scoped key hashes, the pooled-coin
//! ledger view, `receiveShielded`, `repoolOrRemove` and the coin-recipient shapes.
//!
//! Everything here is a **transcription**, not an invention. `sendShielded`, `sendUnshielded`,
//! `mergeCoinImmediate`, `receiveUnshielded`, `kernel.self()` and the three `claimZswap*` effects
//! all exist in `minocrab-std/src/v3/kernel.rs` and are used directly; what this module adds is the
//! handful of pieces the pinned Compact standard library defines as *recipes over* those
//! primitives, plus one ledger-typing workaround.
//!
//! ## `createZswapInput` / `createZswapOutput` cost nothing
//!
//! Both are Void witness natives: they instruct the OFF-CIRCUIT transaction builder to place a coin
//! in the offer and emit no ZKIR and no rows (`minocrab-std/src/v3/kernel.rs:646`). The two calls in
//! `custodyDispatch`'s FR-308 open-offer shape are therefore a no-op to port — only the neighbouring
//! `claimZswap*` calls emit. This is not an omission; it is what the artifact does. The compactc
//! `execute.zkir` op stream confirms it: the open-offer branch's ops are exactly one `kernel.self`
//! read and the effects-map claims, with nothing between them
//! (`evidence/00012/raw/00012-p3.4-execute-impact-ops.txt`, ops 189-226).
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
//! and [`POOLS_READ`] is `LedgerMap::at(0)` over it. Same field index, same key type, same atoms, so
//! the emitted `dup 0; idx [0]; idx {key}; popeq` is byte-identical to what a native `lookup` would
//! emit; the only thing that changed is which Rust type names the popeq's limbs. The atoms are taken
//! from `QualifiedShieldedCoinInfo3`'s own `CircuitAbi` impl rather than re-listed, so the two views
//! cannot drift.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Public};
use minocrab_std::v3::{
    coin_commitment, kernel, CircuitAbi, CoinColor, CoinNonce, CoinRecipient, ContractAddress,
    LedgerMap, LedgerRepr, QualifiedShieldedCoinInfo3, ShieldedCoinInfo3, ZswapCoinPublicKey, B32,
};

use crate::ledger::MANAGER;

// ---- the family tags and the family-scoped keys -------------------------------------------------

/// `shieldedFamilyTag()` — `pad(32, "aa:manager:shielded:v1")` (`manager.compact:317-319`).
pub fn shielded_family_tag(c: &mut Circuit3) -> B32<Public> {
    B32::pad(c, "aa:manager:shielded:v1")
}

/// `unshieldedFamilyTag()` — `pad(32, "aa:manager:unshielded:v1")` (`manager.compact:321-323`).
pub fn unshielded_family_tag(c: &mut Circuit3) -> B32<Public> {
    B32::pad(c, "aa:manager:unshielded:v1")
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
/// `unshieldedKey` and the mux's one key derivation (`manager.compact:325-331`, `:1034-1035`).
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

// ---- the pooled-coin read view ------------------------------------------------------------------

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
    /// (`manager.compact:754-756`). Zero instructions.
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
        // Taken from minocrab's own coin type rather than re-listed, so the two views of field 0
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

/// The READ view of ledger field 0 (`pools`). Same field, same key type, different Rust value type
/// — see the module docs. Writes still go through [`MANAGER.pools`](crate::ledger::Manager::pools),
/// whose `insert_coin` is the one method that needs minocrab's own coin type.
pub const POOLS_READ: LedgerMap<B32<Public>, PooledCoin> = LedgerMap::at(0);

// ---- coin recipients ----------------------------------------------------------------------------

/// `right<ZswapCoinPublicKey, ContractAddress>(addr)` — the contract itself as a coin recipient.
/// A literal: the tag is the constant 0 and the unused left arm is `default<ZswapCoinPublicKey>`.
pub fn contract_recipient(c: &mut Circuit3, me: ContractAddress<Public>) -> CoinRecipient<Public> {
    let zero = c.constant(0u64);
    CoinRecipient {
        is_left: zero,
        left: ZswapCoinPublicKey(B32 { hi: zero, lo: zero }),
        right: me,
    }
}

/// `right<ZswapCoinPublicKey, ContractAddress>(kernel.self())` — a FRESH `kernel.self()` read
/// packaged as a coin recipient. Each call emits its own read, which is what compactc does: the
/// artifact's op stream carries a separate `dup 2; idxc [0]; popeqc` before every `insertCoin`.
pub fn self_recipient(c: &mut Circuit3) -> CoinRecipient<Public> {
    let me = kernel::self_address(c);
    contract_recipient(c, me.address())
}

// ---- the stdlib recipes -------------------------------------------------------------------------

/// The stdlib's `receiveShielded(coin)` (`standard-library.compact:152-156`):
///
/// ```text
/// const recipient = right<ZswapCoinPublicKey, ContractAddress>(kernel.self());
/// createZswapOutput(coin, recipient);                       // Void witness — emits nothing
/// kernel.claimZswapCoinReceive(coinCommitment(coin, recipient));
/// ```
///
/// Transcribed rather than imported: minocrab's own copy lives in `minocrab-contracts`, which is
/// `publish = false` corpus code, and this project's scope forbids depending on it.
pub fn receive_shielded(c: &mut Circuit3, coin: &ShieldedCoinInfo3<Public>) {
    c.region("coin: receive", |c| {
        let recipient = self_recipient(c);
        let cm = coin_commitment(c, coin, &recipient);
        kernel::claim_zswap_coin_receive(c, &cm);
    })
}

/// `repoolOrRemove(col, change)` (`manager.compact:773-780`) — write back what is left of colour
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

/// The stdlib's `sendUnshielded(color, amount, recipient)` (`standard-library.compact:113-120`),
/// transcribed because minocrab's own copy is unusable inside a branch — **finding F-00012-07**.
///
/// ```text
/// kernel.incUnshieldedOutputs(left<Bytes<32>, Bytes<32>>(color), amount);
/// kernel.claimUnshieldedCoinSpend(left<Bytes<32>, Bytes<32>>(color), recipient, amount);
/// if (recipient.is_left && recipient.left.bytes == kernel.self().bytes) {
///   kernel.incUnshieldedInputs(left<Bytes<32>, Bytes<32>>(color), amount);
/// }
/// ```
///
/// `minocrab-std`'s `kernel::send_unshielded` reads `kernel.self()` through `kernel_self_guarded`,
/// which mints the read's `public_input` gates against the **raw** `is_left` wire while the op
/// itself is emitted under `ambient && is_left`. Called inside a `c.when` scope — which is where
/// `custodyDispatch` calls it from — the gates are therefore guarded more weakly than the op, and
/// the run consumes a public-transcript output the ledger never produced. Written here as a scope
/// instead, so the guard on the gates and the guard on the op are the same wire.
pub fn send_unshielded(
    c: &mut Circuit3,
    color: B32<Public>,
    amount: minocrab_std::v3::Uint<128, Public>,
    recipient: &kernel::UnshieldedRecipient<Public>,
) {
    let token = kernel::unshielded(c, CoinColor(color));
    kernel::inc_unshielded_outputs(c, &token, amount);
    kernel::claim_unshielded_coin_spend(c, &token, recipient, amount);

    // `recipient.is_left && recipient.left.bytes == kernel.self().bytes` — the AUTO-RECEIVE guard.
    // The `kernel.self()` read is guarded by `is_left` alone in Compact (a recipient that is a user
    // address never needs the contract's own address), and by `ambient && is_left` here, which is
    // the same wire compactc guards both the gates and the op with.
    let is_left = recipient.is_left.field();
    let zero = c.constant(0u64);
    let me = c
        .when_value(is_left, |c| kernel::self_address(c).address())
        .otherwise(|_c| ContractAddress(B32 { hi: zero, lo: zero }))
        .into_inner();
    let left = recipient.left.bytes();
    let mine = {
        let me = me.bytes();
        let eq_hi = c.test_eq(left.hi, me.hi);
        let eq_lo = c.test_eq(left.lo, me.lo);
        // compactc lowers `&&` on Booleans as a `cond_select`, not a `mul`.
        let both = c.cond_select(eq_hi, eq_lo, 0u64);
        c.cond_select(is_left, both, 0u64)
    };
    kernel::inc_unshielded_inputs_under(c, mine, &token, amount);
}

/// `evolveNonce(index, nonce)` — the pinned standard library's
/// `upgradeFromTransient(transientHash<Vector<3, Field>>([domain, index, degradeToTransient(nonce)]))`.
///
/// **A WORKAROUND item (Phase-2 survey §3.1b): `evolveNonce` is v2-only in minocrab.** The v3
/// module has `derived_nonce`, but that is the private TWO-element form `sendShielded` and
/// `mergeCoin` write inline (`domain ‖ degrade(nonce)`), not the stdlib circuit's three-element form
/// with an index. Transcribed here from minocrab's own v2 body (`minocrab-std/src/coin.rs:172-177`),
/// which is itself compactc's lowering, over the v3 `hash` helpers.
pub fn evolve_nonce(
    c: &mut Circuit3,
    index: u64,
    nonce: &B32<Public>,
) -> B32<Public> {
    let domain = minocrab::Fr::from_le_bytes(b"midnight:kernel:nonce_evolve")
        .expect("the 28-byte domain fits the field");
    let index = c.constant(index);
    let degraded = minocrab_std::v3::hash::degrade_to_transient(c, nonce);
    let h = c.transient_hash(&[
        minocrab::v3::AnyWire3::immediate(domain),
        index.erase(),
        degraded.erase(),
    ]);
    minocrab_std::v3::hash::upgrade_from_transient(c, h)
}
