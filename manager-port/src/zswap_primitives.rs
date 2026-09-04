//! `contracts/modules/ZswapPrimitives.compact` — the zswap-facing leaves.
//!
//! **Compact twin**: `contracts/modules/ZswapPrimitives.compact`. It holds `zswapCoinCommitment`,
//! `zswapCoinNullifier`, `dropMerkleIndex`, the two pure oracles `zswapNullifierOf` /
//! `zswapCommitmentOf`, and the two zswap domain separators. **Circuits ported here: none** — none
//! of those emits a key. What this module holds is the part of that family the *provable* circuits
//! actually use: the coin-recipient shapes, the stdlib's `receiveShielded` recipe, and
//! `evolveNonce`. `zswapCoinCommitment` / `zswapCoinNullifier` are not transcribed at all — the
//! port calls minocrab's own `coin_commitment` and `kernel::claim_zswap_nullifier`, which are the
//! same gadgets. `dropMerkleIndex` is [`crate::shielded_custody::PooledCoin::downcast`], because it
//! is a method on the pooled-coin view that only that module has.
//!
//! Everything here is a **transcription**, not an invention. `sendShielded`, `sendUnshielded`,
//! `mergeCoinImmediate`, `receiveUnshielded`, `kernel.self()` and the three `claimZswap*` effects
//! all exist in `minocrab-std/src/v3/kernel.rs` and are used directly; what this module adds is the
//! handful of pieces the pinned Compact standard library defines as *recipes over* those
//! primitives.
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
//! ## `receiveShielded` is a recipe, not a primitive
//!
//! The pinned Compact standard library defines it as `right(kernel.self())` → `createZswapOutput`
//! (a Void witness native that emits nothing) → `kernel.claimZswapCoinReceive(coinCommitment(...))`.
//! [`receive_shielded`] is that transcription, and the artifact confirms the shape: one
//! `kernel.self()` context read, one `persistent_hash` under `midnight:zswap-cc[v1]`, one effects
//! claim, with nothing between them (`depositShielded.zkir:32-44`).

use minocrab::v3::Circuit3;
use minocrab::Public;
use minocrab_std::v3::{
    coin_commitment, kernel, CoinRecipient, ContractAddress, ShieldedCoinInfo3, ZswapCoinPublicKey,
    B32,
};

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

/// `evolveNonce(index, nonce)` — the pinned standard library's
/// `upgradeFromTransient(transientHash<Vector<3, Field>>([domain, index, degradeToTransient(nonce)]))`.
///
/// **A WORKAROUND item (Phase-2 survey §3.1b): `evolveNonce` is v2-only in minocrab.** The v3
/// module has `derived_nonce`, but that is the private TWO-element form `sendShielded` and
/// `mergeCoin` write inline (`domain ‖ degrade(nonce)`), not the stdlib circuit's three-element form
/// with an index. Transcribed here from minocrab's own v2 body (`minocrab-std/src/coin.rs:172-177`),
/// which is itself compactc's lowering, over the v3 `hash` helpers.
pub fn evolve_nonce(c: &mut Circuit3, index: u64, nonce: &B32<Public>) -> B32<Public> {
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
