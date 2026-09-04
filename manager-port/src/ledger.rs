//! `manager.compact`'s `export ledger` block, as types.
//!
//! **No single Compact twin.** In the split contract the ledger block does not exist as one
//! declaration: `AccountRegistry`, `ShieldedCustody` and `UnshieldedCustody` each declare the
//! fields they own and the preset declares `deploymentDomain`, and the compiler concatenates them.
//! This file is that concatenation, which is what minocrab needs and what the emitted `idx`
//! immediates encode. The table below says which Compact file declares each field.
//!
//! **Declaration order IS the field index**, so this block must mirror the split contract's
//! effective ledger order line for line — a reordering silently retargets every ledger operation
//! in every ported circuit at the wrong slot. The compactc artifact encodes the index as an `idx`
//! immediate (`isRegistered.zkir` reads `["0x50","0x01","0x01","0x00"]` — field **0**,
//! `accounts`), which is what the differential checks.
//!
//! Since the product's module split (product `main` @ `41de69d`, PR #12) the order is no longer
//! one file's declaration order. An imported Compact module contributes its ledger fields as ONE
//! CONTIGUOUS BLOCK, **before** the importer's own, whatever the import's textual position, so the
//! effective order is the module graph's:
//!
//! ```text
//! contracts/modules/AccountRegistry.compact    accounts, accountModes, evmOwners, evmNonces
//! contracts/modules/ShieldedCustody.compact    pools, shieldedBalances
//! contracts/modules/UnshieldedCustody.compact  unshieldedBalances
//! contracts/manager.compact (the preset)       deploymentDomain
//! ```
//!
//! `Custody.compact` imports the two family modules — shielded first — and declares no ledger of
//! its own, which is why `pools, shieldedBalances` precede `unshieldedBalances`.
//!
//! | idx | Compact | declared in | here |
//! |---:|---|---|---|
//! | 0 | `accounts: Set<Bytes<32>>` | `contracts/modules/AccountRegistry.compact:71` | [`Manager::accounts`] |
//! | 1 | `accountModes: Map<Bytes<32>, Uint<8>>` | `contracts/modules/AccountRegistry.compact:75` | [`Manager::account_modes`] |
//! | 2 | `evmOwners: Map<Bytes<32>, Bytes<20>>` | `contracts/modules/AccountRegistry.compact:76` | [`Manager::evm_owners`] |
//! | 3 | `evmNonces: Map<Bytes<32>, Uint<64>>` | `contracts/modules/AccountRegistry.compact:77` | [`Manager::evm_nonces`] |
//! | 4 | `pools: Map<Bytes<32>, QualifiedShieldedCoinInfo>` | `contracts/modules/ShieldedCustody.compact:78` | [`Manager::pools`] |
//! | 5 | `shieldedBalances: Map<Bytes<32>, Uint<128>>` | `contracts/modules/ShieldedCustody.compact:83` | [`Manager::shielded_balances`] |
//! | 6 | `unshieldedBalances: Map<Bytes<32>, Uint<128>>` | `contracts/modules/UnshieldedCustody.compact:55` | [`Manager::unshielded_balances`] |
//! | 7 | `deploymentDomain: Bytes<32>` | `contracts/manager.compact:264` | [`Manager::deployment_domain`] |
//!
//! **BREAKING against the port's pre-`41de69d` artifacts.** The field *names* did not change, so
//! every off-chain read handle still resolves; the *indices* did. `accounts` 1 → 0, `accountModes`
//! 4 → 1, `evmOwners` 5 → 2, `evmNonces` 6 → 3, `pools` 0 → 4, `shieldedBalances` 2 → 5,
//! `unshieldedBalances` 3 → 6; only `deploymentDomain` (7) stayed. Every emitted `.zkir` therefore
//! changes in its `idx` immediates, and both `execute` keys change with it. The pre-split order
//! was `pools, accounts, shieldedBalances, unshieldedBalances, accountModes, evmOwners, evmNonces,
//! deploymentDomain`; see the README § "Contract pin history".

use minocrab::Public;
use minocrab_std::v3::{
    Bytes, Ledger, LedgerCell, LedgerMap, LedgerSet, QualifiedShieldedCoinInfo3, Uint, B32,
};

/// THE LEDGER BLOCK — declaration order is the field index (see the module docs).
#[derive(Ledger)]
pub struct Manager {
    pub accounts: LedgerSet<B32<Public>>,
    pub account_modes: LedgerMap<B32<Public>, Uint<8, Public>>,
    pub evm_owners: LedgerMap<B32<Public>, Bytes<20, Public>>,
    pub evm_nonces: LedgerMap<B32<Public>, Uint<64, Public>>,
    pub pools: LedgerMap<B32<Public>, QualifiedShieldedCoinInfo3<Public>>,
    pub shielded_balances: LedgerMap<B32<Public>, Uint<128, Public>>,
    pub unshielded_balances: LedgerMap<B32<Public>, Uint<128, Public>>,
    pub deployment_domain: LedgerCell<B32<Public>>,
}

/// The contract's ledger block.
pub const MANAGER: Manager = Manager::new();

/// The ledger field indices, **derived from [`MANAGER`]**, never re-listed.
///
/// `#[derive(Ledger)]` hands each slot its declaration-order path, and every slot type exposes
/// that path back as a `const fn index()`. So these constants are the same numbers the emitted
/// `idx` immediates carry, read out of the one place they are decided — the struct above.
///
/// This exists because the `41de69d` re-target had to move seven of the eight indices, and the
/// harnesses that build VM transcripts and pre-state arrays (`tests/differential.rs`,
/// `tests/support/replay.rs`) had them written out as literals and prose. Deriving them means the
/// next reorder is ONE edit — the struct — and a stale literal cannot survive it.
pub mod slot {
    use super::MANAGER;

    pub const ACCOUNTS: u8 = MANAGER.accounts.index();
    pub const ACCOUNT_MODES: u8 = MANAGER.account_modes.index();
    pub const EVM_OWNERS: u8 = MANAGER.evm_owners.index();
    pub const EVM_NONCES: u8 = MANAGER.evm_nonces.index();
    pub const POOLS: u8 = MANAGER.pools.index();
    pub const SHIELDED_BALANCES: u8 = MANAGER.shielded_balances.index();
    pub const UNSHIELDED_BALANCES: u8 = MANAGER.unshielded_balances.index();
    pub const DEPLOYMENT_DOMAIN: u8 = MANAGER.deployment_domain.index();

    /// The Compact field names in ledger order — `ORDER[i]` is the field at index `i`.
    ///
    /// Written out (the field *names* are not recoverable from the handles), but pinned to the
    /// derived indices by `slot::the_names_are_in_ledger_order`, so it cannot drift from the struct.
    pub const ORDER: [&str; 8] = [
        "accounts",
        "accountModes",
        "evmOwners",
        "evmNonces",
        "pools",
        "shieldedBalances",
        "unshieldedBalances",
        "deploymentDomain",
    ];

    /// Every index, in order — the shape a harness that builds the whole state array needs.
    pub const ALL: [u8; 8] = [
        ACCOUNTS,
        ACCOUNT_MODES,
        EVM_OWNERS,
        EVM_NONCES,
        POOLS,
        SHIELDED_BALANCES,
        UNSHIELDED_BALANCES,
        DEPLOYMENT_DOMAIN,
    ];

    /// The derived indices are `0..8` in the order [`ORDER`] names them.
    ///
    /// This is the guard on the whole scheme: it fails if the struct is reordered without
    /// `ORDER`, if two fields collide on a slot, or if a field is dropped.
    #[test]
    fn the_names_are_in_ledger_order() {
        assert_eq!(
            ALL.to_vec(),
            (0u8..8).collect::<Vec<_>>(),
            "the derived ledger indices are not 0..8 in the order `ORDER` lists: {ALL:?}"
        );
        assert_eq!(ORDER.len(), ALL.len());
    }

    /// The post-split order, spelled out once as a fact about the *contract* rather than about
    /// this crate — so a reorder that was not intended fails here with the reason attached.
    #[test]
    fn the_order_is_the_split_contract_s() {
        assert_eq!(
            ORDER,
            [
                "accounts",
                "accountModes",
                "evmOwners",
                "evmNonces",
                "pools",
                "shieldedBalances",
                "unshieldedBalances",
                "deploymentDomain",
            ],
            "this is the ledger order of contracts/manager.compact @ 41de69d (AccountRegistry, \
             then ShieldedCustody, then UnshieldedCustody, then the preset's own). Changing it \
             re-targets every ledger op in every circuit and is BREAKING for deployed state."
        );
    }
}
