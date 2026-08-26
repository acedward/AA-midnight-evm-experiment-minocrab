//! `manager.compact`'s `export ledger` block, as types.
//!
//! **Declaration order IS the field index**, so this block must mirror
//! `contracts/manager.compact:262-278` line for line — a reordering silently retargets every
//! ledger operation in every ported circuit at the wrong slot. The compactc artifact encodes the
//! index as an `idx` immediate (`isRegistered.zkir` reads `["0x50","0x01","0x01","0x01"]` — field
//! **1**, `accounts`), which is what the differential checks.
//!
//! | idx | Compact | here |
//! |---:|---|---|
//! | 0 | `pools: Map<Bytes<32>, QualifiedShieldedCoinInfo>` | [`Manager::pools`] |
//! | 1 | `accounts: Set<Bytes<32>>` | [`Manager::accounts`] |
//! | 2 | `shieldedBalances: Map<Bytes<32>, Uint<128>>` | [`Manager::shielded_balances`] |
//! | 3 | `unshieldedBalances: Map<Bytes<32>, Uint<128>>` | [`Manager::unshielded_balances`] |
//! | 4 | `accountModes: Map<Bytes<32>, Uint<8>>` | [`Manager::account_modes`] |
//! | 5 | `evmOwners: Map<Bytes<32>, Bytes<20>>` | [`Manager::evm_owners`] |
//! | 6 | `evmNonces: Map<Bytes<32>, Uint<64>>` | [`Manager::evm_nonces`] |
//! | 7 | `deploymentDomain: Bytes<32>` | [`Manager::deployment_domain`] |

use minocrab::Public;
use minocrab_std::v3::{
    Bytes, Ledger, LedgerCell, LedgerMap, LedgerSet, QualifiedShieldedCoinInfo3, Uint, B32,
};

/// THE LEDGER BLOCK — declaration order is the field index (see the module docs).
#[derive(Ledger)]
pub struct Manager {
    pub pools: LedgerMap<B32<Public>, QualifiedShieldedCoinInfo3<Public>>,
    pub accounts: LedgerSet<B32<Public>>,
    pub shielded_balances: LedgerMap<B32<Public>, Uint<128, Public>>,
    pub unshielded_balances: LedgerMap<B32<Public>, Uint<128, Public>>,
    pub account_modes: LedgerMap<B32<Public>, Uint<8, Public>>,
    pub evm_owners: LedgerMap<B32<Public>, Bytes<20, Public>>,
    pub evm_nonces: LedgerMap<B32<Public>, Uint<64, Public>>,
    pub deployment_domain: LedgerCell<B32<Public>>,
}

/// The contract's ledger block.
pub const MANAGER: Manager = Manager::new();
