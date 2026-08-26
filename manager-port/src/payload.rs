//! `ExecutePayload` — `execute`'s argument struct (`manager.compact:230-247`).
//!
//! **Field order is the FAB slot order**, and the compactc artifact pins it: `execute.zkir`
//! declares `%payload.0` … `%payload.23`, and these sixteen fields flatten to exactly 24 slots
//! (`Uint<n>` and `Bytes<20>` one each, `Bytes<32>` two each). Reordering, or getting a width
//! wrong, changes the public schema — which the differential's schema-identity clause catches.
//!
//! ```text
//!  slots  field                          Compact type
//!  1      selector                       Uint<8>
//!  1      authMode                       Uint<8>
//!  2      account                        Bytes<32>
//!  1      owner                          Bytes<20>
//!  2      accountSalt                    Bytes<32>
//!  1      nonce                          Uint<64>
//!  1      validUntil                     Uint<64>
//!  2      primaryColor                   Bytes<32>
//!  1      primaryAmount                  Uint<128>
//!  1      recipientKind                  Uint<8>
//!  2      recipient                      Bytes<32>
//!  2      toAccount                      Bytes<32>
//!  2      wantNonce                      Bytes<32>
//!  2      wantColor                      Bytes<32>
//!  1      wantAmount                     Uint<128>
//!  2      creditAccount                  Bytes<32>
//! ---- 24 slots, matching %payload.0..23
//! ```
//!
//! The argument types are the range constraints — a `Uint<64>` field *is* `assert_bits(w, 64)` —
//! so this declaration reproduces compactc's 27 `constrain_bits` instructions without any of them
//! being written by hand.

use minocrab_std::v3::{Bytes, CircuitArg, Uint, B32};

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
