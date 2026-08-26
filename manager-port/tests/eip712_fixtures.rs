//! # Phase 3.2 gate — the EIP-712 chain against the FROZEN fixtures
//!
//! `evmDomainSeparatorFor`, `evmStructHashFor` and `evmDigestFor` are **pure** circuits: compactc
//! emits no proving key for them, so there is no ZKIR to run the Phase-2 differential against.
//! Their correctness bar is different and stricter — the bytes are what a MetaMask signature
//! commits to, so they must be **byte-identical** to the deployed codec.
//!
//! The reference is 00010's keyless suite fixture set,
//! `fixtures/eip712/v1.json` (`AUTH-EIP712-AA-V3-V1/FIXTURES-1`), generated against
//! `@metamask/eth-sig-util` 8.2.0 and cross-checked by that project against the compiled compactc
//! artifact. Every case carries `manual.domainSeparator`, `manual.structHash` and `manual.digest`.
//!
//! This suite evaluates the **ported circuits themselves** — built, then run on
//! `minocrab-sim`'s native simulator — and compares all three intermediate values per case.
//! It therefore also settles the one design decision in `src/eip712.rs`: that hashing the
//! preimage as a sequence of 32-byte FAB atoms yields the same octet string, and so the same
//! digest, as compactc's single wide `Bytes<N>` atom. If that were wrong, every digest would
//! differ and this suite would be red on case one.

use std::borrow::Cow;

use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use minocrab::v3::{Circuit3, Compiled3};
use minocrab::{Fr, Public};
use minocrab_sim::v3::simulate;
use minocrab_std::v3::{Bytes, Uint, B32};
use minocrab_zkir::v3::IrValue;

use manager_port::eip712::*;
use manager_port::payload::ExecutePayload;
use manager_port::words::b32_const;

// ---- fixture loading ---------------------------------------------------------------------------

fn fixtures() -> serde_json::Value {
    // Vendored at `fixtures/eip712/v1.json` (see the file's provenance note in the README):
    // it is test-vector JSON, not a compiled artifact, and the suite is worthless without it.
    let path = std::env::var("AA_EIP712_FIXTURES").unwrap_or_else(|_| {
        format!(
            "{}/../fixtures/eip712/v1.json",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading the frozen fixture set at {path}: {e}"));
    serde_json::from_str(&text).expect("the fixture set parses")
}

fn hex_bytes<const N: usize>(s: &str) -> [u8; N] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert_eq!(s.len(), 2 * N, "expected {N} bytes, got {:?}", s.len() / 2);
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

fn dec_u64(s: &str) -> u64 {
    s.parse().unwrap_or_else(|e| panic!("u64 {s:?}: {e}"))
}

fn dec_u128(s: &str) -> u128 {
    s.parse().unwrap_or_else(|e| panic!("u128 {s:?}: {e}"))
}

fn selector_of(primary_type: &str) -> u8 {
    match primary_type {
        "RegisterEvmAccount" => 1,
        "WithdrawShielded" => 2,
        "WithdrawUnshielded" => 3,
        "TransferInternalShielded" => 4,
        "TransferInternalUnshielded" => 5,
        "OpenSwapShielded" => 6,
        other => panic!("unknown primaryType {other}"),
    }
}

/// Field of the fixture's `action`, or a default when the action shape omits it. The Compact
/// payload is a single muxed struct, so fields the selected action does not use are zero — which
/// is exactly how the deployed harness fills them.
fn s<'a>(action: &'a serde_json::Value, key: &str, dflt: &'a str) -> &'a str {
    action.get(key).and_then(|v| v.as_str()).unwrap_or(dflt)
}

/// A `Uint<128>` constant. `Uint::constant` only takes a `u64`, and the fixture set deliberately
/// includes max-width amounts, so the 16 LE bytes go in directly. The bound holds by construction
/// (a `u128` is below `2^128`), which is what `from_field_unchecked` is claiming.
fn uint128_const(c: &mut Circuit3, v: u128) -> Uint<128, Public> {
    Uint::from_field_unchecked(c.constant(Fr::from_le_bytes(&v.to_le_bytes()).expect("16 bytes fit")))
}

const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

// ---- building the payload as circuit constants -------------------------------------------------

/// `ExecutePayload<Public>` built entirely from constants, so the circuit has no arguments and can
/// be simulated on an empty preimage. The mapping from the fixture's per-action field names to the
/// muxed payload is the deployed harness's own (`harness/src/auth/codec.ts`).
fn payload_consts(c: &mut Circuit3, action: &serde_json::Value) -> ExecutePayload<Public> {
    let primary = action["primaryType"].as_str().expect("primaryType");
    let selector = selector_of(primary);
    let is_swap = selector == 6;

    // `color` on withdraw/transfer, `giveColor` on the swap.
    let primary_color = if is_swap { s(action, "giveColor", ZERO32) } else { s(action, "color", ZERO32) };
    let primary_amount = if is_swap { s(action, "giveAmount", "0") } else { s(action, "amount", "0") };

    ExecutePayload {
        selector: Uint::<8, Public>::constant(c, u64::from(selector)),
        // `authMode` is not part of any EIP-712 struct; it never enters a hash preimage.
        auth_mode: Uint::<8, Public>::constant(c, 1),
        account: b32_const(c, &hex_bytes::<32>(s(action, "accountId", ZERO32))),
        owner: Bytes::<20, Public>::constant(c, &hex_bytes::<20>(s(action, "owner", "0x0000000000000000000000000000000000000000"))),
        account_salt: b32_const(c, &hex_bytes::<32>(s(action, "accountSalt", ZERO32))),
        nonce: Uint::<64, Public>::constant(c, dec_u64(s(action, "nonce", "0"))),
        valid_until: Uint::<64, Public>::constant(c, dec_u64(s(action, "validUntil", "0"))),
        primary_color: b32_const(c, &hex_bytes::<32>(primary_color)),
        primary_amount: uint128_const(c, dec_u128(primary_amount)),
        recipient_kind: Uint::<8, Public>::constant(c, dec_u64(s(action, "recipientKind", "0"))),
        recipient: b32_const(c, &hex_bytes::<32>(s(action, "recipient", ZERO32))),
        to_account: b32_const(c, &hex_bytes::<32>(s(action, "toAccountId", ZERO32))),
        want_nonce: b32_const(c, &hex_bytes::<32>(s(action, "wantNonce", ZERO32))),
        want_color: b32_const(c, &hex_bytes::<32>(s(action, "wantColor", ZERO32))),
        want_amount: uint128_const(c, dec_u128(s(action, "wantAmount", "0"))),
        credit_account: b32_const(c, &hex_bytes::<32>(s(action, "creditAccountId", ZERO32))),
    }
}

/// `evmStructHashFor`'s selector dispatch, with the type hash chosen off-circuit because the
/// selector is a constant in this harness. (The in-circuit mux is `custodyDispatch`'s job and is
/// exercised by Phase 3.4, not here — here the point is the byte recipe per action.)
fn struct_hash_for(c: &mut Circuit3, manager: &B32<Public>, p: &ExecutePayload<Public>, selector: u8) -> B32<Public> {
    let pre = match selector {
        1 => struct_hash_preimage_register(c, manager, p),
        2 | 3 => {
            let t = b32_const(c, if selector == 2 { &WITHDRAW_SHIELDED_TYPE } else { &WITHDRAW_UNSHIELDED_TYPE });
            struct_hash_preimage_withdraw(c, &t, manager, p)
        }
        4 | 5 => {
            let t = b32_const(c, if selector == 4 { &TRANSFER_SHIELDED_TYPE } else { &TRANSFER_UNSHIELDED_TYPE });
            struct_hash_preimage_transfer(c, &t, manager, p)
        }
        6 => struct_hash_preimage_open_swap(c, manager, p),
        other => panic!("selector {other} has no EIP-712 struct"),
    };
    hash_struct_preimage(c, pre)
}

/// Build a no-argument circuit that outputs `[domainSeparator, structHash, digest]` as typed
/// `Bytes<32>` values.
fn chain_circuit(deployment_domain: [u8; 32], action: serde_json::Value) -> Compiled3 {
    let mut c = Circuit3::new();
    let selector = selector_of(action["primaryType"].as_str().unwrap());
    let manager = b32_const(&mut c, &hex_bytes::<32>(action["manager"].as_str().expect("manager")));
    let domain = b32_const(&mut c, &deployment_domain);
    let p = payload_consts(&mut c, &action);

    let ds = evm_domain_separator_for(&mut c, &manager, &domain);
    let sh = struct_hash_for(&mut c, &manager, &p, selector);
    let dg = eip712_digest(&mut c, &ds, &sh);

    for (b, label) in [(ds, "domainSeparator"), (sh, "structHash"), (dg, "digest")] {
        let typed = b.to_typed(&mut c);
        c.output(typed, label);
    }
    // No cross-contract communications commitment: this is a measurement rig, not an entry point.
    c.finish(false)
}

/// An empty preimage — the circuit is all constants, so it consumes nothing.
fn empty_preimage() -> ProofPreimage {
    ProofPreimage {
        inputs: vec![],
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed("manager-port-00012-eip712")),
    }
}

fn out_bytes(v: &IrValue) -> [u8; 32] {
    match v {
        IrValue::Bytes32(b) => *b,
        other => panic!("expected a Bytes32 output, got {other:?}"),
    }
}

fn hex(b: &[u8; 32]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Run one fixture case through the ported chain and compare all three frozen values.
fn check_case(case: &serde_json::Value, failures: &mut Vec<String>, checked: &mut usize) {
    let id = case["id"].as_str().unwrap_or("<no id>").to_string();
    let domain = hex_bytes::<32>(case["deploymentDomain"].as_str().expect("deploymentDomain"));
    let compiled = chain_circuit(domain, case["action"].clone());
    let run = simulate(&compiled.ir, &empty_preimage())
        .unwrap_or_else(|e| panic!("{id}: the ported EIP-712 chain did not run: {e:?}"));
    assert_eq!(run.outputs.len(), 3, "{id}: expected three outputs");

    let manual = &case["manual"];
    for (i, field) in ["domainSeparator", "structHash", "digest"].iter().enumerate() {
        *checked += 1;
        let got = out_bytes(&run.outputs[i]);
        let want = hex_bytes::<32>(manual[field].as_str().unwrap_or_else(|| panic!("{id}: manual.{field}")));
        if got != want {
            failures.push(format!("{id}/{field}: port {} != frozen {}", hex(&got), hex(&want)));
        }
    }
}

// ---- the gate ----------------------------------------------------------------------------------

#[test]
fn eip712_chain_matches_the_frozen_fixtures() {
    let f = fixtures();
    assert_eq!(
        f["fixtureVersion"].as_str(),
        Some("AUTH-EIP712-AA-V3-V1/FIXTURES-1"),
        "the fixture set moved; the frozen bytes must be re-confirmed before trusting this gate"
    );

    let mut failures = Vec::new();
    let mut checked = 0usize;
    let mut cases = 0usize;

    for group in ["boundaryCases", "randomCases"] {
        for case in f[group].as_array().unwrap_or_else(|| panic!("{group} is an array")) {
            cases += 1;
            check_case(case, &mut failures, &mut checked);
        }
    }
    // The KAT is a case in the same shape.
    cases += 1;
    check_case(&f["kat"], &mut failures, &mut checked);

    println!("EIP-712 frozen-fixture gate: {cases} cases, {checked} byte comparisons");
    assert!(
        failures.is_empty(),
        "{} of {checked} frozen values differ:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Every action type must be represented, or a green run would prove less than it appears to.
#[test]
fn the_fixture_set_covers_all_six_action_types() {
    let f = fixtures();
    let mut seen = std::collections::BTreeSet::new();
    for group in ["boundaryCases", "randomCases"] {
        for case in f[group].as_array().unwrap() {
            seen.insert(case["action"]["primaryType"].as_str().unwrap().to_string());
        }
    }
    let want: std::collections::BTreeSet<String> = [
        "OpenSwapShielded",
        "RegisterEvmAccount",
        "TransferInternalShielded",
        "TransferInternalUnshielded",
        "WithdrawShielded",
        "WithdrawUnshielded",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(seen, want, "the fixture set no longer covers all six action types");
}
