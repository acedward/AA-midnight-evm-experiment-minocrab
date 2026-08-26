//! # The Q3-bar-A equivalence gate for the seven Phase-4 circuits
//!
//! `depositShielded`, `depositUnshielded`, `shieldedAccountBalance`, `unshieldedAccountBalance`,
//! `accountRecord`, `poolValue` and `poolHasColour` — the rest of the contract's nine-ZKIR provable
//! surface, against **our own** Phase-1 compactc artifacts.
//!
//! The bar is the owner's Q3 resolution, option A, unchanged from Phases 2 and 3:
//!
//! 1. **Typed schema identity** — same input types in the same order, same output types, same
//!    communications-commitment flag.
//! 2. **PI-vector identity on a shared `ProofPreimage`** — both artifacts simulated on the SAME
//!    preimage must produce the same public-input vector and the same `pi_skips`, and upstream's
//!    own `check()` must agree with the simulation on both sides.
//! 3. **Accept/reject agreement, including tampered inputs** — every single-element mutation of
//!    the preimage is judged the same way by both artifacts.
//!
//! Bar B (reference-VM replay) is `execute`-only per the owner's resolution and is not run here.
//!
//! ## How a scenario is built, and why it is not circular
//!
//! Exactly as in Phase 3. The scenario supplies the hand-written half — the circuit `inputs`, the
//! ledger's answers (`public_transcript_outputs`) and the circuit's declared outputs (which the
//! communications commitment covers, so a wrong one is REJECTED before the port is ever run) — and
//! [`support::synth::synthesize`] then derives `public_transcript_inputs` from the **compactc
//! artifact** by fixpoint. The preimage is therefore "the transcript compactc produces for this
//! scenario", built without consulting the port; the port is then run on it and must agree element
//! for element.
//!
//! `pi_skips` equality is the clause that does the work: one entry per `Impact` instruction,
//! carrying whether that op's guard was on and how many elements it contributed. Two artifacts can
//! only agree on it if they emit the same ledger operations, in the same order, with the same
//! input counts and the same guard truth values.
//!
//! ## Running it
//!
//! ```text
//! COMPACTC_IMAGE=<your-compactc-0.33.0-image> scripts/compile-baseline.sh baseline \
//!     <checkout>/contracts/manager.compact $(scripts/free-port.sh)
//! cargo +1.95.0 test --release -p manager-port --features compactc-baseline
//! ```

mod support;

use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;
use std::borrow::Cow;
use support::model::b32_slots;
use support::synth::synthesize;

// ---- the two sides ------------------------------------------------------------------------------

/// OUR Phase-1 compactc artifact for `name` (not minocrab's corpus).
fn theirs(name: &str) -> IrSource {
    // The compactc baseline is a COMPILED artifact and is deliberately absent from this repo.
    // Produce it with your own compactc 0.33.0 image (`scripts/compile-baseline.sh`), or point
    // `AA_BASELINE_ZKIR_DIR` at a directory of `<circuit>.zkir` files. Expected hashes for the
    // port's own side are in the README.
    let dir = std::env::var("AA_BASELINE_ZKIR_DIR").unwrap_or_else(|_| {
        format!(
            "{}/../generated/baseline/manager/zkir",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let path = format!("{dir}/{name}.zkir");
    minocrab_zkir::v3::read_zkir(&path).unwrap_or_else(|e| {
        panic!(
            "the compactc baseline artifact for `{name}` is missing or unparseable ({e:?}).\n\
             Produce it with a compactc 0.33.0 image — see the README section \
             `Running the differential suite`:\n  \
             COMPACTC_IMAGE=<your-image> scripts/compile-baseline.sh baseline \
             <checkout>/contracts/manager.compact $(scripts/free-port.sh)\n\
             or set AA_BASELINE_ZKIR_DIR to a directory holding `<circuit>.zkir`.\n\
             looked for: {path}"
        )
    })
}

/// The ported circuit of the same name, from the crate's own registry — so a circuit that is not
/// wired into `manager_port::circuits()` cannot be gated (and therefore cannot be measured).
fn ours(name: &str) -> IrSource {
    let build = manager_port::circuits()
        .into_iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("`{name}` is not registered in manager_port::circuits()"))
        .1;
    build().ir
}

// ---- the bar ------------------------------------------------------------------------------------

fn assert_schema_identity(ours: &IrSource, theirs: &IrSource, what: &str) {
    let types = |ir: &IrSource| {
        serde_json::to_value(&ir.inputs)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|ti| ti["type"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(types(ours), types(theirs), "{what}: input schemas differ");
    assert_eq!(ours.outputs, theirs.outputs, "{what}: output schemas differ");
    assert_eq!(
        ours.do_communications_commitment, theirs.do_communications_commitment,
        "{what}: communications-commitment flag differs"
    );
}

/// Clause 2: PI-vector identity on a shared preimage.
fn assert_pi_identity(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage, what: &str) {
    let their_run = simulate(theirs, pi).unwrap_or_else(|e| {
        panic!("{what}: the compactc artifact rejected the synthesized preimage: {e}")
    });
    let our_run = simulate(ours, pi).unwrap_or_else(|e| {
        panic!(
            "{what}: THE PORT REJECTED a preimage the compactc artifact accepts.\n  {e}\n\
             This is a GATE FAILURE and a reportable finding (FR-004), not a harness problem."
        )
    });

    assert_eq!(
        our_run.pi_skips.len(),
        their_run.pi_skips.len(),
        "{what}: different numbers of Impact instructions ({} vs {})",
        our_run.pi_skips.len(),
        their_run.pi_skips.len()
    );
    for (i, (a, b)) in our_run
        .pi_skips
        .iter()
        .zip(their_run.pi_skips.iter())
        .enumerate()
    {
        assert_eq!(
            a, b,
            "{what}: pi_skips differ at Impact {i}: port {a:?} vs compactc {b:?}"
        );
    }
    assert_eq!(
        our_run.pis.len(),
        their_run.pis.len(),
        "{what}: PI vector lengths differ"
    );
    for (i, (a, b)) in our_run.pis.iter().zip(their_run.pis.iter()).enumerate() {
        assert_eq!(a, b, "{what}: PI vectors differ at element {i}");
    }
    assert_eq!(
        our_run.outputs, their_run.outputs,
        "{what}: circuit outputs differ"
    );

    // Upstream's own checker must agree with the simulation, on both sides.
    assert_eq!(
        ours.check(pi).expect("upstream accepts the port"),
        our_run.pi_skips,
        "{what}: upstream check() disagrees with the simulation on the port"
    );
    assert_eq!(
        theirs.check(pi).expect("upstream accepts the compactc artifact"),
        their_run.pi_skips,
        "{what}: upstream check() disagrees with the simulation on the compactc artifact"
    );
}

/// Clause 3: every single-element mutation of the preimage must be judged the same way by both
/// artifacts. Zero acceptance disagreements is the assertion.
fn assert_tamper_agreement(
    ours: &IrSource,
    theirs: &IrSource,
    base: &ProofPreimage,
    what: &str,
) -> usize {
    let mut checked = 0usize;
    let mut disagreements = Vec::new();

    let mut probe = |pi: ProofPreimage, label: String, checked: &mut usize| {
        *checked += 1;
        let ours_ok = simulate(ours, &pi).is_ok();
        let theirs_ok = simulate(theirs, &pi).is_ok();
        if ours_ok != theirs_ok {
            disagreements.push(format!("{label}: port={ours_ok} compactc={theirs_ok}"));
        }
    };

    let bump = |v: &mut Vec<Fr>, i: usize| v[i] = v[i] + Fr::from(1u64);
    for i in 0..base.inputs.len() {
        let mut pi = base.clone();
        bump(&mut pi.inputs, i);
        probe(pi, format!("inputs[{i}]"), &mut checked);
    }
    for i in 0..base.public_transcript_inputs.len() {
        let mut pi = base.clone();
        bump(&mut pi.public_transcript_inputs, i);
        probe(pi, format!("public_transcript_inputs[{i}]"), &mut checked);
    }
    for i in 0..base.public_transcript_outputs.len() {
        let mut pi = base.clone();
        bump(&mut pi.public_transcript_outputs, i);
        probe(pi, format!("public_transcript_outputs[{i}]"), &mut checked);
    }
    for i in 0..base.private_transcript.len() {
        let mut pi = base.clone();
        bump(&mut pi.private_transcript, i);
        probe(pi, format!("private_transcript[{i}]"), &mut checked);
    }

    assert!(checked > 0, "{what}: the tamper sweep probed nothing");
    assert!(
        disagreements.is_empty(),
        "{what}: {} of {checked} tampered preimages were judged differently:\n  {}",
        disagreements.len(),
        disagreements.join("\n  ")
    );
    checked
}

// ---- scenarios ----------------------------------------------------------------------------------

/// One call of one circuit: the hand-written half of a preimage.
struct Case {
    /// The compactc circuit name — also the ZKIR file stem on both sides.
    circuit: &'static str,
    name: &'static str,
    /// The circuit's argument slots, in declaration order.
    inputs: Vec<Fr>,
    /// The values the ledger hands back, in the order the circuit's `public_input` gates consume
    /// them. A guarded-off gate consumes NOTHING, so this is one selector path's reads, not all
    /// the gates in the artifact.
    reads: Vec<Fr>,
    /// The circuit's declared outputs. Covered by the communications commitment, so a wrong one is
    /// rejected by the reference before the port is ever run.
    outputs: Vec<Fr>,
}

impl Case {
    fn preimage(&self) -> ProofPreimage {
        let rand = Fr::from(0xb0_u64);
        let mut comm_vals = self.inputs.clone();
        comm_vals.extend_from_slice(&self.outputs);
        let comm = transient_commit(&comm_vals[..], rand);
        ProofPreimage {
            inputs: self.inputs.clone(),
            private_transcript: vec![],
            public_transcript_inputs: vec![],
            public_transcript_outputs: self.reads.clone(),
            binding_input: 0.into(),
            communications_commitment: Some((comm, rand)),
            key_location: KeyLocation(Cow::Borrowed("manager-port-00012-phase4")),
        }
    }
}

/// The whole bar for one case.
fn gate(case: &Case) {
    let ours = ours(case.circuit);
    let theirs = theirs(case.circuit);
    assert_schema_identity(&ours, &theirs, case.name);

    let pi = synthesize(&theirs, &case.preimage()).unwrap_or_else(|e| panic!("{}: {e}", case.name));
    assert_pi_identity(&ours, &theirs, &pi, case.name);
    let probes = assert_tamper_agreement(&ours, &theirs, &pi, case.name);

    let run = simulate(&theirs, &pi).unwrap();
    println!(
        "GATE {} [{}]: {} Impact ops, {} PI elements, {} transcript inputs, {} ledger answers, \
         {} outputs, {probes} tamper probes, 0 disagreements",
        case.name,
        case.circuit,
        run.pi_skips.len(),
        run.pis.len(),
        pi.public_transcript_inputs.len(),
        pi.public_transcript_outputs.len(),
        case.outputs.len(),
    );
}

// ---- fixtures -----------------------------------------------------------------------------------

fn u128_fr(v: u128) -> Fr {
    Fr::from_le_bytes(&v.to_le_bytes()).expect("16 bytes fit")
}

fn b32(tag: &[u8], last: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..tag.len()].copy_from_slice(tag);
    out[31] = last;
    out
}

fn an_account() -> [u8; 32] {
    b32(b"acct-0012", 0x2a)
}

fn a_colour() -> [u8; 32] {
    b32(b"colour-0012", 0x07)
}

/// The contract's own address, which every `kernel.self()` read answers with.
fn self_addr() -> [u8; 32] {
    b32(b"aa00012-self", 0x11)
}

fn an_owner() -> [u8; 20] {
    let mut o = [0u8; 20];
    o[..8].copy_from_slice(b"evm-0012");
    o[19] = 0x5c;
    o
}

/// Push a `Bytes<32>`'s two slots, `hi` then `lo` — the FAB field repr of a 32-byte atom.
fn push_b32(v: &mut Vec<Fr>, bytes: &[u8; 32]) {
    let (hi, lo) = b32_slots(bytes);
    v.push(hi);
    v.push(lo);
}

fn one() -> Fr {
    Fr::from(1u64)
}

fn zero() -> Fr {
    Fr::from(0u64)
}

// ---- poolHasColour ------------------------------------------------------------------------------

fn pool_has_colour_case(present: bool, name: &'static str) -> Case {
    let mut inputs = Vec::new();
    push_b32(&mut inputs, &a_colour());
    let answer = Fr::from(u64::from(present));
    Case {
        circuit: "poolHasColour",
        name,
        inputs,
        reads: vec![answer],
        outputs: vec![answer],
    }
}

#[test]
fn pool_has_colour_present() {
    gate(&pool_has_colour_case(true, "poolHasColour — the pool exists"));
}

#[test]
fn pool_has_colour_absent() {
    gate(&pool_has_colour_case(
        false,
        "poolHasColour — a colour this Manager has never seen",
    ));
}

// ---- poolValue ----------------------------------------------------------------------------------

/// `pools.member(col) ? pools.lookup(col).value : 0`. The lookup reads a whole
/// `QualifiedShieldedCoinInfo` — six limbs — and only `.value` is selected.
fn pool_value_present() -> Case {
    let mut inputs = Vec::new();
    push_b32(&mut inputs, &a_colour());

    let nonce = b32(b"pool-nonce", 0x33);
    let value: u128 = 7_500;
    let mut reads = vec![one()];
    push_b32(&mut reads, &nonce);
    push_b32(&mut reads, &a_colour());
    reads.push(u128_fr(value));
    reads.push(Fr::from(12u64)); // mt_index

    Case {
        circuit: "poolValue",
        name: "poolValue — a pooled colour",
        inputs,
        reads,
        outputs: vec![u128_fr(value)],
    }
}

fn pool_value_absent() -> Case {
    let mut inputs = Vec::new();
    push_b32(&mut inputs, &a_colour());
    Case {
        circuit: "poolValue",
        name: "poolValue — missing pool reads 0",
        inputs,
        reads: vec![zero()],
        outputs: vec![zero()],
    }
}

#[test]
fn pool_value_pooled() {
    gate(&pool_value_present());
}

#[test]
fn pool_value_missing_reads_zero() {
    gate(&pool_value_absent());
}

// ---- shielded/unshieldedAccountBalance ----------------------------------------------------------

fn balance_case(circuit: &'static str, name: &'static str, held: Option<u128>) -> Case {
    let mut inputs = Vec::new();
    push_b32(&mut inputs, &an_account());
    push_b32(&mut inputs, &a_colour());

    let (reads, out) = match held {
        Some(v) => (vec![one(), u128_fr(v)], u128_fr(v)),
        None => (vec![zero()], zero()),
    };
    Case {
        circuit,
        name,
        inputs,
        reads,
        outputs: vec![out],
    }
}

#[test]
fn shielded_account_balance_held() {
    gate(&balance_case(
        "shieldedAccountBalance",
        "shieldedAccountBalance — a credited cell",
        Some(1_234_567),
    ));
}

#[test]
fn shielded_account_balance_missing_reads_zero() {
    gate(&balance_case(
        "shieldedAccountBalance",
        "shieldedAccountBalance — missing cell reads 0 (FR-206)",
        None,
    ));
}

#[test]
fn unshielded_account_balance_held() {
    gate(&balance_case(
        "unshieldedAccountBalance",
        "unshieldedAccountBalance — a credited cell",
        Some(42),
    ));
}

#[test]
fn unshielded_account_balance_missing_reads_zero() {
    gate(&balance_case(
        "unshieldedAccountBalance",
        "unshieldedAccountBalance — missing cell reads 0 (FR-206)",
        None,
    ));
}

/// The two families answer INDEPENDENTLY for a byte-identical `colour` — the P-COLL property the
/// contract's family tags exist for. Both artifacts derive the key in-circuit, so this is a
/// statement about the ported hash, not about the harness: a shared key would make one of these
/// two runs read the other's cell and the synthesized transcripts would coincide.
#[test]
fn the_two_families_use_different_keys() {
    let s = synthesize(
        &theirs("shieldedAccountBalance"),
        &balance_case("shieldedAccountBalance", "s", Some(1)).preimage(),
    )
    .expect("shielded scenario");
    let u = synthesize(
        &theirs("unshieldedAccountBalance"),
        &balance_case("unshieldedAccountBalance", "u", Some(1)).preimage(),
    )
    .expect("unshielded scenario");
    assert_ne!(
        s.public_transcript_inputs, u.public_transcript_inputs,
        "the two families hashed the same key for the same (account, colour)"
    );
}

// ---- accountRecord ------------------------------------------------------------------------------

fn account_record_unregistered() -> Case {
    let mut inputs = Vec::new();
    push_b32(&mut inputs, &an_account());
    Case {
        circuit: "accountRecord",
        name: "accountRecord — unknown account returns the all-zero inactive record",
        inputs,
        // Only `accounts.member` runs; every later gate is guarded off and consumes nothing.
        reads: vec![zero()],
        outputs: vec![zero(), zero(), zero(), zero()],
    }
}

fn account_record_native() -> Case {
    let mut inputs = Vec::new();
    push_b32(&mut inputs, &an_account());
    Case {
        circuit: "accountRecord",
        name: "accountRecord — a native record carries no EVM state",
        inputs,
        // accounts.member, accountModes.lookup, evmOwners.member, evmNonces.member.
        reads: vec![one(), zero(), zero(), zero()],
        outputs: vec![one(), zero(), zero(), zero()],
    }
}

fn account_record_evm() -> Case {
    let mut inputs = Vec::new();
    push_b32(&mut inputs, &an_account());
    let owner = an_owner();
    let nonce = 9u64;
    Case {
        circuit: "accountRecord",
        name: "accountRecord — a complete EVM record",
        inputs,
        // accounts.member, accountModes.lookup(=1), evmOwners.member, evmNonces.member,
        // evmOwners.lookup, evmNonces.lookup. The native arm's two reads are guarded off.
        reads: vec![
            one(),
            one(),
            one(),
            one(),
            Fr::from_le_bytes(&owner).expect("20 bytes fit"),
            Fr::from(nonce),
        ],
        outputs: vec![
            one(),
            one(),
            Fr::from_le_bytes(&owner).expect("20 bytes fit"),
            Fr::from(nonce),
        ],
    }
}

#[test]
fn account_record_unknown() {
    gate(&account_record_unregistered());
}

#[test]
fn account_record_native_mode() {
    gate(&account_record_native());
}

#[test]
fn account_record_evm_mode() {
    gate(&account_record_evm());
}

/// The two refusals `accountRecord` carries, checked as refusals on BOTH artifacts: a native
/// record that carries EVM state, and an EVM record missing its nonce entry. Neither has an
/// accepted run, so the bar-A form is "both artifacts refuse the same scenario at the same place".
#[test]
fn account_record_refusals_agree() {
    let refuse = |name: &'static str, reads: Vec<Fr>| {
        let mut inputs = Vec::new();
        push_b32(&mut inputs, &an_account());
        let case = Case {
            circuit: "accountRecord",
            name,
            inputs,
            reads,
            outputs: vec![zero(), zero(), zero(), zero()],
        };
        let (pi, err) = support::synth::synthesize_partial(&theirs("accountRecord"), &case.preimage());
        assert!(
            err.is_some(),
            "{name}: the compactc artifact ACCEPTED a run the contract's asserts forbid"
        );
        let ours_err = simulate(&ours("accountRecord"), &pi).err();
        assert!(
            ours_err.is_some(),
            "{name}: the port accepted a run the compactc artifact refuses"
        );
        println!("REFUSAL {name}: both artifacts refuse");
    };

    // mode 0 but `evmOwners` carries the account — "native record carries EVM state".
    refuse(
        "accountRecord — native record carrying EVM state",
        vec![one(), zero(), one()],
    );
    // mode 1, owner present, nonce entry missing — "EVM record is incomplete".
    refuse(
        "accountRecord — EVM record missing its nonce",
        vec![one(), one(), one(), zero()],
    );
}

// ---- depositUnshielded --------------------------------------------------------------------------

fn deposit_unshielded_case(name: &'static str, held: Option<u128>, amount: u128) -> Case {
    let mut inputs = Vec::new();
    push_b32(&mut inputs, &a_colour());
    inputs.push(u128_fr(amount));
    push_b32(&mut inputs, &an_account());

    // accounts.member, then unshieldedBalances.member and (where present) its lookup.
    let mut reads = vec![one()];
    match held {
        Some(v) => {
            reads.push(one());
            reads.push(u128_fr(v));
        }
        None => reads.push(zero()),
    }
    Case {
        circuit: "depositUnshielded",
        name,
        inputs,
        reads,
        outputs: vec![],
    }
}

#[test]
fn deposit_unshielded_first_credit() {
    gate(&deposit_unshielded_case(
        "depositUnshielded — first credit of this (account, colour)",
        None,
        1_000,
    ));
}

#[test]
fn deposit_unshielded_adds_to_an_existing_cell() {
    gate(&deposit_unshielded_case(
        "depositUnshielded — adding to an existing cell",
        Some(2_500),
        1_000,
    ));
}

/// `assert(amt > 0, "deposit must be positive")`, on both artifacts.
#[test]
fn deposit_unshielded_refuses_zero() {
    let case = deposit_unshielded_case("depositUnshielded — zero amount", None, 0);
    let (pi, err) = support::synth::synthesize_partial(&theirs("depositUnshielded"), &case.preimage());
    assert!(err.is_some(), "the compactc artifact accepted a zero deposit");
    assert!(
        simulate(&ours("depositUnshielded"), &pi).is_err(),
        "the port accepted a zero deposit the compactc artifact refuses"
    );
}

// ---- depositShielded ----------------------------------------------------------------------------

/// The first credit of a colour: no pool yet, so the merge arm is guarded off and the pool is
/// created lazily by the `else` arm's `insertCoin`.
fn deposit_shielded_first_credit() -> Case {
    let coin_nonce = b32(b"coin-nonce", 0x91);
    let value: u128 = 4_000;

    let mut inputs = Vec::new();
    push_b32(&mut inputs, &coin_nonce);
    push_b32(&mut inputs, &a_colour());
    inputs.push(u128_fr(value));
    push_b32(&mut inputs, &an_account());

    let mut reads = vec![one()]; // accounts.member
    push_b32(&mut reads, &self_addr()); // receiveShielded's kernel.self()
    reads.push(zero()); // pools.member -> the merge arm is off
    push_b32(&mut reads, &self_addr()); // the else arm's insertCoin recipient
    reads.push(zero()); // shieldedBalances.member

    Case {
        circuit: "depositShielded",
        name: "depositShielded — FIRST CREDIT of a colour (the pool is created here)",
        inputs,
        reads,
        outputs: vec![],
    }
}

/// A second credit of the same colour: the pool exists, so `mergeCoinImmediate` runs — two zswap
/// nullifiers, the colour-equality assert, the evolved nonce, the summed value, and the merged
/// coin's commitment claimed as both a spend and a receive.
fn deposit_shielded_merge() -> Case {
    let coin_nonce = b32(b"coin-nonce", 0x91);
    let pooled_nonce = b32(b"pool-nonce", 0x33);
    let value: u128 = 4_000;
    let pooled_value: u128 = 11_000;
    let held: u128 = 2_000;

    let mut inputs = Vec::new();
    push_b32(&mut inputs, &coin_nonce);
    push_b32(&mut inputs, &a_colour());
    inputs.push(u128_fr(value));
    push_b32(&mut inputs, &an_account());

    let mut reads = vec![one()]; // accounts.member
    push_b32(&mut reads, &self_addr()); // receiveShielded's kernel.self()
    reads.push(one()); // pools.member -> the merge arm runs
    // pools.lookup — six limbs. The pooled coin's COLOUR must equal the deposited coin's, or
    // `mergeCoinImmediate`'s "Can only merge coins of the same color" assert refuses the run.
    push_b32(&mut reads, &pooled_nonce);
    push_b32(&mut reads, &a_colour());
    reads.push(u128_fr(pooled_value));
    reads.push(Fr::from(12u64)); // mt_index
    push_b32(&mut reads, &self_addr()); // mergeCoinImmediate's kernel.self()
    push_b32(&mut reads, &self_addr()); // the merge arm's insertCoin recipient
    reads.push(one()); // shieldedBalances.member
    reads.push(u128_fr(held)); // shieldedBalances.lookup

    Case {
        circuit: "depositShielded",
        name: "depositShielded — MERGE into an existing pool",
        inputs,
        reads,
        outputs: vec![],
    }
}

#[test]
fn deposit_shielded_creates_the_pool() {
    gate(&deposit_shielded_first_credit());
}

#[test]
fn deposit_shielded_merges_into_the_pool() {
    gate(&deposit_shielded_merge());
}

/// `assert(c.value > 0, "deposit must be positive")`, on both artifacts.
#[test]
fn deposit_shielded_refuses_a_zero_coin() {
    let mut case = deposit_shielded_first_credit();
    case.name = "depositShielded — zero-value coin";
    // slot 4 is the coin's value.
    case.inputs[4] = zero();
    let (pi, err) = support::synth::synthesize_partial(&theirs("depositShielded"), &case.preimage());
    assert!(
        err.is_some(),
        "the compactc artifact accepted a zero-value deposit"
    );
    assert!(
        simulate(&ours("depositShielded"), &pi).is_err(),
        "the port accepted a zero-value deposit the compactc artifact refuses"
    );
}

/// `mergeCoinImmediate` refuses two coins of different colours — and the refusal is the STDLIB's,
/// reached through the pool, so it is worth pinning that both artifacts hit it.
#[test]
fn deposit_shielded_refuses_a_mismatched_pool_colour() {
    let mut case = deposit_shielded_merge();
    case.name = "depositShielded — pooled coin of a different colour";
    // The pooled coin's colour limbs are reads[6..8]: 1 (accounts.member) + 2 (kernel.self)
    // + 1 (pools.member) + 2 (the pooled nonce) = 6.
    let other = b32(b"other-colour", 0x5b);
    let (hi, lo) = b32_slots(&other);
    case.reads[6] = hi;
    case.reads[7] = lo;
    let (pi, err) = support::synth::synthesize_partial(&theirs("depositShielded"), &case.preimage());
    assert!(
        err.is_some(),
        "the compactc artifact merged coins of different colours"
    );
    assert!(
        simulate(&ours("depositShielded"), &pi).is_err(),
        "the port merged coins of different colours"
    );
}
