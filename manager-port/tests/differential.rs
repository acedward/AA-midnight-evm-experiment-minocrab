//! # The Q3-bar-A equivalence gate
//!
//! Every circuit that enters the 00012 comparison table must pass this suite first (spec FR-004,
//! owner decision Q3 → A). It is the porting-kit differential from
//! `resources/minocrab/README.md` §Porting kit and
//! `crates/minocrab-contracts/tests/erc20_vault_differential.rs`, with one deliberate change:
//!
//! **`theirs` is OUR OWN Phase-1 compactc artifact**, compiled in this project from
//! `contracts/manager.compact` at clone commit `0eccb66` under the pinned image — *not* minocrab's
//! bundled corpus. That is what the plan's task 2.3 requires, and it is what makes the resulting
//! `(k, rows)` pair a statement about *this* contract.
//!
//! The bar, per Q3 option A:
//!
//! 1. **Typed schema identity** — same input types in the same order, same output types.
//! 2. **PI-vector identity on a shared `ProofPreimage`** — both artifacts simulated on the *same*
//!    preimage must produce the same public-input vector and the same `pi_skips`, and upstream's
//!    own `check()` must agree with the simulation on both sides.
//! 3. **Accept/reject agreement, including tampered inputs** — a preimage either artifact rejects
//!    must be rejected by the other, element by element across the whole transcript.
//!
//! A failure here is a **finding**, never a silent exclusion (FR-004 / US3).
//!
//! ## Running it
//!
//! The compactc side is a generated artifact (gitignored). Produce it first:
//!
//! ```text
//! COMPACTC_IMAGE=<your-compactc-0.33.0-image> scripts/compile-baseline.sh baseline \
//!     <checkout>/contracts/manager.compact $(scripts/free-port.sh)
//! cargo +1.95.0 test --release -p manager-port --features compactc-baseline
//! ```

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
};
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::{to_zkir_string, IrSource};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

// ---- the two sides ----------------------------------------------------------------------------

/// OUR Phase-1 compactc artifact for `name` (task 2.3: not minocrab's corpus).
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

// ---- the gate ---------------------------------------------------------------------------------

/// Q3 bar A, clauses 1 and 2. Lifted from minocrab's own `assert_call_compatible`.
fn assert_call_compatible(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage) {
    let types = |ir: &IrSource| {
        serde_json::to_value(&ir.inputs)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|ti| ti["type"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(types(ours), types(theirs), "input schemas differ");
    assert_eq!(ours.outputs, theirs.outputs, "output schemas differ");

    let our_run = simulate(ours, pi).expect("our artifact accepts");
    let their_run = simulate(theirs, pi).expect("the compactc artifact accepts");
    assert_eq!(our_run.pi_skips, their_run.pi_skips, "pi_skips differ");
    assert_eq!(our_run.pis, their_run.pis, "PI vectors differ");

    assert_eq!(
        ours.check(pi).expect("upstream accepts ours"),
        our_run.pi_skips
    );
    assert_eq!(
        theirs
            .check(pi)
            .expect("upstream accepts the compactc artifact"),
        their_run.pi_skips
    );
}

/// Q3 bar A, clause 3: every single-element mutation of the preimage must be accepted by both
/// artifacts or rejected by both. Zero acceptance disagreements is the assertion.
fn assert_tamper_agreement(ours: &IrSource, theirs: &IrSource, base: &ProofPreimage) {
    let mut checked = 0usize;
    let mut disagreements = Vec::new();

    let mut probe = |pi: ProofPreimage, what: String, checked: &mut usize| {
        *checked += 1;
        let ours_ok = simulate(ours, &pi).is_ok();
        let theirs_ok = simulate(theirs, &pi).is_ok();
        if ours_ok != theirs_ok {
            disagreements.push(format!("{what}: ours={ours_ok} compactc={theirs_ok}"));
        }
    };

    for i in 0..base.inputs.len() {
        let mut pi = base.clone();
        pi.inputs[i] = pi.inputs[i] + Fr::from(1u64);
        probe(pi, format!("inputs[{i}]"), &mut checked);
    }
    for i in 0..base.public_transcript_inputs.len() {
        let mut pi = base.clone();
        pi.public_transcript_inputs[i] = pi.public_transcript_inputs[i] + Fr::from(1u64);
        probe(pi, format!("public_transcript_inputs[{i}]"), &mut checked);
    }
    for i in 0..base.public_transcript_outputs.len() {
        let mut pi = base.clone();
        pi.public_transcript_outputs[i] = pi.public_transcript_outputs[i] + Fr::from(1u64);
        probe(pi, format!("public_transcript_outputs[{i}]"), &mut checked);
    }
    for i in 0..base.private_transcript.len() {
        let mut pi = base.clone();
        pi.private_transcript[i] = pi.private_transcript[i] + Fr::from(1u64);
        probe(pi, format!("private_transcript[{i}]"), &mut checked);
    }

    assert!(checked > 0, "the tamper sweep probed nothing");
    assert!(
        disagreements.is_empty(),
        "{} of {checked} tampered preimages were judged differently:\n  {}",
        disagreements.len(),
        disagreements.join("\n  ")
    );
    println!("tamper sweep: {checked} mutations, 0 acceptance disagreements");
}

// ---- FAB / transcript helpers (same shapes as minocrab's own differentials) --------------------

fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
            length: n,
        })]),
    )
    .expect("the bytes fit the atom")
}

fn cell(av: AlignedValue) -> StateValue {
    StateValue::Cell(Sp::new(av))
}

/// `idx [k]` by one constant `bytes<1>` key — a top-level ledger field.
fn idx(k: u8) -> VmOp {
    Op::Idx {
        cached: false,
        push_path: false,
        path: vec![Key::Value(bytesn_value(1, &[k]))].into(),
    }
}

fn transcript(ops: &[VmOp]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        op.field_repr(&mut out);
    }
    out
}

/// `[hi, lo]` slot pair of a `Bytes<32>` — `hi` is byte 31, `lo` the first 31 bytes LE.
/// Mirrors `minocrab_std::v3::B32`'s own split and minocrab's `vault::prims::b32_slots`.
fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit"),
    )
}

/// The preimage of a circuit that only READS: the op stream is `public_transcript_inputs`, what
/// the ledger hands back (every `popeq` result, value-only, in read order) is
/// `public_transcript_outputs`, and the communications commitment covers the circuit's inputs and
/// its declared outputs.
fn preimage_out(inputs: Vec<Fr>, ops: &[VmOp], reads: &[Fr], outputs: &[Fr]) -> ProofPreimage {
    let rand = Fr::from(0xb0_u64);
    let mut comm_vals = inputs.clone();
    comm_vals.extend_from_slice(outputs);
    let comm = transient_commit(&comm_vals[..], rand);
    ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: transcript(ops),
        public_transcript_outputs: reads.to_vec(),
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("manager-port-00012-test")),
    }
}

// ---- isRegistered -----------------------------------------------------------------------------

/// `accounts`' ledger field index — **derived from the port's own ledger block**, not a literal.
///
/// It was `1` while the contract was one file and is `0` since the module split (product `main` @
/// `41de69d`): `AccountRegistry.compact` contributes its four fields ahead of everything else.
/// Reading it out of [`manager_port::ledger::slot`] means the struct in `src/ledger.rs` is the
/// single place the number lives, on both the emitting and the checking side of this test.
const ACCOUNTS: u8 = manager_port::ledger::slot::ACCOUNTS;

/// The transcript of `accounts.member(owner)` answering `answer`.
fn is_registered_scenario(owner: &[u8; 32], answer: u8) -> ProofPreimage {
    let (hi, lo) = b32_slots(owner);
    let ops = vec![
        Op::Dup { n: 0 },
        idx(ACCOUNTS),
        Op::Push {
            storage: false,
            value: cell(bytesn_value(32, owner)),
        },
        Op::Member,
        Op::Popeq {
            cached: true,
            result: bytesn_value(1, &[answer]),
        },
    ];
    let a = Fr::from(u64::from(answer));
    preimage_out(vec![hi, lo], &ops, &[a], &[a])
}

fn an_account() -> [u8; 32] {
    let mut acct = [0u8; 32];
    acct[..9].copy_from_slice(b"acct-0012");
    acct[31] = 0x2a;
    acct
}

/// The instruction stream, side by side. Not required by Q3 bar A — schema + PI identity is the
/// bar — but when it holds it is the strongest statement available, so it is recorded.
#[test]
fn is_registered_instruction_stream_matches_compactc() {
    let ours = manager_port::account_registry::is_registered().ir;
    let theirs = theirs("isRegistered");

    let canon = |ir: &IrSource| {
        let ir = minocrab_ir::v3::passes::folded(ir);
        canonicalize(&to_zkir_string(&ir).expect("serializes"))
    };
    assert_eq!(
        canon(&ours),
        canon(&theirs),
        "isRegistered: instruction streams differ"
    );
}

#[test]
fn is_registered_matches_compactc_registered() {
    let ours = manager_port::account_registry::is_registered().ir;
    let theirs = theirs("isRegistered");
    assert_call_compatible(&ours, &theirs, &is_registered_scenario(&an_account(), 1));
}

/// The other answer: an account the set does not carry. `member` reading back 0 is a normal
/// accepted run for this circuit (it RETURNS the Boolean; it does not assert on it), so both
/// artifacts must accept and agree on the PI vector.
#[test]
fn is_registered_matches_compactc_not_registered() {
    let ours = manager_port::account_registry::is_registered().ir;
    let theirs = theirs("isRegistered");
    assert_call_compatible(&ours, &theirs, &is_registered_scenario(&[0u8; 32], 0));
}

#[test]
fn is_registered_tamper_agreement() {
    let ours = manager_port::account_registry::is_registered().ir;
    let theirs = theirs("isRegistered");
    assert_tamper_agreement(&ours, &theirs, &is_registered_scenario(&an_account(), 1));
}

// ---- shared ------------------------------------------------------------------------------------

/// Serialized ZKIR with every `%name.index` identifier replaced by `%<order of first appearance>`.
/// Identifier names are the only cosmetic difference two artifacts of the same statement may
/// carry; everything else still compares exactly. (minocrab's own differentials canonicalize the
/// same way.)
fn canonicalize(text: &str) -> String {
    let mut renames: Vec<(String, String)> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest[1..]
            .find(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '.'))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let name = &rest[..end];
        let canon = match renames.iter().find(|(from, _)| from == name) {
            Some((_, to)) => to.clone(),
            None => {
                let to = format!("%{}", renames.len());
                renames.push((name.to_string(), to.clone()));
                to
            }
        };
        out.push_str(&canon);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}
