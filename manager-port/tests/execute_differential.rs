//! # The Q3-bar-A equivalence gate for `execute` (plan task 3.6)
//!
//! The headline circuit — 86.7% of the contract's provable rows — against **our own** Phase-1
//! compactc artifact, per the owner's Q3 resolution:
//!
//! 1. **Typed schema identity** — same input types in the same order, same output types.
//! 2. **PI-vector identity on a shared `ProofPreimage`** — both artifacts simulated on the SAME
//!    preimage must produce the same public-input vector and the same `pi_skips`, and upstream's
//!    own `check()` must agree with the simulation on both sides.
//! 3. **Accept/reject agreement, including tampered inputs.**
//!
//! `pi_skips` equality is the clause that does the work here: it is one entry per `Impact`
//! instruction, carrying whether that op's guard was on and how many elements it contributed. Two
//! artifacts can only agree on it if they emit the same ledger operations, in the same order, with
//! the same input counts and the same guard truth values — for `execute`, 404 of them.
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

mod support;

use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::{ProofPreimage, Zkir};
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;
use support::model::*;
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

fn ours() -> IrSource {
    manager_port::execute::execute().ir
}

// ---- the bar ------------------------------------------------------------------------------------

fn assert_schema_identity(ours: &IrSource, theirs: &IrSource) {
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
    assert_eq!(
        ours.do_communications_commitment, theirs.do_communications_commitment,
        "communications-commitment flag differs"
    );
}

/// Clause 2: PI-vector identity on a shared preimage.
fn assert_pi_identity(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage, what: &str) {
    let their_run = simulate(theirs, pi)
        .unwrap_or_else(|e| panic!("{what}: the compactc artifact rejected the synthesized preimage: {e}"));
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
        assert_eq!(a, b, "{what}: pi_skips differ at Impact {i}: port {a:?} vs compactc {b:?}");
    }
    assert_eq!(our_run.pis.len(), their_run.pis.len(), "{what}: PI vector lengths differ");
    for (i, (a, b)) in our_run.pis.iter().zip(their_run.pis.iter()).enumerate() {
        assert_eq!(a, b, "{what}: PI vectors differ at element {i}");
    }

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
fn assert_tamper_agreement(ours: &IrSource, theirs: &IrSource, base: &ProofPreimage, what: &str) -> usize {
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

/// The whole bar for one scenario.
fn gate(scenario: &Scenario) {
    let ours = ours();
    let theirs = theirs("execute");
    assert_schema_identity(&ours, &theirs);

    let pi = synthesize(&theirs, &scenario.preimage())
        .unwrap_or_else(|e| panic!("{}: {e}", scenario.name));
    assert_pi_identity(&ours, &theirs, &pi, scenario.name);
    let probes = assert_tamper_agreement(&ours, &theirs, &pi, scenario.name);

    println!(
        "GATE {}: {} Impact ops, {} PI elements, {} transcript inputs, {} ledger answers, \
         {probes} tamper probes, 0 disagreements",
        scenario.name,
        simulate(&theirs, &pi).unwrap().pi_skips.len(),
        simulate(&theirs, &pi).unwrap().pis.len(),
        pi.public_transcript_inputs.len(),
        pi.public_transcript_outputs.len(),
    );
}

// ---- fixtures -----------------------------------------------------------------------------------

/// The contract's own address, which every `kernel.self()` read answers with.
fn self_addr() -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..12].copy_from_slice(b"aa00012-self");
    a[31] = 0x11;
    a
}

fn deployment_domain() -> [u8; 32] {
    let mut d = [0u8; 32];
    d[..14].copy_from_slice(b"aa00012-domain");
    d[31] = 0x22;
    d
}

fn owner_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..10].copy_from_slice(b"owner-secr");
    s[31] = 0x33;
    s
}

fn a_colour() -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..6].copy_from_slice(b"colour");
    c[31] = 0x44;
    c
}

/// A signature that is well-formed but not over anything in particular — enough for the paths where
/// the ECDSA result is never asserted on (`authMode == 0`), where the contract still runs the
/// verification straight-line because the pinned backend cannot lower a guarded secp operation.
fn dummy_signature() -> (minocrab_zkir::v3::IrValue, minocrab_zkir::v3::IrValue, minocrab_zkir::v3::IrValue) {
    sign(&[7u8; 32], &scalar(0x5eed), &scalar(0xf00d))
}

// ---- scenario 1: selector 0, native registration -------------------------------------------------

fn native_registration() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let mut reads = Reads::new();
    // 1. `kernel.self()` — `const manager = kernel.self().bytes`.
    reads.b32(&self_addr());
    // 2. `deploymentDomain` — GUARDED OFF: the read is the else arm of
    //    `p.selector == 0 ? default : evmDigestFor(…)`, and this is selector 0.
    // 3-4. `authenticatedActionAccount` — OFF: `is_action = !s0 && !s1` is false.
    // 5. `assertLiveDeadline` — OFF: `authMode == 1` is false.
    // 6. `registerAccount(account, 0)`:
    reads.bool(false); //   `accounts.member(account)`      — not yet registered
    reads.bool(false); //   `accountModes.member(account)`  — no mode collision
    // 7. `custodyDispatch` — OFF: `!isRegistration` is false.
    // 8. `evmNonces.insert` — OFF: `isEvmAuthorized` is false.
    Scenario {
        name: "selector 0 — native registration",
        payload: Payload {
            selector: 0,
            auth_mode: 0,
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

#[test]
fn execute_native_registration() {
    gate(&native_registration());
}

// ---- the native-authorization custody selectors --------------------------------------------------
//
// `authMode == 0`, so the ECDSA result is never asserted on and the deadline and nonce writes stay
// off. Every one of these supplies `p.account = ownerCommitment(localOwnerSecret())` computed
// OFF-CIRCUIT (`support::model::owner_commitment`) — `authenticatedActionAccount` asserts the
// witness-derived account equals the supplied one, so the compactc artifact accepts these runs only
// if that transcription is byte-correct. That is the check the 3.3 hand-over flagged as missing.

fn a_recipient() -> [u8; 32] {
    let mut r = [0u8; 32];
    r[..9].copy_from_slice(b"recipient");
    r[31] = 0x55;
    r
}

fn another_account() -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..7].copy_from_slice(b"other-a");
    a[31] = 0x66;
    a
}

/// The six reads of the native arm of `authenticatedActionAccount`, in source order.
fn native_auth_reads(reads: &mut Reads) {
    reads.bool(true); // `accounts.member(nativeAccount)`
    reads.bool(true); // `accountModes.member(nativeAccount)`
    reads.u8(0); //     `accountModes.lookup(acct)`  — `== 0`, native mode
    reads.u8(0); //     `accountModes.lookup(acct)`  — re-read at manager.compact:872
    reads.bool(false); // `evmOwners.member(acct)`
    reads.bool(false); // `evmNonces.member(acct)` — reached because `!evmOwners.member` held
}

/// Selector 3 — withdraw unshielded, native authorization.
fn withdraw_unshielded_native() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr()); //         `kernel.self()`
    reads.b32(&deployment_domain()); // `deploymentDomain` — selector != 0
    native_auth_reads(&mut reads);
    reads.bool(true); //   `unshieldedBalances.member(debitKey)` — the muxed family is unshielded
    reads.u128(1_000); //  `unshieldedBalances.lookup(debitKey)`
    reads.bool(false); //  `unshieldedBalance(col) < val` — the contract holds enough
    //  `is_self` reads nothing: after PR#10 `recipientKind == 0` is the UserAddress (RIGHT) arm,
    //  so `is_left` is 0 and the auto-receive `kernel.self()` read is guarded off.
    Scenario {
        name: "selector 3 — withdraw unshielded, native",
        payload: Payload {
            selector: 3,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            // PR#10 (project 00016): the envelope now refuses `recipientKind != 0` on a
            // withdrawal, and kind 0 is the User-tagged payout — the only provable shape.
            recipient_kind: 0,
            recipient: a_recipient(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 2 — withdraw shielded, native authorization. The `sendShielded` leg.
fn withdraw_shielded_native() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true); //  `shieldedBalances.member(debitKey)`
    reads.u128(1_000); // `shieldedBalances.lookup(debitKey)`
    reads.bool(true); //  `pools.member(col)`
    reads.coin(&[9u8; 32], &a_colour(), 5_000, 0); // `pools.lookup(col)`
    reads.b32(&self_addr()); // `sendShielded`'s `kernel.self()`
    reads.b32(&self_addr()); // `repoolOrRemove`'s `insertCoin(… right(kernel.self()))`
    Scenario {
        name: "selector 2 — withdraw shielded, native",
        payload: Payload {
            selector: 2,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            // PR#10 (project 00016): a withdrawal may only pay a User (kind 0); the envelope
            // refuses `recipientKind != 0` outright, on both artifacts.
            recipient_kind: 0,
            recipient: a_recipient(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 4 — internal shielded transfer, native authorization.
fn transfer_shielded_native() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true); //  `accounts.member(p.toAccount)` — reached because `isTransfer` held
    reads.bool(true); //  `shieldedBalances.member(debitKey)`
    reads.u128(1_000); // `shieldedBalances.lookup(debitKey)`
    reads.bool(false); // `shieldedBalances.member(creditKey)` — a fresh credit cell
    Scenario {
        name: "selector 4 — internal shielded transfer, native",
        payload: Payload {
            selector: 4,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            to_account: another_account(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 5 — internal unshielded transfer, native authorization.
fn transfer_unshielded_native() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true); //  `accounts.member(p.toAccount)`
    reads.bool(true); //  `unshieldedBalances.member(debitKey)`
    reads.u128(1_000); // `unshieldedBalances.lookup(debitKey)`
    reads.bool(false); // `unshieldedBalances.member(creditKey)`
    Scenario {
        name: "selector 5 — internal unshielded transfer, native",
        payload: Payload {
            selector: 5,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            to_account: another_account(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 6 — open swap, native authorization. The FR-308 open-offer leg, the want leg and the
/// credit write: the widest single path through `custodyDispatch`.
fn open_swap_native() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut want_colour = [0u8; 32];
    want_colour[..4].copy_from_slice(b"want");
    want_colour[31] = 0x77;
    let mut want_nonce = [0u8; 32];
    want_nonce[..5].copy_from_slice(b"nonce");
    want_nonce[31] = 0x88;

    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true); //  `shieldedBalances.member(debitKey)`
    reads.u128(1_000); // `shieldedBalances.lookup(debitKey)`
    reads.bool(true); //  `pools.member(col)`
    reads.coin(&[9u8; 32], &a_colour(), 5_000, 0); // `pools.lookup(col)`
    reads.bool(true); //  `accounts.member(p.creditAccount)` — reached because `isSwap` held
    reads.b32(&self_addr()); // the open leg's `kernel.self()`
    reads.b32(&self_addr()); // the change coin's `insertCoin(… right(kernel.self()))`
    reads.b32(&self_addr()); // `receiveShielded`'s `kernel.self()`
    reads.bool(false); // `pools.member(p.wantColor)` — a colour the pool does not hold yet
    reads.b32(&self_addr()); // the fresh-colour `insertCoin(… right(kernel.self()))`
    reads.bool(false); // `shieldedBalances.member(creditKey)`
    Scenario {
        name: "selector 6 — open swap, native",
        payload: Payload {
            selector: 6,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            recipient_kind: 0,
            want_nonce,
            want_color: want_colour,
            want_amount: 250,
            credit_account: another_account(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

#[test]
fn execute_withdraw_shielded_native() {
    gate(&withdraw_shielded_native());
}

#[test]
fn execute_open_swap_native() {
    gate(&open_swap_native());
}

// ---- selectors 3, 4 and 5 — PROVABLE AGAIN as of PR#9 (project 00013) ----------------------------
//
// PROJECT 00020 UPDATE. The block below documents F-00012-08, the defect that made these three
// selectors unprovable on the `0eccb66` line the 00012 port was gated against. PR#9 (`d97f9d5`,
// merged as `32405ae`) fixed it with the `safeGive` clamp, so on `713a202` all three have accepted
// runs and get the FULL bar-A gate (`gate(..)`) rather than refusal agreement. The three
// `*_has_no_accepted_run` tests have therefore been REPLACED by `execute_withdraw_unshielded_native`,
// `execute_transfer_shielded_native` and `execute_transfer_unshielded_native` below.
//
// The historical text is kept verbatim because it is the reason those scenarios exist and the
// reason this project had to re-gate rather than reuse 00012's result:
//
// `custodyDispatch`'s two shielded give legs compute `pooled.value - p.primaryAmount`
// UNCONDITIONALLY — a circuit compiles every branch, and only the *effects* and *asserts* of the
// `if (needsPool)` block are guarded, not its arithmetic. For selectors 3, 4 and 5 `needsPool` is
// false, so `pools.lookup(col)` is a guarded-off read and hands back the type default 0, while
// `assertActionEnvelope` requires `p.primaryAmount > 0`. The difference is therefore a NEGATIVE
// field element, and it is fed straight into the change coin's `coinCommitment` as a `Uint<128>`:
//
//   execute.zkir:5397  persistent_hash [.. bytes<16> %change.6379 ..]
//
// Upstream's own off-circuit VM — the code the prover runs to build a witness, `ir_vm.rs:478-506` —
// refuses to encode it ("inputs did not match alignment"), and the in-circuit twin decomposes the
// same wire with `assigned_to_le_bytes(.., Some(16))` (`ir_vm.rs:144-170`), which is a range
// constraint no witness can satisfy. So there is no preimage the artifact accepts, and no proof.
//
// THE CAUSE IS LOCALIZED, not inferred: `unprovable_cause_is_the_pool_underflow` reruns the same
// scenario with `primaryAmount = 0` and the run gets PAST instruction 5397, failing instead at
// instruction 134 — the envelope's own "must be positive" assert. The only thing that changed is
// the sign of `pooled.value - primaryAmount`.
//
// FOR THIS PROJECT this is agreement, not a differential failure: the port reproduces the contract
// faithfully and refuses the same runs. It is recorded because a `(k, rows)` number for a circuit
// whose paths cannot be proved is a fact the owner needs alongside it.

/// Both artifacts must refuse, and refuse for the same reason.
fn assert_both_refuse(scenario: &Scenario) {
    let theirs = theirs("execute");
    let (partial, err) = support::synth::synthesize_partial(&theirs, &scenario.preimage());
    let err = err.unwrap_or_else(|| {
        panic!(
            "{}: the compactc artifact ACCEPTED a run F-00012-08 says is impossible — \
             the finding is wrong and must be re-derived",
            scenario.name
        )
    });
    assert!(
        err.contains("inputs did not match alignment"),
        "{}: expected the change-coin FAB encoding to fail, got: {err}",
        scenario.name
    );

    // Upstream's OWN prover-side preprocessing, not just minocrab's simulator.
    assert!(
        theirs.check(&partial).is_err(),
        "{}: upstream's check() accepted a preimage its own VM rejects",
        scenario.name
    );

    // And the port agrees: same preimage, also refused.
    let ours = ours();
    assert!(
        simulate(&ours, &partial).is_err(),
        "{}: the port ACCEPTED a run the compactc artifact refuses — a real divergence",
        scenario.name
    );
    println!(
        "AGREEMENT {}: no accepted run exists; both artifacts refuse (F-00012-08). \
         {} transcript elements derived before the refusal",
        scenario.name,
        partial.public_transcript_inputs.len()
    );
}

// THE THREE SELECTORS PR#9 GAVE BACK. Each gets the full bar: schema identity, PI-vector and
// `pi_skips` identity on a preimage synthesized FROM THE COMPACTC ARTIFACT, upstream `check()`
// agreement on both sides, and a whole-preimage single-element tamper sweep.

#[test]
fn execute_withdraw_unshielded_native() {
    gate(&withdraw_unshielded_native());
}

#[test]
fn execute_transfer_shielded_native() {
    gate(&transfer_shielded_native());
}

#[test]
fn execute_transfer_unshielded_native() {
    gate(&transfer_unshielded_native());
}

/// PR#9's fix, asserted directly on OUR `713a202` compactc artifact: the run that F-00012-08 said
/// could not exist now synthesizes cleanly, and specifically no longer dies in the change coin's
/// FAB encoding. This is the regression sentinel for the clamp — if a future contract change drops
/// `safeGive`, this fails with the original `inputs did not match alignment`.
#[test]
fn pool_underflow_is_fixed_on_this_contract() {
    for sc in [
        withdraw_unshielded_native(),
        transfer_shielded_native(),
        transfer_unshielded_native(),
    ] {
        let (_, err) = support::synth::synthesize_partial(&theirs("execute"), &sc.preimage());
        assert!(
            err.is_none(),
            "{}: the compactc artifact at 713a202 still refuses this run: {}",
            sc.name,
            err.unwrap()
        );
    }
}

/// The control that localized F-00012-08 on the subtraction rather than on the model, kept as a
/// live check that the ENVELOPE still owns the positivity rule: the same scenario with
/// `primaryAmount = 0` dies on the envelope's own assert, not in the change-coin encoding.
#[test]
fn zero_amount_is_refused_by_the_envelope() {
    let mut sc = transfer_unshielded_native();
    sc.payload.primary_amount = 0;
    let (_, err) = support::synth::synthesize_partial(&theirs("execute"), &sc.preimage());
    let err = err.expect("a zero-amount transfer is refused by the envelope");
    assert!(
        err.contains("(assert): failed direct assertion"),
        "with primaryAmount = 0 the run should reach an ENVELOPE assert, not the change-coin \
         encoding. Got: {err}"
    );
    assert!(
        !err.contains("inputs did not match alignment"),
        "with primaryAmount = 0 the change coin must encode cleanly. Got: {err}"
    );
}

/// PR#10 (project 00016), refusal agreement: the envelope must now REFUSE a contract-tagged
/// withdrawal recipient and a contract-tagged swap taker — on both artifacts, for the same reason.
#[test]
fn pr10_envelope_refuses_the_contract_recipient_shapes() {
    let theirs = theirs("execute");
    let ours = ours();

    let mut withdraw = withdraw_unshielded_native();
    withdraw.payload.recipient_kind = 1; // "pay a contract" — refused as of PR#10
    let mut swap = open_swap_native();
    swap.payload.recipient_kind = 2; // a contract taker — refused as of PR#10
    swap.payload.recipient = a_recipient();

    for sc in [withdraw, swap] {
        let (partial, err) = support::synth::synthesize_partial(&theirs, &sc.preimage());
        let err = err.unwrap_or_else(|| {
            panic!("{}: the compactc artifact ACCEPTED a shape PR#10 forbids", sc.name)
        });
        assert!(
            err.contains("(assert): failed direct assertion"),
            "{}: expected an envelope assert, got: {err}",
            sc.name
        );
        assert!(
            simulate(&ours, &partial).is_err(),
            "{}: the port ACCEPTED a run the compactc artifact refuses — a real divergence",
            sc.name
        );
        println!("PR10-REFUSAL-AGREEMENT {}: both artifacts refuse", sc.name);
    }
}

// ---- the EVM-authorized paths ---------------------------------------------------------------------
//
// `authMode == 1`, so the ECDSA result IS asserted on: `signatureOk` and `signer == p.owner` must
// both hold, `assertLiveDeadline` runs, and the nonce is written. These are the only scenarios that
// need a real signature, and building one exercises the whole AUTH-EIP712-AA-V3-V1 chain a second
// time, OFF-CIRCUIT (`support::model`) — an independent witness of the frozen bytes on top of
// `tests/eip712_fixtures.rs`'s 180 comparisons, because a wrong digest here means the compactc
// artifact refuses the run outright.

/// The signing key and the ECDSA nonce. Any nonzero pair works.
fn signing_key() -> (minocrab_zkir::v3::IrValue, minocrab_zkir::v3::IrValue) {
    (scalar(0xA11CE), scalar(0xB0B))
}

/// The EOA the signature authorises: `secp256k1EthereumAddress(d·G)`.
fn signer_address() -> [u8; 20] {
    let (d, k) = signing_key();
    let (_r, _s, pk) = sign(&[0u8; 32], &d, &k);
    ethereum_address(&pk)
}

/// Sign the EIP-712 digest this payload commits to under `manager` / `domain`.
fn sign_payload(
    payload: &Payload,
) -> (minocrab_zkir::v3::IrValue, minocrab_zkir::v3::IrValue, minocrab_zkir::v3::IrValue) {
    let manager = self_addr();
    let sep = domain_separator(&manager, &deployment_domain());
    let digest = eip712_digest(&sep, &payload.struct_hash(&manager));
    let (d, k) = signing_key();
    sign(&digest, &d, &k)
}

/// The two `assertLiveDeadline` reads: `blockTimeGte(validUntil - 3600)` then
/// `blockTimeLt(validUntil)`. Both are `kernel.blockTimeLessThan` under the hood, and `Gte` is its
/// negation — so "the deadline is inside the horizon and has not passed" is `false` then `true`.
fn live_deadline_reads(reads: &mut Reads) {
    reads.bool(false); // `blockTime < validUntil - 3600` — the deadline is not too far out
    reads.bool(true); //  `blockTime < validUntil`        — it has not passed
}

/// Selector 1 — EVM registration. The only selector that REQUIRES `authMode == 1`.
fn evm_registration() -> Scenario {
    let manager = self_addr();
    let owner = signer_address();
    let mut salt = [0u8; 32];
    salt[..4].copy_from_slice(b"salt");
    salt[31] = 0x99;

    let payload = Payload {
        selector: 1,
        auth_mode: 1,
        account: evm_account_id(&manager, &owner, &salt),
        owner,
        account_salt: salt,
        nonce: 0,
        valid_until: 4_000,
        ..Payload::default()
    };
    let (r, s, pk) = sign_payload(&payload);

    let mut reads = Reads::new();
    reads.b32(&manager); //             `kernel.self()`
    reads.b32(&deployment_domain()); // `deploymentDomain`
    live_deadline_reads(&mut reads);
    reads.bool(false); // `accounts.member(account)`     — not yet registered
    reads.bool(false); // `accountModes.member(account)` — no mode collision
    Scenario {
        name: "selector 1 — EVM registration",
        payload,
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 2 — withdraw shielded under EVM authorization. Exercises the EVM arm of
/// `authenticatedActionAccount`, the deadline, the full custody leg and the nonce write.
fn withdraw_shielded_evm() -> Scenario {
    let manager = self_addr();
    let owner = signer_address();
    let account = another_account();

    let payload = Payload {
        selector: 2,
        auth_mode: 1,
        account,
        owner,
        nonce: 5,
        valid_until: 4_000,
        primary_color: a_colour(),
        primary_amount: 100,
        // PR#10 (project 00016): withdrawals are User-tagged only.
        recipient_kind: 0,
        recipient: a_recipient(),
        ..Payload::default()
    };
    let (r, s, pk) = sign_payload(&payload);

    let mut reads = Reads::new();
    reads.b32(&manager);
    reads.b32(&deployment_domain());
    // the EVM arm of `authenticatedActionAccount`, in source order
    reads.bool(true); //   `accounts.member(p.account)`
    reads.bool(true); //   `accountModes.member(p.account)`
    reads.u8(1); //        `accountModes.lookup(p.account)` — EVM mode
    reads.bool(true); //   `evmOwners.member(p.account)`
    reads.bool(true); //   `evmNonces.member(p.account)` — reached because `evmOwners.member` held
    reads.bytes20(&owner); // `evmOwners.lookup(p.account)`
    reads.u64(5); //       `evmNonces.lookup(p.account)`
    live_deadline_reads(&mut reads);
    reads.bool(true); //  `shieldedBalances.member(debitKey)`
    reads.u128(1_000); // `shieldedBalances.lookup(debitKey)`
    reads.bool(true); //  `pools.member(col)`
    reads.coin(&[9u8; 32], &a_colour(), 5_000, 0); // `pools.lookup(col)`
    reads.b32(&manager); // `sendShielded`'s `kernel.self()`
    reads.b32(&manager); // `repoolOrRemove`'s `insertCoin(… right(kernel.self()))`
    Scenario {
        name: "selector 2 — withdraw shielded, EVM",
        payload,
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

#[test]
fn execute_evm_registration() {
    gate(&evm_registration());
}

#[test]
fn execute_withdraw_shielded_evm() {
    gate(&withdraw_shielded_evm());
}

// ---- the branches the selector sweep above does not reach -----------------------------------------
//
// Three arms of `custodyDispatch` are chosen by something other than the selector, so they need
// their own scenarios: the want leg's `mergeCoinImmediate` (chosen by `pools.member(wantColor)`),
// the swap's NAMED recipient shape (chosen by `recipientKind`), and `repoolOrRemove`'s removal arm
// (chosen by the change being zero). With these, every branch of the mux has an accepted run except
// the three F-00012-08 selectors.

fn want_colour() -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..4].copy_from_slice(b"want");
    c[31] = 0x77;
    c
}

fn want_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    n[..5].copy_from_slice(b"nonce");
    n[31] = 0x88;
    n
}

/// Selector 6, open shape, but the pool ALREADY holds the wanted colour — so the want leg takes
/// `mergeCoinImmediate` instead of a bare `insertCoin`. The merged coin's colour must match, which
/// `mergeCoin`'s own "Can only merge coins of the same color" assert enforces.
fn open_swap_merging() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true);
    reads.u128(1_000);
    reads.bool(true);
    reads.coin(&[9u8; 32], &a_colour(), 5_000, 0);
    reads.bool(true); //     `accounts.member(p.creditAccount)`
    reads.b32(&self_addr()); // the open leg's `kernel.self()`
    reads.b32(&self_addr()); // the change coin's `insertCoin`
    reads.b32(&self_addr()); // `receiveShielded`'s `kernel.self()`
    reads.bool(true); //     `pools.member(p.wantColor)` — THIS TIME the pool holds it
    reads.coin(&[3u8; 32], &want_colour(), 700, 1); // `pools.lookup(p.wantColor)`
    reads.b32(&self_addr()); // `mergeCoinImmediate`'s `kernel.self()`
    reads.b32(&self_addr()); // the merged coin's `insertCoin`
    reads.bool(false); //    `shieldedBalances.member(creditKey)`
    Scenario {
        name: "selector 6 — open swap, merging into an existing pool colour",
        payload: Payload {
            selector: 6,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            recipient_kind: 0,
            want_nonce: want_nonce(),
            want_color: want_colour(),
            want_amount: 250,
            credit_account: another_account(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 6 with `recipientKind == 1`: the NAMED swap shape, which shares `custodyDispatch`'s one
/// `sendShielded` with the withdrawal instead of taking the FR-308 open-offer leg.
fn named_swap() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true);
    reads.u128(1_000);
    reads.bool(true);
    reads.coin(&[9u8; 32], &a_colour(), 5_000, 0);
    reads.bool(true); //     `accounts.member(p.creditAccount)`
    reads.b32(&self_addr()); // `sendShielded`'s `kernel.self()` — the NAMED arm this time
    reads.b32(&self_addr()); // `repoolOrRemove`'s `insertCoin`
    reads.b32(&self_addr()); // `receiveShielded`'s `kernel.self()`
    reads.bool(false); //    `pools.member(p.wantColor)`
    reads.b32(&self_addr()); // the fresh-colour `insertCoin`
    reads.bool(false); //    `shieldedBalances.member(creditKey)`
    Scenario {
        name: "selector 6 — named swap (sendShielded arm)",
        payload: Payload {
            selector: 6,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            recipient_kind: 1,
            recipient: a_recipient(),
            want_nonce: want_nonce(),
            want_color: want_colour(),
            want_amount: 250,
            credit_account: another_account(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

/// Selector 2 where the withdrawal empties the pooled coin exactly: `sendShielded` returns
/// `change: none`, so `repoolOrRemove` takes its REMOVAL arm and there is no `insertCoin` — and
/// therefore no `kernel.self()` read for one.
fn withdraw_shielded_emptying_the_pool() -> Scenario {
    let (r, s, pk) = dummy_signature();
    let account = owner_commitment(&owner_secret());
    let mut reads = Reads::new();
    reads.b32(&self_addr());
    reads.b32(&deployment_domain());
    native_auth_reads(&mut reads);
    reads.bool(true);
    reads.u128(1_000);
    reads.bool(true);
    reads.coin(&[9u8; 32], &a_colour(), 100, 0); // pooled value == primaryAmount
    reads.b32(&self_addr()); // `sendShielded`'s `kernel.self()`
    //  no `insertCoin` read: the change is zero, so the colour leaves the map instead.
    Scenario {
        name: "selector 2 — withdraw shielded, pool emptied (removal arm)",
        payload: Payload {
            selector: 2,
            auth_mode: 0,
            account,
            primary_color: a_colour(),
            primary_amount: 100,
            // PR#10 (project 00016): a withdrawal may only pay a User (kind 0); the envelope
            // refuses `recipientKind != 0` outright, on both artifacts.
            recipient_kind: 0,
            recipient: a_recipient(),
            ..Payload::default()
        },
        owner_secret: owner_secret(),
        sig_r: r,
        sig_s: s,
        pk,
        reads,
    }
}

#[test]
fn execute_open_swap_merging() {
    gate(&open_swap_merging());
}

#[test]
fn execute_named_swap() {
    gate(&named_swap());
}

#[test]
fn execute_withdraw_shielded_emptying_the_pool() {
    gate(&withdraw_shielded_emptying_the_pool());
}

// ---- Q3 bar B: replay the accepted runs through Midnight's reference VM ----------------------------
//
// The owner's Q3 resolution adds bar B for `execute`: replay accepted runs through Midnight's
// reference VM/ledger, as minocrab's own spec suite does. See `support::replay` for the mechanics —
// the op stream is DECODED from the bar-A preimage's own `public_transcript_inputs` and re-encoded
// as a check, so bar B runs exactly the program bar A compared.
//
// What a green replay adds over bar A: the transcript is a well-formed Impact program (stack
// discipline, cache discipline, `Idx` paths that exist), every `Popeq` result MATCHES a real ledger
// state (`ResultModeVerify::process_read` errors otherwise), and the post-state is the state the
// contract intends. That last clause is what turns the scenario's hand-written ledger answers from
// an assertion into a fact.

use support::replay;

/// Field indices, from the ledger block's declaration order.
const F_ACCOUNTS: usize = 1;
const F_ACCOUNT_MODES: usize = 4;
const F_EVM_OWNERS: usize = 5;
const F_EVM_NONCES: usize = 6;

/// Decode the accepted run's transcript, check it re-encodes exactly, and run it.
fn replay_accepted(
    scenario: &Scenario,
    pre: &replay::PreState,
    block_time_secs: u64,
) -> replay::Executed {
    let theirs = theirs("execute");
    let pi = synthesize(&theirs, &scenario.preimage())
        .unwrap_or_else(|e| panic!("{}: {e}", scenario.name));

    let ops = replay::decode_ops(&pi.public_transcript_inputs)
        .unwrap_or_else(|e| panic!("{}: the transcript is not a well-formed op stream: {e}", scenario.name));
    replay::assert_round_trip(&ops, &pi.public_transcript_inputs);

    let executed = replay::run(pre, &self_addr(), block_time_secs, &ops).unwrap_or_else(|e| {
        panic!(
            "{}: the reference VM REJECTED the accepted run: {e}\n\
             (`ResultModeVerify` checks every Popeq against the real state, so this means the \
             scenario's ledger answers do not describe a state the VM would produce.)",
            scenario.name
        )
    });
    println!(
        "REPLAY {}: {} ops accepted by the reference VM, post-state produced",
        scenario.name,
        ops.len()
    );
    executed
}

#[test]
fn replay_native_registration() {
    let sc = native_registration();
    let pre = replay::PreState {
        deployment_domain: deployment_domain(),
        ..replay::PreState::default()
    };
    let out = replay_accepted(&sc, &pre, 0);

    // The account the witness derives is what must have been registered — not something the
    // caller supplied. `p.account` is all-zero for selector 0 ("native registration account is
    // derived"), so if the post-state carries this key the derivation is the contract's own.
    let account = owner_commitment(&owner_secret());
    assert!(
        replay::map_member(&out.post, F_ACCOUNTS, &account),
        "the witness-derived account is not in `accounts` after the call"
    );
    assert_eq!(
        replay::map_get_uint(&out.post, F_ACCOUNT_MODES, &account),
        Some(0),
        "`accountModes` must record native mode 0"
    );
    assert!(
        !replay::map_member(&out.post, F_EVM_OWNERS, &account),
        "a native registration must not create an `evmOwners` record"
    );
    assert!(
        !replay::map_member(&out.post, F_EVM_NONCES, &account),
        "a native registration must not create an `evmNonces` record"
    );
}

#[test]
fn replay_evm_registration() {
    let sc = evm_registration();
    let account = sc.payload.account;
    let owner = sc.payload.owner;
    let pre = replay::PreState {
        deployment_domain: deployment_domain(),
        ..replay::PreState::default()
    };
    // `validUntil` is 4,000 and the horizon is 3,600, so any block time in [400, 4,000) is live.
    let out = replay_accepted(&sc, &pre, 1_000);

    assert!(
        replay::map_member(&out.post, F_ACCOUNTS, &account),
        "the derived EVM account id is not in `accounts` after the call"
    );
    assert_eq!(
        replay::map_get_uint(&out.post, F_ACCOUNT_MODES, &account),
        Some(1),
        "`accountModes` must record EVM mode 1"
    );
    assert_eq!(
        replay::map_get(&out.post, F_EVM_OWNERS, &account).as_deref(),
        Some(&owner[..]),
        "`evmOwners` must record the signing EOA"
    );
    assert_eq!(
        replay::map_get_uint(&out.post, F_EVM_NONCES, &account),
        Some(0),
        "an EVM registration stores nonce 0, not the incremented one"
    );
}

/// Bar B on a CUSTODY selector: the pool read, `sendShielded`'s nullifier and spend claims, the
/// removal arm of `repoolOrRemove`, and the debit write — replayed against a real pre-state that
/// actually holds the account, its mode, its colour balance and the pooled coin.
///
/// This is the "emptied pool" scenario deliberately: with zero change there is no `insertCoin`, and
/// `insertCoin` is the one op that needs the transaction's coin-commitment index map
/// (`CallContext::com_indices`) — see the note on remaining bar-B coverage in the plan.
#[test]
fn replay_withdraw_shielded_emptying_the_pool() {
    let sc = withdraw_shielded_emptying_the_pool();
    let account = owner_commitment(&owner_secret());
    let debit_key = family_key(&account, &a_colour(), &shielded_tag());
    let pre = replay::PreState {
        pools: vec![(
            a_colour(),
            replay::pool_coin(&[9u8; 32], &a_colour(), 100, 0),
        )],
        accounts: vec![account],
        shielded_balances: vec![(debit_key, 1_000)],
        account_modes: vec![(account, 0)],
        deployment_domain: deployment_domain(),
        ..replay::PreState::default()
    };
    let out = replay_accepted(&sc, &pre, 0);

    assert!(
        !replay::map_member(&out.post, 0, &a_colour()),
        "the colour must leave `pools` entirely when the pooled coin is fully spent"
    );
    assert_eq!(
        replay::map_get_uint(&out.post, 2, &debit_key),
        Some(900),
        "the per-(account, colour) cell must be debited by the withdrawn amount"
    );
    assert!(
        replay::map_member(&out.post, F_ACCOUNTS, &account),
        "the account must still be registered"
    );
    assert_eq!(
        out.effects.claimed_nullifiers.size(),
        1,
        "spending the pooled coin must claim exactly one nullifier"
    );
    assert_eq!(
        out.effects.claimed_shielded_spends.size(),
        1,
        "the payout must claim exactly one shielded spend"
    );
    assert_eq!(
        out.effects.claimed_shielded_receives.size(),
        0,
        "paying a user address claims no receive"
    );
    println!(
        "REPLAY effects: {} nullifier(s), {} spend(s), {} receive(s)",
        out.effects.claimed_nullifiers.size(),
        out.effects.claimed_shielded_spends.size(),
        out.effects.claimed_shielded_receives.size()
    );
}

/// **Bar B on a selector PR#9 GAVE BACK** (plan task 3.2): selector 3, the unshielded withdrawal.
///
/// This is the strongest single check in the project, because it closes over BOTH statement changes
/// that touch this path at once:
///
/// * **PR#9** — the run exists at all. On the `0eccb66` line the `pooled.value − primaryAmount`
///   underflow meant there was no preimage to decode, so this replay could not have been written.
/// * **PR#10 / F-00020-01** — the reference VM records the payout's recipient in
///   `effects.claimed_unshielded_spends`, keyed by `(TokenType, PublicAddress)`. `PublicAddress` is
///   the ledger's OWN tagged enum, so asserting `User(p.recipient)` here is the ledger itself
///   confirming the recipient tag — the exact thing project 00016 found wrong — and, because the
///   key is built from the muxed `Either`, it is also what pins the unselected arm to the type
///   default rather than to a second copy of `p.recipient`.
#[test]
fn replay_withdraw_unshielded_native() {
    use midnight_coin_structure::coin::{PublicAddress, UserAddress};
    use std::ops::Deref;

    let sc = withdraw_unshielded_native();
    let account = owner_commitment(&owner_secret());
    let debit_key = family_key(&account, &a_colour(), &unshielded_tag());
    let pre = replay::PreState {
        accounts: vec![account],
        unshielded_balances: vec![(debit_key, 1_000)],
        account_modes: vec![(account, 0)],
        deployment_domain: deployment_domain(),
        // `unshieldedBalanceGte(col, val)` reads the contract's KERNEL balance, not a ledger cell.
        kernel_unshielded_balance: vec![(a_colour(), 5_000)],
        ..replay::PreState::default()
    };
    let out = replay_accepted(&sc, &pre, 0);

    assert_eq!(
        replay::map_get_uint(&out.post, 3, &debit_key),
        Some(900),
        "the per-(account, colour) unshielded cell must be debited by the withdrawn amount"
    );

    assert_eq!(
        out.effects.claimed_unshielded_spends.size(),
        1,
        "an unshielded withdrawal must claim exactly one unshielded spend"
    );
    let mut seen = Vec::new();
    for entry in out.effects.claimed_unshielded_spends.iter() {
        let (k, v) = entry.deref();
        let key = k.deref().clone();
        let amount: u128 = *v.deref();
        seen.push((key.into_inner().1, amount));
    }
    let (addr, amount) = seen.pop().expect("one claimed spend");
    assert_eq!(amount, 100, "the claimed amount must be the withdrawn amount");
    assert_eq!(
        addr,
        PublicAddress::User(UserAddress(midnight_base_crypto::hash::HashOutput(
            a_recipient()
        ))),
        "PR#10: an unshielded withdrawal to `recipientKind == 0` must be recorded by the ledger as \
         a USER address. A `Contract(..)` here is exactly the defect project 00016 found, and a \
         `User(..)` carrying the wrong bytes would mean the `Either` arms are muxed wrong \
         (F-00020-01)."
    );
    println!(
        "REPLAY effects (selector 3): 1 claimed unshielded spend, {} unshielded output(s), \
         recipient = PublicAddress::User",
        out.effects.unshielded_outputs.size()
    );
}
