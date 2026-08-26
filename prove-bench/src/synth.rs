//! The transcript synthesizer: derive a run's `public_transcript_inputs` from an artifact by
//! fixpoint, using **upstream's own** `Zkir::check` → `IrSource::preprocess`.
//!
//! # Why this is not circular
//!
//! A benchmark cell needs ONE `ProofPreimage` that BOTH artifacts accept, so that the prove times
//! being compared are times for the same statement on the same witness. The scenario supplies the
//! hand-written half — the 33 circuit inputs, the two-element owner-secret witness and the ledger's
//! answers — and `public_transcript_inputs` (every ledger op the run takes, field-encoded) is
//! **derived from the compactc artifact**, never from the minocrab one. The minocrab artifact is
//! then run on the result and must accept it unchanged.
//!
//! # How it works
//!
//! The VM checks each `impact`'s field-encoded operands against the supplied vector and reports
//! `Public transcript input mismatch for input {idx}; expected: …; computed: Some({fr:?})`
//! (`zkir-v3/src/ir_vm.rs`, `I::Impact`). Writing the computed value at the reported index makes
//! progress every iteration, so the loop terminates. `Fr`'s `Debug` is its trimmed little-endian
//! hex, so the reported value round-trips without loss.
//!
//! Ported from 00012's `tests/support/synth.rs`; the only change is that the fixpoint is driven by
//! upstream's `Zkir::check` instead of minocrab's `simulate`, so the harness links no minocrab code.

use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::{ProofPreimage, Zkir};
use midnight_zkir_v3::IrSource;

/// One VM run. Panics inside upstream (a too-short transcript slices out of range) are turned into
/// ordinary errors so the driver can report them instead of dying.
pub fn check(ir: &IrSource, pi: &ProofPreimage) -> Result<Vec<Option<usize>>, String> {
    let ir = ir.clone();
    let pi = pi.clone();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = std::panic::catch_unwind(move || ir.check(&pi));
    std::panic::set_hook(hook);
    match out {
        Ok(Ok(skips)) => Ok(skips),
        Ok(Err(e)) => Err(format!("{e}")),
        Err(_) => Err("PANIC inside the VM (usually: too few ledger answers supplied)".into()),
    }
}

/// Grow `base.public_transcript_inputs` until `reference` accepts the preimage.
pub fn synthesize(reference: &IrSource, base: &ProofPreimage) -> Result<ProofPreimage, String> {
    let mut pi = base.clone();
    pi.public_transcript_inputs.clear();

    const MAX_ITERATIONS: usize = 20_000;
    for _ in 0..MAX_ITERATIONS {
        match check(reference, &pi) {
            Ok(_) => return Ok(pi),
            Err(msg) => match parse_mismatch(&msg) {
                Some((idx, value)) => {
                    if idx >= pi.public_transcript_inputs.len() {
                        pi.public_transcript_inputs.resize(idx + 1, Fr::from(0u64));
                    } else if pi.public_transcript_inputs[idx] == value {
                        return Err(format!(
                            "the synthesizer stalled: element {idx} already holds the value the \
                             reference computed. Message: {msg}"
                        ));
                    }
                    pi.public_transcript_inputs[idx] = value;
                }
                None => {
                    return Err(format!(
                        "the reference REJECTED the scenario: {msg}\n\
                         (a rejection here is usually a MODEL error — check the ledger answers in \
                         `public_transcript_outputs`: a wrong one trips one of the contract's own \
                         asserts by name.)"
                    ))
                }
            },
        }
    }
    Err(format!(
        "the synthesizer did not converge in {MAX_ITERATIONS} iterations"
    ))
}

fn parse_mismatch(msg: &str) -> Option<(usize, Fr)> {
    let idx: usize = msg
        .split("for input ")
        .nth(1)?
        .split(';')
        .next()?
        .trim()
        .parse()
        .ok()?;
    let computed = msg.split("computed: ").nth(1)?.trim();
    let hex = computed.strip_prefix("Some(")?;
    let hex = hex.split(')').next()?.trim();
    Some((idx, fr_from_debug(hex)?))
}

/// `Fr`'s `Debug` is its trimmed little-endian hex (`-` for zero).
fn fr_from_debug(text: &str) -> Option<Fr> {
    if text == "-" {
        return Some(Fr::from(0u64));
    }
    if text.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks(2) {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
    }
    Fr::from_le_bytes(&bytes)
}
