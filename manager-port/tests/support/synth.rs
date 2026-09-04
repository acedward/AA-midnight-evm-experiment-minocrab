//! The transcript synthesizer: derive a run's `public_transcript_inputs` from the **compactc
//! artifact**, so that Q3 bar A has a shared `ProofPreimage` both artifacts can be run on.
//!
//! # Why this is not circular
//!
//! Bar A asks for *one* preimage that both artifacts accept, with equal PI vectors and equal
//! `pi_skips`. Nothing says how the preimage is built; minocrab's own kit hand-writes one from a
//! reference model. Here it is derived from the **reference** — the compactc artifact — and never
//! from the port. Concretely:
//!
//! - the scenario supplies the circuit `inputs`, the `private_transcript` (the owner secret) and
//!   the `public_transcript_outputs` (what the ledger answers). Those are the honest, hand-written
//!   half, and they are what a wrong model gets caught on: a wrong answer trips one of the
//!   contract's own asserts, by name.
//! - `public_transcript_inputs` — every ledger op the run takes, field-encoded — is then computed
//!   BY THE COMPACTC ARTIFACT, one element at a time.
//!
//! So the resulting preimage is "the transcript compactc produces for this scenario". Running the
//! port on it and comparing PI vectors is exactly the question bar A asks: *does the port compute
//! the same public statement?* A port bug still fails, and fails loudly — the port's own
//! `simulate` reports the first element on which it disagrees with the reference.
//!
//! # How it works
//!
//! `minocrab-sim`'s v3 `Impact` handler computes each op's field elements, pushes them into `pis`,
//! and then compares them to the preimage's declared `public_transcript_inputs`; on a mismatch it
//! reports `expected` (what we supplied) and `computed` (what the artifact says it should be)
//! together with the index (`crates/minocrab-sim/src/v3.rs:625-655`). Start from an empty
//! transcript, re-simulate, write the reported `computed` value at the reported index, repeat. Each
//! iteration fixes at least one element, so the loop terminates; the run is accepted exactly when
//! every element agrees.
//!
//! `Fr`'s `Debug` is its trimmed little-endian hex (`transient-crypto/src/macros.rs:94-117`), so
//! the reported value round-trips through `Fr::from_le_bytes` without loss.

use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab_sim::v3::Sim3Error;
use minocrab_zkir::v3::IrSource;

/// Grow `base.public_transcript_inputs` until `reference` accepts the preimage.
///
/// `base` carries the scenario: `inputs`, `private_transcript`, `public_transcript_outputs`,
/// `binding_input` and the communications commitment. Its `public_transcript_inputs` is ignored and
/// rebuilt.
pub fn synthesize(reference: &IrSource, base: &ProofPreimage) -> Result<ProofPreimage, String> {
    match synthesize_partial(reference, base) {
        (pi, None) => Ok(pi),
        (_, Some(e)) => Err(e),
    }
}

/// [`synthesize`], keeping the transcript derived so far when the reference refuses the run.
///
/// A scenario the reference cannot accept is not necessarily a model error — see
/// `execute_differential.rs`'s selector-3/4/5 tests, where the *contract* has no accepted run —
/// and the partial transcript is what lets the port be asked the same question.
pub fn synthesize_partial(
    reference: &IrSource,
    base: &ProofPreimage,
) -> (ProofPreimage, Option<String>) {
    let mut pi = base.clone();
    pi.public_transcript_inputs.clear();

    // One iteration per transcript element, plus slack for the truncation steps. `execute`'s
    // biggest scenario is a few hundred elements.
    const MAX_ITERATIONS: usize = 20_000;
    for _ in 0..MAX_ITERATIONS {
        match minocrab_sim::v3::simulate(reference, &pi) {
            Ok(_) => return (pi, None),
            Err(Sim3Error::Failed { op: "impact", message, .. }) => {
                let Some((index, value)) = parse_impact_mismatch(&message) else {
                    return (
                        pi,
                        Some(format!("unparseable Impact mismatch from the reference: {message}")),
                    );
                };
                // Extending the vector is progress even when the computed value happens to be the
                // zero we padded with: the run gets one element further next time. A stall is only
                // an element that was already in range and already correct.
                let extended = index >= pi.public_transcript_inputs.len();
                if extended {
                    pi.public_transcript_inputs
                        .resize(index + 1, Fr::from(0u64));
                } else if pi.public_transcript_inputs[index] == value {
                    return (
                        pi,
                        Some(format!(
                            "the synthesizer stalled: element {index} already holds the value the \
                             reference computed. Message: {message}"
                        )),
                    );
                }
                pi.public_transcript_inputs[index] = value;
            }
            Err(Sim3Error::Transcript(message)) => {
                // "public inputs {consumed}/{supplied}, …" — the run finished but the transcript
                // is longer than what it consumed, which happens once the last element is fixed.
                let Some(consumed) = parse_consumed(&message) else {
                    return (
                        pi,
                        Some(format!("unparseable transcript-length report: {message}")),
                    );
                };
                if consumed >= pi.public_transcript_inputs.len() {
                    let supplied = pi.public_transcript_inputs.len();
                    return (
                        pi,
                        Some(format!(
                            "the reference consumed {consumed} public transcript inputs but only \
                             {supplied} were supplied — the scenario is under-specified: {message}"
                        )),
                    );
                }
                pi.public_transcript_inputs.truncate(consumed);
            }
            Err(other) => {
                return (
                    pi,
                    Some(format!(
                        "the compactc artifact REJECTED the scenario: {other}\n\
                         (a rejection here is usually a MODEL error — the port has not run yet, so \
                         check the ledger answers in `public_transcript_outputs`: a wrong one trips \
                         one of the contract's own asserts. It can also be the CONTRACT refusing, \
                         which is finding F-00012-08.)"
                    )),
                )
            }
        }
    }
    (
        pi,
        Some(format!(
            "the synthesizer did not converge in {MAX_ITERATIONS} iterations"
        )),
    )
}

/// `"public transcript input mismatch for input 12; expected: None, computed: Some(0a1b…)"`.
fn parse_impact_mismatch(message: &str) -> Option<(usize, Fr)> {
    let index: usize = message
        .split("for input ")
        .nth(1)?
        .split(';')
        .next()?
        .trim()
        .parse()
        .ok()?;
    let computed = message.split("computed: ").nth(1)?.trim();
    let hex = computed.strip_prefix("Some(")?.strip_suffix(')')?.trim();
    Some((index, fr_from_debug(hex)?))
}

/// `Fr`'s `Debug`, inverted: trimmed little-endian hex, or `-` for zero.
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

/// `"public inputs 40/41, public outputs 13/13, private 2/2"` → 40.
fn parse_consumed(message: &str) -> Option<usize> {
    message
        .split("public inputs ")
        .nth(1)?
        .split('/')
        .next()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_debug_round_trips() {
        for v in [0u64, 1, 42, 0xdead_beef, u64::MAX] {
            let f = Fr::from(v);
            assert_eq!(
                fr_from_debug(&format!("{f:?}")),
                Some(f),
                "round trip of {v}"
            );
        }
    }

    #[test]
    fn messages_parse() {
        assert_eq!(
            parse_impact_mismatch(
                "public transcript input mismatch for input 7; expected: None, computed: Some(2a)"
            ),
            Some((7, Fr::from(42u64)))
        );
        assert_eq!(
            parse_consumed("public inputs 40/41, public outputs 13/13, private 2/2"),
            Some(40)
        );
    }
}
