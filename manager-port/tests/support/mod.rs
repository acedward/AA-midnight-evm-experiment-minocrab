//! Shared machinery for the `execute` equivalence gate (plan task 3.6).
//!
//! Two pieces, and the split matters:
//!
//! - [`synth`] — the **transcript synthesizer**. Q3 bar A needs a `ProofPreimage` that BOTH
//!   artifacts accept, and the expensive half of one is `public_transcript_inputs`: the field
//!   encoding of every Impact op the run takes. It is derived here from the **compactc artifact**
//!   by fixpoint, never from the port — see [`synth::synthesize`] for why that is sound and why it
//!   is not circular.
//! - [`model`] — the **off-circuit model**: the scenario's arguments, its witness, and the
//!   ledger's answers. This is the part that must be written by hand, and it is deliberately small:
//!   a guarded-off Impact consumes no transcript, so one selector's run reads a dozen-odd values,
//!   not all 64 gates.
//!
//! Not a test target (a subdirectory of `tests/`); each binary that wants it declares `mod support;`.
#![allow(dead_code)]

pub mod model;
pub mod replay;
pub mod synth;
