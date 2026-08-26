//! Emit every ported circuit's ZKIR, one `<name>.zkir` per circuit, into a directory.
//!
//! The output of this binary is the **minocrab side** of every comparison row; it is then fed to
//! the SAME `zkir-v3 mock-compile` oracle as the compactc baseline (`scripts/measure-zkir.sh`),
//! which is what makes the two columns comparable (FR-005).
//!
//! ```text
//! cargo +1.95.0 run --release -p manager-port --bin emit-zkir -- <out-dir> [circuit-name ...]
//! ```
//!
//! With no circuit names, every circuit in `manager_port::circuits()` is emitted.

use std::collections::BTreeSet;

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = match args.next() {
        Some(d) => d,
        None => {
            eprintln!("usage: emit-zkir <out-dir> [circuit-name ...]");
            std::process::exit(64);
        }
    };
    let wanted: BTreeSet<String> = args.collect();

    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("creating {dir}: {e}"));

    let circuits = manager_port::circuits();
    let mut emitted = 0usize;
    for (name, build) in &circuits {
        if !wanted.is_empty() && !wanted.contains(*name) {
            continue;
        }
        let compiled = build();
        let text = minocrab_zkir::v3::to_zkir_string(&compiled.ir)
            .unwrap_or_else(|e| panic!("serializing {name}: {e}"));
        let path = format!("{dir}/{name}.zkir");
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("writing {path}: {e}"));
        println!("EMITTED={name} PATH={path}");
        emitted += 1;
    }

    if !wanted.is_empty() {
        let known: BTreeSet<&str> = circuits.iter().map(|(n, _)| *n).collect();
        let unknown: Vec<&String> = wanted.iter().filter(|w| !known.contains(w.as_str())).collect();
        if !unknown.is_empty() {
            eprintln!("unknown circuit(s): {unknown:?}");
            eprintln!("known: {known:?}");
            std::process::exit(65);
        }
    }

    println!("EMIT_COUNT={emitted}");
}
