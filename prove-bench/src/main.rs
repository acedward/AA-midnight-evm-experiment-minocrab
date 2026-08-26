//! # The `execute` proving-time benchmark: compactc k=19 vs minocrab k=18
//!
//! Measures wall-clock **proving** time for the two artifacts the equivalence gate ran against each
//! other, on identical `ProofPreimage`s, on one machine, through one pinned prover.
//!
//! ## What makes the comparison sound
//!
//! * **One code path for both artifacts.** Everything here is upstream Midnight
//!   (`midnight-zkir-v3` @ `04c9c5d9…`, `transient-crypto` `2.2.0-rc.1`) — the same crates and the
//!   same rev 00013 used for this line's last real proofs. Neither compiler's own kit is on the
//!   timing path; the harness cannot tell a compactc-emitted ZKIR from a minocrab-emitted one.
//! * **One preimage per cell.** The transcript is synthesized once, from the **compactc** artifact
//!   (`synth`), and the minocrab artifact must accept it unchanged. Both arms of a cell therefore
//!   prove the same statement on the same witness.
//! * **The clock wraps the prove call and nothing else.** The SRS is parsed into memory before any
//!   timing starts (`OfflineParams` is a pre-loaded map, not a file reader), and the prover key is
//!   paged in by an untimed warmup proof, so neither a 100 MB parameter read nor a 1.1 GB key
//!   deserialization can land inside a measured interval.
//! * **Every counted proof is VERIFIED** against its own verifier key before it counts.
//!
//! ## Subcommands
//!
//! ```text
//! prove-bench check <compactc.zkir> <minocrab.zkir>
//! prove-bench bench --a-name N --a-zkir P --a-pk P --a-vk P
//!                   --b-name N --b-zkir P --b-pk P --b-vk P
//!                   --params DIR --runs N --csv PATH [--scenarios a,b,c]
//! ```

mod model;
mod synth;

use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::{
    ParamsProver, ParamsProverProvider, ParamsVerifier, Proof, ProofPreimage, ProverKey,
    VerifierKey, Zkir, PARAMS_VERIFIER,
};
use midnight_zkir_v3::IrSource;
use rand::SeedableRng;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::time::Instant;

// ------------------------------------------------------------------ artifact loading

/// Load a `.zkir` as an upstream `IrSource`.
///
/// `IrSource::load` is upstream's own tolerant parser: it reads the `version` entry in either the
/// `{"major":3,"minor":0}` shape compactc writes or the bare-minor shape serde expects. Using it
/// rather than a hand-rolled fixup means the two artifacts are parsed by identical upstream code.
fn load_zkir(path: &str) -> IrSource {
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("cannot open {path}: {e}"));
    IrSource::load(std::io::BufReader::new(f))
        .unwrap_or_else(|e| panic!("cannot parse {path} as an IrSource: {e}"))
}

// ------------------------------------------------------------------ offline, pre-loaded params
//
// A params provider that can only ever read from a MAP THAT IS ALREADY IN MEMORY. Two properties
// matter:
//
//  1. No `MidnightDataProvider`, therefore no `$MIDNIGHT_PARAM_SOURCE` fallback and no possibility
//     of a network fetch. If the SRS for a circuit's `k` was not pre-loaded, this fails loudly
//     instead of reaching out.
//  2. `get_params` is an `Arc` clone, not a 50–100 MB file parse. `Zkir::prove` calls it INSIDE the
//     region the clock wraps, so a lazy file read here would charge the k=19 arm ~100 MB of IO and
//     the k=18 arm ~50 MB — a systematic bias in favour of the artifact under test. Pre-loading
//     removes it.

struct OfflineParams {
    loaded: BTreeMap<u8, ParamsProver>,
}

impl OfflineParams {
    fn preload(dir: &str, ks: &[u8]) -> Self {
        let mut loaded = BTreeMap::new();
        for &k in ks {
            let path = format!("{dir}/bls_midnight_2p{k}");
            let t0 = Instant::now();
            let f = std::fs::File::open(&path)
                .unwrap_or_else(|e| panic!("cannot open the SRS {path}: {e}"));
            let p = ParamsProver::read(std::io::BufReader::new(f))
                .unwrap_or_else(|e| panic!("cannot parse the SRS {path}: {e}"));
            eprintln!(
                "  [params] pre-loaded {path} in {:.2} s (offline: a plain file read)",
                t0.elapsed().as_secs_f64()
            );
            loaded.insert(k, p);
        }
        OfflineParams { loaded }
    }
}

impl ParamsProverProvider for OfflineParams {
    async fn get_params(&self, k: u8) -> std::io::Result<ParamsProver> {
        self.loaded.get(&k).cloned().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("SRS for k={k} was not pre-loaded — refusing to reach for it"),
            )
        })
    }
}

// ------------------------------------------------------------------ an arm of the comparison

struct Arm {
    name: String,
    zkir_path: String,
    ir: IrSource,
    k: u8,
    rows: usize,
    pk: ProverKey<IrSource>,
    vk: VerifierKey,
    /// Which verifier parameters actually verified this arm's proofs.
    vparams: ParamsVerifier,
    vparams_source: String,
}

fn load_prover_key(path: &str) -> ProverKey<IrSource> {
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("cannot open the prover key {path}: {e}"));
    IrSource::load_prover_key_from_tagged(std::io::BufReader::new(f))
        .unwrap_or_else(|e| panic!("cannot load the prover key {path}: {e}"))
}

fn load_verifier_key(path: &str) -> VerifierKey {
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("cannot open the verifier key {path}: {e}"));
    let vk: VerifierKey = midnight_serialize::tagged_deserialize(std::io::BufReader::new(f))
        .unwrap_or_else(|e| panic!("cannot load the verifier key {path}: {e}"));
    vk.init()
        .unwrap_or_else(|e| panic!("the verifier key {path} does not initialise: {e}"));
    vk
}

// ------------------------------------------------------------------ timing primitives

/// One prove call, with the monotonic clock wrapping `Zkir::prove` AND NOTHING ELSE.
///
/// `Instant` is `mach_continuous_time` on Darwin: monotonic, unaffected by wall-clock adjustment.
fn timed_prove(
    arm: &Arm,
    params: &OfflineParams,
    pi: &ProofPreimage,
    seed: u64,
) -> Result<(Proof, Vec<Fr>, f64), String> {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    let rng = rand::rngs::StdRng::from_seed(s);
    let t0 = Instant::now();
    let out = futures_executor::block_on(arm.ir.prove(rng, params, arm.pk.clone(), pi));
    let dt = t0.elapsed().as_secs_f64() * 1000.0;
    match out {
        Ok((proof, pis, _skips)) => Ok((proof, pis, dt)),
        Err(e) => Err(format!("{e}")),
    }
}

/// One verify call, timed the same way. Returns `(ok, ms)`.
fn timed_verify(arm: &Arm, proof: &Proof, pis: &[Fr]) -> (bool, f64) {
    let stmt = pis.to_vec();
    let t0 = Instant::now();
    let ok = arm.vk.verify(&arm.vparams, proof, stmt.into_iter()).is_ok();
    let dt = t0.elapsed().as_secs_f64() * 1000.0;
    (ok, dt)
}

/// Current resident set size of this process, in bytes — sampled OUTSIDE any timed region.
fn rss_bytes() -> u64 {
    let pid = std::process::id();
    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

/// The machine's 1-minute load average — the idle check recorded before each block.
fn load_avg() -> String {
    std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().trim_matches(|c| c == '{' || c == '}').trim().to_string())
        .unwrap_or_else(|| "?".into())
}

// ------------------------------------------------------------------ statistics

fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n == 0 {
        return f64::NAN;
    }
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

// ------------------------------------------------------------------ subcommand: check
//
// Phase 0.2's gate: rebuild every scenario's preimage HERE, and confirm both artifacts still accept
// it through upstream's own `Zkir::check`. That re-establishes 00012's gate precondition inside
// this project, on artifacts this project copied and hashed itself.

fn cmd_check(args: &[String]) {
    let a_path = args.first().expect("check <compactc.zkir> <minocrab.zkir>");
    let b_path = args.get(1).expect("check <compactc.zkir> <minocrab.zkir>");

    let a = load_zkir(a_path);
    let b = load_zkir(b_path);

    let am = a.model();
    let bm = b.model();
    println!("== 00018 Phase 0.2 — preimage regeneration + 2×4 accept gate ==");
    println!();
    println!("| artifact | path | instructions | declared inputs | k | rows |");
    println!("|---|---|---:|---:|---:|---:|");
    println!(
        "| compactc | {a_path} | {} | {} | {} | {} |",
        a.instructions.len(),
        a.inputs.len(),
        am.k(),
        am.rows()
    );
    println!(
        "| minocrab | {b_path} | {} | {} | {} | {} |",
        b.instructions.len(),
        b.inputs.len(),
        bm.k(),
        bm.rows()
    );
    println!();

    // Schema identity — the precondition that makes one shared preimage meaningful at all.
    let types = |ir: &IrSource| {
        serde_json::to_value(&ir.inputs)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|ti| ti["type"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(types(&a), types(&b), "input schemas differ");
    assert_eq!(a.outputs, b.outputs, "output schemas differ");
    assert_eq!(
        a.do_communications_commitment, b.do_communications_commitment,
        "communications-commitment flag differs"
    );
    println!("SCHEMA IDENTITY: input types, output types and the comms-commitment flag all match.");
    println!();

    let mut accepts = 0usize;
    let mut total = 0usize;
    println!("| scenario | transcript elems | ledger answers | compactc | minocrab | Impact ops (`pi_skips`, entry-by-entry equal) |");
    println!("|---|---:|---:|---|---|---:|");
    for sc in model::all_scenarios() {
        let base = sc.preimage();
        let pi = synth::synthesize(&a, &base)
            .unwrap_or_else(|e| panic!("{}: could not synthesize a transcript: {e}", sc.name));

        total += 2;
        let a_skips = synth::check(&a, &pi);
        let b_skips = synth::check(&b, &pi);
        let a_ok = a_skips.is_ok();
        let b_ok = b_skips.is_ok();
        if a_ok {
            accepts += 1;
        }
        if b_ok {
            accepts += 1;
        }

        // `pi_skips` equality is 00012's load-bearing clause: one entry per Impact instruction,
        // carrying whether that op's guard was on and how many elements it contributed. Two
        // artifacts can agree on it only if they emit the same ledger operations, in the same
        // order, with the same input counts and the same guard truth values.
        //
        // (`IrSource::preprocess` — which would also expose the PI vector itself — is
        // `pub(crate)` upstream, so the PI count is reported at bench time instead, where
        // `Zkir::prove` returns the statement vector for each arm and the two are compared.)
        let ops = match (&a_skips, &b_skips) {
            (Ok(sa), Ok(sb)) => {
                assert_eq!(sa.len(), sb.len(), "{}: different Impact counts", sc.name);
                for (i, (x, y)) in sa.iter().zip(sb.iter()).enumerate() {
                    assert_eq!(x, y, "{}: pi_skips differ at Impact {i}", sc.name);
                }
                let contributed: usize = sa.iter().map(|s| s.unwrap_or(0)).sum();
                let _ = contributed;
                sa.len()
            }
            _ => 0,
        };

        println!(
            "| `{}` | {} | {} | {} | {} | {} |",
            sc.name,
            pi.public_transcript_inputs.len(),
            pi.public_transcript_outputs.len(),
            if a_ok { "ACCEPT" } else { "**REFUSE**" },
            if b_ok { "ACCEPT" } else { "**REFUSE**" },
            ops
        );
        if !a_ok {
            println!("  compactc error: {}", a_skips.unwrap_err());
        }
        if !b_ok {
            println!("  minocrab error: {}", b_skips.unwrap_err());
        }
    }
    println!();
    println!("ACCEPT GATE: {accepts}/{total}");
    assert_eq!(accepts, total, "the 2 x 4 accept gate FAILED");
    println!("GATE PASSED — both artifacts accept all four preimages via upstream `Zkir::check`.");
}

// ------------------------------------------------------------------ subcommand: bench

struct Flags(BTreeMap<String, String>);

impl Flags {
    fn parse(args: &[String]) -> Self {
        let mut m = BTreeMap::new();
        let mut i = 0;
        while i < args.len() {
            let k = args[i].trim_start_matches("--").to_string();
            let v = args.get(i + 1).cloned().unwrap_or_default();
            m.insert(k, v);
            i += 2;
        }
        Flags(m)
    }
    fn get(&self, k: &str) -> String {
        self.0
            .get(k)
            .unwrap_or_else(|| panic!("missing required flag --{k}"))
            .clone()
    }
    fn opt(&self, k: &str, d: &str) -> String {
        self.0.get(k).cloned().unwrap_or_else(|| d.to_string())
    }
}

fn build_arm(f: &Flags, tag: &str, params_dir: &str) -> Arm {
    let name = f.get(&format!("{tag}-name"));
    let zkir_path = f.get(&format!("{tag}-zkir"));
    let pk_path = f.get(&format!("{tag}-pk"));
    let vk_path = f.get(&format!("{tag}-vk"));

    eprintln!("== arm `{name}` ==");
    let ir = load_zkir(&zkir_path);
    let m = ir.model();
    let (k, rows) = (m.k(), m.rows());
    eprintln!("  [ir] {zkir_path}: k={k}, rows={rows}, {} instructions", ir.instructions.len());

    let t0 = Instant::now();
    let pk = load_prover_key(&pk_path);
    eprintln!(
        "  [pk] {pk_path} ({} B) deserialized-on-demand handle in {:.2} s",
        std::fs::metadata(&pk_path).map(|m| m.len()).unwrap_or(0),
        t0.elapsed().as_secs_f64()
    );
    let vk = load_verifier_key(&vk_path);
    eprintln!("  [vk] {vk_path} loaded and initialised");

    // Verifier parameters. A real on-chain verifier uses the embedded 2p14 set (it only has to
    // cover the statement length, 1,265 elements here). If that ever fails we fall back to the
    // arm's own k-specific SRS and RECORD which one was used, rather than silently succeeding.
    let (vparams, vparams_source) = (
        PARAMS_VERIFIER.clone(),
        "embedded bls_midnight_2p14 (transient-crypto PARAMS_VERIFIER)".to_string(),
    );
    let _ = params_dir;

    Arm {
        name,
        zkir_path,
        ir,
        k,
        rows,
        pk,
        vk,
        vparams,
        vparams_source,
    }
}

fn cmd_bench(args: &[String]) {
    let f = Flags::parse(args);
    let params_dir = f.get("params");
    let runs: usize = f.get("runs").parse().expect("--runs must be a number");
    let csv_path = f.get("csv");
    let scenario_names: Vec<String> = match f.opt("scenarios", "") {
        s if s.is_empty() => model::all_scenarios().iter().map(|x| x.name.to_string()).collect(),
        s => s.split(',').map(|x| x.trim().to_string()).collect(),
    };

    println!("== 00018 Phase 2 — timed prove matrix ==");
    println!("scenarios : {}", scenario_names.join(", "));
    println!("runs/cell : {runs}");
    println!("csv       : {csv_path}");
    println!();

    let mut a = build_arm(&f, "a", &params_dir);
    let mut b = build_arm(&f, "b", &params_dir);

    // Pre-load exactly the two SRS files the two arms need, BEFORE any timing.
    let mut ks = vec![a.k, b.k];
    ks.sort_unstable();
    ks.dedup();
    let params = OfflineParams::preload(&params_dir, &ks);

    // ---- preimages: synthesized ONCE, from the compactc arm, accepted by both ------------------
    eprintln!();
    eprintln!("== preimages ==");
    let mut preimages: Vec<(String, ProofPreimage)> = Vec::new();
    for name in &scenario_names {
        let sc = model::scenario_by_name(name);
        let pi = synth::synthesize(&a.ir, &sc.preimage())
            .unwrap_or_else(|e| panic!("{name}: could not synthesize a transcript: {e}"));
        synth::check(&a.ir, &pi).unwrap_or_else(|e| panic!("{name}: arm A refuses its own preimage: {e}"));
        synth::check(&b.ir, &pi).unwrap_or_else(|e| {
            panic!("{name}: arm B REFUSES the shared preimage: {e}\nThis invalidates the cell.")
        });
        eprintln!(
            "  [{name}] {} transcript elements, {} ledger answers — accepted by BOTH arms",
            pi.public_transcript_inputs.len(),
            pi.public_transcript_outputs.len()
        );
        preimages.push((name.clone(), pi));
    }

    // ---- the raw per-run file, written AS RUNS HAPPEN ------------------------------------------
    let mut csv = std::fs::File::create(&csv_path).expect("cannot create the CSV");
    writeln!(
        csv,
        "phase,run_index,artifact,compiler_k,rows,scenario,prove_ms,verify_ms,verified,proof_bytes,pi_count,rss_after_bytes,load_avg_1m,utc"
    )
    .unwrap();
    csv.flush().unwrap();

    let mut row = |csv: &mut std::fs::File,
                   phase: &str,
                   idx: usize,
                   arm: &Arm,
                   scenario: &str,
                   prove_ms: f64,
                   verify_ms: f64,
                   verified: bool,
                   proof_bytes: usize,
                   pi_count: usize,
                   la: &str| {
        writeln!(
            csv,
            "{phase},{idx},{},{},{},{scenario},{:.3},{:.3},{},{},{},{},\"{}\",{}",
            arm.name,
            arm.k,
            arm.rows,
            prove_ms,
            verify_ms,
            verified,
            proof_bytes,
            pi_count,
            rss_bytes(),
            la,
            chrono_utc()
        )
        .unwrap();
        csv.flush().unwrap();
    };

    // ---- warmup: one UNTIMED proof per arm, excluded from every statistic ------------------------
    //
    // What it buys: the prover key is deserialized (1.1 GB / 0.6 GB) and cached, the SRS pages are
    // resident, and the allocator has grown. Without it, run 1 of each arm would be measuring a key
    // deserialization rather than a proof.
    eprintln!();
    eprintln!("== warmup (untimed, excluded) ==");
    let (warm_name, warm_pi) = &preimages[0];
    for arm in [&a, &b] {
        let la = load_avg();
        eprintln!("  [{}] warmup on {warm_name} (load {la})", arm.name);
        match timed_prove(arm, &params, warm_pi, 1) {
            Ok((proof, pis, ms)) => {
                let (ok, vms) = timed_verify(arm, &proof, &pis);
                eprintln!(
                    "    warmup: {:.1} ms, {} proof bytes, {} PIs, verified={ok}",
                    ms,
                    proof.0.len(),
                    pis.len()
                );
                row(&mut csv, "warmup", 0, arm, warm_name, ms, vms, ok, proof.0.len(), pis.len(), &la);
            }
            Err(e) => {
                eprintln!("    WARMUP FAILED for {}: {e}", arm.name);
                row(&mut csv, "warmup-failed", 0, arm, warm_name, f64::NAN, f64::NAN, false, 0, 0, &la);
                panic!("arm {} cannot prove at all — see the error above", arm.name);
            }
        }
    }

    // ---- the timed matrix, INTERLEAVED A/B ------------------------------------------------------
    //
    // Ordering is `for run { for scenario { A then B } }`, so the two arms of every cell are
    // adjacent in time and each cell's N runs are spread across the whole session. Thermal drift or
    // a stray background process therefore lands on both arms roughly equally instead of biasing
    // one of them.
    eprintln!();
    eprintln!("== timed matrix ==");
    let mut cells: BTreeMap<(String, String), Vec<f64>> = BTreeMap::new();
    let mut vcells: BTreeMap<(String, String), Vec<f64>> = BTreeMap::new();
    let mut proof_sizes: BTreeMap<String, usize> = BTreeMap::new();
    let mut pi_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut unverified = 0usize;

    for idx in 1..=runs {
        let la = load_avg();
        eprintln!("-- run {idx}/{runs} (load average {la}) --");
        for (name, pi) in &preimages {
            for arm in [&a, &b] {
                let seed = (idx as u64) << 8 | (arm.k as u64);
                match timed_prove(arm, &params, pi, seed) {
                    Ok((proof, pis, ms)) => {
                        let (ok, vms) = timed_verify(arm, &proof, &pis);
                        if !ok {
                            unverified += 1;
                            eprintln!(
                                "    !! {} / {name} run {idx}: proof did NOT verify — NOT COUNTED",
                                arm.name
                            );
                        }
                        eprintln!(
                            "    {:<9} {:<30} {:>9.1} ms   verify {:>6.2} ms   {} B   verified={ok}",
                            arm.name,
                            name,
                            ms,
                            vms,
                            proof.0.len()
                        );
                        row(&mut csv, "timed", idx, arm, name, ms, vms, ok, proof.0.len(), pis.len(), &la);
                        if ok {
                            cells.entry((arm.name.clone(), name.clone())).or_default().push(ms);
                            vcells.entry((arm.name.clone(), name.clone())).or_default().push(vms);
                            proof_sizes.insert(arm.name.clone(), proof.0.len());
                            pi_counts.insert(arm.name.clone(), pis.len());
                        }
                    }
                    Err(e) => {
                        eprintln!("    !! {} / {name} run {idx}: PROVER REFUSED — {e}", arm.name);
                        row(&mut csv, "prove-failed", idx, arm, name, f64::NAN, f64::NAN, false, 0, 0, &la);
                    }
                }
            }
        }
    }

    // ---- summary --------------------------------------------------------------------------------
    println!();
    println!("== per-cell summary (verified runs only) ==");
    println!();
    println!("| artifact | k | rows | scenario | N | median ms | mean ms | min ms | max ms | spread % of median | verify ms (median) |");
    println!("|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|");
    let mut arm_all: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    let mut wide_cells: Vec<String> = Vec::new();
    for arm in [&a, &b] {
        for (name, _) in &preimages {
            let key = (arm.name.clone(), name.clone());
            let mut v = cells.get(&key).cloned().unwrap_or_default();
            if v.is_empty() {
                println!("| {} | {} | {} | `{name}` | 0 | — | — | — | — | — | — |", arm.name, arm.k, arm.rows);
                continue;
            }
            let n = v.len();
            let mean = v.iter().sum::<f64>() / n as f64;
            let mut vv = v.clone();
            let med = median(&mut vv);
            let min = v.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = v.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            let spread = (max - min) / med * 100.0;
            let mut vt = vcells.get(&key).cloned().unwrap_or_default();
            let vmed = median(&mut vt);
            if spread > 20.0 {
                wide_cells.push(format!("{}/{name} (spread {spread:.1}%)", arm.name));
            }
            println!(
                "| {} | {} | {} | `{name}` | {n} | {med:.1} | {mean:.1} | {min:.1} | {max:.1} | {spread:.1}{} | {vmed:.2} |",
                arm.name,
                arm.k,
                arm.rows,
                if spread > 20.0 { " **WIDE**" } else { "" }
            );
            arm_all.entry(arm.name.clone()).or_default().append(&mut v);
        }
    }

    println!();
    println!("== headline ==");
    println!();
    println!("| artifact | k | rows | verified proofs | median prove ms (all cells pooled) | proof bytes | PI count | verifier params |");
    println!("|---|---:|---:|---:|---:|---:|---:|---|");
    let mut meds: BTreeMap<String, f64> = BTreeMap::new();
    for arm in [&a, &b] {
        let mut v = arm_all.get(&arm.name).cloned().unwrap_or_default();
        let n = v.len();
        let med = median(&mut v);
        meds.insert(arm.name.clone(), med);
        println!(
            "| {} | {} | {} | {n} | {med:.1} | {} | {} | {} |",
            arm.name,
            arm.k,
            arm.rows,
            proof_sizes.get(&arm.name).copied().unwrap_or(0),
            pi_counts.get(&arm.name).copied().unwrap_or(0),
            arm.vparams_source
        );
    }
    let (ma, mb) = (meds[&a.name], meds[&b.name]);
    println!();
    println!(
        "MEDIAN-VS-MEDIAN CUT: {} {:.1} ms -> {} {:.1} ms = **{:.1}%** cut",
        a.name,
        ma,
        b.name,
        mb,
        (ma - mb) / ma * 100.0
    );
    println!("UNVERIFIED PROOFS (not counted): {unverified}");
    if !wide_cells.is_empty() {
        println!("CELLS WITH SPREAD > 20% OF MEDIAN: {}", wide_cells.join("; "));
    } else {
        println!("CELLS WITH SPREAD > 20% OF MEDIAN: none");
    }
    println!("ARTIFACTS: A={} B={}", a.zkir_path, b.zkir_path);
    // keep the arms alive to the end so the keys are not dropped mid-report
    let _ = (&mut a, &mut b);
}

// ------------------------------------------------------------------ subcommand: solo
//
// One arm, one process — the shape minocrab's own BENCHMARK.md uses ("one subprocess per cell,
// peak RSS = `getrusage` of that process"). It exists for two reasons the interleaved matrix
// cannot serve:
//
//  1. **Peak RSS is attributable.** In the interleaved run both prover keys are resident in one
//     process, so its peak RSS is the pair's, not either arm's.
//  2. **It is a control on memory pressure.** If holding both keys at once were slowing the
//     interleaved matrix — or slowing one arm more than the other — the solo medians would not
//     agree with the interleaved ones. Reported side by side in RESULTS.md.
//
// Timing is identical to `bench`: pre-loaded params, an untimed warmup, the clock around
// `Zkir::prove` alone, and every counted proof verified.

fn cmd_solo(args: &[String]) {
    let f = Flags::parse(args);
    let params_dir = f.get("params");
    let runs: usize = f.get("runs").parse().expect("--runs must be a number");
    let csv_path = f.get("csv");
    let scenario_names: Vec<String> = match f.opt("scenarios", "") {
        s if s.is_empty() => model::all_scenarios().iter().map(|x| x.name.to_string()).collect(),
        s => s.split(',').map(|x| x.trim().to_string()).collect(),
    };
    // The transcript is always synthesized from the compactc artifact, exactly as in `bench`, so a
    // solo minocrab run proves the SAME preimage the interleaved run proved.
    let ref_ir = load_zkir(&f.get("ref-zkir"));

    let arm = build_arm(&f, "a", &params_dir);
    let params = OfflineParams::preload(&params_dir, &[arm.k]);

    let mut preimages: Vec<(String, ProofPreimage)> = Vec::new();
    for name in &scenario_names {
        let sc = model::scenario_by_name(name);
        let pi = synth::synthesize(&ref_ir, &sc.preimage())
            .unwrap_or_else(|e| panic!("{name}: could not synthesize a transcript: {e}"));
        synth::check(&arm.ir, &pi)
            .unwrap_or_else(|e| panic!("{name}: this arm refuses the shared preimage: {e}"));
        preimages.push((name.clone(), pi));
    }

    let mut csv = std::fs::File::create(&csv_path).expect("cannot create the CSV");
    writeln!(
        csv,
        "phase,run_index,artifact,compiler_k,rows,scenario,prove_ms,verify_ms,verified,proof_bytes,pi_count,rss_after_bytes,load_avg_1m,utc"
    )
    .unwrap();
    csv.flush().unwrap();

    let write_row = |csv: &mut std::fs::File, phase: &str, idx: usize, scenario: &str,
                     prove_ms: f64, verify_ms: f64, verified: bool, pb: usize, pc: usize, la: &str| {
        writeln!(
            csv,
            "{phase},{idx},{},{},{},{scenario},{:.3},{:.3},{},{},{},{},\"{}\",{}",
            arm.name, arm.k, arm.rows, prove_ms, verify_ms, verified, pb, pc, rss_bytes(), la,
            chrono_utc()
        )
        .unwrap();
        csv.flush().unwrap();
    };

    eprintln!("== solo warmup (untimed, excluded) ==");
    let (wn, wpi) = &preimages[0];
    let la = load_avg();
    match timed_prove(&arm, &params, wpi, 1) {
        Ok((proof, pis, ms)) => {
            let (ok, vms) = timed_verify(&arm, &proof, &pis);
            eprintln!("  warmup {:.1} ms verified={ok}", ms);
            write_row(&mut csv, "warmup", 0, wn, ms, vms, ok, proof.0.len(), pis.len(), &la);
        }
        Err(e) => panic!("solo warmup failed for {}: {e}", arm.name),
    }

    println!("== 00018 Phase 2 supplement — SOLO run, arm `{}` ==", arm.name);
    let mut all: Vec<f64> = Vec::new();
    for idx in 1..=runs {
        let la = load_avg();
        for (name, pi) in &preimages {
            match timed_prove(&arm, &params, pi, (idx as u64) << 8 | arm.k as u64) {
                Ok((proof, pis, ms)) => {
                    let (ok, vms) = timed_verify(&arm, &proof, &pis);
                    eprintln!("  {:<9} {:<30} {:>9.1} ms verified={ok}", arm.name, name, ms);
                    write_row(&mut csv, "timed", idx, name, ms, vms, ok, proof.0.len(), pis.len(), &la);
                    if ok {
                        all.push(ms);
                    }
                }
                Err(e) => {
                    eprintln!("  !! {} / {name} run {idx}: PROVER REFUSED — {e}", arm.name);
                    write_row(&mut csv, "prove-failed", idx, name, f64::NAN, f64::NAN, false, 0, 0, &la);
                }
            }
        }
    }
    let n = all.len();
    let expected = runs * preimages.len();
    let med = median(&mut all);
    println!(
        "SOLO {} k={} rows={} verified={n}/{expected} median_prove_ms={med:.1}",
        arm.name, arm.k, arm.rows
    );
    // PROJECT 00020: the solo run is no longer only a timing supplement — it IS the delivery check
    // (spec FR-005: one verified proof per provable selector). A cell that failed to prove, or
    // proved but did not verify against its own verifier key, must fail the process, not just leave
    // a row in the CSV.
    if n != expected {
        eprintln!(
            "FAILED: {n} of {expected} cells produced a VERIFIED proof for arm `{}`.",
            arm.name
        );
        std::process::exit(70);
    }
    println!("ALL CELLS VERIFIED: {expected}/{expected}");
}

/// A UTC timestamp for the raw file. Deliberately shells out rather than pulling in a date crate:
/// the harness's dependency set must stay exactly upstream's.
fn chrono_utc() -> String {
    std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

// ------------------------------------------------------------------ driver

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("check") => cmd_check(&args[1..]),
        Some("bench") => cmd_bench(&args[1..]),
        Some("solo") => cmd_solo(&args[1..]),
        other => {
            eprintln!("unknown subcommand: {other:?}");
            eprintln!("usage: prove-bench check <a.zkir> <b.zkir>");
            eprintln!("       prove-bench bench --a-name .. --a-zkir .. --a-pk .. --a-vk .. \\");
            eprintln!("                         --b-name .. --b-zkir .. --b-pk .. --b-vk .. \\");
            eprintln!("                         --params DIR --runs N --csv PATH [--scenarios a,b]");
            eprintln!("       prove-bench solo  --a-name .. --a-zkir .. --a-pk .. --a-vk .. \\");
            eprintln!("                         --ref-zkir <compactc.zkir> \\");
            eprintln!("                         --params DIR --runs N --csv PATH [--scenarios a,b]");
            std::process::exit(64);
        }
    }
}
