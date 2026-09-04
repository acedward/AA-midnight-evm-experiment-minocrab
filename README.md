# AA Manager — the MinoCrab port

The nine provable circuits of [`contracts/manager.compact`][contract] from
[**acedward/AA-midnight-evm-experiment-v3**][product] — an account-abstraction custody contract for
Midnight — transcribed into [**MinoCrab**][minocrab], a third-party Rust eDSL alternative compiler
for Midnight contracts.

The port is a **faithful** one: same typed argument and output schema per circuit, same
disclosures, same guard set in the same order, FAB-compatible public-input encoding, **no statement
change**. MinoCrab's own instruction-selection choices are the only thing allowed to differ — and
they are the whole point:

> ### `execute` drops from **k = 19 / 382,781 rows** to **k = 18 / 211,059 rows** — −44.86%
>
> Crossing the k = 19 → k = 18 boundary **halves the proving time and halves the proving key**,
> at an unchanged proof size, public-input count and verifier-key size.

Everything here is source. The compiled outputs — ZKIR, BZKIR, proving and verifying keys, SRS —
are deliberately **not** in this repository; their expected SHA-256 hashes are in
[§ Regenerating the artifacts](#regenerating-the-artifacts), so anything you rebuild is checkable
against exactly what was measured.

> ## ⚠ Read this first
>
> **EXPERIMENTAL. Unaudited third-party compiler.** The artifacts this crate emits are not produced
> by `compactc`. They are produced by MinoCrab, which is **unaudited**. The statement has been
> **tested** for equivalence against the product's own `compactc` artifact — extensively, see
> [§ What "equivalent" was tested to mean](#what-equivalent-was-tested-to-mean) — but equivalence
> is **not formally proven**. Do not deploy this on the strength of this README.

---

## Layout

```
manager-port/          the port: one module per circuit family, plus the differential suite
  src/                   circuits — envelope, custody, coins, deposits, eip712, execute, queries…
  src/bin/emit_zkir.rs   emits one <circuit>.zkir per circuit into a directory
  tests/                 the equivalence gate (see below)
prove-bench/           compiler-neutral keygen/prove/verify harness — links NO minocrab code, so
                       neither compiler's tooling is ever on the timing path
scripts/               toolchain (the compactc pin) · compile (compactc baseline) · measure
                       (k, rows) · keygen · check-port-artifacts (the emitted-ZKIR gate) · helpers
docker/                compactc.Dockerfile — the pinned toolchain, built from a SHA-256-pinned
                       release archive, so the reference side needs no private image
fixtures/eip712/       the frozen EIP-712 test-vector set (see § Vendored fixtures)
fixtures/port-artifact-hashes.json   the expected-hash table below, in machine form
```

## Pins

Every number below was measured at exactly these pins. They are not suggestions.

| thing | pin |
|---|---|
| **MinoCrab** | [`sig-net/minocrab`][minocrab] @ `1522f9dd024d2d9941a6fdcda1ad8f88ab7533b9` (upstream `main`, 2026-09-02) — **unaudited third party**. Previous pin `6a53f2b54850955406cd0f45dd78cc1e152182c7`; what the move cost is in [§ MinoCrab pin history](#minocrab-pin-history) |
| **Rust** | `cargo` / `rustc` **1.95.0** (`aarch64-apple-darwin`). 1.92 and below do not build this workspace: `sysinfo@0.39.6` declares `rust-version = "1.95"` and arrives through `midnight-storage`, i.e. through the `midnight-ledger` rev minocrab pins. minocrab's own workspace floor is `rust-version = "1.85"`; 1.95.0 is what the dependency graph actually requires, re-checked at `1522f9d` |
| **Contract ported** | [`contracts/manager.compact`][contract] @ [`713a20215f33e02904ea5bd699b7de7f76562e1b`][pin] — 1,420 lines, 78,004 B, sha256 `164cf112dc52ba88f1e16cfbd1e63c3bc6b2831539be12e7de229847dd7025c7` |
| **Reference compiler** | **Compact 0.34.0** / language 0.26.0 / runtime 0.19.0 / `--feature-zkir-v3`, the toolchain the product repository pins on `main`. Obtained and hash-verified by `scripts/toolchain.sh`, which builds `docker/compactc.Dockerfile` from release archive `compactc_v0.34.0_aarch64-unknown-linux-musl.zip` (sha256 `d3e292c4f48e257dcd6b3d3e3e4743d7d8ea0729f48953eab91a366d44cd026d`) — arm64. The verified binaries are `compactc.bin` `628b343f9b0ebe32e6e6a141b6f73cc66edb19c516a4817b478c3b47f74230d5` and `zkir-v3` `6a91308419d24bc0633210897d10c7c1b2193444e8bde09ce763e9556cb8f93a`. See the history note below |
| **Keygen tool** | `zkir-v3 compile` (`/opt/compactc/zkir-v3`), from that same image |
| **Upstream ledger crates** | `midnightntwrk/midnight-ledger` rev `04c9c5d9bcebb8d4427d8589fb54d58a55599c14`; `midnight-transient-crypto` tag `transient-crypto-2.2.0-rc.1` |
| **SRS used for keygen** | `bls_midnight_2p18`, 50,332,036 B, sha256 `e8436dc5d8b598f169c127c745135d889744007e6d384ff126df8d1332522f86` |

**Toolchain history.** Every number in this README up to 2026-09-04 was measured with a compiler
**0.33.0** / language 0.25.0 image (id `sha256:f57ca2d88cec1c66f377eb8bb2d616779202dd1ccb99517a4f7ddfffa9d0d86b`)
that was built locally and is not publicly pullable, and the scripts defaulted to it by digest — so
a fresh clone could not produce the reference side at all. The pin is now the release ARCHIVE, not
an image, and the 0.34.0 move re-derived every affected number rather than assuming it:

* the compactc baseline compiled on 0.34.0 from the same contract source is **byte-identical** to
  the recorded 0.33.0 baseline, all nine circuits; and
* this image's `zkir-v3` (`6a913084…`) reports the **same (k, rows)** and writes a **byte-identical
  `.bzkir`** for every one of the port's nine ZKIRs as the 0.33.0 `zkir-v3` (`75153f47…`) did —
  `execute` at k = 18 / 211,056 included.

So the tables below stand unchanged under the new toolchain. The 0.33.0 toolchain itself is still
reproducible — its archive and both binary hashes are recorded in `docker/compactc.Dockerfile` —
if an older artifact ever has to be re-derived.

The statement includes three fixes that landed in the product contract before this snapshot: the
`aa:manager:*` domain-tag rename (PR #7), the `safeGive` pool-underflow clamp (PR #9) and the
unshielded-withdraw recipient tag plus envelope guards (PR #10).

`Cargo.toml` mirrors minocrab's own `[patch.crates-io]` block at the **workspace root**, which is
load-bearing: cargo honours `[patch]` only from the root of the workspace being built, never
through a path or git dependency. Without it, resolution fails on
`midnight-transient-crypto = "^2.2.0"`, a version never published to crates.io.

## Build

```bash
cargo +1.95.0 build --release --locked
cargo +1.95.0 test  --release --locked
```

That is the whole setup — no side-by-side checkout, no vendoring: minocrab is a pinned **git**
dependency. The default test run is **10 tests** — 8 in-crate assertions that each circuit's
*declared* disclosures are exactly the ones it makes, plus the 2 EIP-712 fixture tests — and needs
nothing that is not in this repository. The three differential test targets need a `compactc`
baseline artifact and are feature-gated off; see
[§ Running the differential suite](#running-the-differential-suite).

## Measured results

### Rows and `k`

| artifact | k | rows | prover key | verifier key |
|---|---:|---:|---:|---:|
| `compactc` `execute` @ `713a202` | **19** | 382,781 | 1,141,041,970 B | 3,321 B |
| **this port's `execute`** | **18** | **211,059** | **570,484,400 B** | 3,321 B |
| | | **−44.86%** | **−50.0%** | **±0** |

The k = 18 ceiling is 262,144 rows; this lands at 211,059 — **51,085 rows of headroom**, 80.51% of
the ceiling. The measurement is double-derived here and both agree: `zkir-v3 mock-compile` reports
`(k=18, rows=211059)`, and upstream's own `IrSource::model()` reports k = 18 / 211,059 over 1,444
instructions — against 5,787 instructions for the compactc artifact. (The third derivation, the
`zkir-v3 compile` keygen banner, agreed at the previous pin's 211,056; the keys are not yet
regenerated at this pin — see the note under § Expected hashes.)

The other eight circuits are **not** where the win is, and **no `k` moves but `execute`'s**. Their
port-side rows at this snapshot are 42,256 / 7,917 / 4,000 / 4,000 / 332 / 158 / 129 / 129 —
58,921 in aggregate. Measured against compactc on the immediately preceding snapshot of the same
contract, those eight went 58,892 → 58,921: **+29 rows, +0.049% — a wash, marginally in MinoCrab's
disfavour.** The −44.86% on `execute` comes from replacing per-byte explode/rebuild chains, which
are 54.3% of `execute`'s instructions and ≈0% of everything else's. Do not transfer the headline
percentage to another contract without checking that it, too, is byte-chain heavy.

### Proving

Measured on an Apple M4 Max (12P + 4E, 48 GiB, macOS 15.7.3 arm64), both artifacts proved through
the **same** upstream prover on **identical `ProofPreimage`s** that both accept, interleaved A/B
across two sessions.

**These are the MinoCrab `6a53f2b` numbers** (`execute` at 211,056 rows). The current pin's
`execute` is three rows larger at the same k = 18, and k is what proving time and key size are a
function of, so the table transfers — but it has not been re-measured, and the row that would move
is none of them:

| | compactc k = 19 | MinoCrab k = 18 | Δ |
|---|---:|---:|---:|
| prove, median (N = 48/side) | 38.5 s | **19.3 s** | **−49.8%** |
| keygen | 149.6 s | 57.5 s | −61.6% |
| prover key | 1,088 MiB | **544 MiB** | −50.0% |
| peak RSS while proving | 10,806 MiB | 6,925 MiB | −35.9% |
| verify | 8.2 ms | 10.5 ms | **+2.3 ms** |
| proof size | 10,304 B | 10,304 B | ±0 |
| public inputs | 1,265 | 1,265 | ±0 |
| verifier key | 3,321 B | 3,321 B | ±0 |

Cross-checked by a paired back-to-back statistic (shared machine load cancels) at **−48.3%, IQR
−46.7% to −50.7%**; the four scenarios' individual medians span only −47.6% to −49.0%. **112 proofs
were produced and 112 were verified** against their own verifier key; zero unverified proofs are
counted and neither artifact ever refused a run.

**Rows are not prove time — `k` is.** The row cut mattered *because* it crossed a power of two. A
cut that does not cross one buys approximately nothing.

Three things must travel with those numbers:

1. **The baseline is already hand-tuned for exactly what the port attacks.** The 382,781-row
   compactc figure already banks a big-endian-encoder optimization worth −267,216 rows (−27.42%),
   landed before this comparison. The win is on top of that, not instead of it.
2. **The timing table was measured on the immediately preceding statement** (211,028 rows), whose
   four benchmarkable scenarios covered selectors 0, 1, 2 and 6. A same-session control on **this**
   snapshot's keys re-measured selector 3 at **18,980 ms** on the k = 18 key against **40,173 ms**
   on the k = 19 compactc key — consistent with the table.
3. **Absolute seconds are machine-relative and the host was not idle.** Treat the *ratio* as the
   transferable number.

### What the three contract fixes cost `execute`

Each change set was applied cumulatively to the port, re-emitted, and re-measured with the same
oracle — measured, not estimated. (The crate was then restored and re-emits `execute.zkir`
byte-identically, which is what makes the intermediate numbers safe to publish.)

All four rows are MinoCrab `6a53f2b` measurements — the statement's cost, with the compiler held
still. (At the current pin the same final statement is 211,059; see
[§ MinoCrab pin history](#minocrab-pin-history) for those +3.)

| cumulative statement | rows | Δ |
|---|---:|---:|
| previous snapshot | 211,028 | — |
| + PR #7 domain-tag rename | 211,028 | **+0** |
| + PR #9 `safeGive` clamp | 211,039 | **+11** |
| + PR #10 recipient tag & envelope guards | **211,056** | **+17** |

## Regenerating the artifacts

Emission is deterministic. From a clean clone:

```bash
# 1. every circuit's ZKIR  (writes generated/port-zkir/<circuit>.zkir — gitignored)
cargo +1.95.0 run --release --locked -p manager-port --bin emit-zkir -- generated/port-zkir

# 2. check what you got against what was measured
shasum -a 256 generated/port-zkir/*.zkir
```

Or let the gate do both, against the machine-readable copy of the table below:

```bash
scripts/check-port-artifacts.sh          # re-emits into a temp dir and compares every size + hash
#   -> PORT ARTIFACT GATE OK — 10 circuit(s), every size and hash identical
```

It needs no compactc, no Docker, no SRS and no network — emission is deterministic and the hashes
are decided by the pinned `minocrab` rev and this crate's source, nothing else. Pass
`--no-toolchain-check` to skip even the (purely informational) toolchain probe. The record it
compares against is `fixtures/port-artifact-hashes.json`, which also carries the `minocrab` rev,
the contract pin and the toolchain provenance; `--write` re-records it, and is only ever run for an
intended byte change that the commit message explains.

### Expected hashes

`execute` — the circuit the whole comparison is about:

| file | bytes | SHA-256 |
|---|---:|---|
| `execute.zkir` | 124,332 | `de0b523298b8280a42e23d3fc837c75c33b426dd14d3ed80cdaf804772f7edc1` |
| `execute.bzkir` | 52,303 | `ea9b708d9b05926d83ff8cc2de5ed29a3703bc10dd0eff385f319897dd9b030d` |

**The keys are NOT re-recorded yet.** The pair below was generated from the previous pin's
`execute.zkir` (`aed45e80…`), so it belongs to that ZKIR and not to the one above; the sizes are a
function of k = 18 alone and do not move, the bytes do. They are kept here as the `6a53f2b` record
until the pair is regenerated:

| file | bytes | SHA-256 | of which ZKIR |
|---|---:|---|---|
| `execute.prover` | 570,484,400 | `6919a054f2df9ba23b40752d740eaff50bd14c6ebf651445dcdc3e1f335208de` | `aed45e80…` (superseded) |
| `execute.verifier` | 3,321 | `6d2b443391faba265407cbe6a0d755844fd6a4bc0fac672a6eb2ebe44bbdd082` | `aed45e80…` (superseded) |

The other eight circuits (`.bzkir` is what `zkir-v3 mock-compile` writes; no keys were generated
for these — only `execute` was at k = 19):

| circuit | `.zkir` bytes | `.zkir` SHA-256 | `.bzkir` bytes | `.bzkir` SHA-256 |
|---|---:|---|---:|---|
| `depositShielded` | 14,927 | `dd049233d4c6919d3c142c0a6509277d1de46f0b4360248b1b94665f041cc13d` | 5,713 | `1e086e6bb0326b8fa2a5a2e985fa07b8e76b3c6c64ecaeb2da16f7e4e61bbf60` |
| `depositUnshielded` | 4,333 | `b228a30b533b29966de36f3c007c270cc2f910c9d8200fa25858709e1025edcb` | 1,659 | `50cc264a8b790f7288aa873bb7dbf57d347f09b92792596a7af2026e576cf5b9` |
| `shieldedAccountBalance` | 1,768 | `2311b13ee29a2101dd62682240135c351cfde4cad2f261cb6602ea28d16a2436` | 612 | `db8fd4e154333f7626dd81a45cc5128a3955a51f0010e008ee14f5ae5a2e5e73` |
| `unshieldedAccountBalance` | 1,772 | `3f449ff9e79786c831cc5b61454b569426b138e8c81146deba5b633deddd8dd9` | 616 | `6f06a9aab8e5f903e842fff0d9bb0d70099eceb21fc1aee99a3de30de3ad23cf` |
| `accountRecord` | 6,065 | `ab6a0afd75d46d3f77a2cfb998b5106004eb90cd5528393ca0d2039bda1b2d59` | 2,430 | `143e7b0bd0bcb0b364124e2cb8c105d8ef8ccca989302c173c71c05f1d7d95c9` |
| `poolValue` | 1,632 | `17868ae25867ac78f159961f52c253ffbb3de8e6f289bb0632bd815d396c3699` | 555 | `71e17fd55c44425c583781f4c892aaf98a64dacc6bbce7800267e134d146b022` |
| `isRegistered` | 786 | `a6da7f83589283327789ae7a91bb5585efc6e73d69ce1bf48ba568e58a5c3ae3` | 263 | `baadf974aad06acd6d93b71ace20c41b633e0f4fea6f658284d1f091885c1adf` |
| `poolHasColour` | 792 | `9a92ddc5dd5c85aea5af5d42f5f79801617ff073cd92e0cb1bec92d798497587` | 269 | `dabe9fb2c42a4a08843a1b6b0b09b6220544c06e11c0018289c7126c31619076` |

`emit-zkir` also writes a tenth file, `hello_positive_amount.zkir` — a minimal smoke circuit used
during bring-up. It is not part of the contract's provable surface, but
`scripts/check-port-artifacts.sh` gates it like the rest: 314 B,
`be3bfc7c376b26ef5d5b848a6a0d1650636210176e3cf9c6ffe8ea23bcec91db`.

**If a hash does not match, do not proceed as if it did.** The overwhelmingly likely cause is a
moved pin — a different minocrab rev, or a different `midnight-ledger` rev pulled in through the
`[patch.crates-io]` block.

### Measuring (k, rows) and generating keys

Both need the pinned Compact toolchain, because both drive the `zkir-v3` binary that ships inside
it. `scripts/toolchain.sh` obtains it for you — from a local image, or by building
`docker/compactc.Dockerfile` from the SHA-256-pinned release archive — and verifies the compiler
version, the language version and both binary hashes before anything runs. No `COMPACTC_IMAGE` to
set, no private image to find.

```bash
# (k, rows) via `zkir-v3 mock-compile` — also writes the .bzkir hashed above
scripts/measure-zkir.sh generated/port-zkir execute $(scripts/free-port.sh) 1800 port
#   -> Mock compiling circuit "execute.zkir" (k=18, rows=211059)

# proving + verifying keys, offline, from the raw ZKIR
#   put the SRS in generated/zk-params/ first — the container runs --network none and
#   cannot fetch it
scripts/keygen-zkir.sh port-execute generated/port-zkir/execute.zkir $(scripts/free-port.sh)
```

Set `COMPACTC_IMAGE=<ref>` only to drive a *different* build of the toolchain — to re-derive a
0.33.0-era artifact, say. The version and both binary hashes are still checked, so a mismatched
image exits 70 instead of silently re-baselining.

`keygen-zkir.sh` runs `zkir-v3 compile` rather than `compactc` deliberately: a MinoCrab artifact has
no `.compact` source at all, so keying it from the raw ZKIR is the only route — and it means both
artifacts are keyed by the *identical* tool, in the identical image, under identical bounds.

### Proving and verifying

`prove-bench` loads a `.zkir` plus its key pair through Midnight's own crates and produces real
proofs. At MinoCrab `6a53f2b` it produced **one verified proof per selector, 7 of 7**, each 10,304
bytes over 1,265 public inputs, on preimages synthesized from the *compactc* artifact and accepted
unchanged by this one. That run used the key pair recorded above, which belongs to the superseded
`execute.zkir`; re-running it at the current pin needs the pair regenerated first:

```bash
cargo +1.95.0 build --release --locked -p prove-bench
target/release/prove-bench solo \
  --a-name minocrab-k18 \
  --a-zkir   generated/port-zkir/execute.zkir \
  --a-pk     generated/keys/port-execute/execute.prover \
  --a-vk     generated/keys/port-execute/execute.verifier \
  --ref-zkir generated/baseline/manager/zkir/execute.zkir \
  --params   generated/zk-params --runs 1 --csv /tmp/proofs.csv
#   -> ALL CELLS VERIFIED: 7/7
```

Selectors 3, 4 and 5 could not be proved *at all* before PR #9; the clamp in this statement is what
gives them accepted runs.

## Running the differential suite

The equivalence gate compares this port's emitted ZKIR against the **`compactc`-emitted artifact for
the same contract commit**, circuit by circuit and run by run. That baseline is a compiled file and
is not in this repository — you build it — so the three differential targets are behind a cargo
feature and are not even compiled by a default `cargo test`. What you need is Docker and a network
for step 2; the toolchain builds itself from the pinned archive.

```bash
# 1. get the contract at the pinned commit
git clone https://github.com/acedward/AA-midnight-evm-experiment-v3
git -C AA-midnight-evm-experiment-v3 checkout 713a20215f33e02904ea5bd699b7de7f76562e1b
shasum -a 256 AA-midnight-evm-experiment-v3/contracts/manager.compact
#   -> 164cf112dc52ba88f1e16cfbd1e63c3bc6b2831539be12e7de229847dd7025c7

# 2. compile the baseline (--skip-zk: no keys are generated). scripts/toolchain.sh obtains and
#    verifies compactc 0.34.0 on the way in; the compile itself runs --network none.
scripts/compile-baseline.sh baseline \
  AA-midnight-evm-experiment-v3/contracts/manager.compact $(scripts/free-port.sh)

# 3. run the gate
cargo +1.95.0 test --release --locked -p manager-port --features compactc-baseline
#   -> 56 tests, all green
```

The suite looks for `generated/baseline/manager/zkir/<circuit>.zkir`; set `AA_BASELINE_ZKIR_DIR` to
point it somewhere else.

**Check your baseline before you trust a red run.** A different compactc version will emit a
different artifact, and a mismatch will then be reported against *your* baseline rather than
against the one these results describe — which is why `scripts/toolchain.sh` refuses to run on a
compiler it does not recognise. The published gate ran against a baseline whose `execute` side
measured k = 19 / 382,781 rows, whose nine ZKIR hashes are byte-identical under 0.33.0 and 0.34.0.

## What "equivalent" was tested to mean

**56/56 tests, gate green**, against the product's own `compactc` artifact compiled from `713a202`:

* **Typed schema identity** — input types in order, output types, communications-commitment flag.
* **`pi_skips` equality entry by entry over all 404 Impact instructions**, on every scenario. Two
  artifacts can agree here only if they emit the same ledger operations, in the same order, with the
  same input counts and the same guard truth values.
* **Public-input-vector equality element by element** on a shared `ProofPreimage` (1,265 elements),
  with upstream's own `Zkir::check()` agreeing with the simulation on both sides.
* **11 accepted scenarios covering all seven `execute` selectors**, with **4,888 single-element
  tamper probes across the whole preimage and 0 acceptance disagreements** — every mutation is
  accepted or rejected identically by both artifacts.
* **Refusal agreement** on the shapes PR #10 forbids (contract-tagged withdrawal recipient,
  contract-tagged swap taker): both artifacts refuse, at an envelope assert.
* **Reference-VM replay ×4** (selectors 0, 1, 2, 3): the accepted transcript is decoded back into
  Impact ops, re-encoded as a check, and run through Midnight's own `QueryContext::query` in
  `ResultModeVerify` against a constructed pre-state. Every `Popeq` is checked against real state,
  and the post-state and `Effects` are asserted.
* **The EIP-712 chain** — domain separator, struct hash and digest — byte-compared against the
  frozen fixture set on every case. These are pure circuits with no proving key, so they get a
  stricter bar: the bytes are what a MetaMask signature commits to.

What this does **not** establish: a formal proof of statement equivalence, or any claim about
MinoCrab's correctness in general. It is a strong *empirical* gate on **this** circuit against
**this** reference artifact.

## MinoCrab pin history

### `6a53f2b` → `1522f9d` (2026-09-04): **+4 rows, in two circuits, and nothing else**

81 upstream commits. Everything was re-emitted and all nine circuits re-measured through the same
`zkir-v3 mock-compile` oracle:

| circuit | `.zkir` bytes | rows | k | Δ rows |
|---|---:|---:|---:|---:|
| `execute` | 124,071 → **124,332** | 211,056 → **211,059** | 18 → 18 | **+3** |
| `depositShielded` | 14,847 → **14,927** | 42,255 → **42,256** | 16 → 16 | **+1** |
| `depositUnshielded` | 4,333 | 7,917 | 13 | ±0 (byte-identical) |
| `accountRecord` | 6,065 | 332 | 9 | ±0 (byte-identical) |
| `poolValue` | 1,632 | 158 | 8 | ±0 (byte-identical) |
| `shieldedAccountBalance` | 1,768 | 4,000 | 13 | ±0 (byte-identical) |
| `unshieldedAccountBalance` | 1,772 | 4,000 | 13 | ±0 (byte-identical) |
| `isRegistered` | 786 | 129 | 8 | ±0 (byte-identical) |
| `poolHasColour` | 792 | 129 | 8 | ±0 (byte-identical) |

**`execute` stays at k = 18**, with 51,085 rows of headroom, so nothing in the § Proving table
moves. The whole delta is attributable, instruction for instruction:

* `execute` gains exactly 3 `cond_select` instructions (251 → 254) and `depositShielded` exactly 1
  (9 → 10). **No other opcode count changes in any circuit**, and each added instruction costs
  exactly one row.
* Every `impact` operation is unchanged: 404 in `execute` and 90 in `depositShielded`, identical
  in order, guard wire and operands once SSA numbering is normalised. The `public_input` count is
  unchanged too (64 and 18). So the ledger effects, the guard truth values and the public-input
  vector are the same statement.
* The added instructions are all the same shape — `cond_select(value, 0, guard)` immediately
  before a guarded `constrain_bits(128)` — and come from upstream commit `f7580c25` ("one choke
  point for every guarded effect"). That commit made a range check inside a guarded scope check
  `select(g, w, 0)` **because that is what compactc itself emits** for a cast inside an `if`. The
  port is therefore *more* faithful to the reference at this pin, and pays 4 rows for it.
* The differential suite is green at this pin: **56/56**, including `pi_skips` equality entry by
  entry over all 404 Impact instructions and element-by-element public-input equality against the
  `compactc` artifact.

Two upstream API changes had to be absorbed, both type-level and both zero-instruction — which the
byte-identical output of the other seven circuits demonstrates rather than asserts:

* the newtype sweep (`CoinNonce`, `CoinColor`, `ZswapCoinPublicKey`, `ContractAddress`) and
  `SelfAddress` (`kernel.self()` as a proof of self, not a value): 21 call sites now wrap or
  `.address()`-unwrap. Upstream documents the newtypes as "provably zero-instruction and
  snapshot-neutral" because every impl delegates.
* the M24 tier boundary (`807b9b19`) moved the simulator VM behind `minocrab-sim`'s `unstable`
  feature, which the differential harness needs; the dev-dependency now enables it, as upstream's
  own in-workspace crates do.

What did NOT move: upstream still pins `midnight-ledger` rev `04c9c5d9…`, and its
`[patch.crates-io]` block is byte-identical to this workspace's, so the port links exactly the same
upstream code as before. The `Cargo.lock` change is the eight `minocrab-*` packages' rev plus one
new internal edge (`minocrab-sim` now also depends on `minocrab-ir`) — 397 packages before and
after, no other version moved.

## Caveats

1. **EXPERIMENTAL — emitted by an unaudited third-party compiler.** MinoCrab is pre-1.0 and
   unaudited. Nothing here has been audited either.
2. **Equivalence is tested, not proven.** See the section above for exactly what was tested; a
   passing empirical gate is not a proof.
3. **The standard Node ZK-config loader will REFUSE these keys in its default integrity mode.**
   Keys produced by `zkir-v3 compile` from a raw ZKIR carry no compiler manifest
   (`contract-manifest.json`), and `@midnight-ntwrk/midnight-js-node-zk-config-provider`'s *default*
   integrity mode requires one. A proof server or client must either be configured with a
   relaxed/disabled integrity check, or be supplied with a manifest. This is an integration cost of
   the raw-ZKIR keying route — it would affect *either* compiler taking that route — not a defect in
   the artifact: the keys are valid and were used to produce and verify 7 real proofs.
4. **Verification is ~2.3 ms slower** on the port, consistently. At ~10 ms either way this is
   practically irrelevant, but it is the one column that moves the wrong way.
5. **The row win does not generalise by percentage.** It is a byte-chain result; see the note under
   [§ Rows and `k`](#rows-and-k).
6. **Pin drift is the failure mode.** If a regenerated hash differs, suspect a moved rev before
   anything else.

## Vendored fixtures

`fixtures/eip712/v1.json` (310,192 B, sha256
`83381f7741138472d9632d56d0ceb628a34a176de93f7e6239d1d0788bcfe67b`) is the frozen EIP-712 test-vector
set `AUTH-EIP712-AA-V3-V1/FIXTURES-1`, copied verbatim from [`tests/fixtures/v1.json`][fixtures] in
the product repository at the pinned commit. It was generated against `@metamask/eth-sig-util`
8.2.0 and cross-checked there against the compiled `compactc` artifact. It is test-vector data, not
a compiled artifact — it is vendored so the EIP-712 suite runs from a fresh clone with no second
checkout. Override its location with `AA_EIP712_FIXTURES`.

## A note on the comments

Source comments throughout cite project numbers (`00012`, `00018`, `00020`) and finding IDs
(`F-00012-07`, `F-00012-08`, `F-00020-01`, …) from the research log that produced this port. They
are provenance markers for *why* a line is the way it is — they are not files in this repository.
Two worth knowing while reading:

* **F-00012-08** — the pool-underflow defect this port surfaced: `execute` had no provable run for
  three of its seven selectors, because an unguarded change-coin commitment hashed a value that
  underflowed. Fixed upstream in the product contract by PR #9, and that fix is in this statement.
* **F-00020-01** — a latent infidelity in the port itself: it had put the same recipient in *both*
  arms of the unshielded-recipient `Either`, where Compact muxes the unselected arm to the type
  default. Fixed here, and proved necessary by a control run.

## Credits

* [**sig-net/minocrab**][minocrab] — the Rust eDSL and its ZKIR backend. This repository is a
  *user* of minocrab; the compiler is theirs.
* [**midnightntwrk/midnight-ledger**][ledger] — the reference VM, FAB encoder, prover and verifier
  that both sides of every comparison run through.
* [**acedward/AA-midnight-evm-experiment-v3**][product] — the Compact contract being ported, and
  the origin of the frozen EIP-712 fixture set.

[product]: https://github.com/acedward/AA-midnight-evm-experiment-v3
[contract]: https://github.com/acedward/AA-midnight-evm-experiment-v3/blob/713a20215f33e02904ea5bd699b7de7f76562e1b/contracts/manager.compact
[pin]: https://github.com/acedward/AA-midnight-evm-experiment-v3/commit/713a20215f33e02904ea5bd699b7de7f76562e1b
[fixtures]: https://github.com/acedward/AA-midnight-evm-experiment-v3/blob/713a20215f33e02904ea5bd699b7de7f76562e1b/tests/fixtures/v1.json
[minocrab]: https://github.com/sig-net/minocrab
[ledger]: https://github.com/midnightntwrk/midnight-ledger
