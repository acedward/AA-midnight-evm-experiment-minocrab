# AA Manager — the MinoCrab port

The nine provable circuits of [`contracts/manager.compact`][contract] from
[**acedward/AA-midnight-evm-experiment-v3**][product] — an account-abstraction custody contract for
Midnight — transcribed into [**MinoCrab**][minocrab], a third-party Rust eDSL alternative compiler
for Midnight contracts.

The port is a **faithful** one: same typed argument and output schema per circuit, same
disclosures, same guard set in the same order, FAB-compatible public-input encoding, **no statement
change**. MinoCrab's own instruction-selection choices are the only thing allowed to differ — and
they are the whole point:

> ### `execute` drops from **k = 19 / 382,780 rows** to **k = 18 / 211,047 rows** — −44.86%
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

> ## ⚠ BREAKING since the first published snapshot
>
> **Every emitted `.zkir`, every `.bzkir` and both `execute` keys have changed.** Two independent
> causes, each measured on its own:
>
> 1. **The ported contract's ledger slot order changed.** The product split
>    `contracts/manager.compact` into a preset plus nine modules, and a Compact module contributes
>    its ledger fields as one contiguous block ahead of the importer's — so seven of the eight
>    fields were renumbered. Field *names* are unchanged, so off-chain read handles still resolve;
>    the on-chain *indices* are not, and **a contract deployed from the old artifact must be
>    redeployed**. The same split hoisted two registry membership reads out of custody and into
>    `execute` (the registry-to-custody seam), which moves `execute`'s read schedule.
> 2. **The MinoCrab pin moved** `6a53f2b` → `1522f9d`, which changes instruction selection.
>
> [§ Contract pin history](#contract-pin-history) and [§ MinoCrab pin history](#minocrab-pin-history)
> carry the before/after numbers and the instruction-level attribution for each. If you hold
> artifacts or keys from an earlier snapshot of this repository, regenerate them.

---

## Layout

```
manager-port/          the port: ONE MODULE PER COMPACT MODULE (see below), plus the equivalence gate
  src/                   the transcription — one file per contracts/modules/*.compact
  src/bin/emit_zkir.rs   emits one <circuit>.zkir per circuit into a directory
  tests/                 the equivalence gate (see § Running the differential suite)
prove-bench/           compiler-neutral keygen/prove/verify harness — links NO minocrab code, so
                       neither compiler's tooling is ever on the timing path
scripts/               toolchain (the compactc pin) · compile-baseline (the compactc artifact) ·
                       measure-zkir (k, rows) · keygen-zkir · check-port-artifacts (the emitted-ZKIR
                       gate) · check-refs (resolves every `contracts/…compact:NNN` citation) ·
                       free-port · decode-impact · diff-ledger-events
docker/                compactc.Dockerfile — the pinned toolchain, built from a SHA-256-pinned
                       release archive, so the reference side needs no private image
fixtures/eip712/       the frozen EIP-712 test-vector set (see § Vendored fixtures)
fixtures/port-artifact-hashes.json   the expected-hash table below, in machine form
.github/workflows/ci.yml   build · tests · `cargo fmt --check` · the artifact gate (see § CI)
```

### One Rust module per Compact module

The contract is a **preset plus nine modules**, and this crate carries the same names, so a reader
moving between the two repositories opens the file with the same name and finds the same circuits.

| Compact | here | key-emitting circuits it holds |
|---|---|---|
| `contracts/manager.compact` (the preset) | `src/execute.rs` | `execute` |
| `contracts/modules/AccountRegistry.compact` | `src/account_registry.rs` | `isRegistered`, `accountRecord` |
| `contracts/modules/ShieldedCustody.compact` | `src/shielded_custody.rs` | `shieldedAccountBalance`, `poolValue`, `poolHasColour` |
| `contracts/modules/UnshieldedCustody.compact` | `src/unshielded_custody.rs` | `unshieldedAccountBalance` |
| `contracts/modules/Custody.compact` | `src/custody.rs` | `depositShielded`, `depositUnshielded` |
| `contracts/modules/ActionEnvelope.compact` | `src/action_envelope.rs` | — (pure: `ExecutePayload` + the envelope asserts) |
| `contracts/modules/Eip712.compact` | `src/eip712.rs` | — (pure: the frozen bytes) |
| `contracts/modules/ByteCodec.compact` | `src/byte_codec.rs` | — (pure: where the row win is) |
| `contracts/modules/ZswapPrimitives.compact` | `src/zswap_primitives.rs` | — (pure: recipes over the kernel) |
| `contracts/modules/SemanticCommitment.compact` | **no counterpart** | — (not ported) |

`SemanticCommitment` is not ported: it is pure, emits no key, and is not among the nine provable
circuits, so there is nothing for the differential suite to compare. Four Rust modules have no
Compact twin and say so in their own headers: `ledger.rs` (the slot table — in Compact the block
does not exist as one declaration; the four state-owning modules each declare their fields and the
compiler concatenates them), `checks.rs` (predicates Compact expresses as syntax),
`disclosures.rs` (one type per `disclose(…)` label, which Compact expresses as the argument's name)
and `hello.rs` (a bring-up scaffold).

The mapping is **not** one-to-one on every function. Where a Compact internal only ever runs inside
`custodyDispatch` — `_credit`, `_writeCell`, `_pooled`, `_sendNamed`, `_releaseOpen`, `_claimWant`,
`_give` — it is inlined there rather than given a Rust function of its own, because the emitted op
stream is what has to match and inlining is what compactc does. Each is cited at its point of use,
and every module header states which of its twin's circuits it holds and which it does not.

## Pins

Every number below was measured at exactly these pins. They are not suggestions.

| thing | pin |
|---|---|
| **MinoCrab** | [`sig-net/minocrab`][minocrab] @ `1522f9dd024d2d9941a6fdcda1ad8f88ab7533b9` (upstream `main`, 2026-09-02) — **unaudited third party**. Previous pin `6a53f2b54850955406cd0f45dd78cc1e152182c7`; what the move cost is in [§ MinoCrab pin history](#minocrab-pin-history). **Note**: at this rev upstream carries a port of this same contract in its own corpus (`crates/minocrab-contracts/src/manager.rs`, over the 1,420-line pre-split source). That is a **different, semantic** port with its own goals; this repository does not use it, depend on it, or compare against it. Do not read a number from one as a number about the other |
| **Rust** | `cargo` / `rustc` **1.95.0**. Every number here was measured on `aarch64-apple-darwin`; the emitted ZKIR is also reproduced on `aarch64-unknown-linux-gnu` (§ CI). 1.92 and below do not build this workspace: `sysinfo@0.39.6` declares `rust-version = "1.95"` and arrives through `midnight-storage`, i.e. through the `midnight-ledger` rev minocrab pins. minocrab's own workspace floor is `rust-version = "1.85"`; 1.95.0 is what the dependency graph actually requires, re-checked at `1522f9d` |
| **Contract ported** | [`contracts/manager.compact`][contract] @ [`41de69ded41ff933fe0db8697b264dc46fc6e0cb`][pin] — since the product's module split this is a **398-line preset plus nine modules**, and the port transcribes all ten files; the per-file hashes are below. Previous pin `713a20215f33e02904ea5bd699b7de7f76562e1b` (one 1,420-line file, sha256 `164cf112…`); what the move cost is in [§ Contract pin history](#contract-pin-history) |
| **Reference compiler** | **Compact 0.34.0** / language 0.26.0 / runtime 0.19.0 / `--feature-zkir-v3`, the toolchain the product repository pins on `main`. Obtained and hash-verified by `scripts/toolchain.sh`, which builds `docker/compactc.Dockerfile` from release archive `compactc_v0.34.0_aarch64-unknown-linux-musl.zip` (sha256 `d3e292c4f48e257dcd6b3d3e3e4743d7d8ea0729f48953eab91a366d44cd026d`) — arm64. The verified binaries are `compactc.bin` `628b343f9b0ebe32e6e6a141b6f73cc66edb19c516a4817b478c3b47f74230d5` and `zkir-v3` `6a91308419d24bc0633210897d10c7c1b2193444e8bde09ce763e9556cb8f93a`. See the history note below |
| **Keygen tool** | `zkir-v3 compile` (`/opt/compactc/zkir-v3`), from that same image |
| **Upstream ledger crates** | `midnightntwrk/midnight-ledger` rev `04c9c5d9bcebb8d4427d8589fb54d58a55599c14`; `midnight-transient-crypto` tag `transient-crypto-2.2.0-rc.1` |
| **SRS used for keygen** | `bls_midnight_2p18`, 50,332,036 B, sha256 `e8436dc5d8b598f169c127c745135d889744007e6d384ff126df8d1332522f86` |

### The ten contract files this port transcribes

At `41de69d`. `scripts/check-port-artifacts.sh` carries the same table in
`fixtures/port-artifact-hashes.json` and prints the pin on every run;
`scripts/check-refs.sh` resolves every `contracts/…compact:NNN` citation in this repository against
a checkout of that commit and prints the line it lands on, so the citations are checkable rather
than decorative.

| file | sha256 |
|---|---|
| `contracts/manager.compact` (the preset) | `8e063ccfafbcda3cfaed572c00cce9c9436a958f1a7b5de23a3d7e37976a69b5` |
| `contracts/modules/AccountRegistry.compact` | `5930a7fe58ef141734989d8a1e7bc93077d239afbc3c3b2635fd2405363fe67c` |
| `contracts/modules/ActionEnvelope.compact` | `258135d5a5a7d19488dbe501db4631e65817d97813118e0e781b11e67f8e774b` |
| `contracts/modules/ByteCodec.compact` | `e38dc28ac5600298a150cbceca5b9832b46c3c0824219d834853665bf1444ebe` |
| `contracts/modules/Custody.compact` | `8186a3ad4454883c8820c26115c6dfc03541b08f04097bac1319b7cdd2dc6d70` |
| `contracts/modules/Eip712.compact` | `b7ed601f3911f6f380945d16430ae2ea484d9687bf0cee214c1d747ce83fe031` |
| `contracts/modules/SemanticCommitment.compact` | `d6a5228ebe4afdceea1e25559a3272c85776b6dc60e9fecdb18e1072454acebb` |
| `contracts/modules/ShieldedCustody.compact` | `266fc8108b0ea6fdb30749951e68ad25ba3568da910999d8e235d650d05dd538` |
| `contracts/modules/UnshieldedCustody.compact` | `e25bb7e7f9e74821030f40b0fcfd7dfe1b7814278dcd4cb344002ebfbccbe15c` |
| `contracts/modules/ZswapPrimitives.compact` | `a4bea887671e5088fa74ab589daff43aa35fca6c352361699ce194dad00af49b` |

`SemanticCommitment.compact` is transcribed by nobody here: it is pure, emits no key, and is not
among the nine provable circuits. It is pinned anyway because it is part of the compiled contract
the baseline is built from.

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
dependency. The default test run is **13 tests**: 8 in-crate assertions that each circuit's
*declared* disclosures are exactly the ones it makes, 3 that pin the ledger slot table (the derived
indices against the struct, the order against the split contract, and the pooled-coin read view
against the write view — see [§ Contract pin history](#contract-pin-history) for why those exist),
and the 2 EIP-712 fixture tests. None of them needs anything that is not in this repository. The
three differential test targets need a `compactc` baseline artifact and are feature-gated off; see
[§ Running the differential suite](#running-the-differential-suite).

## Measured results

### Rows and `k`

| artifact | k | rows | prover key | verifier key |
|---|---:|---:|---:|---:|
| `compactc` `execute` @ `41de69d` | **19** | 382,780 | 1,141,041,970 B | 3,321 B |
| **this port's `execute`** | **18** | **211,047** | **570,484,204 B** | 3,321 B |
| | | **−44.86%** | **−50.0%** | **±0** |

The k = 18 ceiling is 262,144 rows; this lands at 211,047 — **51,097 rows of headroom**, 80.51% of
the ceiling. The measurement is **triple**-derived here and all three agree: `zkir-v3 mock-compile`
reports `(k=18, rows=211047)`; upstream's own `IrSource::model()` reports k = 18 / 211,047 over
1,436 instructions — against 5,786 for the compactc artifact; and the `zkir-v3 compile` keygen
banner, which is a different code path in the same binary, printed
`Compiling circuit "/ir/execute.zkir" (k=18, rows=211047)` while producing the key pair recorded
below.

The other eight circuits are **not** where the win is, and **no `k` moves but `execute`'s**. Their
port-side rows are 42,256 / 7,917 / 4,000 / 4,000 / 332 / 158 / 129 / 129 — 58,921 in aggregate,
against compactc's 58,892 on the same contract: **+29 rows, +0.049% — a wash, marginally in
MinoCrab's disfavour.** (Neither side's eight moved when the contract was split; only `execute`
did.) The −44.86% on `execute` comes from replacing per-byte explode/rebuild chains, which are
54.3% of `execute`'s instructions and ≈0% of everything else's. Do not transfer the headline
percentage to another contract without checking that it, too, is byte-chain heavy.

### Proving

Measured on an Apple M4 Max (12P + 4E, 48 GiB, macOS 15.7.3 arm64), both artifacts proved through
the **same** upstream prover on **identical `ProofPreimage`s** that both accept, interleaved A/B
across two sessions.

**These are the MinoCrab `6a53f2b` / contract `713a202` numbers** (`execute` at 211,056 rows).
The current snapshot's `execute` is 211,047 rows at the same k = 18, and k is what proving time and
key size are a function of, so the table transfers — but it has not been re-measured in full. A
single-scenario smoke on the CURRENT keys (`sel0-native-registration`, one prove + one verify)
produced a verified proof in **18.05 s**, consistent with the 19.3 s median below:

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

1. **The baseline is already hand-tuned for exactly what the port attacks.** The compactc figure
   (382,781 rows then, 382,780 now) already banks a big-endian-encoder optimization worth −267,216
   rows (−27.42%), landed before this comparison. The win is on top of that, not instead of it.
2. **The timing table was measured on the immediately preceding statement** (211,028 rows), whose
   four benchmarkable scenarios covered selectors 0, 1, 2 and 6. A same-session control on **this**
   snapshot's keys re-measured selector 3 at **18,980 ms** on the k = 18 key against **40,173 ms**
   on the k = 19 compactc key — consistent with the table.
3. **Absolute seconds are machine-relative and the host was not idle.** Treat the *ratio* as the
   transferable number.

### History: what each change cost `execute`

Three things have moved this circuit since the port was first published, and each was isolated and
measured on its own rather than inferred from the total. Read in order:

| # | change | rows | Δ | where |
|---|---|---:|---:|---|
| 0 | the port, as first published (MinoCrab `6a53f2b`, contract `713a202`) | 211,056 | — | the table below |
| 1 | Compact toolchain 0.33.0 → 0.34.0 | 211,056 | **±0** | [§ Pins](#pins) — no tool delta at all: same k, same rows, byte-identical `.bzkir` for all nine |
| 2 | MinoCrab `6a53f2b` → `1522f9d` | 211,059 | **+3** | [§ MinoCrab pin history](#minocrab-pin-history) |
| 3 | contract `713a202` → `41de69d` (the module split) | **211,047** | **−12** | [§ Contract pin history](#contract-pin-history) |

**k = 18 throughout.** Nothing in the § Proving table moves, because `k` is what proving time and
key size are a function of.

#### The three contract fixes that produced row 0

Each change set was applied cumulatively to the port, re-emitted, and re-measured with the same
oracle — measured, not estimated. (The crate was then restored and re-emits `execute.zkir`
byte-identically, which is what makes the intermediate numbers safe to publish.)

All four rows below are MinoCrab `6a53f2b` / contract `713a202` measurements — the statement's
cost, with the compiler held still.

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
| `execute.zkir` | 123,635 | `50f09e0b36bb8cf34e6db52fbbff46a4d94746dd4fc10895e8c770c4f26298c0` |
| `execute.bzkir` | 51,990 | `209d7139d9945bcd6fac0ca545a4e8c6886165a315118c768901fb5507f28d19` |

The key pair, regenerated from that ZKIR against the pinned SRS:

| file | bytes | SHA-256 |
|---|---:|---|
| `execute.prover` | 570,484,204 | `eb4405382ba8dd2fc86434410f284db3493e804148ce7b0e3d54952d1a5db5a9` |
| `execute.verifier` | 3,321 | `13096f6f22344b264d85b86af2da811f797cce55e76d085e0185eb81bc359b60` |

The prover key is 196 bytes smaller than the one the first published snapshot recorded
(570,484,400): key size tracks k *almost* entirely, but not exactly, so it is re-recorded rather
than carried forward. The verifier key stays 3,321 B.

The other eight circuits (`.bzkir` is what `zkir-v3 mock-compile` writes; no keys were generated
for these — only `execute` was at k = 19):

| circuit | `.zkir` bytes | `.zkir` SHA-256 | `.bzkir` bytes | `.bzkir` SHA-256 |
|---|---:|---|---:|---|
| `depositShielded` | 14,927 | `eada91aa306819d4dfd0395b2efb03d882131f33d42f1b8ed34a984e76859cd8` | 5,713 | `ceda8bffcf270c12bacbdd514e0b47a0d7991acb820f34c6dddcaa493add650c` |
| `depositUnshielded` | 4,333 | `29ba8b53bbe4bc233f41f3ab5371c13a11a5698f587554f89b298bedc764ea53` | 1,659 | `45f79a599c22de5da1bd5a19ffa37cf4a00a5f571b96948051eb9a26d9341619` |
| `shieldedAccountBalance` | 1,768 | `132a4afceb81c656d34493c9806a42bb321fe0373341b1bf5bbd4e85c110abdb` | 612 | `c51aa2ff6fd3511c2b566220de4e6602722cbdc26d01f2d9f52449049b358b9b` |
| `unshieldedAccountBalance` | 1,772 | `e609149de5161522555677b777ba82717d71c5bb0e96afab8acf4c68f214e982` | 616 | `652188daffd451bf00b0b9b30400163ee49b5ecd47f175899dcc7da52035acc9` |
| `accountRecord` | 6,065 | `2530fca640e76a817c234b84ba4144fe5f2341fcda319e1af3a5c16ce3977ffa` | 2,430 | `5a9c8b7ff2dd4e5b5d2f833e63120b6f6b6fd9a95ccc6bec86218ac59ca171c2` |
| `poolValue` | 1,632 | `9aeab69ad730f80f747e0fedd5a5301be0e8b7367db6f99af47275366a40dad3` | 555 | `ad012dd0726153e99d045710fafc0deb6ba1525fd99e78b4081926325b605b45` |
| `isRegistered` | 786 | `25eaf82d9391232e00ce0c15e95cbaf004f7acb59d82827c7429be08328bcb0f` | 263 | `4da9bbd859ca5d42bccfb02951466d010ef24df0f1e22a149e76bac5057e114d` |
| `poolHasColour` | 792 | `55c30b8add242f7093c2e40e2124d02a9f4f3a9d19259736ab142a3ebd7d0709` | 269 | `4616eb019c61c17693aa5ac0cc1a1c30c5216ed1d48ecf51d049ccc1995ed054` |

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
#   -> Mock compiling circuit "execute.zkir" (k=18, rows=211047)

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
proofs. At MinoCrab `6a53f2b` / contract `713a202` it produced **one verified proof per selector,
7 of 7**, each 10,304 bytes over 1,265 public inputs, on preimages synthesized from the *compactc*
artifact and accepted unchanged by this one. At the current pins the full sweep has not been
re-run; what has, on the key pair recorded above, is `prove-bench check` (**14/14 ACCEPT**: both
artifacts accept all seven scenarios' preimages, `pi_skips` equal entry by entry over all 404
Impact ops) and a one-scenario prove/verify smoke (**1/1 verified**, 18.05 s). To re-run it:

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
#      (add `--scenarios sel0-native-registration` for the one-proof smoke)
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
git -C AA-midnight-evm-experiment-v3 checkout 41de69ded41ff933fe0db8697b264dc46fc6e0cb
shasum -a 256 AA-midnight-evm-experiment-v3/contracts/manager.compact \
              AA-midnight-evm-experiment-v3/contracts/modules/*.compact
#   -> the ten hashes under § Pins

# 2. compile the baseline (--skip-zk: no keys are generated). scripts/toolchain.sh obtains and
#    verifies compactc 0.34.0 on the way in; the compile itself runs --network none.
#
#    Point it at the PRESET; `compile-baseline.sh` mounts the whole directory the file lives in, so
#    the compiler resolves the preset's `./modules/*` imports inside the container. Compiling a
#    module on its own is meaningless — a module emits no artifact.
scripts/compile-baseline.sh baseline \
  AA-midnight-evm-experiment-v3/contracts/manager.compact $(scripts/free-port.sh)
#   -> ZKIR_CIRCUITS=9

# 3. run the gate
cargo +1.95.0 test --release --locked -p manager-port --features compactc-baseline
#   -> 59 tests, all green

# 4. (optional) check that every source-line citation in this repository still resolves
scripts/check-refs.sh AA-midnight-evm-experiment-v3
#   -> CHECK-REFS OK — every reference resolves inside the product checkout
```

The suite looks for `generated/baseline/manager/zkir/<circuit>.zkir`; set `AA_BASELINE_ZKIR_DIR` to
point it somewhere else.

**Check your baseline before you trust a red run.** A different compactc version will emit a
different artifact, and a mismatch will then be reported against *your* baseline rather than
against the one these results describe — which is why `scripts/toolchain.sh` refuses to run on a
compiler it does not recognise. The published gate ran against a baseline whose `execute` side
measured k = 19 / 382,780 rows, and whose nine ZKIR files are byte-identical to the artifact the
product repository recorded for the same commit.

## What "equivalent" was tested to mean

**59/59 tests, gate green**, against the product's own `compactc` artifact compiled from
`41de69d` — the split contract, preset plus nine modules:

* **Typed schema identity** — input types in order, output types, communications-commitment flag.
* **`pi_skips` equality entry by entry over all 404 Impact instructions** of `execute`, on every
  scenario (and over each other circuit's own count: 90 for `depositShielded`, 37 for
  `accountRecord`, 5 for `poolHasColour`, …). Two artifacts can agree here only if they emit the
  same ledger operations, in the same order, with the same input counts and the same guard truth
  values.
* **Public-input-vector equality element by element** on a shared `ProofPreimage` (1,265 elements),
  with upstream's own `Zkir::check()` agreeing with the simulation on both sides.
* **26 accepted scenarios** — 11 covering all seven `execute` selectors plus every
  selector-independent arm of the mux, and 15 across the other eight circuits — each with a
  single-element tamper sweep over its whole preimage: **5,128 probes, 0 acceptance
  disagreements** (plus 19 more on `isRegistered`'s own sweep). Every mutation is accepted or
  rejected identically by both artifacts.
* **The ledger slot table is derived, not asserted.** `manager-port/src/ledger.rs` is the one place
  a field index is written down; the harnesses' VM transcripts, pre-state arrays and post-state
  assertions read it out of `#[derive(Ledger)]`'s own paths (`ledger::slot`), and two unit tests
  pin the order to the split contract's. A third pins the pooled-coin READ view to the same slot as
  the write view — the one place where a second copy of an index used to live, and the one the
  re-target caught.
* **Refusal agreement** on the shapes PR #10 forbids (contract-tagged withdrawal recipient,
  contract-tagged swap taker): both artifacts refuse, at an envelope assert.
* **Reference-VM replay ×4** (selectors 0, 1, 2, 3): the accepted transcript is decoded back into
  Impact ops, re-encoded as a check, and run through Midnight's own `QueryContext::query` in
  `ResultModeVerify` against a constructed pre-state. Every `Popeq` is checked against real state,
  and the post-state and `Effects` are asserted.
* **The EIP-712 chain** — domain separator, struct hash and digest — byte-compared against the
  frozen fixture set: **60 cases, 180 byte comparisons**. These are pure circuits with no proving
  key, so they get a stricter bar: the bytes are what a MetaMask signature commits to.

What this does **not** establish: a formal proof of statement equivalence, or any claim about
MinoCrab's correctness in general. It is a strong *empirical* gate on **this** circuit against
**this** reference artifact.

## Contract pin history

### `713a202` → `41de69d` (2026-09-04): the module split — **every artifact changes; `execute` −12 rows**

The product repository split its 1,420-line `contracts/manager.compact` into a 398-line preset plus
nine modules under `contracts/modules/`. For the *contract* that was a pure refactor. For this
*port* it is two separate statement-level moves, and both were measured on their own.

#### 1. The ledger slot order — immediates only, not one row

A Compact module contributes its ledger fields as ONE CONTIGUOUS BLOCK, **before** the importer's
own, whatever the import's textual position. So the effective order is the module graph's:

```
before   pools, accounts, shieldedBalances, unshieldedBalances, accountModes, evmOwners, evmNonces, deploymentDomain
after    accounts, accountModes, evmOwners, evmNonces, pools, shieldedBalances, unshieldedBalances, deploymentDomain
```

Seven of the eight fields moved (`pools` 0→4, `accounts` 1→0, `shieldedBalances` 2→5,
`unshieldedBalances` 3→6, `accountModes` 4→1, `evmOwners` 5→2, `evmNonces` 6→3; only
`deploymentDomain` stayed at 7). **Field names did not change**, so off-chain read handles still
resolve — but the on-chain indices did, so **a contract deployed from the old artifact must be
redeployed**, and every artifact this crate emits changes.

What it cost, measured: **nothing**. All nine `.zkir` files kept their exact byte length, all nine
kept their `k` and their row count, and every changed byte is a slot immediate:

| | `execute` | `depositShielded` | `accountRecord` | the other six |
|---|---:|---:|---:|---|
| changed Impact instructions | 43 | 8 | 8 | 1–4 each |
| changed opcodes | **0** | **0** | **0** | **0** |
| rows | 211,059 → 211,059 | 42,256 → 42,256 | 332 → 332 | unchanged |

71 instructions changed across the nine circuits and **71 tokens** with them — one per instruction,
every one the single one-byte key of a root ledger field access (`idx`/`idx_p`), moving exactly as
the table above says. No opcode, no guard, no operand, no input or output schema changed. The
control runs the other way too: putting the eight struct fields back in the old order and changing
nothing else reproduces the previous snapshot's ten hashes exactly.

#### 2. The registry-to-custody seam — a real move, and it is cheaper

`Custody.compact` holds no registry state, and a Compact module never resolves caller identity, so
the split hoisted the two membership reads custody needs out of `custodyDispatch` and into
`execute`, which passes them down as Booleans
(`custodyDispatch(p, account, isRegistered(p.toAccount), isRegistered(p.creditAccount))`). The
asserts stayed at their original positions with their original messages.

That changes `execute`'s read schedule: the two `accounts.member` ops move earlier and lose their
inner short-circuit guards (they used to be reached only under `isTransfer` / `isSwap`). The port
follows it, because the port transcribes the contract. Measured, on `execute` alone — the other
eight circuits are byte-identical across this step:

| | before | after | Δ |
|---|---:|---:|---:|
| rows | 211,059 | **211,047** | **−12** |
| k | 18 | 18 | ±0 |
| instructions | 1,444 | **1,436** | **−8** |
| `cond_select` | 254 | **246** | **−8** |
| every other opcode | — | — | **±0** |
| Impact ops | 404 | 404 | ±0 |
| `public_input` | 64 | 64 | ±0 |
| input/output schema | — | — | identical |

The eight instructions are the guard muxes the two short-circuited reads needed and no longer do.
Upstream's row estimator attributes exactly −8 rows to them; `zkir-v3 mock-compile` reports −12,
the extra four being table packing the estimator does not model (its offset from the measured
figure moves 8,806 → 8,810 across the step). On the compactc side the same seam costs **one** row
(382,781 → 382,780) — a different number for the same change, because the two compilers lower a
guarded read differently, which is what this whole comparison measures.

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

**`execute` stayed at k = 18**, so nothing in the § Proving table moved. The whole delta is
attributable, instruction for instruction:

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
* The differential suite was green at this pin against the then-current contract `713a202`:
  **56/56**, including `pi_skips` equality entry by entry over all 404 Impact instructions and
  element-by-element public-input equality against the `compactc` artifact. (Against the split
  contract it is 59/59; see [§ Contract pin history](#contract-pin-history).)

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

## CI

`.github/workflows/ci.yml` runs on every push and pull request, on `ubuntu-24.04`, and does four
things: `cargo fmt --all -- --check`, `cargo build --release --locked`,
`cargo test --release --locked` (the default targets), and
`scripts/check-port-artifacts.sh --no-toolchain-check`. Cargo's registry, git checkouts and
`target/` are cached on `Cargo.lock`.

**It does not run the differential suite, and that is deliberate.** The suite's `compactc` baseline
is a compiled file that is not in this repository and cannot be: reproducing it needs the pinned
Compact toolchain in Docker plus a checkout of the product repository. So the division of labour is:

| | question it answers |
|---|---|
| CI | did the emitted **bytes** change, and does the crate still build and pass its own tests? |
| the local suite | is the **statement** still equivalent to the contract? |

A byte change with a green differential suite is a legitimate re-record; a byte change with no
explanation is a bug. CI can only ever see the first half of that sentence, so a green badge here
is not a claim of equivalence — [§ What "equivalent" was tested to mean](#what-equivalent-was-tested-to-mean)
is.

CI therefore also serves as the port's only **cross-platform** check: every number in this README
was measured on `aarch64-apple-darwin`, and the artifact gate re-emitting identically on another
platform is what says the hashes are a property of the crate rather than of one laptop. That was
verified before this workflow was added — a clean clone, built and gated in a Linux container on
`aarch64-unknown-linux-gnu`, emits **all ten `.zkir` files byte-identically** to the macOS record
and passes `cargo fmt --check`, the default tests and the artifact gate. `x86_64` is what the
workflow itself confirms.

(That exercise paid for itself immediately: it is how `mktemp: too few X's in template` was found —
`mktemp -t NAME` is BSD's spelling and GNU coreutils rejects it, so the gate would have failed on
CI's very first run, before emitting anything.)

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
   the artifact: the keys are valid and have been used to produce and verify real proofs (7 of 7 at
   the previous pins, 1 of 1 as a smoke on the current pair).
4. **Verification is ~2.3 ms slower** on the port, consistently. At ~10 ms either way this is
   practically irrelevant, but it is the one column that moves the wrong way.
5. **The row win does not generalise by percentage.** It is a byte-chain result; see the note under
   [§ Rows and `k`](#rows-and-k).
6. **Pin drift is the failure mode.** If a regenerated hash differs, suspect a moved rev before
   anything else — the gate prints the recorded `minocrab` rev next to the observed one for exactly
   that reason.
7. **The ledger slot order is BREAKING against artifacts from before contract `41de69d`**, and a
   contract deployed from those must be redeployed. See the notice at the top and
   [§ Contract pin history](#contract-pin-history).
8. **The proving table was measured at the previous pins** (`6a53f2b` / `713a202`) and is labelled
   as such wherever it appears. `k` has not moved, which is what makes it transferable, and a
   single-scenario smoke on the current keys is consistent with it — but it is not a fresh full
   run.

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
[contract]: https://github.com/acedward/AA-midnight-evm-experiment-v3/blob/41de69ded41ff933fe0db8697b264dc46fc6e0cb/contracts/manager.compact
[pin]: https://github.com/acedward/AA-midnight-evm-experiment-v3/commit/41de69ded41ff933fe0db8697b264dc46fc6e0cb
[fixtures]: https://github.com/acedward/AA-midnight-evm-experiment-v3/blob/41de69ded41ff933fe0db8697b264dc46fc6e0cb/tests/fixtures/v1.json
[minocrab]: https://github.com/sig-net/minocrab
[ledger]: https://github.com/midnightntwrk/midnight-ledger
