#!/usr/bin/env bash
#
# check-port-artifacts.sh — THE PORT'S ARTIFACT GATE: prove this crate still emits the same ZKIR.
#
# WHAT IT DOES
#   Re-emits every circuit with `emit-zkir` into a throwaway directory and compares each file's
#   SIZE and SHA-256 against the committed record `fixtures/port-artifact-hashes.json`. Any
#   difference — a changed hash, a changed size, a missing circuit, an unexpected extra one — is a
#   non-zero exit with a readable per-circuit diff.
#
# WHY IT EXISTS
#   The README publishes an expected SHA-256 for every emitted `.zkir`, and the whole claim of this
#   repository ("the port is a faithful transcription and here is exactly what it emits") rests on
#   those hashes being true. Until this script existed they were only as true as the last person who
#   ran `shasum` by hand. Emission is deterministic, needs no Docker, no compactc, no SRS and no
#   network, so the check is cheap enough to run on every push — which is what makes a silent drift
#   in the eDSL, the pinned rev, or a refactor impossible to miss.
#
#   Note the division of labour. This gate answers "did the BYTES change". It does not answer "is
#   the statement still equivalent to the contract" — that is the differential suite
#   (`cargo test --features compactc-baseline`), which needs the compactc baseline and stays a
#   local, feature-gated gate. A byte change with a green differential suite is a legitimate
#   re-record; a byte change with no explanation is a bug.
#
# THE RECORD IS PROVENANCE, NOT JUST HASHES
#   `fixtures/port-artifact-hashes.json` carries, next to the per-circuit sizes and hashes:
#     * `minocrabRev`      — the eDSL rev that emitted them, read out of the root Cargo.toml and
#                            re-checked on every run: it is the single most likely cause of a
#                            mismatch, so the gate names it before you go looking anywhere else.
#     * `contractPin`      — the product commit and `manager.compact` sha256 whose statement these
#                            circuits transcribe. Carried forward across a `--write` unless you
#                            override it, and printed every time so it cannot rot invisibly.
#     * `toolchain`        — the compactc image ref and the SHA-256 of its `compactc.bin` and
#                            `zkir-v3`, from scripts/toolchain.sh. These do NOT decide a single byte
#                            of the port's ZKIR (nothing here is compiled by compactc); they are
#                            recorded because the same record is what the README's reference and key
#                            numbers were measured with, and a reader deserves to see which
#                            toolchain that was.
#
# usage:
#   scripts/check-port-artifacts.sh                    re-emit and compare (THE GATE)
#   scripts/check-port-artifacts.sh --zkir-dir <dir>   compare an already-emitted directory
#   scripts/check-port-artifacts.sh --write            RE-RECORD the fixture from this emission
#   scripts/check-port-artifacts.sh --write \
#       --contract-pin <sha> --contract-sha256 <sha>   re-record and move the contract pin with it
#   scripts/check-port-artifacts.sh --no-toolchain-check   skip the Docker toolchain probe
#
# `--write` never runs by accident: the gate itself is the no-argument form. Re-record only when a
# byte change is INTENDED and explained — the commit message must say which hashes moved and why.
#
# Environment:
#   CARGO_TOOLCHAIN   rustup toolchain used for the re-emit. Default `1.95.0`, the pinned one
#                     (1.92 and below are below minocrab's floor). Set empty to use the default.
#   COMPACTC_IMAGE    passed through to scripts/toolchain.sh; see there.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$repo_root/fixtures/port-artifact-hashes.json"

mode="compare"
zkir_dir=""
toolchain_check=1
contract_pin_override=""
contract_sha_override=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --write)                mode="write"; shift ;;
    --zkir-dir)             zkir_dir="${2:?--zkir-dir needs a directory}"; shift 2 ;;
    --no-toolchain-check)   toolchain_check=0; shift ;;
    --contract-pin)         contract_pin_override="${2:?--contract-pin needs a commit sha}"; shift 2 ;;
    --contract-sha256)      contract_sha_override="${2:?--contract-sha256 needs a sha256}"; shift 2 ;;
    -h|--help)              sed -n '2,50p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)                      echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

echo "=== check-port-artifacts ==="
echo "MODE=$mode"

# --- the eDSL rev that decides every byte below -------------------------------------------------
# Read from the root manifest rather than hard-coded here: the manifest is where a bump actually
# happens, and a gate that carried its own copy of the rev could disagree with the build.
minocrab_rev="$(sed -n 's/^minocrab = .*rev = "\([0-9a-f]\{40\}\)".*/\1/p' "$repo_root/Cargo.toml" | head -1)"
[ -n "$minocrab_rev" ] || { echo "could not read the minocrab rev out of $repo_root/Cargo.toml" >&2; exit 65; }
echo "MINOCRAB_REV=$minocrab_rev"

# --- toolchain provenance (recorded, never load-bearing for the hashes) -------------------------
toolchain_image="not-probed"
compactc_bin_sha256="not-probed"
zkir_v3_sha256="not-probed"
if [ "$toolchain_check" -eq 1 ]; then
  # shellcheck source=scripts/toolchain.sh
  . "$repo_root/scripts/toolchain.sh"
  ensure_image
  toolchain_image="$COMPACTC_IMAGE"
  compactc_bin_sha256="${TOOLCHAIN_COMPACTC_BIN_SHA256:-unknown}"
  zkir_v3_sha256="${TOOLCHAIN_ZKIR_V3_SHA256:-unknown}"
else
  echo "--no-toolchain-check: the compactc toolchain is not probed (it decides none of the hashes below)"
fi

# --- emit ---------------------------------------------------------------------------------------
work=""
cleanup() { [ -n "$work" ] && rm -rf "$work"; }
trap cleanup EXIT INT TERM

if [ -n "$zkir_dir" ]; then
  zkir_dir="$(cd "$zkir_dir" && pwd)"
  echo "REUSING=$zkir_dir"
else
  work="$(mktemp -d -t minocrab-port-artifacts)"
  zkir_dir="$work/port-zkir"
  toolchain_arg=()
  if [ -n "${CARGO_TOOLCHAIN-1.95.0}" ]; then
    toolchain_arg=("+${CARGO_TOOLCHAIN:-1.95.0}")
  fi
  echo "EMITTING into $zkir_dir with cargo ${toolchain_arg[*]:-<default toolchain>}"
  ( cd "$repo_root" && cargo "${toolchain_arg[@]}" run --release --locked \
      -p manager-port --bin emit-zkir -- "$zkir_dir" ) >/dev/null
fi

# --- compare (or write) -------------------------------------------------------------------------
ZKIR_DIR="$zkir_dir" \
FIXTURE="$fixture" \
MODE="$mode" \
MINOCRAB_REV="$minocrab_rev" \
TOOLCHAIN_IMAGE="$toolchain_image" \
COMPACTC_BIN_SHA256="$compactc_bin_sha256" \
ZKIR_V3_SHA256="$zkir_v3_sha256" \
CONTRACT_PIN_OVERRIDE="$contract_pin_override" \
CONTRACT_SHA_OVERRIDE="$contract_sha_override" \
python3 - <<'PY'
import datetime, hashlib, json, os, sys

zkir_dir = os.environ["ZKIR_DIR"]
fixture = os.environ["FIXTURE"]
mode = os.environ["MODE"]

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

names = sorted(f[:-5] for f in os.listdir(zkir_dir) if f.endswith(".zkir"))
if not names:
    print(f"no .zkir files in {zkir_dir}", file=sys.stderr)
    sys.exit(66)
observed = {
    n: {"bytes": os.path.getsize(os.path.join(zkir_dir, n + ".zkir")),
        "sha256": sha256(os.path.join(zkir_dir, n + ".zkir"))}
    for n in names
}

prev = json.load(open(fixture)) if os.path.exists(fixture) else {}

# The contract pin is not derivable from anything in this repository — the port does not contain
# the `.compact` source — so it is RECORDED here and carried forward across a re-record unless the
# caller moves it explicitly. It is printed on every run so a stale pin is visible, not silent.
contract = dict(prev.get("contractPin", {}))
if os.environ["CONTRACT_PIN_OVERRIDE"]:
    contract["commit"] = os.environ["CONTRACT_PIN_OVERRIDE"]
if os.environ["CONTRACT_SHA_OVERRIDE"]:
    contract["managerCompactSha256"] = os.environ["CONTRACT_SHA_OVERRIDE"]

if mode == "write":
    doc = {
        "note": (
            "The SIZE and SHA-256 of every .zkir `emit-zkir` produces, i.e. the README's expected-hash "
            "table in machine form. Compared by scripts/check-port-artifacts.sh; re-record with "
            "`--write` ONLY when a byte change is intended and the commit message says which hashes "
            "moved and why. Emission is deterministic and needs no compactc, no Docker and no network: "
            "the hashes are decided by the `minocrab` rev below and by this crate's source, nothing else."
        ),
        "recordedAt": datetime.date.today().isoformat(),
        "minocrabRev": os.environ["MINOCRAB_REV"],
        "contractPin": contract,
        "toolchain": {
            "note": (
                "Recorded for the reader, NOT load-bearing for the hashes: nothing in this repository is "
                "compiled by compactc. This is the toolchain the README's reference (compactc baseline) "
                "and key numbers were measured with."
            ),
            "image": os.environ["TOOLCHAIN_IMAGE"],
            "compactcBinSha256": os.environ["COMPACTC_BIN_SHA256"],
            "zkirV3Sha256": os.environ["ZKIR_V3_SHA256"],
        },
        "circuits": observed,
    }
    with open(fixture, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    print(f"WROTE {fixture}")
    print(f"  {len(observed)} circuit(s), minocrab rev {doc['minocrabRev']}")
    print(f"  contract pin {contract.get('commit', '(unset)')} "
          f"manager.compact {contract.get('managerCompactSha256', '(unset)')}")
    for n in names:
        print(f"  {n:28} {observed[n]['bytes']:>9} B  {observed[n]['sha256']}")
    sys.exit(0)

if not prev:
    print(f"no record at {fixture} — seed it with `--write`", file=sys.stderr)
    sys.exit(66)

failures = []

print("--- provenance")
rec_rev = prev.get("minocrabRev")
obs_rev = os.environ["MINOCRAB_REV"]
print(f"  minocrabRev   recorded {rec_rev}")
print(f"                observed {obs_rev}  {'==' if rec_rev == obs_rev else '!= (THIS IS THE FIRST THING TO SUSPECT BELOW)'}")
rec_contract = prev.get("contractPin", {})
print(f"  contractPin   {rec_contract.get('commit', '(unset)')}  manager.compact "
      f"{rec_contract.get('managerCompactSha256', '(unset)')}")
rec_tool = prev.get("toolchain", {})
print(f"  toolchain     {rec_tool.get('image', '(unset)')}  zkir-v3 {rec_tool.get('zkirV3Sha256', '(unset)')}")

print("--- circuits (bytes, sha256)")
recorded = prev.get("circuits", {})
for n in sorted(set(recorded) | set(observed)):
    want, got = recorded.get(n), observed.get(n)
    if want is None:
        print(f"  + {n:28} {got['bytes']:>9} B  {got['sha256']}   NOT IN THE RECORD")
        failures.append(f"{n}: emitted but not in the record")
        continue
    if got is None:
        print(f"  - {n:28} {want['bytes']:>9} B  {want['sha256']}   IN THE RECORD, NOT EMITTED")
        failures.append(f"{n}: in the record but not emitted")
        continue
    ok = want["bytes"] == got["bytes"] and want["sha256"] == got["sha256"]
    if ok:
        print(f"    {n:28} {got['bytes']:>9} B  {got['sha256']}  ==")
    else:
        print(f"  ! {n:28} recorded {want['bytes']:>9} B  {want['sha256']}")
        print(f"    {'':28} observed {got['bytes']:>9} B  {got['sha256']}")
        failures.append(
            f"{n}: recorded {want['bytes']} B/{want['sha256'][:16]}…, "
            f"observed {got['bytes']} B/{got['sha256'][:16]}…"
        )

print("---")
if failures:
    print(f"PORT ARTIFACT GATE FAILED ({len(failures)} difference(s)):")
    for f in failures:
        print(f"  * {f}")
    if rec_rev != obs_rev:
        print("  The recorded minocrab rev is NOT the one that just emitted these files. A rev bump")
        print("  changes instruction selection, so a hash change is expected — re-record with")
        print("  `--write` and say so in the commit message.")
    else:
        print("  The minocrab rev is unchanged, so this is a change in THIS crate's source. If the")
        print("  statement moved on purpose, run the differential suite first")
        print("  (`cargo test --features compactc-baseline`) and only then re-record.")
    sys.exit(1)
print(f"PORT ARTIFACT GATE OK — {len(observed)} circuit(s), every size and hash identical")
PY
