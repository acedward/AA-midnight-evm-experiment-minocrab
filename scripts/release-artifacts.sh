#!/usr/bin/env bash
#
# release-artifacts.sh — build EVERY file a release publishes, and prove what each one IS.
#
# ## What a release of this repository contains, and why it exists at all
#
# This repository ships **no compiled output**: `generated/` is gitignored, keys are hundreds of
# megabytes, and the README's expected-hash tables were, until now, the only way to find out what a
# correct artifact looks like. That is fine for a reader who is going to regenerate everything, and
# useless for a CONSUMER — a deployment that needs a verifier key for every exported circuit at
# deploy time and a prover key for every circuit it proves, and that wants those files identified by
# SHA-256 rather than re-derived at bring-up. Keying a raw ZKIR needs `zkir-v3` from a pinned
# compactc archive plus the Midnight SRS for the circuit's `k`; asking every consumer to reproduce
# that is asking every consumer to re-earn the trust this repository has already earned once.
#
# So a release publishes, for each of the nine provable circuits:
#
#     <circuit>.zkir       the emitted IR                        (deterministic, no toolchain)
#     <circuit>.bzkir      the binary IR `zkir-v3` derives from it
#     <circuit>.prover     the proving key
#     <circuit>.verifier   the verifying key
#
# plus `SHA256SUMS` over all 37 other files and `manifest.json` — **38 files**. Individual files,
# never an archive: a consumer that needs three kilobytes of verifier key must not have to download
# 780 megabytes to get it, and each file must be verifiable on its own.
#
# `emit-zkir` writes a tenth circuit, `hello_positive_amount`, a bring-up smoke that is not part of
# the contract's provable surface. It is GATED here like the rest and PUBLISHED nowhere. The release
# set is exactly the nine circuits named in `fixtures/srs-hashes.json`.
#
# ## What this script gates before it produces a single byte of key material
#
# A key is a claim about a circuit, and a key whose provenance is unknown is worse than no key:
#
#   1. **The IR.** Every emitted `.zkir` is compared, size and SHA-256, against
#      `fixtures/port-artifact-hashes.json` — the same record `check-port-artifacts.sh` gates on.
#      One mismatch aborts. A key generated from IR nobody recognises would be published under a
#      hash table that describes something else.
#   2. **The SRS.** Each structured reference string is verified against `fixtures/srs-hashes.json`
#      before use. The SRS decides the key bytes as much as the IR does: the same ZKIR keyed against
#      a different SRS is a different key.
#   3. **`k`.** `fixtures/srs-hashes.json` records which circuits belong to which `k`, so the `k`
#      `zkir-v3` reports is compared against the recorded one. A circuit that silently grew past a
#      power of two would otherwise be keyed against an SRS chosen for its old `k`.
#   4. **The tool.** `zkir-v3` is verified by SHA-256 against `scripts/toolchain.sh`'s pin, whether
#      it runs natively or in the image. Exit 70, never a warning.
#   5. **The keys themselves, once they have been recorded.** When
#      `fixtures/port-artifact-hashes.json` carries `prover`/`verifier` entries for a circuit, the
#      regenerated pair must match them exactly. This is what makes a release reproducible rather
#      than merely repeatable, and it is the check that fails a tag rather than publishing a
#      surprise. `--write-keys` records the entries in the first place, and is only ever run
#      deliberately, for a change the commit message explains.
#
# ## Native or in Docker — the same static binary either way
#
# The pinned asset is `aarch64-unknown-linux-musl` and `zkir-v3` inside it is a STATIC ELF
# executable, so on an arm64 Linux host it runs with no image and no container: that is the CI
# runner's path (`.github/workflows/release.yml`), and it is why a release does not need
# Docker-in-Docker. Everywhere else — a macOS laptop, an x86_64 box — the pinned image from
# `scripts/toolchain.sh` provides it, `--network none`, with the SRS mounted read-only. Both paths
# drive byte-identical bytes of the same binary, which is the only reason the outputs may be
# compared at all.
#
# ## Determinism, and what is deliberately NOT in the manifest
#
# `manifest.json` is a statement about artifact IDENTITY, so nothing host-specific goes in it — no
# timestamp, no hostname, no wall time, no peak memory, not even whether the keys were made
# natively or in a container. Two runs of the same commit, one on a laptop through Docker and one on
# a Linux runner natively, produce byte-identical `manifest.json` and `SHA256SUMS`. That property is
# worth more than the convenience of a date field, and it is what lets a consumer treat a hash as an
# identity rather than as a fingerprint of one machine. The host-specific numbers are all PRINTED —
# they belong in a log, and the log is where they are.
#
# Offline after the SRS is present: only the SRS fetch touches the network, and only for a file
# whose SHA-256 is already committed.
#
# ## usage
#
#   scripts/release-artifacts.sh [options]
#
#     --out <dir>        where the 38 files go            (default: generated/release)
#     --tag <tag>        the tag to record in manifest.json (default: unreleased). A tag other
#                        than `unreleased` requires a clean tree.
#     --params <dir>     SRS directory                    (default: generated/zk-params)
#     --zkir-dir <dir>   reuse an already-emitted ZKIR directory instead of running `emit-zkir`
#     --skip-download    never touch the network: every SRS must already be present and correct
#     --write-keys       RE-RECORD the key sizes and hashes into fixtures/port-artifact-hashes.json
#     --force            proceed even if --out holds files this script does not recognise
#
# Environment:
#   CARGO_TOOLCHAIN   rustup toolchain for the re-emit. Default `1.95.0` (the pinned one).
#   ZKIR_V3           path to a `zkir-v3` to use natively, instead of probing $PATH / using Docker.
#   COMPACTC_IMAGE    passed through to scripts/toolchain.sh; see there.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

out_dir="$repo_root/generated/release"
params_dir="$repo_root/generated/zk-params"
port_fixture="$repo_root/fixtures/port-artifact-hashes.json"
srs_fixture="$repo_root/fixtures/srs-hashes.json"
tag="unreleased"
zkir_dir_in=""
skip_download=0
write_keys=0
force=0

# Container bounds for the Docker path. `execute` at k=18 peaked well under 1 GiB in the 00028
# measurement, so 20g is headroom rather than a requirement; it is stated so the log says what the
# run was allowed to use.
cpus=4
memory=20g
timeout_seconds=7200

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)            out_dir="${2:?--out needs a directory}"; shift 2 ;;
    --tag)            tag="${2:?--tag needs a tag}"; shift 2 ;;
    --params)         params_dir="${2:?--params needs a directory}"; shift 2 ;;
    --zkir-dir)       zkir_dir_in="${2:?--zkir-dir needs a directory}"; shift 2 ;;
    --skip-download)  skip_download=1; shift ;;
    --write-keys)     write_keys=1; shift ;;
    --force)          force=1; shift ;;
    -h|--help)        sed -n '2,100p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)                echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 69; }

# Both directories end up as Docker bind-mount sources, and `docker run -v` reads a RELATIVE path
# as a named volume rather than a directory ("includes invalid characters for a local volume
# name"), so they are made absolute here rather than at each use.
abspath() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$PWD/$1" ;; esac; }
out_dir="$(abspath "$out_dir")"
params_dir="$(abspath "$params_dir")"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1
  else shasum -a 256 "$1" | cut -d ' ' -f 1; fi
}
now() { python3 -c 'import time; print(f"{time.time():.3f}")'; }

# --- provenance of the tree we are about to release ---------------------------------------------
minocrab_rev="$(sed -n 's/^minocrab = .*rev = "\([0-9a-f]\{40\}\)".*/\1/p' "$repo_root/Cargo.toml" | head -1)"
[ -n "$minocrab_rev" ] || { echo "could not read the minocrab rev out of $repo_root/Cargo.toml" >&2; exit 65; }
git_commit="$(git -C "$repo_root" rev-parse HEAD)"
git_dirty=0
# `status --porcelain` rather than `diff --quiet`: an UNTRACKED source file changes what
# `emit-zkir` emits just as surely as a modified one, and `generated/` and `evidence/` are
# gitignored so they never make a clean tree look dirty.
[ -z "$(git -C "$repo_root" status --porcelain)" ] || git_dirty=1

echo "=== release-artifacts ==="
echo "RELEASE_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "TAG=$tag"
echo "GIT_COMMIT=$git_commit"
echo "GIT_DIRTY=$git_dirty"
echo "MINOCRAB_REV=$minocrab_rev"
echo "OUT_DIR=$out_dir"
echo "PARAMS_DIR=$params_dir"

# A real tag must describe a tree that exists. A dry run may be as dirty as you like.
if [ "$tag" != "unreleased" ] && [ "$git_dirty" -ne 0 ]; then
  echo "REFUSING: --tag $tag with a dirty working tree — the assets would not correspond to $git_commit." >&2
  echo "An UNTRACKED file counts: a new source file changes what emit-zkir emits just as surely as" >&2
  echo "a modified one. What is dirty:" >&2
  git -C "$repo_root" status --porcelain | sed 's/^/  /' >&2
  exit 96
fi

# --- the toolchain ------------------------------------------------------------------------------
# shellcheck source=scripts/toolchain.sh
. "$repo_root/scripts/toolchain.sh"

keygen_mode="docker"
zkir_v3_native=""
uname_s="$(uname -s)"
uname_m="$(uname -m)"
if [ -n "${ZKIR_V3:-}" ]; then
  keygen_mode="native"; zkir_v3_native="$ZKIR_V3"
elif [ "$uname_s" = "Linux" ] && { [ "$uname_m" = "aarch64" ] || [ "$uname_m" = "arm64" ]; } \
     && command -v zkir-v3 >/dev/null 2>&1; then
  keygen_mode="native"; zkir_v3_native="$(command -v zkir-v3)"
fi

echo "HOST=$uname_s/$uname_m"
echo "KEYGEN_MODE=$keygen_mode"
echo "COMPACTC_ARCHIVE_URL=$COMPACTC_ARCHIVE_URL"
echo "COMPACTC_ARCHIVE_SHA256=$COMPACTC_ARCHIVE_SHA256"

if [ "$keygen_mode" = "native" ]; then
  verify_zkir_v3 "$zkir_v3_native"
  echo "ZKIR_V3_VERSION=$("$zkir_v3_native" --version | tr -d '\r')"
  image=""
else
  ensure_image
  image="$COMPACTC_IMAGE"
  echo "ZKIR_V3_VERSION=$(docker run --rm --network none "$image" /opt/compactc/zkir-v3 --version | tr -d '\r')"
fi
zkir_v3_sha256="${TOOLCHAIN_ZKIR_V3_SHA256:-$ZKIR_V3_SHA256_EXPECTED}"

marker_port="$("$repo_root/scripts/free-port.sh")"
echo "MARKER_PORT=$marker_port"
echo "BOUNDS=cpus:$cpus,memory:$memory,memory-swap:$memory,wall-seconds:$timeout_seconds,network:none (Docker path)"

# --- scratch ------------------------------------------------------------------------------------
work="$(mktemp -d "${TMPDIR:-/tmp}/minocrab-release.XXXXXX")"
containers=""
cleanup() {
  for c in $containers; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

# --- 1. the IR ----------------------------------------------------------------------------------
if [ -n "$zkir_dir_in" ]; then
  zkir_dir="$(cd "$zkir_dir_in" && pwd)"
  echo "ZKIR_REUSED=$zkir_dir"
else
  zkir_dir="$work/zkir"
  toolchain_arg=()
  if [ -n "${CARGO_TOOLCHAIN-1.95.0}" ]; then toolchain_arg=("+${CARGO_TOOLCHAIN:-1.95.0}"); fi
  echo "EMITTING into $zkir_dir with cargo ${toolchain_arg[*]:-<default toolchain>}"
  ( cd "$repo_root" && cargo "${toolchain_arg[@]}" run --release --locked \
      -p manager-port --bin emit-zkir -- "$zkir_dir" ) >/dev/null
fi

# --- 2. gate the IR, and derive the release set from fixtures/srs-hashes.json -------------------
echo "--- IR gate (every emitted .zkir against fixtures/port-artifact-hashes.json)"
ZKIR_DIR="$zkir_dir" PORT_FIXTURE="$port_fixture" SRS_FIXTURE="$srs_fixture" WORK="$work" \
python3 - <<'PY'
import hashlib, json, os, sys

zkir_dir = os.environ["ZKIR_DIR"]
port = json.load(open(os.environ["PORT_FIXTURE"]))
srs = json.load(open(os.environ["SRS_FIXTURE"]))
work = os.environ["WORK"]

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

emitted = sorted(f[:-5] for f in os.listdir(zkir_dir) if f.endswith(".zkir"))
recorded = port.get("circuits", {})
failures = []

for name in sorted(set(emitted) | set(recorded)):
    if name not in recorded:
        failures.append(f"{name}: emitted but not in fixtures/port-artifact-hashes.json")
        print(f"  + {name:28} NOT IN THE RECORD")
        continue
    if name not in emitted:
        failures.append(f"{name}: in the record but not emitted")
        print(f"  - {name:28} IN THE RECORD, NOT EMITTED")
        continue
    p = os.path.join(zkir_dir, name + ".zkir")
    b, h = os.path.getsize(p), sha256(p)
    want = recorded[name]
    if b == want["bytes"] and h == want["sha256"]:
        print(f"    {name:28} {b:>9} B  {h}  ==")
    else:
        failures.append(f"{name}: recorded {want['bytes']} B/{want['sha256'][:16]}…, "
                        f"emitted {b} B/{h[:16]}…")
        print(f"  ! {name:28} recorded {want['bytes']:>9} B  {want['sha256']}")
        print(f"    {'':28} emitted  {b:>9} B  {h}")

# The release set: exactly the circuits fixtures/srs-hashes.json assigns a k to.
release = {}
for srs_name, rec in srs["params"].items():
    for circuit in rec["circuits"]:
        if circuit in release:
            failures.append(f"{circuit}: assigned to two SRS files in fixtures/srs-hashes.json")
        release[circuit] = (rec["k"], srs_name)
for circuit in sorted(release):
    if circuit not in emitted:
        failures.append(f"{circuit}: in the release set but `emit-zkir` did not produce it")

if failures:
    print("---")
    print(f"IR GATE FAILED ({len(failures)} difference(s)):")
    for f in failures:
        print(f"  * {f}")
    print("  Keys must never be generated from IR the record does not recognise: a release would")
    print("  publish key material under a hash table that describes something else. If the bytes")
    print("  moved on purpose, re-record with scripts/check-port-artifacts.sh --write first.")
    sys.exit(1)

print(f"IR GATE OK — {len(emitted)} circuit(s) match the record; "
      f"{len(release)} are published, {len(set(emitted) - set(release))} are not "
      f"({', '.join(sorted(set(emitted) - set(release))) or 'none'})")

# k ascending, so a broken run fails in a second rather than after a k=18 keygen.
with open(os.path.join(work, "circuits.tsv"), "w") as fh:
    for circuit, (k, srs_name) in sorted(release.items(), key=lambda kv: (kv[1][0], kv[0])):
        fh.write(f"{circuit}\t{k}\t{srs_name}\n")

with open(os.path.join(work, "srs-needed.tsv"), "w") as fh:
    url_tpl = srs["source"]["downloadUrl"]
    for srs_name in sorted({s for _, s in release.values()}, key=lambda n: srs["params"][n]["k"]):
        rec = srs["params"][srs_name]
        fh.write(f"{srs_name}\t{rec['bytes']}\t{rec['sha256']}\t{url_tpl.replace('{name}', srs_name)}\n")
PY

# --- 3. the SRS ---------------------------------------------------------------------------------
echo "--- SRS (fixtures/srs-hashes.json)"
srs_repo="$(python3 -c 'import json;print(json.load(open("'"$srs_fixture"'"))["source"]["repo"])')"
srs_release="$(python3 -c 'import json;print(json.load(open("'"$srs_fixture"'"))["source"]["release"])')"
mkdir -p "$params_dir"
while IFS="$(printf '\t')" read -r srs_name srs_bytes srs_want srs_url; do
  [ -n "$srs_name" ] || continue
  srs_path="$params_dir/$srs_name"
  if [ -f "$srs_path" ] && [ "$(sha256_of "$srs_path")" = "$srs_want" ]; then
    printf '    %-20s %10s B  %s  == (present)\n' "$srs_name" "$srs_bytes" "$srs_want"
    continue
  fi
  if [ "$skip_download" -eq 1 ]; then
    echo "REFUSING: $srs_name is missing or does not match, and --skip-download was given." >&2
    exit 75
  fi
  echo "    fetching $srs_name from $srs_repo release $srs_release"
  if command -v gh >/dev/null 2>&1 \
     && gh release download "$srs_release" --repo "$srs_repo" --pattern "$srs_name" \
          --dir "$params_dir" --clobber >/dev/null 2>&1; then
    :
  else
    curl -fsSL -o "$srs_path" "$srs_url"
  fi
  srs_got="$(sha256_of "$srs_path")"
  if [ "$srs_got" != "$srs_want" ]; then
    echo "REFUSING: $srs_name hashed $srs_got, the record says $srs_want." >&2
    exit 75
  fi
  printf '    %-20s %10s B  %s  == (fetched)\n' "$srs_name" "$srs_bytes" "$srs_want"
done < "$work/srs-needed.tsv"

# --- 4. the output directory --------------------------------------------------------------------
# Idempotent: a previous run's assets are replaced, anything else is left alone and refused.
if [ -d "$out_dir" ]; then
  unexpected=""
  tab="$(printf '\t')"
  for path in "$out_dir"/* "$out_dir"/.[!.]*; do
    [ -e "$path" ] || continue
    entry="$(basename "$path")"
    case "$entry" in
      SHA256SUMS|manifest.json) continue ;;
      *.zkir|*.bzkir|*.prover|*.verifier)
        base="${entry%.*}"
        if grep -q "^$base$tab" "$work/circuits.tsv"; then continue; fi ;;
    esac
    unexpected="$unexpected $entry"
  done
  if [ -n "$unexpected" ] && [ "$force" -eq 0 ]; then
    echo "REFUSING: $out_dir holds files this script did not produce:$unexpected" >&2
    echo "Point --out somewhere else, or pass --force." >&2
    exit 97
  fi
  find "$out_dir" -maxdepth 1 -type f \
    \( -name '*.zkir' -o -name '*.bzkir' -o -name '*.prover' -o -name '*.verifier' \
       -o -name 'SHA256SUMS' -o -name 'manifest.json' \) -delete
fi
mkdir -p "$out_dir"

# --- 5. keygen ----------------------------------------------------------------------------------
if [ "$keygen_mode" = "native" ]; then
  peak_metric="/proc/<pid>/status VmHWM — peak RSS of zkir-v3 itself, no page cache"
else
  peak_metric="cgroup v2 memory.peak — charged memory of the container, page cache included"
fi
echo "PEAK_MEMORY_METRIC=$peak_metric"
echo "--- keygen ($keygen_mode)"
: > "$work/observed.tsv"
while IFS="$(printf '\t')" read -r circuit k srs_name; do
  [ -n "$circuit" ] || continue

  # `zkir-v3` writes the .bzkir NEXT TO ITS INPUT, so the IR is staged into a writable per-circuit
  # directory and the emitted .zkir is never touched. (A read-only IR mount dies in ~0.3 s with
  # `Read-only file system` before any key work begins — see scripts/keygen-zkir.sh.)
  ir_dir="$work/ir/$circuit"
  mkdir -p "$ir_dir"
  cp "$zkir_dir/$circuit.zkir" "$ir_dir/$circuit.zkir"
  chmod u+w "$ir_dir/$circuit.zkir"

  keylog="$work/$circuit.keygen.log"
  peakfile="$ir_dir/$circuit.peak"
  t0="$(now)"

  if [ "$keygen_mode" = "native" ]; then
    (
      export MIDNIGHT_PP="$params_dir" MINOCRAB_PORT_MARKER="$marker_port"
      exec "$zkir_v3_native" compile \
        "$ir_dir/$circuit.zkir" "$out_dir/$circuit.prover" "$out_dir/$circuit.verifier"
    ) >"$keylog" 2>&1 &
    kg_pid=$!
    # `exec` above means $kg_pid IS zkir-v3, so /proc/<pid>/status VmHWM is its own peak resident
    # set — a kernel high-water mark, monotonic, so the largest value ever read is the true peak
    # (a run shorter than the polling interval can miss it entirely, and then reports nothing
    # rather than guessing). `set +e` because polling a process that has just exited fails, and
    # under the inherited `set -e`/`pipefail` that kills the sampler on its first tick — which is
    # exactly how the first version of this reported 0 bytes for every circuit.
    ( set +e
      while kill -0 "$kg_pid" 2>/dev/null; do
        awk '/^VmHWM:/ { print $2 * 1024 }' "/proc/$kg_pid/status" 2>/dev/null >> "$peakfile"
        sleep 0.5
      done ) >/dev/null 2>&1 &
    sampler_pid=$!
  else
    container="minocrab-release-keygen-$(printf '%s' "$circuit" | tr '[:upper:]' '[:lower:]')"
    containers="$containers $container"
    docker rm -f "$container" >/dev/null 2>&1 || true
    # `cgroup v2` keeps a true high-water mark for the container in `memory.peak`, so the peak is
    # READ FROM THE KERNEL after the run rather than sampled and hoped for. It is charged memory,
    # page cache included — the number that decides whether a `--memory` bound is survivable, and
    # therefore the one a runner budget wants; it is NOT comparable to the native path's VmHWM
    # (peak RSS, no cache). $peak_metric names which of the two the log printed.
    docker run --rm --network none --name "$container" \
      --cpus "$cpus" --memory "$memory" --memory-swap "$memory" \
      -e MINOCRAB_PORT_MARKER="$marker_port" \
      -v "$params_dir:/params:ro" -e MIDNIGHT_PP=/params \
      -v "$ir_dir:/ir" -v "$out_dir:/out" -w /out \
      "$image" /bin/sh -c "/opt/compactc/zkir-v3 compile /ir/$circuit.zkir /out/$circuit.prover /out/$circuit.verifier; rc=\$?; cat /sys/fs/cgroup/memory.peak > /ir/$circuit.peak 2>/dev/null || true; exit \$rc" \
      >"$keylog" 2>&1 &
    kg_pid=$!
    sampler_pid=""
    ( sleep "$timeout_seconds"
      docker kill "$container" >/dev/null 2>&1 || true ) >/dev/null 2>&1 &
    watchdog_pid=$!
  fi

  set +e
  wait "$kg_pid"; kg_exit=$?
  set -e
  if [ -n "${sampler_pid:-}" ]; then
    kill "$sampler_pid" >/dev/null 2>&1 || true; wait "$sampler_pid" >/dev/null 2>&1 || true
  fi
  if [ "$keygen_mode" != "native" ]; then
    kill "${watchdog_pid:-}" >/dev/null 2>&1 || true; wait "${watchdog_pid:-}" >/dev/null 2>&1 || true
  fi
  t1="$(now)"

  if [ "$kg_exit" -ne 0 ]; then
    echo "KEYGEN FAILED for $circuit (exit $kg_exit):" >&2
    cat "$keylog" >&2
    exit 71
  fi

  secs="$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }')"
  peak="n/a"
  if [ -s "$peakfile" ]; then
    peak="$(awk 'BEGIN { m = 0 } /^[0-9]+$/ { if ($1 > m) m = $1 } END { print m }' "$peakfile")"
  fi

  # `zkir-v3 compile` announces the circuit it is keying; that banner is a DIFFERENT code path from
  # `mock-compile` and is the (k, rows) of record for the key that was just written.
  kr="$(sed -n 's/.*(k=\([0-9]*\), rows=\([0-9]*\)).*/\1 \2/p' "$keylog" | head -1)"
  obs_k="${kr%% *}"; rows="${kr##* }"
  if [ -z "$obs_k" ]; then
    echo "could not read (k, rows) out of the keygen banner for $circuit:" >&2
    cat "$keylog" >&2
    exit 72
  fi
  if [ "$obs_k" != "$k" ]; then
    echo "REFUSING: $circuit keyed at k=$obs_k, fixtures/srs-hashes.json records k=$k." >&2
    echo "A moved k means the SRS chosen for it is the wrong one. Re-record the fixture" >&2
    echo "deliberately, with the row change explained." >&2
    exit 73
  fi

  test -s "$ir_dir/$circuit.bzkir"
  cp "$ir_dir/$circuit.bzkir" "$out_dir/$circuit.bzkir"
  cp "$zkir_dir/$circuit.zkir" "$out_dir/$circuit.zkir"

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$circuit" "$k" "$rows" "$srs_name" "$secs" "$peak" \
    >> "$work/observed.tsv"
  printf '    %-26s k=%-2s rows=%-8s %8s s  peak %10s B  %s\n' \
    "$circuit" "$k" "$rows" "$secs" "$peak" "$srs_name"
done < "$work/circuits.tsv"

# --- 6. gate the keys, then write manifest.json and SHA256SUMS ----------------------------------
echo "--- assets"
OUT_DIR="$out_dir" WORK="$work" PORT_FIXTURE="$port_fixture" SRS_FIXTURE="$srs_fixture" \
TAG="$tag" GIT_COMMIT="$git_commit" MINOCRAB_REV="$minocrab_rev" \
ZKIR_V3_SHA256="$zkir_v3_sha256" \
COMPACTC_ARCHIVE_URL="$COMPACTC_ARCHIVE_URL" COMPACTC_ARCHIVE_SHA256="$COMPACTC_ARCHIVE_SHA256" \
COMPACTC_VERSION="$COMPACTC_VERSION_EXPECTED" COMPACTC_LANGUAGE="$COMPACTC_LANGUAGE_EXPECTED" \
python3 - <<'PY'
import hashlib, json, os, sys

out = os.environ["OUT_DIR"]
work = os.environ["WORK"]
port = json.load(open(os.environ["PORT_FIXTURE"]))
srs = json.load(open(os.environ["SRS_FIXTURE"]))

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def entry(path):
    return {"bytes": os.path.getsize(path), "sha256": sha256(path)}

observed = []
for line in open(os.path.join(work, "observed.tsv")):
    circuit, k, rows, srs_name, secs, peak = line.rstrip("\n").split("\t")
    observed.append((circuit, int(k), int(rows), srs_name))

circuits, failures = {}, []
for circuit, k, rows, srs_name in observed:
    files = {kind: entry(os.path.join(out, f"{circuit}.{kind}"))
             for kind in ("zkir", "bzkir", "prover", "verifier")}
    circuits[circuit] = {"k": k, "rows": rows, "srs": srs_name, **files}

    # FR-004: once a key pair has been recorded, a release must reproduce it exactly.
    rec = port.get("circuits", {}).get(circuit, {})
    for kind in ("prover", "verifier"):
        want = rec.get(kind)
        if not want:
            continue
        got = files[kind]
        if want["bytes"] != got["bytes"] or want["sha256"] != got["sha256"]:
            failures.append(f"{circuit}.{kind}: recorded {want['bytes']} B/{want['sha256'][:16]}…, "
                            f"produced {got['bytes']} B/{got['sha256'][:16]}…")

recorded_keys = sum(1 for c, _, _, _ in observed
                    for kind in ("prover", "verifier")
                    if port.get("circuits", {}).get(c, {}).get(kind))
if failures:
    print(f"KEY GATE FAILED ({len(failures)} difference(s)):")
    for f in failures:
        print(f"  * {f}")
    print("  The IR and the SRS both matched their records, so this is keygen itself producing")
    print("  different bytes than the ones this repository publishes. Do NOT re-record: find out")
    print("  why first (a different zkir-v3 build, a different SRS file under the same name, or")
    print("  genuine non-determinism in keygen — each of which invalidates a published hash).")
    sys.exit(74)
print(f"KEY GATE OK — {recorded_keys} recorded key hash(es) reproduced "
      f"({'no keys recorded yet' if recorded_keys == 0 else 'exactly'})")

circuit_files = sorted(f"{c}.{kind}" for c in circuits
                       for kind in ("zkir", "bzkir", "prover", "verifier"))
circuit_bytes = sum(circuits[c][kind]["bytes"] for c in circuits
                    for kind in ("zkir", "bzkir", "prover", "verifier"))

manifest = {
    "schema": "aa-manager-minocrab-port/release-manifest/1",
    "note": (
        "What this release publishes and exactly what each file is. Every field is derived from a "
        "pinned input, so two runs of the same commit produce a byte-identical manifest whatever "
        "host they run on: there is deliberately no timestamp, no hostname and no wall-clock or "
        "memory figure here, because a manifest is a statement about artifact identity and an "
        "identity must not depend on which machine produced it. Verify a download with "
        "`sha256sum -c --ignore-missing SHA256SUMS`."
    ),
    "tag": os.environ["TAG"],
    "repository": "acedward/AA-midnight-evm-experiment-minocrab",
    "gitCommit": os.environ["GIT_COMMIT"],
    "minocrabRev": os.environ["MINOCRAB_REV"],
    "contractPin": port.get("contractPin", {}),
    "toolchain": {
        "note": (
            "`zkir-v3` from the pinned compactc archive is what turned each .zkir into a .bzkir and "
            "a key pair. It decides every key byte, so it is pinned by the SHA-256 of the archive "
            "and of the binary. The port's .zkir files are emitted by the MinoCrab eDSL and touch "
            "no part of this toolchain; their provenance is `minocrabRev`."
        ),
        "compactcVersion": os.environ["COMPACTC_VERSION"],
        "compactcLanguageVersion": os.environ["COMPACTC_LANGUAGE"],
        "compactcArchiveUrl": os.environ["COMPACTC_ARCHIVE_URL"],
        "compactcArchiveSha256": os.environ["COMPACTC_ARCHIVE_SHA256"],
        "zkirV3Sha256": os.environ["ZKIR_V3_SHA256"],
    },
    "srs": {
        "note": (
            "The structured reference string each circuit was keyed against, one per distinct k. "
            "The same .zkir keyed against a different SRS is a different key, so these hashes are "
            "as load-bearing as the tool's."
        ),
        "source": srs["source"],
        "used": {
            name: {"k": srs["params"][name]["k"],
                   "bytes": srs["params"][name]["bytes"],
                   "sha256": srs["params"][name]["sha256"]}
            for name in sorted({s for _, _, _, s in observed},
                               key=lambda n: srs["params"][n]["k"])
        },
    },
    "assets": {
        "circuitFiles": len(circuit_files),
        "circuitBytes": circuit_bytes,
        "releaseFiles": len(circuit_files) + 2,
        "note": ("<circuit>.{zkir,bzkir,prover,verifier} for each circuit below, plus SHA256SUMS "
                 "and manifest.json. SHA256SUMS covers every released file except itself."),
    },
    "circuits": {c: circuits[c] for c in sorted(circuits)},
}

with open(os.path.join(out, "manifest.json"), "w") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=False)
    fh.write("\n")

# SHA256SUMS last, over everything else — including manifest.json, so the only file in the release
# whose hash is not published by the release is SHA256SUMS itself.
lines = []
for name in sorted(circuit_files + ["manifest.json"]):
    lines.append(f"{sha256(os.path.join(out, name))}  {name}\n")
with open(os.path.join(out, "SHA256SUMS"), "w") as fh:
    fh.writelines(lines)

print(f"{'file':30} {'bytes':>12}  sha256")
total = 0
for name in sorted(circuit_files) + ["manifest.json", "SHA256SUMS"]:
    p = os.path.join(out, name)
    b = os.path.getsize(p)
    total += b
    print(f"{name:30} {b:>12}  {sha256(p)}")
print(f"{'TOTAL (' + str(len(circuit_files) + 2) + ' files)':30} {total:>12}")
print(f"RELEASE_FILES={len(circuit_files) + 2}")
print(f"RELEASE_BYTES={total}")
PY

# --- 7. optionally record the key hashes --------------------------------------------------------
if [ "$write_keys" -eq 1 ]; then
  echo "--- --write-keys: recording the key sizes and hashes into fixtures/port-artifact-hashes.json"
  OUT_DIR="$out_dir" WORK="$work" PORT_FIXTURE="$port_fixture" python3 - <<'PY'
import hashlib, json, os

out = os.environ["OUT_DIR"]
fixture = os.environ["PORT_FIXTURE"]
doc = json.load(open(fixture))

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

manifest = json.load(open(os.path.join(out, "manifest.json")))
for circuit, rec in manifest["circuits"].items():
    prev = doc["circuits"][circuit]
    entry = {"bytes": prev["bytes"], "sha256": prev["sha256"],
             "k": rec["k"], "rows": rec["rows"]}
    for kind in ("prover", "verifier"):
        p = os.path.join(out, f"{circuit}.{kind}")
        entry[kind] = {"bytes": os.path.getsize(p), "sha256": sha256(p)}
    doc["circuits"][circuit] = entry
    print(f"  {circuit:26} k={rec['k']:<3} rows={rec['rows']:<7} "
          f"prover   {entry['prover']['bytes']:>10} B  {entry['prover']['sha256']}")
    print(f"  {'':26} {'':6} {'':12} "
          f"verifier {entry['verifier']['bytes']:>10} B  {entry['verifier']['sha256']}")

doc["keysNote"] = (
    "`prover`/`verifier` (and the `k`/`rows` next to them) are present for the circuits a release "
    "publishes keys for. Unlike the .zkir hashes above, these are NOT decided by this crate alone: "
    "they are decided by the .zkir, by the `zkir-v3` in `toolchain` and by the SRS in "
    "fixtures/srs-hashes.json. scripts/release-artifacts.sh reproduces them on every run and fails "
    "if any moves; scripts/check-port-artifacts.sh --with-keys <dir> checks a directory of keys "
    "against them. Regenerating them takes minutes and hundreds of megabytes, which is why the "
    "cheap gate does not do it by default."
)
# A stable field order, so a re-record produces a readable diff rather than a reshuffle.
order = ["note", "keysNote", "recordedAt", "minocrabRev", "contractPin", "toolchain", "circuits"]
doc = {k: doc[k] for k in order if k in doc} | {k: v for k, v in doc.items() if k not in order}
with open(fixture, "w") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
print(f"WROTE {fixture}")
PY
fi

echo "RELEASE_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "--- keygen cost (host-specific; deliberately NOT in manifest.json)"
echo "    peak-bytes metric: $peak_metric"
printf '    %-26s %-4s %-10s %10s  %14s\n' circuit k rows seconds peak-bytes
while IFS="$(printf '\t')" read -r circuit k rows srs_name secs peak; do
  [ -n "$circuit" ] || continue
  printf '    %-26s %-4s %-10s %10s  %14s\n' "$circuit" "$k" "$rows" "$secs" "$peak"
done < "$work/observed.tsv"
echo "RELEASE_ARTIFACTS_OK"
