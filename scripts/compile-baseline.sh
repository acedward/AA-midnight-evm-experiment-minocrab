#!/usr/bin/env bash
# Pinned skip-ZK compile of a Compact contract — the `compactc` side of every comparison.
#
# MEASUREMENT-ONLY. `--skip-zk` never generates a prover or verifier key.
#
# This produces the BASELINE ARTIFACT the differential suite compares the port against. It is not
# shipped in this repository (it is a compiled file) — this script makes it, and as of 2026-09-04 it
# makes it on any arm64 host with a network and nothing else: the toolchain is obtained and verified
# by `scripts/toolchain.sh`, which builds `docker/compactc.Dockerfile` from a SHA-256-pinned release
# archive when no image is present. See README § "Running the differential suite".
#
#   COMPACTC_IMAGE   OPTIONAL override. Defaults to the pinned toolchain `aa-compactc:0.34.0`
#                    (compiler 0.34.0 / language 0.26.0 / --feature-zkir-v3), obtained and
#                    hash-verified by scripts/toolchain.sh. Point it at another build only to
#                    re-derive an artifact from a superseded compiler; the version and both binary
#                    hashes are still checked, so a mismatched image is a hard failure, not a
#                    silent re-baseline.
#
# usage: compile-baseline.sh <arm-name> <path-to-contract.compact> <confirmed-free-marker-port>
#
# The marker port is a run marker only: nothing listens on it, it is passed into the container as
# an env var so a concurrent run on a shared machine is identifiable. Get one with
# `scripts/free-port.sh`.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <arm> <path-to-contract.compact> <marker-port>" >&2
  exit 64
fi

arm="$1"
src="$2"
marker_port="$3"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The pinned Compact toolchain — ONE source of truth for this script, measure-zkir.sh and
# keygen-zkir.sh. `ensure_image` (called below, in the header block, so its output lands in the log)
# obtains the image and verifies the compiler version, the language version and the SHA-256 of both
# compiler binaries before a single byte is compiled.
# shellcheck source=scripts/toolchain.sh
. "$repo_root/scripts/toolchain.sh"

out_dir="$repo_root/generated/$arm"
container="minocrab-port-compile-${arm}"
timeout_seconds=900

test -f "$src"
src_dir="$(cd "$(dirname "$src")" && pwd)"
src_base="$(basename "$src")"

if lsof -nP -iTCP:"$marker_port" -sTCP:LISTEN >/dev/null 2>&1 || \
   nc -z 127.0.0.1 "$marker_port" >/dev/null 2>&1; then
  echo "marker port is busy: $marker_port" >&2
  exit 98
fi

rm -rf "$out_dir"
mkdir -p "$out_dir"

watchdog_flag="$(mktemp "${TMPDIR:-/tmp}/minocrab-port-compile-watchdog.XXXXXX")"
rm -f "$watchdog_flag"

cleanup() {
  kill "${watchdog_pid:-}" >/dev/null 2>&1 || true
  wait "${watchdog_pid:-}" >/dev/null 2>&1 || true
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -f "$watchdog_flag" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "COMPILE_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "ARM=$arm"
echo "SOURCE=$src"
echo "SOURCE_SHA256=$(shasum -a 256 "$src" | cut -d ' ' -f 1)"
echo "MARKER_PORT=$marker_port"
echo "BOUNDS=cpus:2,memory:8g,memory-swap:8g,rayon:2,wall-seconds:$timeout_seconds,network:none"
ensure_image
image="$COMPACTC_IMAGE"

# The watchdog must NOT inherit this script's stdout/stderr: a background writer keeps a
# consuming pipe open for its whole sleep, which would stall any caller reading our output.
(
  sleep "$timeout_seconds"
  if docker inspect "$container" >/dev/null 2>&1; then
    : > "$watchdog_flag"
    docker kill "$container" >/dev/null 2>&1 || true
  fi
) >/dev/null 2>&1 &
watchdog_pid=$!

set +e
/usr/bin/time -p docker run --rm --network none \
  --name "$container" --cpus 2 --memory 8g --memory-swap 8g \
  -e RAYON_NUM_THREADS=2 -e MINOCRAB_PORT_MARKER="$marker_port" \
  -v "$src_dir:/work/contracts:ro" \
  -v "$out_dir:/out" \
  -w /work \
  "$image" \
  compactc --feature-zkir-v3 --skip-zk "/work/contracts/$src_base" /out/manager
compile_exit=$?
set -e

kill "$watchdog_pid" >/dev/null 2>&1 || true
wait "$watchdog_pid" >/dev/null 2>&1 || true
watchdog_pid=""

echo "COMPILE_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "COMPILE_EXIT=$compile_exit"
echo "WATCHDOG_TIMEOUT=$( [ -e "$watchdog_flag" ] && echo 1 || echo 0 )"
echo "KEY_FILES=$(find "$out_dir" -name '*.prover' -o -name '*.verifier' | wc -l | tr -d ' ')"
if [ "$compile_exit" -eq 0 ]; then
  echo "ZKIR_CIRCUITS=$(ls "$out_dir/manager/zkir"/*.zkir 2>/dev/null | wc -l | tr -d ' ')"
  ls "$out_dir/manager/zkir"/*.zkir 2>/dev/null | xargs -n1 basename | sed 's/^/CIRCUIT=/'
  echo "BASELINE_ZKIR_DIR=$out_dir/manager/zkir"
  echo "# point the differential suite at it with:"
  echo "#   AA_BASELINE_ZKIR_DIR=$out_dir/manager/zkir \\"
  echo "#     cargo +1.95.0 test --release -p manager-port --features compactc-baseline"
fi
exit "$compile_exit"
