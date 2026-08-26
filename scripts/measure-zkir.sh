#!/usr/bin/env bash
# Pinned `zkir-v3 mock-compile` (k, rows) measurement of ONE .zkir file.
#
# This is THE oracle for both sides of the comparison: the same pinned image, the same
# `zkir-v3 mock-compile` subcommand, the same container bounds, whether the input ZKIR came out of
# compactc or out of the minocrab eDSL. It takes a *directory* plus a circuit name precisely so a
# minocrab-emitted ZKIR can be fed to it unchanged.
#
# MEASUREMENT-ONLY. `mock-compile` reports (k, rows) and writes a transient BZKIR;
# it never generates a prover or verifier key.
#
# The image is overridable:
#   COMPACTC_IMAGE   docker image (or image@sha256:...) providing the pinned toolchain. The default
#                    below is the exact locally-built image every published number was measured
#                    with (Compact 0.33.0 / language 0.25.0 / --feature-zkir-v3); it is NOT
#                    publicly pullable, so set this to your own compactc 0.33.0 image.
#
# usage: measure-zkir.sh <zkir-dir> <circuit-name> <confirmed-free-marker-port> [timeout-seconds=900] [tag]
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 5 ]; then
  echo "usage: $0 <zkir-dir> <circuit> <marker-port> [timeout-seconds] [tag]" >&2
  exit 64
fi

zkir_dir="$(cd "$1" && pwd)"
circuit="$2"
marker_port="$3"
timeout_seconds="${4:-900}"
tag="${5:-measure}"

image="${COMPACTC_IMAGE:-aa00006-compactc@sha256:f57ca2d88cec1c66f377eb8bb2d616779202dd1ccb99517a4f7ddfffa9d0d86b}"
input_zkir="$zkir_dir/$circuit.zkir"
output_bzkir="$zkir_dir/$circuit.bzkir"
safe_tag="$(printf '%s-%s' "$tag" "$circuit" | tr '[:upper:]/' '[:lower:]-')"
container="minocrab-port-measure-${safe_tag}"

test -f "$input_zkir"
rm -f "$output_bzkir"

if lsof -nP -iTCP:"$marker_port" -sTCP:LISTEN >/dev/null 2>&1 || \
   nc -z 127.0.0.1 "$marker_port" >/dev/null 2>&1; then
  echo "marker port is busy: $marker_port" >&2
  exit 98
fi

watchdog_flag="$(mktemp -t minocrab-port-measure-watchdog)"
rm -f "$watchdog_flag"

cleanup() {
  kill "${watchdog_pid:-}" >/dev/null 2>&1 || true
  wait "${watchdog_pid:-}" >/dev/null 2>&1 || true
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -f "$watchdog_flag" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "MEASURE_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "TAG=$tag"
echo "ZKIR_DIR=$zkir_dir"
echo "CIRCUIT=$circuit"
echo "MARKER_PORT=$marker_port"
echo "BOUNDS=cpus:2,memory:8g,memory-swap:8g,rayon:2,wall-seconds:$timeout_seconds,network:none"
echo "IMAGE=$image"
echo "ZKIR_BYTES=$(wc -c < "$input_zkir" | tr -d ' ')"
echo "ZKIR_SHA256=$(shasum -a 256 "$input_zkir" | cut -d ' ' -f 1)"

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
  -v "$zkir_dir:/measure" -w /measure \
  "$image" /opt/compactc/zkir-v3 mock-compile "$circuit.zkir"
measure_exit=$?
set -e

kill "$watchdog_pid" >/dev/null 2>&1 || true
wait "$watchdog_pid" >/dev/null 2>&1 || true
watchdog_pid=""

echo "MEASURE_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "MEASURE_EXIT=$measure_exit"
echo "WATCHDOG_TIMEOUT=$( [ -e "$watchdog_flag" ] && echo 1 || echo 0 )"
if [ "$measure_exit" -eq 0 ]; then
  test -s "$output_bzkir"
  echo "BZKIR_BYTES=$(wc -c < "$output_bzkir" | tr -d ' ')"
  echo "BZKIR_SHA256=$(shasum -a 256 "$output_bzkir" | cut -d ' ' -f 1)"
fi
echo "KEY_FILES=$(find "$zkir_dir" -name '*.prover' -o -name '*.verifier' | wc -l | tr -d ' ')"
exit "$measure_exit"
