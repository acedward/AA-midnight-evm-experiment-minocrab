#!/usr/bin/env bash
# Proving-key generation from a RAW ZKIR — the only script here that produces key material.
#
# ## Why `zkir-v3 compile` and not `compactc`
#
# `compactc --feature-zkir-v3 <source.compact>` compiles a contract AND keys all of its circuits.
# That path cannot cover a minocrab artifact: it has **no `.compact` source at all** — it is emitted
# by a Rust eDSL. `zkir-v3 compile` takes a raw ZKIR and writes the prover/verifier pair, so BOTH
# artifacts are keyed by the identical tool, in the identical image, under identical bounds — the
# same "one oracle, both sides" property that makes the row comparison sound, one layer up.
#
# Bounds, all printed into the log:
#   * container `--network none` — the SRS is MOUNTED, never fetched;
#   * `MIDNIGHT_PP` points at the parameter directory, whose contents are hashed into the log;
#   * bounded cpu / memory / wall;
#   * it REFUSES to run if output already exists — a previous result is never silently overwritten;
#   * output under the gitignored `generated/`; keys are never committed.
#
# ## Prerequisites
#
#   generated/zk-params/    the Midnight SRS (`bls_midnight_2p18` for a k=18 circuit). Placed there
#                           by you; the container is `--network none` and cannot fetch it.
#
# The toolchain comes from `scripts/toolchain.sh`: the pinned `aa-compactc:0.34.0` (compiler
# 0.34.0 / language 0.26.0), obtained from a local image, a published cache, or a SHA-256-verified
# build of `docker/compactc.Dockerfile`, and verified by version and by both binary hashes before
# any key material is produced. KEYS INHERIT THAT PROVENANCE: a key pair is only as identifiable as
# the `zkir-v3` that made it, which is why the verification is unconditional and a mismatch exits
# 70 rather than warning.
#
#   COMPACTC_IMAGE   OPTIONAL override, for keying on another build of the toolchain. The version
#                    and both binary hashes are still verified, so a mismatch fails hard.
#
# usage: keygen-zkir.sh <arm-name> <zkir-path> <confirmed-free-marker-port>
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <arm-name> <zkir-path> <marker-port>" >&2
  exit 64
fi

name="$1"
zkir="$2"
marker_port="$3"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The pinned Compact toolchain — the same file compile-baseline.sh and measure-zkir.sh source.
# `ensure_image` is called in the header block below, before any key work begins.
# shellcheck source=scripts/toolchain.sh
. "$repo_root/scripts/toolchain.sh"

out_dir="$repo_root/generated/keys/$name"
params_dir="$repo_root/generated/zk-params"
container="minocrab-port-keygen-${name}"
timeout_seconds=7200
cpus=4
memory=20g

test -f "$zkir"
test -d "$params_dir"

# HARD SINGLE-ATTEMPT GUARD: refuse to run if a previous attempt already produced output here.
if [ -e "$out_dir" ]; then
  echo "REFUSING: $out_dir already exists — a previous keygen result stands." >&2
  echo "Move or remove it deliberately if you really mean to re-key." >&2
  exit 97
fi

if lsof -nP -iTCP:"$marker_port" -sTCP:LISTEN >/dev/null 2>&1 || \
   nc -z 127.0.0.1 "$marker_port" >/dev/null 2>&1; then
  echo "marker port is busy: $marker_port" >&2
  exit 98
fi

mkdir -p "$out_dir"

# `zkir-v3 compile` writes a transient `.bzkir` NEXT TO ITS INPUT, so the IR mount cannot be `:ro`
# (a `:ro` IR mount dies in ~0.3 s with `Read-only file system (os error 30)` before any key work
# begins). The input ZKIR must stay untouched, so it is STAGED into a writable scratch directory and
# that is what the container sees. The staged copy is re-hashed here and the hash is printed, so the
# log proves the container was fed the same bytes.
zkir_dir="$repo_root/generated/ir-stage/$name"
zkir_base="$(basename "$zkir")"
key_base="${zkir_base%.zkir}"
rm -rf "$zkir_dir"
mkdir -p "$zkir_dir"
cp "$zkir" "$zkir_dir/$zkir_base"
chmod u+w "$zkir_dir/$zkir_base"

watchdog_flag="$(mktemp "${TMPDIR:-/tmp}/minocrab-port-keygen-watchdog.XXXXXX")"
rm -f "$watchdog_flag"

cleanup() {
  kill "${watchdog_pid:-}" >/dev/null 2>&1 || true
  wait "${watchdog_pid:-}" >/dev/null 2>&1 || true
  kill "${sampler_pid:-}" >/dev/null 2>&1 || true
  wait "${sampler_pid:-}" >/dev/null 2>&1 || true
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -f "$watchdog_flag" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "KEYGEN_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "ARM=$name"
echo "ZKIR=$zkir"
echo "ZKIR_BYTES=$(wc -c < "$zkir" | tr -d ' ')"
echo "ZKIR_SHA256=$(shasum -a 256 "$zkir" | cut -d ' ' -f 1)"
echo "ZKIR_STAGED=$zkir_dir/$zkir_base"
echo "ZKIR_STAGED_SHA256=$(shasum -a 256 "$zkir_dir/$zkir_base" | cut -d ' ' -f 1)"
echo "MARKER_PORT=$marker_port"
echo "BOUNDS=cpus:$cpus,memory:$memory,memory-swap:$memory,wall-seconds:$timeout_seconds,network:none"
echo "ATTEMPTS_AUTHORIZED=1"
ensure_image
image="$COMPACTC_IMAGE"
echo "TOOL=/opt/compactc/zkir-v3 compile"
echo "DOCKER_VM_MEMTOTAL=$(docker info --format '{{.MemTotal}}')"
echo "DOCKER_VM_NCPU=$(docker info --format '{{.NCPU}}')"
echo "HOST_LOADAVG=$(sysctl -n vm.loadavg)"
echo "KEY_FILES_BEFORE=$(find "$repo_root" -name '*.prover' -o -name '*.verifier' | wc -l | tr -d ' ')"
echo "MIDNIGHT_PP=/params (pre-fetched and hash-pinned; the container stays network:none)"
echo "SRS_INVENTORY:"
for f in "$params_dir"/bls_midnight_2p*; do
  printf '  %-22s %12s  %s\n' "$(basename "$f")" "$(wc -c < "$f" | tr -d ' ')" "$(shasum -a 256 "$f" | cut -d ' ' -f 1)"
done

# Watchdog: hard wall bound. Never inherits stdout/stderr.
(
  sleep "$timeout_seconds"
  if docker inspect "$container" >/dev/null 2>&1; then
    : > "$watchdog_flag"
    docker kill "$container" >/dev/null 2>&1 || true
  fi
) >/dev/null 2>&1 &
watchdog_pid=$!

# Live observation checkpoints every 30 s, so an OOM or a stall is diagnosable from the log alone.
(
  while true; do
    sleep 30
    if docker inspect "$container" >/dev/null 2>&1; then
      stat=$(docker stats --no-stream --format '{{.MemUsage}} cpu={{.CPUPerc}}' "$container" 2>/dev/null || true)
      [ -n "$stat" ] && echo "CHECKPOINT $(date -u +%H:%M:%SZ) $stat"
    else
      break
    fi
  done
) &
sampler_pid=$!

set +e
/usr/bin/time -p docker run --rm --network none \
  --name "$container" --cpus "$cpus" --memory "$memory" --memory-swap "$memory" \
  -e MINOCRAB_PORT_MARKER="$marker_port" \
  -v "$params_dir:/params:ro" -e MIDNIGHT_PP=/params \
  -v "$zkir_dir:/ir" \
  -v "$out_dir:/out" \
  -w /out \
  "$image" \
  /opt/compactc/zkir-v3 compile "/ir/$zkir_base" "/out/$key_base.prover" "/out/$key_base.verifier"
keygen_exit=$?
set -e

kill "$sampler_pid" >/dev/null 2>&1 || true
wait "$sampler_pid" >/dev/null 2>&1 || true
sampler_pid=""
kill "$watchdog_pid" >/dev/null 2>&1 || true
wait "$watchdog_pid" >/dev/null 2>&1 || true
watchdog_pid=""

echo "KEYGEN_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "KEYGEN_EXIT=$keygen_exit"
echo "WATCHDOG_TIMEOUT=$( [ -e "$watchdog_flag" ] && echo 1 || echo 0 )"
echo "OUT_DIR=$out_dir"
echo "KEY_FILE_INVENTORY (bytes, sha256, path):"
find "$out_dir" \( -name '*.prover' -o -name '*.verifier' \) -print0 \
  | sort -z \
  | while IFS= read -r -d '' f; do
      printf '  %12s  %s  %s\n' "$(wc -c < "$f" | tr -d ' ')" "$(shasum -a 256 "$f" | cut -d ' ' -f 1)" "${f#"$out_dir"/}"
    done
echo "TOTAL_KEY_BYTES=$(find "$out_dir" \( -name '*.prover' -o -name '*.verifier' \) -exec wc -c {} + 2>/dev/null | tail -1 | awk '{print $1}')"
echo "KEY_FILES_OUTSIDE_GITIGNORED_PATH=$(find "$repo_root" -name '*.prover' -o -name '*.verifier' | grep -cv '^'"$repo_root"'/generated/' || true)"
exit "$keygen_exit"
