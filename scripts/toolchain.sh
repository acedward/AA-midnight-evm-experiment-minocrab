#!/usr/bin/env bash
#
# toolchain.sh — THE ONE PLACE THE COMPACT TOOLCHAIN IS PINNED, and the code that obtains it.
#
# WHY THIS FILE EXISTS
#   `compile-baseline.sh` (the reference artifact), `measure-zkir.sh` (the (k, rows) oracle) and
#   `keygen-zkir.sh` (the proving keys) all need the same toolchain, obtained the same way and
#   checked the same way. Until 2026-09-04 each carried its own copy of a DIGEST-PINNED LOCAL IMAGE
#   NAME that no host but one could resolve, so a fresh clone could not run any of them. This is
#   the single copy, and it obtains the toolchain itself.
#   Source it (`. "$(dirname "$0")/toolchain.sh"`) and call `ensure_image` before the first
#   `docker run`. Run it directly (`scripts/toolchain.sh`) to obtain the image and print its
#   identity.
#
# NOTE WHAT IS *NOT* PINNED HERE. The port's own ZKIR is emitted by the MinoCrab eDSL and never
#   touches `compactc`; its provenance is the `minocrab` rev in the root `Cargo.toml`. This file
#   pins the REFERENCE side (the compactc baseline the differential suite compares against) and the
#   `zkir-v3` binary that measures and keys BOTH sides. See docker/compactc.Dockerfile.
#
# WHAT IS PINNED — compiler 0.34.0, language 0.26.0, Compact runtime 0.19.0 (Midnight ledger 9),
#   the toolchain the product repository pins on `main`.
#   The pin of record is the RELEASE ARCHIVE SHA-256 in docker/compactc.Dockerfile, verified with
#   `sha256sum -c` while the image is built. Everything below is a way of getting that archive's
#   binaries onto this host and then PROVING that is what arrived:
#     * `compactc --version` and `--language-version` must equal the expected pair, and
#     * `compactc.bin` and `zkir-v3` must hash to the values recorded here.
#   `ensure_image` also leaves the two OBSERVED binary hashes in $TOOLCHAIN_COMPACTC_BIN_SHA256 and
#   $TOOLCHAIN_ZKIR_V3_SHA256 for callers that record toolchain provenance
#   (`check-port-artifacts.sh` writes both into `fixtures/port-artifact-hashes.json`).
#   The second check is what makes a pulled image as trustworthy as a locally built one: an image
#   tag is mutable and an image ID is not reproducible across rebuilds — two byte-identical builds
#   of the same pinned archive get different IDs — but the compiler binaries are the artifact that
#   actually decides every reference ZKIR byte and every key.
#
# HOW THE IMAGE IS OBTAINED (in order)
#   1. If $COMPACTC_IMAGE already exists locally, use it. (Set COMPACTC_IMAGE=<ref> to point the
#      scripts at any other build — that override is how a second toolchain is driven, e.g. to
#      re-derive a 0.33.0-era artifact.)
#   2. Else, if $COMPACTC_PUBLISHED_IMAGE is non-empty, pull it and tag it as $COMPACTC_IMAGE. It
#      is only ever a CACHE of the archive, so it is pinned by digest when it is set at all.
#   3. Else build docker/compactc.Dockerfile, which fetches the release archive and verifies its
#      SHA-256. This is the self-healing path: it works on any arm64 host with a network, and it
#      needs nobody to have published anything.
#   Either way the verification above runs. A mismatch is a hard failure (exit 70), never a warning.
#
# HISTORY. Until 2026-09-04 all three scripts defaulted to
# `aa00006-compactc@sha256:f57ca2d88cec1c66f377eb8bb2d616779202dd1ccb99517a4f7ddfffa9d0d86b`
# (compiler 0.33.0 / language 0.25.0) — a LOCAL tag that no registry can serve, which the README
# had to tell every reader to replace by hand with "your own compactc 0.33.0 image". Measured on
# 2026-09-04: the 0.34.0 toolchain reproduces all nine 0.33.0 baseline ZKIR hashes from the same
# contract source, and its `zkir-v3` reproduces every (k, rows) pair and every `.bzkir` byte for
# the port's own ZKIRs, so nothing published under the old pin needed re-measuring.

# The pinned toolchain: Compact compiler 0.34.0, language 0.26.0.
COMPACTC_IMAGE="${COMPACTC_IMAGE:-aa-compactc:0.34.0}"
COMPACTC_VERSION_EXPECTED="0.34.0"
COMPACTC_LANGUAGE_EXPECTED="0.26.0"

# A published copy of the same archive, pinned by digest, used as a cache when it is set. Empty
# means "there is no published image": the Dockerfile build is then the only path, and that is a
# supported, fully verified configuration rather than a degraded one.
COMPACTC_PUBLISHED_IMAGE="${COMPACTC_PUBLISHED_IMAGE:-}"

# The compiler binaries inside the 0.34.0 archive
# (compactc_v0.34.0_aarch64-unknown-linux-musl.zip, sha256 d3e292c4…).
COMPACTC_BIN_SHA256_EXPECTED="628b343f9b0ebe32e6e6a141b6f73cc66edb19c516a4817b478c3b47f74230d5"
ZKIR_V3_SHA256_EXPECTED="6a91308419d24bc0633210897d10c7c1b2193444e8bde09ce763e9556cb8f93a"

toolchain_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ensure_image() {
  if ! docker image inspect "$COMPACTC_IMAGE" >/dev/null 2>&1; then
    if [ -n "$COMPACTC_PUBLISHED_IMAGE" ]; then
      echo "pulling $COMPACTC_PUBLISHED_IMAGE (published cache of the pinned archive)"
      docker pull -q "$COMPACTC_PUBLISHED_IMAGE" >/dev/null
      docker tag "$COMPACTC_PUBLISHED_IMAGE" "$COMPACTC_IMAGE"
    else
      echo "building $COMPACTC_IMAGE from docker/compactc.Dockerfile (the release archive is SHA-256 pinned)"
      docker build -q -f "$toolchain_repo_root/docker/compactc.Dockerfile" \
        -t "$COMPACTC_IMAGE" "$toolchain_repo_root" >/dev/null
    fi
  fi

  local ver lang bin_sha zkir_sha
  ver="$(docker run --rm --network none "$COMPACTC_IMAGE" compactc --version | tr -d '[:space:]')"
  lang="$(docker run --rm --network none "$COMPACTC_IMAGE" compactc --language-version | tr -d '[:space:]')"
  bin_sha="$(docker run --rm --network none "$COMPACTC_IMAGE" sha256sum /opt/compactc/compactc.bin | cut -d ' ' -f 1)"
  zkir_sha="$(docker run --rm --network none "$COMPACTC_IMAGE" sha256sum /opt/compactc/zkir-v3 | cut -d ' ' -f 1)"

  echo "IMAGE=$COMPACTC_IMAGE"
  echo "IMAGE_ID=$(docker image inspect "$COMPACTC_IMAGE" --format '{{.Id}}')"
  echo "COMPILER_VERSION=$ver"
  echo "LANGUAGE_VERSION=$lang"
  echo "COMPACTC_BIN_SHA256=$bin_sha"
  echo "ZKIR_V3_SHA256=$zkir_sha"

  [ "$ver" = "$COMPACTC_VERSION_EXPECTED" ] \
    || { echo "pinned toolchain mismatch: compiler $ver, expected $COMPACTC_VERSION_EXPECTED" >&2; exit 70; }
  [ "$lang" = "$COMPACTC_LANGUAGE_EXPECTED" ] \
    || { echo "pinned toolchain mismatch: language $lang, expected $COMPACTC_LANGUAGE_EXPECTED" >&2; exit 70; }
  [ "$bin_sha" = "$COMPACTC_BIN_SHA256_EXPECTED" ] \
    || { echo "pinned toolchain mismatch: compactc.bin $bin_sha, expected $COMPACTC_BIN_SHA256_EXPECTED" >&2; exit 70; }
  [ "$zkir_sha" = "$ZKIR_V3_SHA256_EXPECTED" ] \
    || { echo "pinned toolchain mismatch: zkir-v3 $zkir_sha, expected $ZKIR_V3_SHA256_EXPECTED" >&2; exit 70; }

  # Publish what was OBSERVED in the image (not the constants above) so a caller can record
  # provenance without re-running `docker`. Unlike an image ID these two hashes are reproducible:
  # any host that builds or pulls the pinned archive gets the same values, so a rebuilt image
  # produces no spurious drift in a recorded baseline.
  TOOLCHAIN_COMPACTC_BIN_SHA256="$bin_sha"
  TOOLCHAIN_ZKIR_V3_SHA256="$zkir_sha"
}

# Executed rather than sourced: obtain the toolchain and print what arrived.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  set -euo pipefail
  ensure_image
  echo "TOOLCHAIN_OK"
fi
