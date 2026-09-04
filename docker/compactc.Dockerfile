# The pinned Compact toolchain: compiler 0.34.0, language 0.26.0, Compact runtime 0.19.0.
#
# WHAT THIS IMAGE IS FOR IN *THIS* REPOSITORY — and what it is not.
#   Nothing in this repository is compiled by `compactc`. The port's ZKIR comes out of the MinoCrab
#   Rust eDSL (`cargo run -p manager-port --bin emit-zkir`), which needs no Compact toolchain at
#   all. This image is here for the two jobs that DO need the reference toolchain, and both of them
#   are measurement or keying, never emission:
#
#     1. THE REFERENCE SIDE OF THE COMPARISON — `scripts/compile-baseline.sh` compiles the ported
#        `.compact` contract with `compactc --skip-zk` to produce the baseline artifact the
#        differential suite (`--features compactc-baseline`) compares this port against, circuit by
#        circuit and run by run.
#     2. THE ONE ORACLE FOR BOTH SIDES — `scripts/measure-zkir.sh` (`zkir-v3 mock-compile`, the
#        (k, rows) measurement) and `scripts/keygen-zkir.sh` (`zkir-v3 compile`, the proving and
#        verifying keys) drive the SAME `zkir-v3` binary over a compactc-emitted ZKIR and over a
#        MinoCrab-emitted one. That the tool is identical on both sides is what makes the headline
#        row comparison, and the key sizes, sound. See the note at the top of `keygen-zkir.sh`.
#
#   So: the pin below is the provenance record of every *reference* number and every *key* this
#   repository publishes. The port's own ZKIR hashes are decided by the MinoCrab rev in
#   `Cargo.toml`, not by anything in here.
#
# THE PIN THAT MATTERS is the RELEASE ARCHIVE by SHA-256 below: it is checked with `sha256sum -c`
# during the build, so the build cannot silently drift, and it is reproducible on any host from the
# upstream release page. A published image would only ever be a cache of this archive;
# `scripts/toolchain.sh` verifies `compactc --version`, `--language-version` and the SHA-256 of
# both binaries (`compactc.bin`, `zkir-v3`) whichever way the image arrives.
#
# WHY 0.34.0. It is the official toolchain for Midnight ledger 9 (release `compactc-v0.34.0`,
# published 2026-08-25, marked Latest) and it is what the product repository
# (acedward/AA-midnight-evm-experiment-v3) pins on `main` since its PR #11. The port must be
# measured against the product's current compiler, not a superseded one.
#
# LANGUAGE 0.26.0 makes `Secp256k1Point`, `Secp256k1Base`, `Secp256k1Scalar`, `JubjubPoint` and
# `JubjubScalar` standard-library imports rather than built-ins, removes the std-lib `add`/`mul`
# circuits in favour of infix operators, makes `secp256k1EthereumAddress` assert a non-identity
# input, and fixes defects #588/#590/#608/#609/#704 in the secp256k1 and hashing paths.
#
# MEASURED CONSEQUENCE FOR THIS REPOSITORY: NONE — and that is a result, not an assumption.
# Compiling the pinned contract source (sha256 `164cf112…`, byte-identical across the product's
# 0.33.0→0.34.0 migration) with this image reproduces all nine 0.33.0 baseline ZKIR hashes exactly,
# and this image's `zkir-v3` reproduces every (k, rows) pair and every `.bzkir` byte the 0.33.0
# `zkir-v3` produced for the port's own ZKIRs — `execute` included, at k=18 / 211,056 rows. The
# toolchain move therefore invalidates none of the published numbers.
#
# TRANSPORT MOVED ONCE, IDENTITY DID NOT. Upstream relocated from `midnightntwrk/compact` to
# `LFDT-Minokawa/compact` during the 0.33.0 era and the old release URLs now 404. Everything since
# is served from the LFDT-Minokawa release pages, which is where the archive below comes from.
#
# ARCHITECTURE. The pinned asset is `aarch64-unknown-linux-musl`, so THIS FILE BUILDS AN arm64
# IMAGE and the resulting binaries run on arm64 only. Upstream publishes an `x86_64` asset from the
# same release; building for x86_64 means switching both the URL and the SHA-256, which is a
# deliberate re-pin and would need its own verification that the outputs are identical. Until that
# is done, the toolchain here is arm64.
#
# HISTORY (0.33.0, superseded 2026-09-04). Every number in the README up to that date was measured
# with a compiler 0.33.0 / language 0.25.0 image that was built locally and is **not publicly
# pullable** — the scripts pinned it by digest as `aa00006-compactc@sha256:f57ca2d8…`, a local tag
# no registry can ever serve, so a fresh clone could not reproduce the reference side at all. That
# is exactly why the archive, and not an image, is now the pin. The 0.33.0 toolchain itself remains
# reproducible from the LFDT-Minokawa release page: asset
# `compactc_v0.33.0-rc.2_aarch64-unknown-linux-musl.zip`, archive SHA-256
# `3aa23812b0b086dbce07da3931a40dcb01bec9676b1ceed7f2d0be370ab2dc46`, whose binaries hash to
# `compactc.bin` `2abdacfddf1b8ccc85ce6f4317b7a75b9f53641de6df0f387f86819084d10947` and `zkir-v3`
# `75153f473f8d1920fcbfc6c207e1038c9049bd0f17ae88c81367cd08c3522176` — swap the two ARGs below to
# rebuild it if an older artifact ever has to be re-derived.

FROM alpine:3.22

RUN apk add --no-cache libstdc++ libgcc unzip curl bash

ARG COMPACTC_URL=https://github.com/LFDT-Minokawa/compact/releases/download/compactc-v0.34.0/compactc_v0.34.0_aarch64-unknown-linux-musl.zip
ARG COMPACTC_SHA256=d3e292c4f48e257dcd6b3d3e3e4743d7d8ea0729f48953eab91a366d44cd026d

RUN set -eux; \
    curl -sSL -o /tmp/compactc.zip "$COMPACTC_URL"; \
    echo "${COMPACTC_SHA256}  /tmp/compactc.zip" | sha256sum -c -; \
    mkdir -p /opt/compactc; \
    unzip -q /tmp/compactc.zip -d /opt/compactc; \
    chmod +x /opt/compactc/compactc /opt/compactc/compactc.bin /opt/compactc/zkir \
             /opt/compactc/zkir-v3 /opt/compactc/fixup-compact /opt/compactc/format-compact; \
    rm -f /tmp/compactc.zip

ENV PATH="/opt/compactc:${PATH}"
WORKDIR /work
ENTRYPOINT []
CMD ["compactc", "--version"]
