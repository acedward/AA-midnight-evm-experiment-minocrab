#!/usr/bin/env bash
#
# check-refs.sh — RESOLVE every `contracts/…compact:NNN` reference in this repository and print the
# line it lands on, so the mapping is reviewable instead of asserted.
#
# WHY IT EXISTS
#   This crate is a transcription. Nearly every module, circuit and comment cites the Compact source
#   it transcribes by file and line, and those citations are the only thing that lets a reader check
#   the port against the contract. They are also the first thing to rot: the product repository
#   split `contracts/manager.compact` into a preset plus nine modules (product `main` @ `41de69d`),
#   which moved every line, and BEFORE that the references had ALREADY drifted — they were written
#   against a snapshot two contract pins older than the one the README pinned, so a reader following
#   `manager.compact:317-319` in the pinned file landed on unrelated code.
#
#   A citation nobody can resolve is worse than no citation, so this script resolves all of them:
#   it prints, for every reference, the file, the line range, and the actual source line, and it
#   fails when a reference points past the end of a file or at a file that does not exist. What it
#   cannot do is tell you the line is the RIGHT one — that is a review, and printing the line is
#   what makes the review a minute's work.
#
# usage:
#   scripts/check-refs.sh [<path-to-the-product-checkout>]
#
#   With no argument it looks for the checkout at $AA_PRODUCT_DIR, then at the sibling paths listed
#   below. The checkout must be the pinned contract commit — the script prints its HEAD and warns
#   loudly when it is not the pin recorded in fixtures/port-artifact-hashes.json.
#
#   --quiet  print only the failures and the summary.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
quiet=0
product=""
for arg in "$@"; do
  case "$arg" in
    --quiet) quiet=1 ;;
    *)       product="$arg" ;;
  esac
done

# The pin the references are anchored to, read from the artifact record rather than duplicated here.
pinned_commit="$(sed -n 's/.*"commit": "\([0-9a-f]\{40\}\)".*/\1/p' "$repo_root/fixtures/port-artifact-hashes.json" | head -1)"

if [ -z "$product" ]; then
  for cand in \
      "${AA_PRODUCT_DIR:-}" \
      "$repo_root/../AA-midnight-evm-experiment-v3" \
      "$repo_root/../00014-manager-split"; do
    [ -n "$cand" ] && [ -d "$cand/contracts" ] && { product="$cand"; break; }
  done
fi

if [ -z "$product" ] || [ ! -d "$product/contracts" ]; then
  cat >&2 <<EOF
no product checkout found — pass it as an argument or set AA_PRODUCT_DIR.

  git clone https://github.com/acedward/AA-midnight-evm-experiment-v3
  git -C AA-midnight-evm-experiment-v3 checkout $pinned_commit
  scripts/check-refs.sh AA-midnight-evm-experiment-v3

The contract source is NOT vendored here on purpose: this repository transcribes it, it does not
copy it, and a stale copy would be a second source of truth.
EOF
  exit 64
fi

product="$(cd "$product" && pwd)"
echo "=== check-refs ==="
echo "PORT=$repo_root"
echo "PRODUCT=$product"
if [ -d "$product/.git" ]; then
  head_sha="$(git -C "$product" rev-parse HEAD)"
  echo "PRODUCT_HEAD=$head_sha"
  echo "PINNED_COMMIT=$pinned_commit"
  if [ "$head_sha" != "$pinned_commit" ]; then
    echo "WARNING: the checkout is NOT at the pinned contract commit — line numbers below are that"
    echo "         checkout's, not the pin's. Check it out at $pinned_commit before believing them."
  fi
fi

PRODUCT="$product" REPO="$repo_root" QUIET="$quiet" python3 - <<'PY'
import os, re, sys

repo = os.environ["REPO"]
product = os.environ["PRODUCT"]
quiet = os.environ["QUIET"] == "1"

REF = re.compile(r'(contracts/(?:modules/)?[A-Za-z0-9_]+\.compact):(\d+)(?:-(\d+))?')
SKIP_DIRS = {".git", "target", "generated", "evidence", ".github"}
EXT = (".rs", ".md", ".sh", ".py", ".toml", ".json")

cache = {}
def lines_of(rel):
    if rel not in cache:
        path = os.path.join(product, rel)
        cache[rel] = open(path).read().split("\n") if os.path.exists(path) else None
    return cache[rel]

refs, failures = [], []
for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for f in sorted(files):
        if not f.endswith(EXT):
            continue
        path = os.path.join(root, f)
        try:
            text = open(path).read()
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.split("\n"), 1):
            for m in REF.finditer(line):
                rel, a = m.group(1), int(m.group(2))
                b = int(m.group(3)) if m.group(3) else a
                refs.append((os.path.relpath(path, repo), lineno, rel, a, b))

# `scripts/check-refs.sh` documents the reference shape in its own header; those mentions are real
# references too and are resolved like any other.
by_file = {}
for rel_src, lineno, rel, a, b in refs:
    by_file.setdefault(rel_src, []).append((lineno, rel, a, b))

for rel_src in sorted(by_file):
    if not quiet:
        print(f"\n--- {rel_src}")
    for lineno, rel, a, b in by_file[rel_src]:
        src = lines_of(rel)
        where = f"{rel}:{a}" + (f"-{b}" if b != a else "")
        if src is None:
            failures.append(f"{rel_src}:{lineno} -> {where}: NO SUCH FILE in the product checkout")
            print(f"  ! {lineno:>5}  {where:<58} NO SUCH FILE")
            continue
        if a < 1 or b > len(src) or a > b:
            failures.append(
                f"{rel_src}:{lineno} -> {where}: out of range (the file has {len(src)} lines)")
            print(f"  ! {lineno:>5}  {where:<58} OUT OF RANGE ({len(src)} lines)")
            continue
        first = src[a - 1].strip()
        if not quiet:
            print(f"    {lineno:>5}  {where:<58} {first[:96]}")
            if b != a:
                print(f"    {'':>5}  {'':<58} … {src[b - 1].strip()[:94]}")

print()
print(f"{len(refs)} reference(s) in {len(by_file)} file(s)")
if failures:
    print(f"CHECK-REFS FAILED — {len(failures)} unresolvable reference(s):")
    for f in failures:
        print(f"  * {f}")
    sys.exit(1)
print("CHECK-REFS OK — every reference resolves inside the product checkout")
PY
