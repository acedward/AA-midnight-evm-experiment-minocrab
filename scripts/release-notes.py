#!/usr/bin/env python3
"""Turn a release's `manifest.json` into the release body.

The body is GENERATED rather than written, for one reason: a hand-written release note and a
manifest will eventually disagree, and when they do the reader has no way to tell which one is
lying. Everything below comes out of the manifest the assets were produced with, so the page and
the files cannot drift apart. The only prose is the part that is true of every release.

usage: scripts/release-notes.py <manifest.json> [> NOTES.md]
"""

import json
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 64

    m = json.load(open(sys.argv[1]))
    tag = m["tag"]
    circuits = m["circuits"]
    out = []
    w = out.append

    w(f"The AA manager contract, ported to the [MinoCrab](https://github.com/sig-net/minocrab) "
      f"Rust eDSL, with **every circuit keyed**: proving and verifying keys for all "
      f"{len(circuits)} provable circuits, the IR they were generated from, and the hashes that "
      f"identify each one.")
    w("")
    w("## What is here")
    w("")
    w(f"`<circuit>.zkir` (the emitted IR), `.bzkir` (the binary IR `zkir-v3` derives from "
      f"it), `.prover` and `.verifier` — for each circuit below — plus `SHA256SUMS` and "
      f"`manifest.json`. **{m['assets']['releaseFiles']} files**, "
      f"{m['assets']['circuitBytes']:,} bytes of circuit assets.")
    w("")
    w("Individual files, not an archive, so a consumer that needs three kilobytes of verifier key "
      "does not download half a gigabyte to get it. Fetch what you need and check it:")
    w("")
    w("```bash")
    w(f"gh release download {tag} --repo {m['repository']} \\")
    w("    --pattern 'SHA256SUMS' --pattern 'manifest.json' \\")
    w("    --pattern 'execute.verifier' --pattern 'execute.prover'")
    w("sha256sum -c --ignore-missing SHA256SUMS")
    w("```")
    w("")
    w("`SHA256SUMS` covers every file in this release except itself, `manifest.json` included.")
    w("")
    w("## Circuits")
    w("")
    w("| circuit | k | rows | `.prover` | `.verifier` | SRS |")
    w("|---|---:|---:|---:|---:|---|")
    for name, c in sorted(circuits.items(), key=lambda kv: (-kv[1]["k"], kv[0])):
        w(f"| `{name}` | {c['k']} | {c['rows']:,} | {c['prover']['bytes']:,} B "
          f"| {c['verifier']['bytes']:,} B | `{c['srs']}` |")
    w("")
    w("## Exactly what these were built from")
    w("")
    w("| | |")
    w("|---|---|")
    w(f"| commit | [`{m['gitCommit'][:12]}`](https://github.com/{m['repository']}/commit/"
      f"{m['gitCommit']}) |")
    w(f"| MinoCrab rev | [`{m['minocrabRev'][:12]}`](https://github.com/sig-net/minocrab/commit/"
      f"{m['minocrabRev']}) |")
    contract = m.get("contractPin", {})
    if contract.get("commit"):
        w(f"| contract pin | `{contract['commit'][:12]}` "
          f"({len(contract.get('files', {}))} files, hashed in `manifest.json`) |")
    tc = m["toolchain"]
    w(f"| Compact toolchain | {tc['compactcVersion']} / language "
      f"{tc['compactcLanguageVersion']} |")
    w(f"| archive SHA-256 | `{tc['compactcArchiveSha256']}` |")
    w(f"| `zkir-v3` SHA-256 | `{tc['zkirV3Sha256']}` |")
    for srs_name, srs in m["srs"]["used"].items():
        w(f"| SRS k={srs['k']} | `{srs_name}` `{srs['sha256']}` |")
    w("")
    w("These are the identity of the keys, not decoration: the same `.zkir` keyed by a different "
      "`zkir-v3`, or against a different SRS, is a different key. Reproduce any of it with "
      "`scripts/release-artifacts.sh`, which fails rather than publishing if a single recorded "
      "hash moves.")
    w("")
    w("## Read this before you deploy it")
    w("")
    w("The `execute` circuit these keys are for is **tested-equivalent to the Compact contract at "
      "the pinned commit, not proven equivalent**: the differential suite compares this port "
      "against the `compactc` artifact circuit by circuit and run by run, over thousands of "
      "tamper probes, and found no acceptance disagreement — which is evidence, not a proof. The "
      "README states the scope of that claim, and the slot-order caveat, in full.")

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
