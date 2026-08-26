#!/usr/bin/env python3
"""Diff the LEDGER EVENT SEQUENCE of two ZKIR artifacts (Phase 4 development aid).

The equivalence gate (Q3 bar A) is `pi_skips` + PI-vector identity on a shared
`ProofPreimage`, which is a statement about the run.  This script is the *static*
counterpart the Phase-3 executor used at milestone 3.6a: it lists, in order, every
instruction that touches the transcript — `impact` (a ledger op) and `public_input`
(a gate that consumes a ledger answer) — with its decoded op and a CANONICALIZED
guard, and diffs two artifacts position by position.

Guards are canonicalized because the two compilers name wires differently: the
literal `0x01` stays `AMBIENT`, `null` stays `null`, and every other wire becomes
`g<n>` in order of first appearance.  Two artifacts that agree here emit the same
ledger operations, in the same order, under guards that are the same *function* of
earlier guards — which is necessary (not sufficient) for `pi_skips` equality.

    usage: diff-ledger-events.py <a.zkir> <b.zkir>
           diff-ledger-events.py --dump <a.zkir>
"""
import json
import re
import sys

# decode-impact.py has a dash in its name; load it by path.
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "decode_impact", __file__.rsplit("/", 1)[0] + "/decode-impact.py"
)
decode_impact = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(decode_impact)


def canon_guard(g, table):
    if g is None:
        return "null"
    if g == "0x01":
        return "AMBIENT"
    if g.startswith("0x"):
        return f"const:{g}"
    if g not in table:
        table[g] = f"g{len(table)}"
    return table[g]


# `Fr` is serialized as TRIMMED LITTLE-ENDIAN hex by upstream's own serde, which is what
# minocrab writes; compactc's writer spells small negatives as `-0x01` instead. Both parse to
# the same element through the same upstream deserializer (which is why Phase 3's `execute` gate
# was green on the `insertCoin` scenarios), but the two spellings have to be folded together
# before two artifacts can be compared as text.
MINUS_ONE_LE = "0x00000000fffffffffe5bfeff02a4bd5305d8a10908d83933487d9d2953a7ed73"

WIRE = re.compile(r"%[A-Za-z0-9_.]+")


def norm_tokens(toks):
    return ["-0x01" if t == MINUS_ONE_LE else t for t in toks]


def events(path):
    d = json.load(open(path))
    table = {}
    out = []
    for k, ins in enumerate(d["instructions"]):
        op = ins.get("op")
        if op == "impact":
            toks = norm_tokens(ins["inputs"])
            try:
                ops = " ; ".join(decode_impact.decode_ops(toks))
            except Exception as e:  # noqa: BLE001
                # decode-impact.py does not model a stack key under `idxc`/`idxcp`; both sides
                # fail identically, so the NORMALIZED token list is what gets compared.
                ops = f"!!UNDECODED :: {toks}"
            # Operand wire names differ between compilers; keep the op SHAPE by replacing
            # every %name with a positional marker.
            shape = WIRE.sub("%", ops)
            out.append((f"impact[{canon_guard(ins['guard'], table)}]", shape, k))
        elif op == "public_input":
            out.append((f"public_input[{canon_guard(ins['guard'], table)}]", "", k))
    return out


def fmt(e):
    return f"{e[0]:<28} {e[1]}"


def main():
    if sys.argv[1] == "--dump":
        for i, e in enumerate(events(sys.argv[2])):
            print(f"[{i:4d}] @{e[2]:5d} {fmt(e)}")
        return 0

    a, b = events(sys.argv[1]), events(sys.argv[2])
    print(f"A = {sys.argv[1]}: {len(a)} transcript events")
    print(f"B = {sys.argv[2]}: {len(b)} transcript events")
    bad = 0
    for i in range(max(len(a), len(b))):
        ea = a[i] if i < len(a) else None
        eb = b[i] if i < len(b) else None
        ka = (ea[0], ea[1]) if ea else None
        kb = (eb[0], eb[1]) if eb else None
        if ka != kb:
            bad += 1
            if bad <= 25:
                print(f"  [{i:4d}] A: {fmt(ea) if ea else '<none>'}")
                print(f"         B: {fmt(eb) if eb else '<none>'}")
    print(f"MISMATCHED_POSITIONS={bad} OF={max(len(a), len(b))}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
