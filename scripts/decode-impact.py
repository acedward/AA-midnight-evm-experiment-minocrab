#!/usr/bin/env python3
"""Decode the `impact` instruction stream of a compactc ZKIR into readable Impact ops.

Encoding mirrors `Op::<ResultModeVerify>::field_repr` in
midnight-ledger/onchain-vm/src/ops.rs and the FAB `AlignedValue`/`StateValue`
field reprs in transient-crypto/src/fab.rs + onchain-state/src/state.rs.
"""
import json
import sys

FR_BYTES_STORED = 31


def is_imm(tok):
    return isinstance(tok, str) and tok.startswith("0x")


# The field modulus (BLS12-381 scalar field). compactc serializes small negative field
# elements as `-0x01`; minocrab serializes the same element as its reduced representative. Both
# parse to the same `Fr`, so the decoder normalizes to a signed view for the few opcodes (only
# `Key::Stack`) that use one.
FR_MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001


def imm(tok):
    v = int(tok, 16)
    if v > FR_MODULUS // 2:
        v -= FR_MODULUS
    return v


class Cursor:
    def __init__(self, toks):
        self.toks = toks
        self.i = 0

    def peek(self):
        return self.toks[self.i]

    def take(self):
        t = self.toks[self.i]
        self.i += 1
        return t

    def take_imm(self):
        t = self.take()
        if not is_imm(t):
            raise ValueError(f"expected immediate, got {t!r}")
        return imm(t)

    def done(self):
        return self.i >= len(self.toks)


def read_alignment(cur):
    """Returns (segments, field_len)."""
    n = cur.take_imm()
    segs = []
    total = 0
    for _ in range(n):
        a = cur.take_imm()
        # atoms: length (positive); Compress = -1, Field = -2 encoded as huge field
        # values -- our contract only uses Bytes{n}, so assume small positives.
        segs.append(a)
        total += -(-a // FR_BYTES_STORED) if a > 0 else 1
    return segs, total


def read_aligned_value(cur):
    segs, flen = read_alignment(cur)
    limbs = [cur.take() for _ in range(flen)]
    return {"align": segs, "limbs": limbs}


def read_state_value(cur):
    tag = cur.take_imm()
    if tag == 0:
        return {"kind": "Null"}
    if tag == 1:
        return {"kind": "Cell", "value": read_aligned_value(cur)}
    if (tag & 0xF) == 2:
        size = tag >> 4
        entries = []
        for _ in range(size):
            entries.append((read_aligned_value(cur), read_state_value(cur)))
        return {"kind": "Map", "entries": entries}
    if (tag & 0xF) == 3:
        n = tag >> 4
        return {"kind": "Array", "elems": [read_state_value(cur) for _ in range(n)]}
    raise ValueError(f"unhandled StateValue tag {tag:#x}")


def decode_ops(toks):
    cur = Cursor(toks)
    ops = []
    while not cur.done():
        t = cur.peek()
        if not is_imm(t):
            raise ValueError(f"op stream starts with an operand: {t!r}")
        b = cur.take_imm()
        if b == 0x00:
            ops.append("noop")
        elif b == 0x01:
            ops.append("lt")
        elif b == 0x02:
            ops.append("eq")
        elif b == 0x03:
            ops.append("type")
        elif b == 0x04:
            ops.append("size")
        elif b == 0x05:
            ops.append("new")
        elif b == 0x06:
            ops.append("and")
        elif b == 0x07:
            ops.append("or")
        elif b == 0x08:
            ops.append("neg")
        elif b == 0x09:
            ops.append("log")
        elif b == 0x0A:
            ops.append("root")
        elif b == 0x0B:
            ops.append("pop")
        elif b in (0x0C, 0x0D):
            av = read_aligned_value(cur)
            ops.append(f"popeq{'_cached' if b == 0x0D else ''}({fmt_av(av)})")
        elif b == 0x0E:
            ops.append(f"addi({fmt_av(read_aligned_value(cur))})")
        elif b == 0x0F:
            ops.append(f"subi({fmt_av(read_aligned_value(cur))})")
        elif b in (0x10, 0x11):
            sv = read_state_value(cur)
            ops.append(f"push{'_s' if b == 0x11 else ''}({fmt_sv(sv)})")
        elif b == 0x12:
            ops.append(f"branch({cur.take()})")
        elif b == 0x13:
            ops.append(f"jmp({cur.take()})")
        elif b == 0x14:
            ops.append("add")
        elif b == 0x15:
            ops.append("sub")
        elif b in (0x16, 0x17):
            ops.append(f"concat{'_c' if b == 0x17 else ''}({cur.take()})")
        elif b == 0x18:
            ops.append("member")
        elif b in (0x19, 0x1A):
            ops.append(f"rem{'_c' if b == 0x1A else ''}")
        elif 0x30 <= b <= 0x3F:
            ops.append(f"dup({b & 0xF})")
        elif 0x40 <= b <= 0x4F:
            ops.append(f"swap({b & 0xF})")
        elif 0x50 <= b <= 0x8F:
            base = b & 0xF0
            n = (b & 0xF) + 1
            kind = {0x50: "idx", 0x60: "idx_c", 0x70: "idx_p", 0x80: "idx_cp"}[base]
            path = []
            for _ in range(n):
                nxt = cur.peek()
                if is_imm(nxt) and imm(nxt) == -1:
                    cur.take()
                    path.append("STACK")
                else:
                    path.append(fmt_av(read_aligned_value(cur)))
            ops.append(f"{kind}([{', '.join(path)}])")
        elif 0x90 <= b <= 0x9F:
            ops.append(f"ins({b & 0xF})")
        elif 0xA0 <= b <= 0xAF:
            ops.append(f"ins_c({b & 0xF})")
        elif b == 0xFF:
            ops.append("ckpt")
        else:
            raise ValueError(f"unknown opcode {b:#x} at token {cur.i}")
    return ops


def fmt_av(av):
    return f"<{'+'.join(str(a) for a in av['align'])}>[{', '.join(av['limbs'])}]"


def fmt_sv(sv):
    if sv["kind"] == "Cell":
        return "cell" + fmt_av(sv["value"])
    if sv["kind"] == "Null":
        return "null"
    if sv["kind"] == "Map":
        return f"map({len(sv['entries'])})"
    if sv["kind"] == "Array":
        return f"array({len(sv['elems'])})"
    return sv["kind"]


def main():
    path = sys.argv[1]
    d = json.load(open(path))
    n = 0
    for k, ins in enumerate(d["instructions"]):
        if ins.get("op") != "impact":
            continue
        n += 1
        guard = ins["guard"]
        try:
            ops = decode_ops(ins["inputs"])
        except Exception as e:  # noqa
            ops = [f"!!DECODE FAILED: {e} :: {ins['inputs']}"]
        print(f"[{n:3d}] @{k:5d} guard={guard:<24} {' ; '.join(ops)}")
    print(f"total impact instructions: {n}")


if __name__ == "__main__":
    main()
