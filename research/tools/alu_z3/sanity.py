#!/usr/bin/env python3
"""Non-vacuity + sensitivity checks for alu_z3_int.py.
(1) completeness: for edge/random (A, B), the model is SAT with C == reference (not over-constrained).
(2) sensitivity: re-introduce known historical bugs by dropping one constraint; z3 must find a forged C.
"""
import random, sys, time
import alu_z3_int as m
from z3 import *

EDGE = [0, 1, 2, 31, 32, 0x7fffffff, 0x80000000, 0xffffffff, 0xfffffffe, 0x80000001]
rng = random.Random(7)
PAIRS = [(a, b) for a in EDGE for b in EDGE] + [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(10)]

def complete(op):
    bad = []
    for a, b in PAIRS:
        s, cols = m.model(op); s.set("timeout", 60000)
        s.add(cols["A"] == a, cols["B"] == b)
        exp = simplify(m.ref(op, BitVecVal(a, 32), BitVecVal(b, 32))).as_long()
        s.add(cols["C"] == exp)
        r = s.check()
        if r != sat: bad.append((hex(a), hex(b), str(r)))
    return bad

def sensitive():
    cases = [("Mulhu", "mul_lo_limbs"), ("Div", "divz_b"), ("Sll", "sll_qh3"), ("Srl", "rshift_t"), ("Mulh", "mulh_borrow_bool")]
    for op, tag in cases:
        m.DROP.clear(); m.DROP.add(tag)
        t = time.time(); r = m.run(op, 600000, "out"); m.DROP.clear()
        print("drop", tag, "->", op, r.get("wrong_output"), {k: r["witness"][k] for k in ("A", "B", "C")} if "witness" in r else "", round(time.time() - t, 1), flush=True)

if __name__ == "__main__":
    # usage: python3 sanity.py --sensitivity   (the five drop-a-constraint regressions)
    #        python3 sanity.py [OP ...]        (completeness on edge + random pairs; default every op)
    if sys.argv[1:] == ["--sensitivity"]:
        sensitive()
    else:
        for op in sys.argv[1:] or m.OPS:
            t = time.time()
            print(op, "incomplete pairs:", complete(op), round(time.time() - t, 1), flush=True)
